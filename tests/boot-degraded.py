# The gate's 30 seconds for an absent device, nixpkgs' 60-second import loop, 30 seconds
# for the dead disk's swap in stage 2, and room for a VM to do the rest of its boot.
DEGRADED_BOOT_SECONDS = 180
LOST_ENCRYPTED_VOLUMES = re.compile(r"Dependency failed for Local Encrypted Volumes")


def degraded_boot(name, disks, survivor, expected_failed=()):
    boot(disks)
    started = time.monotonic()
    booted = type_until_stage2(target, serial(), timeout=DEGRADED_BOOT_SECONDS)
    took = time.monotonic() - started
    control(name, booted, f"no stage 2 after {took:.0f}s")
    # What nofail on the leg is for. Without it the boot gets through all the same, but the leg
    # brings cryptsetup.target down with it.
    lost = [m.string for m in console_findall(target, LOST_ENCRYPTED_VOLUMES)]
    control(f"{name}-encrypted-volumes-target-holds", lost == [], str(lost))
    status = pool_status()
    control(f"{name}-pool-degraded", "state: DEGRADED" in status, status)
    control(f"{name}-root-up", root_is_the_pool(), target.succeed("findmnt /"))
    leg = re.search(rf"/dev/mapper/{survivor}\s+(\S+)", status)
    control(f"{name}-survivor-online", leg is not None and leg.group(1) == "ONLINE", status)
    target.log(f"{name}: stage 2 {took:.0f}s after the prompt wait began")
    # What a pull deploy reads to decide a node is healthy (lib/cluster-upgrade.nix). A node
    # that lost a disk has alerts to fire, not a closure to blame.
    target.wait_for_unit("multi-user.target")
    failed = target.succeed("systemctl list-units --state=failed,auto-restart --no-legend --plain")
    units = sorted(line.split()[0] for line in failed.splitlines() if line.strip())
    control(f"{name}-failed-units", units == sorted(expected_failed), failed)


def can_switch(name, mode):
    rc, out = target.execute(f"/run/current-system/bin/switch-to-configuration {mode} 2>&1 | tail -n 5", timeout=300)
    control(f"{name}-switch", rc == 0, out)


def unmounted_esp_untouched(name, esp):
    """With its disk gone an ESP's mountpoint is a plain directory on the root, and the boot
    must not write there (nixpkgs points systemd-boot-random-seed at /boot, and bootctl does
    no ESP check of its own on a path given that way). Before boot-security-core ordered the
    seed after the mount, the seed went there on every boot with the first ESP gone.

    Called before any switch, so it covers what the boot wrote and nothing else. A switch
    writing through the unmounted ESP is the guarded hook's `mountpoint -q`, the same check
    whatever unmounted the ESP, and esp-unmounted-guard holds it (mutant
    upstream-install-hook). Checked after the switch here, the upstream hook's write to the
    root would fail this control first and that mutant could never reach its own."""
    rc, _ = target.execute(f"mountpoint -q {esp}")
    written = target.succeed(f"find {esp} -mindepth 1 | head -n 5").strip()
    control(
        f"{name}-unmounted-esp-untouched",
        rc != 0 and written == "",
        f"{esp} mounted: {rc == 0}, written to root: {written!r}",
    )


def disk_dead():
    disks = new_case(a="blank")
    degraded_boot("disk-a-dead", disks, "crypt-b")
    unmounted_esp_untouched("disk-a-dead", "/boot")
    # A real `switch`: the guarded hook skips the ESP that's gone, and that's what keeps a
    # node on one good disk deployable.
    can_switch("disk-a-dead", "switch")
    # A DEGRADED pool isn't a plaintext one, and the audit has to know the difference.
    control("disk-a-dead-audit", audit_metric("cluster_zpool_plain_vdevs") == "0", audit_text())
    power_off()

    disks = new_case(b="blank")
    degraded_boot("disk-b-dead", disks, "crypt-a")
    unmounted_esp_untouched("disk-b-dead", "/boot-fallback")
    can_switch("disk-b-dead", "switch")
    power_off()


def disk_absent():
    """Not exercised before this: no blank disk, no device at all."""
    disks = new_case()
    restore = without_drive("a")
    try:
        degraded_boot("disk-absent", disks, "crypt-b")
        unmounted_esp_untouched("disk-absent", "/boot")
        power_off()
    finally:
        restore()


def disk_luks_header_corrupt():
    disks = new_case()
    installer_up(disks)
    installer.succeed(
        "dd if=/dev/zero of=/dev/disk/by-partlabel/disk-nvme0-luks bs=1M count=32 conv=fsync 2>&1"
    )
    installer.shutdown()
    degraded_boot("disk-luks-header-corrupt", disks, "crypt-b")
    power_off()


def replacement_partitioned_not_formatted():
    """Halfway through replacing a disk, a leg that exists and holds no LUKS header."""
    disks = new_case(a="blank")
    installer_up(disks)
    installer.succeed(
        "sgdisk -n1:0:+1G -t1:EF00 -c1:disk-nvme0-ESP -n2:0:+32G -c2:disk-nvme0-swap "
        "-n3:0:0 -c3:disk-nvme0-luks /dev/disk/by-id/virtio-nvme-a",
        "udevadm settle",
        "test -e /dev/disk/by-partlabel/disk-nvme0-luks",
    )
    installer.shutdown()
    # The new ESP has no filesystem yet either, and systemd's right that it can't be
    # mounted. The operator is mid-replacement and holds the node's deploys, so this one
    # failed unit is expected, for exactly as long as the ESP is unformatted.
    degraded_boot(
        "replacement-partitioned-not-formatted",
        disks,
        "crypt-b",
        expected_failed=("boot.mount",),
    )
    power_off()


def healthy_boot():
    disks = new_case()
    boot(disks)
    booted = type_until_stage2(target, serial())
    control("healthy-boot", booted and both_legs_online(pool_status()), "no healthy boot")
    return disks


def trim_through_dmcrypt():
    granularity = target.succeed("lsblk -D -n -o DISC-GRAN /dev/mapper/crypt-a").strip()
    table = target.succeed("dmsetup table crypt-a")
    target.succeed("zpool trim -w rpool", timeout=300)
    status = target.succeed("zpool status -t rpool")
    legs = re.findall(r"crypt-[ab].*\((\d+)% trimmed", status)
    control(
        "trim-through-dmcrypt",
        granularity not in ("", "0B") and "allow_discards" in table and legs == ["100", "100"],
        f"granularity {granularity!r}, table {table!r}, {status}",
    )


def audit_text():
    target.succeed("systemctl start cluster-boot-audit.service")
    return target.succeed("cat /var/lib/prometheus-node-exporter-text/boot_audit.prom")


def audit_metric(name):
    found = re.search(rf"^{re.escape(name)} (\S+)$", audit_text(), re.M)
    return found.group(1) if found else None


def read_vdevs():
    """The pool's vdevs by path, the kernel's word for what those paths are, and the audit's
    word, on a node as it should be."""
    vdevs = re.findall(r"^\s*(/\S+)", target.succeed("zpool list -vHP rpool"), re.M)
    good = len(vdevs) == 2
    detail = [str(vdevs)]
    for vdev in vdevs:
        name = os.path.basename(vdev)
        table = target.succeed(f"dmsetup table {name}") if vdev.startswith("/dev/mapper/crypt-") else ""
        good = good and " crypt " in table
        detail.append(table)
    for part in ("disk-nvme0-luks", "disk-nvme1-luks"):
        kind = target.succeed(f"blkid -p -o value -s TYPE /dev/disk/by-partlabel/{part}").strip()
        good = good and kind == "crypto_LUKS"
        detail.append(f"{part} {kind}")
    return good, detail, audit_metric("cluster_zpool_plain_vdevs")


def no_plain_vdev(good, detail, clean):
    """And the audit with what it exists to catch added to the pool: a mapping named like a
    leg that isn't dm-crypt, and a plain file. Its own disks, since neither can be taken
    away again, and the file's gone at the next boot."""
    disks = new_case()
    boot(disks)
    control("audit-boot", type_until_stage2(target, serial()), "no boot")
    target.wait_for_unit("multi-user.target")
    metrics = audit_text()
    control(
        "audit-other-metrics",
        'cluster_esp_mounted{esp="/boot"} 1' in metrics
        and 'cluster_esp_mounted{esp="/boot-fallback"} 1' in metrics
        and re.search(r"^cluster_iommu_groups \d+$", metrics, re.M) is not None
        and re.search(r"^cluster_watchdog_device [01]$", metrics, re.M) is not None
        and re.search(r"^cluster_core_pattern_ok [01]$", metrics, re.M) is not None
        and re.search(r"^cluster_tang_vlan_present [01]$", metrics, re.M) is not None,
        metrics,
    )
    target.succeed(
        "truncate -s 256M /dev/shm/fake.img",
        "losetup -f --show /dev/shm/fake.img > /tmp/loop",
        'dmsetup create crypt-fake --table "0 $(blockdev --getsz $(cat /tmp/loop)) linear $(cat /tmp/loop) 0"',
        "zpool add -f -o ashift=12 rpool /dev/mapper/crypt-fake",
    )
    fake = audit_metric("cluster_zpool_plain_vdevs")
    target.succeed(
        "truncate -s 256M /dev/shm/plain.img",
        "zpool add -f -o ashift=12 rpool /dev/shm/plain.img",
    )
    plain = audit_metric("cluster_zpool_plain_vdevs")
    power_off()
    detail.append(f"audit: clean {clean}, fake mapping {fake}, plus plain file {plain}")
    control("no-plain-vdev", good and clean == "0" and fake == "1" and plain == "2", " ".join(detail))


def swap_keys():
    """Each active swap device's mapping table, key included."""
    names = target.succeed("swapon --show=NAME --noheadings --raw").split()
    tables = {}
    for name in names:
        tables[name] = target.succeed(
            f"dmsetup table --showkeys $(lsblk -n -o NAME --raw {name} | head -n 1)"
        )
    return tables


def swap_random_key(disks):
    tables = swap_keys()
    plain = target.succeed("blkid -p -o value -s TYPE /dev/disk/by-partlabel/disk-nvme0-swap || true").strip()
    good = (
        len(tables) == 2
        and all(" crypt " in t for t in tables.values())
        and not any("allow_discards" in t for t in tables.values())
        # The key itself, so that comparing two boots below compares keys.
        and all(re.search(r" crypt \S+ [0-9a-f]{64,} ", t) for t in tables.values())
        and plain != "swap"
    )
    control("swap-is-dm-crypt", good, f"{tables} raw partition type {plain!r}")
    power_off()

    boot(disks)
    booted = type_until_stage2(target, serial())
    control("swap-second-boot", booted, "no second boot")
    again = swap_keys()
    control(
        "swap-random-key",
        tables.keys() == again.keys() and all(tables[n] != again[n] for n in tables),
        f"{tables} then {again}",
    )
    power_off()


def zpool_replace_new_leg():
    """The whole replacement, from a blank disk, on the running node, and a boot off it."""
    disks = new_case(a="blank")
    degraded_boot("replace-starts-degraded", disks, "crypt-b")
    guid = re.search(r"^\s*(\d{10,})\s+\S+\s+.*(?:was|/dev/mapper/crypt-a)", target.succeed("zpool status -g rpool"), re.M)
    control("replace-finds-dead-leg", guid is not None, target.succeed("zpool status -g rpool"))
    device = "/dev/disk/by-id/virtio-nvme-a"
    target.succeed(
        f"sgdisk -n1:0:+1G -t1:EF00 -c1:disk-nvme0-ESP -n2:0:+32G -c2:disk-nvme0-swap -n3:0:0 -c3:disk-nvme0-luks {device}",
        "udevadm settle",
        "mkfs.vfat -F 32 /dev/disk/by-partlabel/disk-nvme0-ESP",
        f"printf %s '{PASSPHRASE}' | cryptsetup luksFormat --type luks2 --batch-mode --key-file=- /dev/disk/by-partlabel/disk-nvme0-luks",
        f"printf %s '{PASSPHRASE}' | cryptsetup open --allow-discards --key-file=- /dev/disk/by-partlabel/disk-nvme0-luks crypt-a",
        f"zpool replace -f rpool {guid.group(1)} /dev/mapper/crypt-a",
    )
    target.wait_until_succeeds("zpool status rpool | grep -q 'scan: resilvered'", timeout=600)
    status = pool_status()
    control("zpool-replace-new-leg", both_legs_online(status), status)
    power_off()

    boot(disks)
    booted = type_until_stage2(target, serial())
    status = pool_status() if booted else ""
    control("zpool-replace-survives-reboot", booted and both_legs_online(status), status)
    power_off()


# ── ESPs ──────────────────────────────────────────────────────────────────


def healthy_node(firmware=None):
    disks = new_case()
    boot(disks, firmware=firmware)
    control("esp-case-boots", type_until_stage2(target, serial()), "no boot")
    target.wait_for_unit("multi-user.target")
    return disks


def second_generation():
    newgen = target.succeed(f"readlink -f {TOPLEVEL}/specialisation/newgen").strip()
    set_generation(newgen)
    return newgen


def esp_boot_each_alone(sealed, sealed_firmware):
    """Under enforcing Secure Boot, each disk's ESP on its own: the firmware has to find it by
    the removable path, its signatures have to hold, and the loader says which one it ran from."""
    for survivor, lost in (("disk-nvme0-ESP", "disk-nvme1-ESP"), ("disk-nvme1-ESP", "disk-nvme0-ESP")):
        disks = new_case(base=sealed)
        installer_up(disks)
        # The whole start of it, not wipefs: firmware's FAT driver doesn't need the signatures
        # wipefs removes, so with only those gone it went on booting from this ESP.
        installer.succeed(f"dd if=/dev/zero of=/dev/disk/by-partlabel/{lost} bs=1M count=64 conv=fsync status=none")
        expected = installer.succeed(f"blkid -p -o value -s PART_ENTRY_UUID /dev/disk/by-partlabel/{survivor}").strip().lower()
        installer.shutdown()
        boot(disks, firmware=new_firmware(sealed_firmware))
        booted = type_until_stage2(target, serial())
        control(f"esp-boot-each-alone-{survivor}-boots", booted, "no stage 2 from this ESP alone")
        # UTF-16 in the EFI variable, four bytes of attributes first.
        loader = target.succeed(
            "tail -c +5 /sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f | tr -d '\\000'"
        ).strip().lower()
        control(
            f"esp-boot-each-alone-{survivor}",
            loader == expected and enforcing() and both_legs_online(pool_status()),
            f"loader ran from {loader}, expected {expected}, {secure_boot_status()}",
        )
        power_off()


def esp_unmounted_and_gone():
    healthy_node()
    target.succeed("umount /boot")
    second_generation()
    rc, out = install_bootloader()
    written = target.succeed("find /boot -mindepth 1 | head -n 5").strip()
    control(
        "esp-unmounted-guard",
        rc == 0
        and "WARNING: /boot is not a mountpoint" in out
        and written == ""
        and len(on_esp("/boot-fallback", 2)) == 1,
        f"rc={rc} written to root: {written!r} {out}",
    )

    target.succeed("umount /boot-fallback")
    rc, out = install_bootloader()
    written = target.succeed("find /boot /boot-fallback -mindepth 1 | head -n 5").strip()
    control(
        "esp-both-gone-refused",
        rc != 0 and "no ESP is mounted, refusing" in out and written == "",
        f"rc={rc} written to root: {written!r} {out}",
    )
    power_off()


def esp_full_refused_then_boots():
    disks = healthy_node()
    # Full, with a stale file from an earlier ENOSPC, on the second ESP in the list. So the first
    # would go ahead if the hook decided one ESP at a time, and has to stay as it is.
    target.succeed(
        "touch /boot-fallback/EFI/nixos/stale..tmp /boot-fallback/EFI/Linux/stale..tmp",
        "dd if=/dev/zero of=/boot-fallback/filler bs=1M status=none || true",
        "sync",
    )
    second_generation()
    rc, out = install_bootloader()
    stale = target.succeed("find /boot-fallback/EFI -name '*.tmp'").strip()
    control(
        "esp-full-refused",
        rc != 0
        and "refusing" in out
        and on_esp("/boot", 2) == []
        and on_esp("/boot-fallback", 2) == []
        and stale == "",
        f"rc={rc} stale {stale!r} {on_esp('/boot', 2)} {on_esp('/boot-fallback', 2)} {out}",
    )
    power_off()

    boot(disks)
    booted = type_until_stage2(target, serial())
    control(
        "esp-full-refused-then-boots",
        booted and booted_closure() == TOPLEVEL,
        f"booted {booted_closure() if booted else None}, expected the old entry {TOPLEVEL}",
    )
    target.wait_for_unit("multi-user.target")

    # A stale file on the next run, with room this time: it goes, and the install goes through.
    target.succeed(
        "rm /boot-fallback/filler",
        "touch /boot-fallback/EFI/nixos/stale..tmp",
    )
    rc, out = install_bootloader()
    stale = target.succeed("find /boot /boot-fallback -name '*.tmp'").strip()
    control(
        "esp-stale-tmp-cleaned-on-the-next-run",
        rc == 0 and stale == "" and len(on_esp("/boot", 2)) == 1 and len(on_esp("/boot-fallback", 2)) == 1,
        f"rc={rc} stale {stale!r} {out}",
    )
    power_off()


def host_key_and_generations():
    """The initrd's host key is appended at install, so it matters only to a new generation."""
    healthy_node()
    target.succeed(f"mv {HOST_KEY_PATH} /root/host-key")
    rc, out = install_bootloader()
    control("unchanged-generation-still-ok", rc == 0, f"rc={rc} {out}")

    second_generation()
    rc, out = install_bootloader()
    control(
        "missing-host-key-new-generation-fails",
        rc != 0 and on_esp("/boot", 2) == [] and on_esp("/boot-fallback", 2) == [],
        f"rc={rc} {on_esp('/boot', 2)} {on_esp('/boot-fallback', 2)} {out}",
    )

    target.succeed(f"mv /root/host-key {HOST_KEY_PATH}")
    rc, out = install_bootloader()
    control(
        "restored-host-key-new-generation-installs",
        rc == 0 and len(on_esp("/boot", 2)) == 1 and len(on_esp("/boot-fallback", 2)) == 1,
        f"rc={rc} {out}",
    )
    power_off()


# ── rescues ───────────────────────────────────────────────────────────────

RESCUE_HOSTID = "deadbeef"


def rescue_opens_legs():
    for letter, label in (("a", "disk-nvme0-luks"), ("b", "disk-nvme1-luks")):
        installer.succeed(
            f"printf %s '{PASSPHRASE}' | cryptsetup open --key-file=- /dev/disk/by-partlabel/{label} crypt-{letter}"
        )


def rescue_system():
    """A rescue system is some other machine as far as the pool can tell."""
    installer.succeed(f"rm -f /etc/hostid; zgenhostid {RESCUE_HOSTID}")
    rescue_opens_legs()


def identity_repair_rehearsal():
    """The row in the install's recovery table, done in order, including the rescue that gets
    interrupted before its export, which leaves a pool the node then refuses to import."""
    disks = new_case()
    installer_up(disks)
    rescue_opens_legs()
    installer.succeed(
        "zpool import -N -d /dev/mapper rpool",
        "mkdir -p /mnt",
        "mount -t zfs rpool/root /mnt",
        f"rm /mnt{IDENTITY_PATH}",
    )
    release_disks()
    installer.shutdown()

    boot(disks)
    said = type_until_console(target, serial(), PASSPHRASE, re.compile("volume-identity: MISMATCH"), timeout=180)
    stopped = wait_console(target, HALTED, 20)
    control("identity-repair-damage-halts", said and stopped is not None, "\n".join(target.full_console_log[-15:]))
    power_off()

    # The halted node never exported its pool, and this is another system. So -f.
    installer_up(disks)
    rescue_system()
    rc, out = installer.execute("zpool import -N -d /dev/mapper rpool 2>&1")
    control("identity-repair-rescue-needs-force", rc != 0, out)
    installer.succeed(
        "zpool import -f -N -d /dev/mapper rpool",
        "mkdir -p /mnt",
        "mount -t zfs rpool/root /mnt",
        f"printf %s '{IDENTITY_SECRET}' | install -m 0400 /dev/stdin /mnt{IDENTITY_PATH}",
        "sync",
    )
    # And here the rescue is interrupted: no umount, no export, power gone.
    installer.crash()

    boot(disks)
    answered = type_until_console(target, serial(), PASSPHRASE, EMERGENCY, timeout=180)
    rc, pools = initrd_ssh("zpool list -H -o name 2>&1")
    control(
        "identity-repair-interrupted-refuses-import",
        answered and rc == 0 and "rpool" not in pools,
        f"rc={rc} {pools}\n" + "\n".join(target.full_console_log[-15:]),
    )
    power_off()

    # Finished properly, the next boot needs nothing else.
    installer_up(disks)
    rescue_system()
    installer.succeed(
        "zpool import -f -N -d /dev/mapper rpool",
        "mkdir -p /mnt",
        "mount -t zfs rpool/root /mnt",
        f"[ \"$(sha256sum < /mnt{IDENTITY_PATH} | cut -d' ' -f1)\" = {IDENTITY_HASH} ]",
        "umount /mnt",
        "zpool export rpool",
        "cryptsetup close crypt-a",
        "cryptsetup close crypt-b",
    )
    installer.shutdown()

    boot(disks)
    booted = type_until_stage2(target, serial())
    journal = target.succeed("journalctl -b -o cat | grep 'volume-identity:' || true") if booted else ""
    control(
        "identity-repair-rehearsal",
        booted and "volume-identity: OK" in journal and both_legs_online(pool_status()),
        journal,
    )
    power_off()


def sbctl_keys_lost_recovery(sealed, sealed_firmware):
    """Signing keys gone with the root intact. The installed generations still boot and no new
    one can be signed. Getting out: new keys, Setup Mode, enroll, and re-sign BEFORE the next
    reboot, because the firmware won't run the old signatures once the new keys are in."""
    disks = new_case(base=sealed)
    firmware = new_firmware(sealed_firmware)
    boot(disks, firmware=firmware)
    control("keys-lost-boots", type_until_stage2(target, serial()), "no boot")
    target.wait_for_unit("multi-user.target")
    target.succeed(f"rm -rf {PKI_BUNDLE}")
    second_generation()
    rc, out = install_bootloader()
    control(
        "keys-lost-new-generation-fails",
        rc != 0 and on_esp("/boot", 2) == [] and on_esp("/boot-fallback", 2) == [],
        f"rc={rc} {out}",
    )
    power_off()

    boot(disks, firmware=firmware)
    control("keys-lost-installed-generation-still-boots", type_until_stage2(target, serial()), "no boot")
    control("keys-lost-still-enforcing", enforcing(), secure_boot_status())
    power_off()

    # The firmware screen: keys cleared, so Setup Mode. Same TPM.
    time.sleep(2)
    (firmware / "vars.fd").unlink()
    boot(disks, firmware=firmware)
    control("keys-lost-setup-mode-boots", type_until_stage2(target, serial()), "no boot in Setup Mode")
    target.wait_for_unit("multi-user.target")
    target.succeed("sbctl create-keys 2>&1")
    rc, out = enroll_keys()
    control("keys-lost-reenroll", rc == 0, out)
    rc, out = install_bootloader()
    control("keys-lost-resign", rc == 0, f"rc={rc} {out}")
    power_off()

    boot(disks, firmware=firmware)
    booted = type_until_stage2(target, serial())
    control(
        "sbctl-keys-lost-recovery",
        booted and enforcing() and both_legs_online(pool_status()),
        secure_boot_status() if booted else "\n".join(target.full_console_log[-15:]),
    )
    power_off()


def main():
    tang.start()
    tang.wait_for_unit("multi-user.target")
    ssh_ready()
    provision()
    disk_dead()
    disk_absent()
    disk_luks_header_corrupt()
    replacement_partitioned_not_formatted()
    esp_unmounted_and_gone()
    disks = healthy_boot()
    trim_through_dmcrypt()
    vdevs = read_vdevs()
    swap_random_key(disks)
    no_plain_vdev(*vdevs)
    zpool_replace_new_leg()

    esp_full_refused_then_boots()
    host_key_and_generations()
    identity_repair_rehearsal()
    sealed, sealed_firmware = sealed_checkpoint()
    esp_boot_each_alone(sealed, sealed_firmware)
    sbctl_keys_lost_recovery(sealed, sealed_firmware)
