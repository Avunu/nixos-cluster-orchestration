ATTACKER = "the-attackers-own-passphrase"
LEGS = (("a", "disk-nvme0-luks"), ("b", "disk-nvme1-luks"))

MISMATCH = re.compile(r"volume-identity: MISMATCH")
PAYLOAD = re.compile(r"FORGED-PAYLOAD-RAN")
SWITCH_ROOT = re.compile(r"Reached target .*Switch Root")
LINUX = re.compile(r"Linux version")
VERDICT = re.compile(r"volume-identity: MISMATCH|FORGED-PAYLOAD-RAN")
# What the TPM said when asked to open a copy of a real LUKS header: from the forged root's
# payload, per leg, and from the emergency shell.
PAYLOAD_ANSWER = re.compile(r"TPM-ANSWER-([ab])=(opened|refused)")
SHELL_ANSWER = re.compile(r"SHELL-ANSWER=(opened|refused)")
BURNED = re.compile(r"emergency-pcr-burn: PCR 7 burned")
BURN_FAILED = re.compile(r"Failed to start .*Extend PCR 7|Dependency failed for .*(Emergency|Rescue)")
EARLY_FAILED = re.compile(r"Failed to start .*Fail before the TPM is up")
SHELL = re.compile(r"RIGHT-SHELL-42")
MARKER = re.compile(r"BURN-MARKER-PRESENT")
# Time for firmware and the stub to get to the kernel, generously, on a loaded build machine.
NO_KERNEL_SECONDS = 90
# A binding that still holds opens both legs in the first seconds of the initrd.
NO_UNLOCK_SECONDS = 45


def seen(regex):
    return console_seen(target, regex)


def tail():
    return "\n".join(target.full_console_log[-25:])


# ── the unsigned parts of the ESP ─────────────────────────────────────────


def unsigned_loader_refused(sealed, sealed_firmware):
    """Firmware keeps the loader from running at all. With Secure Boot off, the very same
    ESP has to start a kernel, or the tampering just broke the file."""
    disks = new_case(base=sealed)
    edit_esp(
        disks,
        "sbattach --remove /e/EFI/BOOT/BOOTX64.EFI",
        "sbattach --remove /e/EFI/systemd/systemd-bootx64.efi",
    )
    boot(disks, firmware=new_firmware(sealed_firmware))
    started = wait_console(target, LINUX, NO_KERNEL_SECONDS)
    control("unsigned-loader-refused", started is None, tail())
    power_off()

    boot(disks)
    started = wait_console(target, LINUX, 180)
    control("unsigned-loader-boots-with-secure-boot-off", started is not None, tail())
    power_off()


def tampered_initrd_refused(sealed, sealed_firmware):
    """The signed stub holds the initrd's hash. The same disks with this one change undone
    are what sealed_checkpoint booted."""
    disks = new_case(base=sealed)
    edit_esp(disks, "for f in /e/EFI/nixos/initrd-*; do printf X >> \"$f\"; done")
    boot(disks, firmware=new_firmware(sealed_firmware))
    started = wait_console(target, LINUX, NO_KERNEL_SECONDS)
    control("tampered-initrd-refused", started is None, tail())
    target.log("tampered-initrd: " + ("the stub said so" if seen(re.compile("hash does not match")) else "no message on the serial console"))
    power_off()


def espread(sealed):
    """What reading the ESP gets you: the hash and the things that have to be there for an
    unattended initrd to work, which section 6 accepts. Never the volume identity secret."""
    disks = new_case(base=sealed)
    installer_up(disks)
    found = {}
    for part in ("disk-nvme0-ESP", "disk-nvme1-ESP"):
        installer.succeed(
            "mkdir -p /e",
            f"mount /dev/disk/by-partlabel/{part} /e",
            "for f in /e/EFI/nixos/initrd-*; do zstd -dcq \"$f\"; done | strings -n 8 > /tmp/initrd.strings",
        )
        for name, needle in (
            ("hash", IDENTITY_HASH),
            ("secret", IDENTITY_SECRET),
            ("host-key", HOST_KEY_LINE),
            ("emergency-hash", EMERGENCY_HASH),
        ):
            rc, _ = installer.execute(f"grep -qF -- {shlex.quote(needle)} /tmp/initrd.strings")
            found[(part, name)] = rc == 0
        rc, _ = installer.execute(f"grep -rqlF -- {shlex.quote(IDENTITY_SECRET)} /e")
        found[(part, "secret-anywhere")] = rc == 0
        installer.succeed("umount /e")
    installer.shutdown()
    wanted = all(
        found[(part, name)]
        for part in ("disk-nvme0-ESP", "disk-nvme1-ESP")
        for name in ("hash", "host-key", "emergency-hash")
    )
    absent = not any(
        found[(part, name)]
        for part in ("disk-nvme0-ESP", "disk-nvme1-ESP")
        for name in ("secret", "secret-anywhere")
    )
    control("espread", wanted and absent, str(found))


# ── forged disks ──────────────────────────────────────────────────────────


def open_real():
    for letter, label in LEGS:
        installer.succeed(
            f"printf %s '{PASSPHRASE}' | cryptsetup open --key-file=- /dev/disk/by-partlabel/{label} crypt-{letter}"
        )
    installer.succeed("zpool import -N -d /dev/mapper rpool")


def open_forged():
    for letter, label in LEGS:
        installer.succeed(
            f"printf %s '{ATTACKER}' | cryptsetup open --key-file=- /dev/disk/by-partlabel/{label} crypt-{letter}"
        )
    installer.succeed(
        "zpool import -N -d /dev/mapper rpool",
        "mkdir -p /mnt",
        "mount -t zfs rpool/root /mnt",
    )


def payload_text(head):
    """What the attacker puts where the signed command line will run it. It announces itself,
    and, given copies of the real LUKS headers, asks the TPM to open each one. The genuine boot
    chain ran to get here, so PCR 7 is the value their slots are sealed to. The answer is
    printed from a variable, so that the text of this script can never be taken for one."""
    return "\n".join(
        [
            head,
            "echo FORGED-PAYLOAD-RAN > /dev/console",
            "echo FORGED-PAYLOAD-RAN",
            "if [ -d /stolen ]; then",
            "  mount -t proc proc /proc 2>/dev/null",
            "  mount -t sysfs sysfs /sys 2>/dev/null",
            "  mount -t devtmpfs devtmpfs /dev 2>/dev/null",
            "  for d in /nix/store/*/bin; do PATH=$PATH:$d; done",
            "  export PATH",
            "  for l in a b; do",
            "    said=refused",
            f"    {tpm_opens('/stolen/$l.hdr')} && said=opened",
            # Standard output reaches the serial log through the unit's journal+console.
            # /dev/console doesn't: with console=tty0 last, it is the first VT.
            "    echo \"TPM-ANSWER-$l=$said\"",
            "  done",
            "fi",
            "exit 1",
            "",
        ]
    )


def forge(base):
    """The attacker's workbench. Their disks copy everything public about the real ones (the
    LUKS UUIDs, the pool's GUID, the partition labels, a byte copy of the ESP) and hold the
    same signed closure, with a payload where the signed command line will run it from, in the
    default entry and in `nocheck`. They know the secret's length, not its value. A LUKS
    header is public, TPM slot and all, so they keep a copy of each before they wipe. The real
    GUID is read with the real passphrase here, which is more than an attacker needs: pool
    GUIDs aren't what stops them."""
    disks = new_case(base=base)
    installer_up(disks)
    installer.succeed("mkdir -p /stolen")
    for name, device in sorted(LUKS_DEVICES.items()):
        copy = f"/stolen/{name[-1]}.hdr"
        installer.succeed(
            f"cryptsetup luksHeaderBackup {device} --header-backup-file {copy}",
            f"cryptsetup luksDump --dump-json-metadata {copy} "
            "| jq -e '[.tokens[] | select(.type == \"systemd-tpm2\")] | length == 1'",
        )
    open_real()
    guid = installer.succeed("zpool get -H -o value guid rpool").strip()
    installer.succeed("zpool export rpool", "cryptsetup close crypt-a", "cryptsetup close crypt-b")
    for letter, label in LEGS:
        device = f"/dev/disk/by-partlabel/{label}"
        uuid = installer.succeed(f"cryptsetup luksUUID {device}").strip()
        installer.succeed(
            f"printf %s '{ATTACKER}' | cryptsetup luksFormat --type luks2 --batch-mode --uuid {uuid} --key-file=- {device}",
            f"printf %s '{ATTACKER}' | cryptsetup open --key-file=- {device} crypt-{letter}",
        )
    installer.succeed(
        "zpool create -f -o ashift=12 -O mountpoint=none rpool mirror /dev/mapper/crypt-a /dev/mapper/crypt-b",
        f"zpool reguid -g {guid} rpool",
        "zfs create -o mountpoint=legacy rpool/root",
        "zfs create -o mountpoint=legacy rpool/nix",
        "mkdir -p /mnt",
        "mount -t zfs rpool/root /mnt",
        "mkdir -p /mnt/nix /mnt/dev /mnt/proc /mnt/sys",
        "mount -t zfs rpool/nix /mnt/nix",
        # The payload may run before anything has populated /dev.
        "mknod /mnt/dev/console c 5 1",
        "cp -r /stolen /mnt/stolen",
    )
    installer.succeed(
        f"nix copy --no-check-sigs --to 'local?root=/mnt' {TOPLEVEL} >&2",
        timeout=900,
    )
    # A guess: the right length, the wrong value. The one thing the attacker doesn't have.
    installer.succeed(
        f"install -d /mnt{os.path.dirname(IDENTITY_PATH)}",
        f"head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \\n' > /mnt{IDENTITY_PATH}",
    )
    # In the very store paths the signed command lines name. The interpreter is fine as it is.
    nocheck = installer.succeed(f"readlink /mnt{TOPLEVEL}/specialisation/nocheck").strip()
    for closure in (TOPLEVEL, nocheck):
        path = f"/mnt{closure}/prepare-root"
        head = installer.succeed(f"head -n 1 {path}").strip()
        installer.succeed(f"cat > {path} << 'PAYLOAD'\n{payload_text(head)}PAYLOAD")
    release_disks()
    installer.shutdown()
    return freeze(disks)


def forged_boot(disks, sealed_firmware):
    """The real firmware and the attacker at its console. Returns (saw a verdict, saw a
    payload), having waited long enough for either to have been followed by anything else."""
    boot(disks, firmware=new_firmware(sealed_firmware))
    answered = type_until_console(target, serial(), ATTACKER, VERDICT)
    # A halt follows a refusal within a second or so, and nothing more follows that.
    wait_console(target, HALTED, 20)
    time.sleep(10)
    return answered


def forged_identity_mismatch(forged, firmware):
    disks = new_case(base=forged)
    answered = forged_boot(disks, firmware)
    refused = seen(MISMATCH) and seen(HALTED)
    payload = seen(PAYLOAD)
    switched = seen(SWITCH_ROOT)
    detail = f"mismatch+halt={refused} payload={payload} switch-root={switched}\n{tail()}"
    # A mutant only proves anything if the attack it exposes really works. If the payload didn't
    # run, this forged disk is no attack, and the check passing proves nothing either.
    if MUTANT == "forged-identity-mismatch" and not payload:
        raise Exception(f"control removed and the payload did not run: {detail}")
    control("forged-identity-mismatch", answered and refused and not payload and not switched, detail)
    power_off()


def forged_control_nocheck_steals_keys(forged, firmware):
    """The built-in negative control: the same forged disks, through the signed `nocheck` entry,
    which the unsigned loader.conf selects. Without the identity check the payload runs inside
    the genuine boot, with PCR 7 intact, and the TPM opens both real headers for it: opening a
    header's slot is having the key to the data it was copied from. If it doesn't, this attack
    wasn't reproduced and the check above has proven nothing."""
    disks = new_case(base=forged)
    select_entry(disks, "nocheck")
    boot(disks, firmware=new_firmware(firmware))
    type_until_console(target, serial(), ATTACKER, PAYLOAD)
    deadline = time.monotonic() + 90
    said = {}
    while time.monotonic() < deadline and len(said) < 2:
        said = {m.group(1): m.group(2) for m in console_findall(target, PAYLOAD_ANSWER)}
        time.sleep(1)
    control(
        "forged-control-nocheck-steals-keys",
        seen(PAYLOAD) and said == {"a": "opened", "b": "opened"},
        f"the TPM said {said}\n{tail()}",
    )
    power_off()


def forged_variant(name, forged, firmware, change, says):
    disks = new_case(base=forged)
    installer_up(disks)
    open_forged()
    installer.succeed(*change)
    release_disks()
    installer.shutdown()
    answered = forged_boot(disks, firmware)
    control(
        f"forged-variant-{name}",
        answered and seen(re.compile(says)) and seen(HALTED) and not seen(PAYLOAD) and not seen(SWITCH_ROOT),
        tail(),
    )
    power_off()


def plain_pool_not_imported(sealed, sealed_firmware):
    """No LUKS at all, so nobody has to type anything: a plaintext pool on the raw partitions
    with the right name. Only /dev/mapper is scanned, so it's never considered."""
    disks = new_case(base=sealed)
    installer_up(disks)
    labels = [f"/dev/disk/by-partlabel/{label}" for _, label in LEGS]
    installer.succeed(
        f"wipefs -a {' '.join(labels)}",
        f"zpool create -f -o ashift=12 -O mountpoint=none rpool mirror {' '.join(labels)}",
        "zfs create -o mountpoint=legacy rpool/root",
        "zfs create -o mountpoint=legacy rpool/nix",
        "zpool export rpool",
    )
    installer.shutdown()
    boot(disks, firmware=new_firmware(sealed_firmware))
    time.sleep(100)
    rc, pools = initrd_ssh("zpool list -H -o name 2>&1")
    # A halt ends SSH, so an import that went on to fail the identity check shows up there.
    imported = seen(re.compile("volume-identity:")) or "rpool" in pools
    control("plain-pool-not-imported", rc == 0 and not imported, f"rc={rc} {pools}\n{tail()}")
    power_off()


def identity_stall_does_not_halt(sealed, sealed_firmware):
    """A check that times out has reached no verdict. It lands in emergency mode, not a halt
    that would need someone at the power button of a node with nothing wrong with its disk."""
    disks = new_case(base=sealed)
    select_entry(disks, "stallcheck")
    boot(disks, firmware=new_firmware(sealed_firmware))
    answered = type_until_console(target, serial(), PASSPHRASE, EMERGENCY, timeout=180)
    control(
        "identity-stall-does-not-halt",
        answered and not seen(HALTED) and not seen(MISMATCH) and wait_initrd_ssh(),
        tail(),
    )
    power_off()


# ── the firmware moves: PCR 7 with it ─────────────────────────────────────


def firmware_changed(name, disks, firmware, reference_pcr7, same_pcr7=False, also=None):
    """What every change to the firmware's trust must come to: the prompt is there, nothing
    unlocks by itself, the TPM still refuses every leg when asked from stage 2, and the
    passphrase still boots. `also` returns (ok, detail) for what is particular to a case."""
    boot(disks, firmware=firmware)
    stage2 = connecting(target)
    prompt = next_prompt(target, 0, 90, ANY_PROMPT) is not None
    stage2.join(NO_UNLOCK_SECONDS)
    unlocked = not stage2.is_alive()
    booted = not unlocked and type_until_stage2(target, serial(), thread=stage2)
    refused, answer, now_pcr7, extra_ok, extra = False, "", "", False, ""
    if booted:
        rc, answer = tpm_answer()
        refused = rc != 0
        now_pcr7 = pcr7()
        extra_ok, extra = also() if also else (True, "")
    moved = now_pcr7 == reference_pcr7 if same_pcr7 else now_pcr7 != reference_pcr7
    control(
        name,
        prompt and not unlocked and booted and refused and moved and extra_ok and both_legs_online(pool_status()),
        f"prompt={prompt} unlocked-unattended={unlocked} typed-boot={booted} tpm-refused={refused} "
        f"PCR 7 {reference_pcr7} then {now_pcr7}\n"
        f"{extra}\nTPM: {answer.strip()[-300:]}",
    )
    power_off()


def sb_toggled_off(bound, firmware, bound_pcr7):
    fw = new_firmware(firmware)
    run(VIRT_FW_VARS, "--inplace", vars_of(fw), "--set-false", "SecureBootEnable")
    firmware_changed(
        "sb-toggled-off",
        new_case(base=bound),
        fw,
        bound_pcr7,
        also=lambda: (efi_flag("SecureBoot") == "0", f"SecureBoot={efi_flag('SecureBoot')}"),
    )


def keys_cleared(bound, firmware, bound_pcr7):
    """Fresh variables, the same TPM: Setup Mode, as a firmware reset leaves it."""
    fw = new_firmware(firmware)
    vars_of(fw).unlink()
    firmware_changed(
        "keys-cleared",
        new_case(base=bound),
        fw,
        bound_pcr7,
        also=lambda: (efi_flag("SetupMode") == "1", f"SetupMode={efi_flag('SetupMode')}"),
    )


def db_cert_added(bound, firmware, bound_pcr7):
    fw = refusing_firmware(firmware)
    firmware_changed(
        "db-cert-added",
        new_case(base=bound),
        fw,
        bound_pcr7,
        also=lambda: (enforcing(), secure_boot_status()),
    )
    return fw


def other_signed_loader(bound, db_firmware):
    """Rebound with the extra db cert already trusted, so that the one change left is who
    signed the loader. Signed by the other cert alone: a loader that still carried its own
    signature as well did not change PCR 7."""
    fw = new_firmware(db_firmware)
    disks = new_case(base=bound)
    boot(disks, firmware=fw)
    control("other-signed-loader-rebind-boot", type_until_stage2(target, serial()), "no typed boot")
    rc, out = bind("--replace")
    db_pcr7 = pcr7()
    control("other-signed-loader-rebound", rc == 0 and set(tpm_tokens().values()) == {1}, f"rc={rc}\n{out}")
    power_off()
    # The rebinding holds in that state, so the refusal below is the signer's doing.
    booted, took = boot_unattended(disks, fw)
    control("other-signed-loader-rebound-unlocks", booted, f"no unattended boot after {took:.0f}s")
    power_off()

    installer_up(disks)
    installer.copy_from_host(str(other_cert() / "other.key"), "/root/other.key")
    installer.copy_from_host(str(other_cert() / "other.crt"), "/root/other.crt")
    for part in ("disk-nvme0-ESP", "disk-nvme1-ESP"):
        installer.succeed(
            "mkdir -p /e",
            f"mount /dev/disk/by-partlabel/{part} /e",
            *[
                f"sbattach --remove {f} && sbsign --key /root/other.key --cert /root/other.crt --output {f} {f}"
                for f in ("/e/EFI/BOOT/BOOTX64.EFI", "/e/EFI/systemd/systemd-bootx64.efi")
            ],
            "umount /e",
        )
    installer.shutdown()
    firmware_changed(
        "other-signed-loader",
        disks,
        fw,
        db_pcr7,
        also=lambda: (enforcing(), secure_boot_status()),
    )
    return disks, fw


def foreign_authority_bind_refused(disks, fw):
    """The disks above boot through a loader the other cert verified, before this node's own
    cert verified the stub: every boot logs that cert in PCR 7 first. On a real board it is
    an option ROM signed by Microsoft's CA, on a node that enrolled Microsoft's keys. The
    firmware logs each authority once per boot, so anything else that cert lets run adds
    nothing to PCR 7 and can extend it with this node's cert's event, which anyone can work
    out from the public db: the value a binding here would seal to, with our initrd never
    run. So bind refuses, says whose authority it saw, and leaves the slots alone."""
    boot(disks, firmware=fw)
    control("foreign-authority-boot", type_until_stage2(target, serial()), "no typed boot")
    target.wait_for_unit("multi-user.target")
    before = tpm_tokens()
    rc, out = bind("--replace")
    after = tpm_tokens()
    control(
        "foreign-authority-bind-refused",
        rc != 0
        and "other than this node's own" in out
        and "another signer" in out
        and enforcing()
        and after == before,
        f"rc={rc} tokens {before} then {after}\n{out}",
    )
    power_off()


def tpm_cleared(bound, firmware, bound_pcr7):
    """From the running system, as anyone with root there could. The firmware is unchanged, so
    PCR 7 is too: what is gone is the TPM's own seed."""
    fw = new_firmware(firmware)
    disks = new_case(base=bound)
    booted, took = boot_unattended(disks, fw)
    control("tpm-cleared-unlocks-before", booted, f"no unattended boot after {took:.0f}s")
    target.succeed("TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_clear -c l")
    power_off()
    firmware_changed("tpm-cleared", disks, fw, bound_pcr7, same_pcr7=True)


# ── a shell in the genuine initrd ─────────────────────────────────────────


def emergency_on_forged(forged, firmware, specialisation):
    """The forged disks with no root dataset, so /sysroot fails to mount and the genuine initrd
    drops to emergency mode under enforcing Secure Boot. The attacker types their own
    passphrase, then the emergency password (the hash is on the ESP to crack), and has the
    initrd's own systemd-cryptsetup open a copy of a real header they left on the ESP, from
    the TPM alone. Any block device does for the data: the header is what the TPM opens.
    Returns (what the TPM said, burned, detail)."""
    disks = new_case(base=forged)
    installer_up(disks)
    open_forged()
    installer.succeed(
        "mkdir -p /e",
        "mount /dev/disk/by-partlabel/disk-nvme0-ESP /e",
        "cp /mnt/stolen/a.hdr /e/stolen-a.hdr",
        "umount /e",
        "umount /mnt",
        "zfs destroy -r rpool/root",
    )
    release_disks()
    installer.shutdown()
    if specialisation:
        select_entry(disks, specialisation)
    boot(disks, firmware=new_firmware(firmware))
    reached = type_until_console(target, serial(), ATTACKER, EMERGENCY, timeout=240)
    time.sleep(8)
    send = tty0()
    send(EMERGENCY_PASSWORD)
    time.sleep(5)
    send(
        "(mkdir -p /e; mount /dev/disk/by-partlabel/disk-nvme0-ESP /e; "
        "for d in /nix/store/*/bin; do PATH=$d:$PATH; done; "
        "systemd-cryptsetup attach stolen /dev/disk/by-partlabel/disk-nvme1-ESP - "
        "header=/e/stolen-a.hdr,tpm2-device=auto,headless=true; "
        "said=refused; [ -e /dev/mapper/stolen ] && said=opened; "
        "echo SHELL-ANSWER=$said) > /dev/ttyS0 2>&1"
    )
    found, match = wait_console_match(target, SHELL_ANSWER, 120)
    said = None
    if found is not None:
        said = match.group(1)
    detail = f"emergency: {reached}, the TPM said {said}\n{tail()}"
    burned = seen(BURNED)
    power_off()
    return said, burned, detail


def emergency_noburn_recovers_key(forged, firmware):
    """The built-in negative control: through the signed `noburn` entry the shell gets the key."""
    said, _, detail = emergency_on_forged(forged, firmware, "noburn")
    control("emergency-noburn-recovers-key", said == "opened", detail)


def emergency_burn_refused(forged, firmware):
    """The same, through the default entry. The shell runs (its output is there) and the TPM
    refuses, because PCR 7 was burned before it started."""
    said, burned, detail = emergency_on_forged(forged, firmware, None)
    control("emergency-burn-refused", said == "refused" and burned, f"burned: {burned}, {detail}")


def answer_until_open():
    """From initrd SSH, as an operator does once emergency mode has the node: start the legs'
    units again and answer their queries. Returns what /dev/mapper holds at the end."""
    initrd_ssh(
        "systemctl --no-block start 'systemd-cryptsetup@crypt\\x2da.service' 'systemd-cryptsetup@crypt\\x2db.service'"
    )
    deadline = time.monotonic() + 120
    opened = ""
    while time.monotonic() < deadline:
        answer_over_ssh(PASSPHRASE)
        opened = initrd_ssh("ls /dev/mapper")[1]
        if "crypt-a" in opened and "crypt-b" in opened:
            break
    return opened


def burn_lasts_one_boot(bound, firmware):
    """A genuine node whose firmware came to trust one more signer, with no gate: the TPM
    refuses, nobody types, the import gives up, and it is in emergency mode with PCR 7 burned.
    Recovered over SSH, it has a binding to redo and a PCR 7 that is not the firmware's. The
    seal tool must say so and refuse to seal to that value. On the next boot PCR 7 is the
    firmware's own again, the same rebinding goes through, and the boot after unlocks by
    itself."""
    disks = new_case(base=bound)
    select_entry(disks, "nogate")
    fw = refusing_firmware(firmware)
    boot(disks, firmware=fw)
    reached = wait_console(target, EMERGENCY, 240) is not None
    control("burn-emergency-reached", reached and seen(BURNED), tail())
    control("burn-emergency-ssh", wait_initrd_ssh(), "no ssh in emergency mode")
    opened = answer_until_open()
    rc, out = initrd_ssh("systemctl restart zfs-import-rpool.service && systemctl --no-block default")
    booted = wait_stage2(target, 180)
    control("burn-recovered-over-ssh", booted, f"{opened}\n{out}")

    def marker():
        return target.succeed("test -e /run/cluster-boot/pcr7-burned && echo yes || echo no").strip()

    burned_marker, burned_pcr7 = marker(), pcr7()
    rc, out = bind("--replace")
    tokens = tpm_tokens()
    control(
        "bind-refused-after-burn",
        rc != 0 and "PCR 7 was burned this boot" in out and set(tokens.values()) == {1},
        f"rc={rc} tokens={tokens}\n{out}",
    )
    rc, out = target.execute("cluster-boot-seal check 2>&1")
    control("preflight-reports-burn", rc == 3 and "BURNED" in out, f"rc={rc}\n{out}")
    power_off()

    # The same entry on the same firmware, with someone typing before the import gives up.
    boot(disks, firmware=fw)
    typed = type_until_stage2(target, serial())
    clean_marker, clean_pcr7 = (marker(), pcr7()) if typed else ("", "")
    control(
        "burn-survives-switch-root",
        burned_marker == "yes" and typed and clean_marker == "no" and burned_pcr7 != clean_pcr7,
        f"burned boot: marker {burned_marker!r}, PCR 7 {burned_pcr7}; "
        f"the boot after: typed {typed}, marker {clean_marker!r}, PCR 7 {clean_pcr7}",
    )
    rc, out = bind("--replace") if typed else (1, "")
    control("rebind-after-the-burned-boot", rc == 0, f"rc={rc}\n{out}")
    power_off()

    booted, took = boot_unattended(disks, fw)
    last_marker = marker() if booted else ""
    rc, _ = tpm_answer() if booted else (1, "")
    control(
        "burn-lasts-one-boot",
        booted and last_marker == "no" and rc == 0,
        f"unattended: {booted} after {took:.0f}s, marker {last_marker!r}, TPM rc={rc}",
    )
    power_off()


def burn_fails_blocks_shell(bound, firmware):
    """A burn that can't reach the TPM must keep the local shell from starting. Recovery is
    initrd SSH, which stays up. The firmware trusts one more signer, so nothing unlocks and
    the boot gets as far as emergency mode."""
    disks = new_case(base=bound)
    select_entry(disks, "burnfail")
    boot(disks, firmware=refusing_firmware(firmware))
    failed = wait_console(target, BURN_FAILED, 240) is not None
    time.sleep(8)
    send = tty0()
    send(EMERGENCY_PASSWORD)
    time.sleep(5)
    send("echo RIGHT-SHELL-$((40 + 2)) > /dev/ttyS0")
    shell = wait_console(target, SHELL, 30) is not None
    ssh = wait_initrd_ssh()
    marker = initrd_ssh("test -e /run/cluster-boot/pcr7-burned && echo yes || echo no")[1].strip() if ssh else ""
    control(
        "burn-fails-blocks-shell",
        failed and not shell and ssh and marker == "no",
        f"burn failed: {failed}, shell: {shell}, ssh: {ssh}, marker {marker!r}\n{tail()}",
    )
    power_off()


def burn_before_early_failure(bound, firmware):
    """A failure before tpm2.target sends the initrd to emergency mode early. The burn still
    pulls in the TPM and runs before the shell does."""
    disks = new_case(base=bound)
    select_entry(disks, "earlyfail")
    boot(disks, firmware=new_firmware(firmware))
    reached = wait_console(target, EMERGENCY, 240)

    def first(regex):
        # The line where the first match ends, counted from 0 as this always was: `reached`
        # is the index past its line, so a burn on the line before it is still `<`.
        found = wait_console(target, regex, 0)
        return None if found is None else found - 1

    early, burned = first(EARLY_FAILED), first(BURNED)
    time.sleep(8)
    send = tty0()
    send(EMERGENCY_PASSWORD)
    time.sleep(5)
    send("test -e /run/cluster-boot/pcr7-burned && echo BURN-MARKER-PRESENT > /dev/ttyS0")
    marker = wait_console(target, MARKER, 30) is not None
    control(
        "burn-before-early-failure",
        reached is not None
        and early is not None
        and burned is not None
        and early < burned < reached
        and marker,
        f"early failure at line {early}, burn at {burned}, emergency at {reached}, marker: {marker}\n{tail()}",
    )
    power_off()


# ── what is left in stage 2, and what the ESP can add ─────────────────────


def cached_key_visible():
    return target.succeed("grep -cE ' user +cryptsetup: ' /proc/keys || true").strip() != "0"


def keyring_purged(bound):
    """The passphrase is cached in root's keyring as `user cryptsetup`, and outlives
    switch-root by about two minutes. Typed, on fresh firmware, read straight after. The
    signed `nopurge` entry is the control: without it, the key has to be there to be seen."""
    disks = new_case(base=bound)
    select_entry(disks, "nopurge")
    boot(disks)
    control("keyring-nopurge-boot", type_until_stage2(target, serial()), "no typed boot")
    visible_without = cached_key_visible()
    power_off()

    boot(new_case(base=bound))
    control("keyring-purge-boot", type_until_stage2(target, serial()), "no typed boot")
    visible_with = cached_key_visible()
    keys = target.succeed("cat /proc/keys")
    power_off()
    control(
        "keyring-purged",
        visible_without and not visible_with,
        f"cached key seen without the purge: {visible_without}, with it: {visible_with}\n{keys}",
    )


def credential_companion_inert(bound, firmware):
    """Lanzaboote's stub packs ESP companion files into the initrd with no hash check: a .cred
    in \\loader\\credentials\\, and .cred and .raw files beside the signed image. The signed
    command line's systemd.import_credentials=no means they are delivered and nothing takes
    them in. The firmware trusts one more signer, so the TPM refuses and the initrd waits at
    the prompt long enough to be looked at."""
    disks = new_case(base=bound)
    edit_esp(
        disks,
        "mkdir -p /e/loader/credentials",
        "echo planted > /e/loader/credentials/nco-planted-global.cred",
        "u=$(ls /e/EFI/Linux/nixos-generation-1-*.efi | grep -v specialisation | head -n 1); "
        "mkdir -p \"$u.extra\"; echo planted > \"$u.extra/nco-planted-local.cred\"; "
        "head -c 4096 /dev/zero > \"$u.extra/nco-planted.raw\"",
    )
    boot(disks, firmware=refusing_firmware(firmware))
    ssh = wait_initrd_ssh(90)
    _, delivered = initrd_ssh("ls -laR /.extra 2>&1") if ssh else (1, "")
    _, initrd_creds = initrd_ssh("ls -laR /run/credentials 2>&1") if ssh else (1, "")
    booted = ssh and type_until_stage2(target, serial())
    creds = target.succeed("ls -laR /run/credentials 2>&1 || true") if booted else ""
    sysext = target.succeed("systemd-sysext list 2>&1 || true") if booted else ""
    # PID 1 says so, in the initrd where the files arrived as well as in stage 2: both are in
    # this boot's journal.
    said = (
        int(target.succeed("journalctl -b -o cat --no-pager | grep -c 'import_credentials=no is set' || true").strip())
        if booted
        else 0
    )
    in_initrd = said >= 2
    planted = ("nco-planted-global.cred", "nco-planted-local.cred", "nco-planted.raw")
    control(
        "credential-companion-inert",
        booted
        and all(name in delivered for name in planted)
        and "nco-planted" not in initrd_creds
        and "nco-planted" not in creds
        and "nco-planted" not in sysext
        and in_initrd,
        f"ssh: {ssh}, stage 2: {booted}, 'import_credentials=no is set' x{said} in this boot\n"
        f"delivered to the initrd:\n{delivered}\ninitrd credentials:\n{initrd_creds}\n"
        f"stage 2 credentials:\n{creds}\nsysext:\n{sysext}",
    )
    # And a signed boot never leaves them in place: the next install refuses.
    rc, out = install_bootloader() if booted else (0, "")
    control(
        "credential-companion-tripwire",
        rc != 0 and "carries loader/credentials or an *.extra companion dir" in out,
        f"rc={rc}\n{out}",
    )
    power_off()


def main():
    peer.start()
    peer.wait_for_unit("multi-user.target")
    ssh_ready()
    provision()
    sealed, sealed_firmware = sealed_checkpoint()

    unsigned_loader_refused(sealed, sealed_firmware)
    tampered_initrd_refused(sealed, sealed_firmware)
    espread(sealed)
    # Before anything reads `zpool status` by its /dev/mapper names, so that the mutant that
    # widens the scan (boot-zfs-any-devnodes) is caught here, by the case it is about.
    # Each named mutant takes one control out of the whole node, which is why the order of
    # what follows matters.
    plain_pool_not_imported(sealed, sealed_firmware)

    bound, bound_firmware, bound_pcr7 = bound_checkpoint(sealed, sealed_firmware)
    sb_toggled_off(bound, bound_firmware, bound_pcr7)
    keys_cleared(bound, bound_firmware, bound_pcr7)
    db_firmware = db_cert_added(bound, bound_firmware, bound_pcr7)
    foreign_disks, foreign_firmware = other_signed_loader(bound, db_firmware)
    foreign_authority_bind_refused(foreign_disks, foreign_firmware)
    tpm_cleared(bound, bound_firmware, bound_pcr7)

    forged = forge(bound)
    forged_identity_mismatch(forged, bound_firmware)
    # After the forged case, which the identity-check mutants are about: without the check, or
    # with it late, a stall can't hold anything up either.
    identity_stall_does_not_halt(sealed, sealed_firmware)
    forged_control_nocheck_steals_keys(forged, bound_firmware)
    emergency_burn_refused(forged, bound_firmware)
    emergency_noburn_recovers_key(forged, bound_firmware)
    forged_variant(
        "missing", forged, bound_firmware, [f"rm /mnt{IDENTITY_PATH}"], r"MISMATCH \(secret missing\)"
    )
    forged_variant(
        "fifo",
        forged,
        bound_firmware,
        [f"rm /mnt{IDENTITY_PATH}", f"mkfifo /mnt{IDENTITY_PATH}"],
        r"MISMATCH \(wrong type or size: fifo",
    )
    forged_variant(
        "symlink",
        forged,
        bound_firmware,
        [f"rm /mnt{IDENTITY_PATH}", f"ln -s /etc/volume-identity.sha256 /mnt{IDENTITY_PATH}"],
        r"MISMATCH \(wrong type or size: symbolic link",
    )

    burn_lasts_one_boot(bound, bound_firmware)
    burn_fails_blocks_shell(bound, bound_firmware)
    burn_before_early_failure(bound, bound_firmware)
    keyring_purged(bound)
    credential_companion_inert(bound, bound_firmware)
