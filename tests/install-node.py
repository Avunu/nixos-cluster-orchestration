OPERATOR_SSH = (
    "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=ERROR -o ConnectTimeout=5 -i /root/id"
)


def encrypt_to_master(rel, value=None, source=None):
    """A source in the site: encrypted to the operators' master key and to nothing else."""
    out = f"{SITE}/{rel}"
    feed = f"printf %s {shlex.quote(value)}" if source is None else f"cat {source}"
    peer.succeed(f"mkdir -p $(dirname {out}) && {feed} | age -e -r {MASTER_PUB} -o {out}")


def decrypt_with_master(rel):
    """What an operator reads with the master key (a YubiKey, on a site)."""
    return peer.succeed(f"age -d -i /root/master-identity.txt {SITE}/{rel}")


def make_site():
    """The site as `avc secrets provision` leaves it before a node exists: its boot secrets
    and one secret it reads, each as ciphertext; no recipient, nothing rekeyed."""
    peer.succeed(
        f"mkdir -p {SITE} && touch {SITE}/flake.nix",
        f"install -m 0400 {MASTER_IDENTITY} /root/master-identity.txt",
        f"install -m 0600 {SSH_KEY} /root/id",
        "ssh-keygen -q -t ed25519 -N '' -C initrd-host -f /root/initrd-host-key",
    )
    encrypt_to_master("secrets/per-machine/target/luks/passphrase.age", PASSPHRASE)
    encrypt_to_master("secrets/per-machine/target/volume-identity/secret.age", IDENTITY_SECRET)
    encrypt_to_master("secrets/per-machine/target/initrd-ssh/ssh_host_ed25519_key.age", source="/root/initrd-host-key")
    encrypt_to_master("secrets/shared/canary/value.age", CANARY)
    peer.succeed("rm /root/initrd-host-key")


def plaintext_on_the_operator():
    """Where a disk secret is in the clear on the operator's machine, outside memory that is
    the test's own: files under the site, /tmp, /root and the tmpfs the installer staged in."""
    return peer.succeed(
        f"grep -rlF -e {shlex.quote(PASSPHRASE)} -e {shlex.quote(IDENTITY_SECRET)} "
        f"{SITE} /tmp /root /dev/shm /run/user 2>/dev/null || true"
    ).split()


def install(fingerprint, someone_else=None):
    """`avc boot install target root@<rescue> --host-key-fingerprint <fingerprint>`, less
    its evaluation: the host key pinned, and the site's installer under the pin."""
    env = f"IH_STORE_PATHS='{DISKO} {TOPLEVEL}' AVC_AGE={AGE} AVC_AGE_PLUGIN_TPM={AGE_PLUGIN_TPM} "
    if someone_else:
        env += f"INSTALL_TEST_SOMEONE_ELSE={shlex.quote(someone_else)} "
    # The installer's own account of itself goes to this machine's console as it happens
    # (the log of this test), and to a file the controls below read. No stdin: this shell's
    # is the test driver's channel, which looks like a terminal, and nixos-anywhere would
    # hand it to ssh as one (`-t`) and wait on it for ever. An operator's is a terminal.
    return peer.execute(
        f"cd {SITE} && {env} {INSTALL_RUN} {shlex.quote(fingerprint)} root@{WAN_ADDRESS} "
        f"{DEPLOY} root@{WAN_ADDRESS} -i /root/id --kexec {KEXEC} "
        "--no-substitute-on-destination < /dev/null 2>&1 | tee /tmp/install.log >&2; rc=${PIPESTATUS[0]}; "
        "tail -n 60 /tmp/install.log; exit $rc",
        timeout=2400,
    )


def rescue_state():
    """What an install changes first on the machine it reaches: logins (nixos-anywhere's
    key, the kexec's files), then the disks. And the boot it is in."""
    return rescue.succeed(
        "cat /proc/sys/kernel/random/boot_id; "
        "journalctl -u sshd -o cat | grep -c '^Accepted' || true; "
        "ls -d /root/kexec 2>&1 || true; grep -c nixos-anywhere /root/.ssh/authorized_keys 2>/dev/null || true; "
        "lsblk -nro NAME,TYPE,SIZE,FSTYPE,PTTYPE"
    )


def refused_untouched(name, said, rc, out, state, site):
    """A refused install: it says why, and the machine, its disks and the site are as they were."""
    log = peer.succeed("cat /tmp/install.log")
    now = rescue_state()
    files = peer.succeed(f"cd {SITE} && find secrets -type f | sort").split()
    left = peer.succeed("ls -d /dev/shm/avc-install-* /run/user/*/avc-install-* 2>/dev/null || true").split()
    control(
        name,
        rc != 0 and all(s in log for s in said) and now == state and files == site and left == []
        and "staged for age1" not in log,
        f"rc={rc}; rescue before:\n{state}\nafter:\n{now}\nsite {files}; pins left {left}\n{out}",
    )


def rescue_gone(timeout=180):
    """The installer reboots the machine, and the driver's -no-reboot ends QEMU there."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if rescue.process is None or rescue.process.poll() is not None:
            break
        time.sleep(1)
    else:
        rescue.crash()
        return False
    try:
        rescue.wait_for_shutdown()
    except Exception:
        pass
    return True


def installed_state():
    """What the hooks and nixos-install left, read on the node: boot-install's
    install-via-disko-hook, from the running system."""
    state = target.succeed(
        f"stat -c '%a' {IDENTITY_PATH}; sha256sum < {IDENTITY_PATH} | cut -d' ' -f1; "
        f"stat -c '%a' {HOST_KEY_PATH}; "
        f"stat -c '%a' {PKI_BUNDLE}/keys/db/db.key; "
        f"test -s {PKI_BUNDLE}/keys/db/db.pem && test -s {PKI_BUNDLE}/GUID && echo keys-made; "
        "test -s /boot/EFI/BOOT/BOOTX64.EFI && test -s /boot/EFI/systemd/systemd-bootx64.efi && echo loader-placed; "
        "ls /boot/EFI/Linux | grep -c '^nixos-generation-1-' || true; "
        "cat /boot/loader/loader.conf"
    )
    lines = state.split("\n")
    return (
        lines[0] == "400"
        and lines[1] == IDENTITY_HASH
        and lines[2] == "400"
        and lines[3] == "400"
        and "keys-made" in lines
        and "loader-placed" in lines
        and int(lines[lines.index("loader-placed") + 1]) >= 1
        and "editor false" in state
    ), state


def slots(machine):
    """Per leg: (key slots, the PCRs of each TPM slot)."""
    out = {}
    for name, device in sorted(LUKS_DEVICES.items()):
        header = luks_header(machine, device)
        out[name] = (len(header["keyslots"]), [t.get("tpm2-pcrs") for t in tpm2_tokens(header)])
    return out


def main():
    peer.start()
    peer.wait_for_unit("multi-user.target")
    make_site()

    # ── the machine, as handed over ────────────────────────────────────────
    BASE.mkdir(parents=True)
    TPM.mkdir(parents=True, exist_ok=True)
    for letter in "ab":
        new_blank(BASE / f"{letter}.qcow2")
    firmware = new_firmware()
    use_disks(BASE)
    os.environ["NIX_SWTPM_DIR"] = str(firmware / "t")
    rescue.start()
    rescue.wait_for_unit("sshd.service")
    peer.wait_until_succeeds(f"ssh {OPERATOR_SSH} root@{WAN_ADDRESS} true", timeout=120)
    before = peer.succeed(f"cd {SITE} && find secrets -type f | sort").split()
    # What the operator reads at the machine's console, in the rescue system.
    host_key = rescue.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").strip()
    fingerprint = rescue.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").split()[1]
    state = rescue_state()

    # ── a host key that is not the machine's ───────────────────────────────
    # The fingerprint given is another machine's: refused at the first read of the host
    # key, before any connection that logs in.
    peer.succeed("ssh-keygen -q -t ed25519 -N '' -C someone-else -f /root/someone-else")
    someone_else = " ".join(peer.succeed("cat /root/someone-else.pub").split()[:2])
    wrong = peer.succeed("ssh-keygen -lf /root/someone-else.pub").split()[1]
    rc, out = install(wrong)
    refused_untouched(
        "wrong-fingerprint-is-refused-with-the-machine-untouched",
        [f"does not present the host key {wrong}", fingerprint, "Nothing was sent to it"],
        rc, out, state, before,
    )
    # The right fingerprint, and then a far end whose key is not the pinned one: the
    # installer's own first connection is refused, and the installer stopped.
    rc, out = install(fingerprint, someone_else=someone_else)
    refused_untouched(
        "installers-connections-are-held-to-the-pinned-key",
        ["not one verified for this install", "before `avc boot stage`", "no secret was sent"],
        rc, out, state, before,
    )

    # ── the install ────────────────────────────────────────────────────────
    rc, out = install(fingerprint)
    log = peer.succeed("cat /tmp/install.log")
    control("install-through-the-installer", rc == 0 and "staged for age1" in log, f"rc={rc}\n{out}")
    # Every connection was checked against the one verified key: nixos-anywhere's went
    # through the pin (it asks ssh for no checking, and ssh then says "Permanently
    # added" at each), and the installer answered with the key the rescue system had.
    pinned = re.search(r"pinned: (\d+) connections before the hook, (\d+) keys", log)
    control(
        "install-is-held-to-the-verified-host-key",
        pinned is not None and int(pinned.group(1)) >= 3 and pinned.group(2) == "2"
        and f"installer host key: {' '.join(host_key.split()[:2])}" in log
        and "Permanently added" not in log and "Host key verification failed" not in log,
        f"{pinned and pinned.groups()}; rescue host key {host_key}\n{out}",
    )
    # The new recipient was shown before anything was rekeyed to it.
    control("recipient-shown-before-the-rekey", re.search(r"new recipient shown: age1\S+ from root@\S+; rekeyed by then: 0", log) is not None, out)
    control("installer-reboots-the-machine", rescue_gone(), "the rescue VM never went down")
    for letter in "ab":
        (BASE / f"{letter}.qcow2").chmod(stat.S_IRUSR)

    # What the hook left in the site: the node's recipient, its identity file as
    # ciphertext the master key opens, and the one secret it reads, rekeyed. Nothing else
    # is new, and nothing in the clear.
    after = peer.succeed(f"cd {SITE} && find secrets -type f | sort").split()
    new = sorted(set(after) - set(before))
    recipient = peer.succeed(f"cat {SITE}/secrets/recipients/target.pub").strip()
    identity = decrypt_with_master("secrets/identities/target.age")
    rekeyed = [f for f in new if f.startswith("secrets/rekeyed/target/")]
    control(
        "site-holds-the-recipient-the-identity-and-what-was-rekeyed",
        len(new) == 3
        and "secrets/recipients/target.pub" in new
        and "secrets/identities/target.age" in new
        and len(rekeyed) == 1
        and rekeyed[0].endswith("-shared/canary/value.age")
        and recipient.startswith("age1")
        and f"# Recipient: {recipient}" in identity
        and "AGE-PLUGIN-TPM-" in identity,
        f"new files {new}; recipient {recipient!r}",
    )
    # The rekeyed file is the node's alone: the operators' key does not open it.
    rc_master, _ = peer.execute(f"age -d -i /root/master-identity.txt {SITE}/{rekeyed[0]} 2>&1")
    control("rekeyed-is-for-the-nodes-tpm-only", rc_master != 0, f"the master key opened {rekeyed[0]}")
    # The disk secrets were in a tmpfs between the hook and the upload, and are gone.
    left = plaintext_on_the_operator()
    staged = peer.succeed("ls -d /dev/shm/ih-disk-keys.* /run/user/*/ih-disk-keys.* /tmp/tmp.* 2>/dev/null || true").split()
    control("operator-keeps-no-disk-secret", left == [] and staged == [], f"plaintext in {left}; staging left {staged}")
    # What an operator recovers the node with, from the site and the master key alone.
    recovery_key = decrypt_with_master("secrets/per-machine/target/luks/passphrase.age")
    control("recovery-key-is-in-the-site-as-ciphertext", recovery_key == PASSPHRASE, "the site's luks/passphrase is not the key the legs were given")

    # ── first boot: the machine's own TPM, and nobody types ────────────────
    disks = new_case()
    booted, took = boot_unattended(disks, firmware)
    opened = tpm_opened_legs() if booted else []
    status = pool_status() if booted else ""
    control(
        "first-boot-unattended",
        booted and opened == sorted(LUKS_DEVICES) and both_legs_online(status),
        f"stage 2: {booted} after {took:.0f}s, legs opened by the TPM: {opened}\n{status}",
    )
    target.wait_for_unit("multi-user.target")
    ok, state = installed_state()
    control("install-via-disko-hook", ok, state)
    journal = target.succeed("journalctl -b -o cat | grep 'volume-identity:' || true")
    control("identity-ok-first-boot", "volume-identity: OK" in journal, journal)
    control("default-entry-is-the-generation", booted_closure() == TOPLEVEL, booted_closure())

    # Each leg: the TPM's slot, bound to no PCR, and the recovery key's. The key the leg
    # was formatted with has no slot, and the installer's memory, where it and the
    # partitioning secrets were, is gone with the installer.
    found = slots(target)
    control(
        "legs-hold-a-tpm-slot-and-the-recovery-key",
        all(v == (2, [[]]) for v in found.values()) and recovery_key_opens(),
        f"{found}",
    )
    gone = target.succeed("ls -d /run/partitioning-secrets /run/cluster-install 2>&1 || true")
    control("installers-memory-is-gone", gone.count("No such file") == 2, gone)

    # The secrets the node reads decrypt with the identity made on its TPM at the install:
    # the library's agenix, at activation, from the file the hook staged.
    on_node = target.succeed(f"cat {NODE_IDENTITY_PATH}")
    mode = target.succeed(f"stat -c '%a %U' {NODE_IDENTITY_PATH}").strip()
    value = target.succeed(f"cat {CANARY_PATH}")
    control(
        "secret-decrypts-with-the-provisioned-identity",
        value == CANARY and on_node.strip() == identity.strip() and mode == "400 root",
        f"value {value!r}; identity file {mode}; same as the site's: {on_node.strip() == identity.strip()}",
    )
    control("canary-is-what-the-library-declares", CANARY_PATH == "/run/secrets/shared/canary/value", CANARY_PATH)
    power_off()

    # ── another machine's TPM ──────────────────────────────────────────────
    # The same disks behind a TPM that is not the node's, with firmware nobody configured:
    # a mainboard swap, or the disks in someone else's server. The TPM has nothing for
    # them, so the node asks; the recovery key, typed, is what opens it.
    other = new_case()
    boot(other)
    prompt = next_prompt(target, 0, timeout=180)
    unlocked = wait_stage2(target, 20) if prompt is None else False
    control("another-tpm-does-not-unlock", prompt is not None and not unlocked, f"prompt at {prompt}, stage 2 without typing: {unlocked}")
    booted = type_until_stage2(target, serial(), after=prompt or 0)
    opened = tpm_opened_legs() if booted else None
    status = pool_status() if booted else ""
    control(
        "recovery-key-typed-opens-the-node",
        booted and opened == [] and both_legs_online(status),
        f"stage 2: {booted}, legs opened by a TPM: {opened}\n{status}",
    )
    # And its secrets stay shut: the identity file is a handle to a key in the other TPM.
    rc, out = target.execute(f"test -e {CANARY_PATH}")
    failed = target.succeed("journalctl -b -o cat | grep -c 'age: error' || true").strip()
    control("another-tpm-decrypts-no-secret", rc != 0 and int(failed) >= 1, f"canary present: {rc == 0}; age errors: {failed}")
    power_off()

    # ── a rescue boot of the disks ─────────────────────────────────────────
    # From the provider's side, or an operator's: the TPM there opens nothing, and the
    # recovery key from the site opens both legs, the pool and the root.
    installer_up(new_case())
    refused = {
        name: installer.execute(f"{tpm_opens(device)} 2>&1 < /dev/null")[0]
        for name, device in sorted(LUKS_DEVICES.items())
    }
    control("rescue-tpm-opens-nothing", all(rc != 0 for rc in refused.values()), f"{refused}")
    for name, device in sorted(LUKS_DEVICES.items()):
        installer.succeed(f"printf %s {shlex.quote(recovery_key)} | cryptsetup open --key-file - {device} {name}")
    installer.succeed("zpool import -f -N -d /dev/mapper rpool", "mkdir -p /mnt && mount -t zfs rpool/root /mnt")
    secret_hash = installer.succeed(f"sha256sum < /mnt{IDENTITY_PATH} | cut -d' ' -f1").strip()
    control("recovery-key-opens-the-disks", secret_hash == IDENTITY_HASH, f"the root's identity secret hashes to {secret_hash}")
    release_disks()
    installer.shutdown()
