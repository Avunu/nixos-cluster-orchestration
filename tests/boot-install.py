def installed():
    """What the hook and nixos-install left, read from the new root before its first boot."""
    state = installer.succeed(
        f"stat -c '%a' /mnt{IDENTITY_PATH}; sha256sum < /mnt{IDENTITY_PATH} | cut -d' ' -f1; "
        f"stat -c '%a' /mnt{HOST_KEY_PATH}; "
        f"stat -c '%a' /mnt{PKI_BUNDLE}/keys/db/db.key; "
        f"test -s /mnt{PKI_BUNDLE}/keys/db/db.pem && test -s /mnt{PKI_BUNDLE}/GUID && echo keys-made; "
        f"test -s /mnt/boot/EFI/BOOT/BOOTX64.EFI && test -s /mnt/boot/EFI/systemd/systemd-bootx64.efi && echo loader-placed; "
        "ls /mnt/boot/EFI/Linux | grep -c '^nixos-generation-1-' || true; "
        "cat /mnt/boot/loader/loader.conf"
    )
    lines = state.split("\n")
    control(
        "install-via-disko-hook",
        lines[0] == "400"
        and lines[1] == IDENTITY_HASH
        and lines[2] == "400"
        and lines[3] == "400"
        and "keys-made" in lines
        and "loader-placed" in lines
        and int(lines[lines.index("loader-placed") + 1]) >= 1
        and "editor false" in state,
        state,
    )


def sbctl_verified(esp):
    """Every PE on the ESP signed, the stub-checked kernels aside. The stub verifies a
    kernel by the hash in its signed section, and they're unsigned on purpose."""
    _, out = target.execute(f"SYSTEMD_ESP_PATH={esp} sbctl verify 2>&1")
    target.log(out)
    signed = [line for line in out.splitlines() if "is signed" in line and esp in line]
    unsigned = [
        line
        for line in out.splitlines()
        if "is not signed" in line and not re.search(r"/kernel-[^/]*\.efi", line)
    ]
    return len(signed) >= 3 and not unsigned, out


def esps_identical():
    return esp_differences(target, "/boot", "/boot-fallback")


def audit_metric(name):
    target.succeed("systemctl start cluster-boot-audit.service")
    found = re.search(
        rf"^{re.escape(name)} (\S+)$",
        target.succeed("cat /var/lib/prometheus-node-exporter-text/boot_audit.prom"),
        re.M,
    )
    return found.group(1) if found else None


def unattended(disks, firmware, unplugged=False):
    """A boot nobody types into: both legs opened from their TPM slots. Returns whether it
    was that, and what happened."""
    booted, took = boot_unattended(disks, firmware, unplugged=unplugged)
    status = pool_status() if booted else ""
    opened = tpm_opened_legs() if booted else []
    detail = f"stage 2: {booted} after {took:.0f}s, legs opened by the TPM: {opened}\n{status}"
    target.log(detail)
    return booted and opened == sorted(LUKS_DEVICES) and both_legs_online(status), detail


DB = "/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
EVENT_LOG = "/sys/kernel/security/tpm0/binary_bios_measurements"


def pcr7_authorities():
    """The PCR 7 authority events of this boot, as the length of each one's data: what the
    seal tool reads. For the record."""
    return target.succeed(
        f"tpm2_eventlog {EVENT_LOG} | awk '/^  PCRIndex:/ {{p=$2}} /^  EventType:/ {{t=$2}} "
        "/^    VariableDataLength:/ && p == 7 && t == \"EV_EFI_VARIABLE_AUTHORITY\" {print $2}' | sort | uniq -c"
    ).strip()


def seal_tool(sub):
    return target.execute(f"cluster-boot-seal {sub} 2>&1")


def audit_value(text, name):
    found = re.search(rf"^{re.escape(name)} (\S+)$", text, re.M)
    return found.group(1) if found else None


def audit_all():
    target.succeed("systemctl start cluster-boot-audit.service")
    return target.succeed("cat /var/lib/prometheus-node-exporter-text/boot_audit.prom")


def what_the_next_boot_needs():
    """`avc boot reboot` reads the bindings and the identity secret as they are now, through the
    seal tool, and the audit exports both: a leg left unbound after a disk swap holds the next
    boot at the prompt, and a deleted secret halts it. Both must show before the reboot."""
    legs = sorted(LUKS_DEVICES.items())

    def tokens_in(text):
        return {n: audit_value(text, f'cluster_boot_tpm_tokens{{device="{d}"}}') for n, d in legs}

    rc, out = seal_tool("check")
    text = audit_all()
    tokens = tokens_in(text)
    control(
        "seal-check-clean-after-unattended",
        rc == 0
        and out.count("OK: ") == len(legs)
        and audit_value(text, "cluster_volume_identity_ok") == "1"
        and set(tokens.values()) == {"1"},
        f"rc={rc} tokens={tokens}\n{out}\n{text}",
    )

    # A leg with no binding, as after a disk replaced and never bound.
    name, device = legs[-1]
    target.succeed(f"systemd-cryptenroll --wipe-slot=tpm2 {device}")
    rc, out = seal_tool("check")
    text = audit_all()
    control(
        "seal-check-sees-unbound-leg",
        rc == 1 and f"{device} has no TPM binding" in out and tokens_in(text)[name] == "0",
        f"rc={rc}\n{out}\n{text}",
    )
    rc, out = bind("--device", device)
    control("seal-check-rebound-leg", rc == 0 and set(tpm_tokens().values()) == {1}, f"rc={rc}\n{out}")

    # A slot that is there and does not open: sealed to a PCR 7 that is not this firmware's,
    # as a binding made before a firmware update is after it. The header shows one TPM slot,
    # like the good leg's, so only asking the TPM tells. Made with systemd-cryptenroll
    # itself, since cluster-boot-seal seals to nothing but the PCR 7 it is run under.
    stale = "11" * 32
    target.succeed(
        f"systemd-cryptenroll --wipe-slot=tpm2 {device}",
        f"printf %s {shlex.quote(PASSPHRASE)} | systemd-cryptenroll --unlock-key-file=/dev/stdin "
        f"--tpm2-device=auto --tpm2-pcrs=7:sha256={stale} {device}",
        timeout=300,
    )
    rc, out = seal_tool("check")
    text = audit_all()
    control(
        "seal-check-sees-slot-that-does-not-open",
        rc == 1 and f"{device}: its TPM slot does not open" in out and tokens_in(text)[name] == "1",
        f"rc={rc}\n{out}\n{text}",
    )
    # Bound already, so a plain bind refuses and leaves it. --replace is what puts it right,
    # and leaves one slot on each leg.
    rc_plain, out_plain = bind("--device", device)
    rc, out = bind("--replace")
    rc_check, out_check = seal_tool("check")
    control(
        "bind-replace-renews-a-stale-slot",
        rc_plain != 0
        and "already bound" in out_plain
        and rc == 0
        and rc_check == 0
        and set(tpm_tokens().values()) == {1},
        f"plain: rc={rc_plain} {out_plain.strip()}; replace: rc={rc} tokens={tpm_tokens()}\n{out}\n"
        f"check: rc={rc_check}\n{out_check}",
    )

    # The identity secret gone: every generation would halt at its check.
    target.succeed(f"mv {IDENTITY_PATH} {IDENTITY_PATH}.away")
    rc_gone, out_gone = seal_tool("identity")
    gone = audit_value(audit_all(), "cluster_volume_identity_ok")
    target.succeed(f"mv {IDENTITY_PATH}.away {IDENTITY_PATH}")
    rc_back, out_back = seal_tool("identity")
    back = audit_value(audit_all(), "cluster_volume_identity_ok")
    control(
        "identity-check-sees-missing-secret",
        rc_gone == 1 and "no identity file" in out_gone and gone == "0" and rc_back == 0 and back == "1",
        f"gone: rc={rc_gone} metric={gone} {out_gone.strip()}; back: rc={rc_back} metric={back} {out_back.strip()}",
    )


def booted_entry_kept(disks, firmware):
    """Lanzaboote keeps the entry the node booted on the ESP past configurationLimit, by finding
    /run/booted-system among the generation links. So it holds while that link exists, which is
    why the weekly GC keeps it (lib/generation-gc.nix, tests/deploy-safety.nix)."""
    # other-kernel-same-pcr7 left loader.conf on generation 1's kernelupdate entry. An install
    # writes the newest generation back as the default, and the next boot takes that.
    first, _ = boot_unattended(disks, firmware)
    rc, out = install_bootloader() if first else (None, "")
    power_off()
    ok, detail = unattended(disks, firmware)
    control("booted-entry-boot", first and rc == 0 and ok, f"first={first} install rc={rc}\n{out}\n{detail}")
    booted = booted_closure()
    gen = int(target.succeed(
        "for l in /nix/var/nix/profiles/system-*-link; do "
        f"if [ \"$(readlink -f $l)\" = {booted} ]; then basename $l; fi; done | sed 's/system-\\([0-9]*\\)-link/\\1/' | sort -n | tail -n 1"
    ).strip())
    other = target.succeed(f"readlink -f {TOPLEVEL}/specialisation/kernelupdate").strip()
    results = []
    for i in range(6):
        set_generation(other if i % 2 == 0 else TOPLEVEL)
        results.append(install_bootloader()[0])
    newest = int(target.succeed("readlink /nix/var/nix/profiles/system | sed 's/system-\\([0-9]*\\)-link/\\1/'").strip())
    kept = {esp: on_esp(esp, gen) for esp in ("/boot", "/boot-fallback")}
    dropped = {esp: on_esp(esp, gen + 1) for esp in ("/boot", "/boot-fallback")}
    control(
        "booted-entry-kept-past-the-limit",
        results == [0] * 6 and all(kept.values()) and not any(dropped.values()) and newest - gen >= 6,
        f"booted generation {gen}, newest {newest}, installs {results}; kept {kept}; next one {dropped}",
    )
    # Without its link the entry goes at the next install: what nix.gc's 14 days would do.
    target.succeed(f"nix-env -p /nix/var/nix/profiles/system --delete-generations {gen}")
    set_generation(other)
    rc, out = install_bootloader()
    gone = {esp: on_esp(esp, gen) for esp in ("/boot", "/boot-fallback")}
    control(
        "booted-entry-needs-its-link",
        rc == 0 and not any(gone.values()),
        f"rc={rc} {gone}\n{out}",
    )
    power_off()


def report_tpm():
    """What the node says about the boot nobody typed into, and what the Worker stored of it:
    both legs opened by the TPM, under enforcing Secure Boot, nobody in the initrd."""
    metrics = report_metrics()
    bid = this_boot()
    event = delivered_boot_event(bid)
    booted = booted_closure()
    # sysfs prints the digest in capitals; the report writes it as the Worker takes it.
    digest = pcr7().lower()
    want = {
        "cluster_boot_unlock_passphrase": "0",
        "cluster_boot_unlock_tpm_devices": str(len(LUKS_DEVICES)),
        "cluster_boot_unlock_expected_devices": str(len(LUKS_DEVICES)),
        "cluster_unlock_tpm_ok": "1",
        "cluster_boot_tpm_refusals": "0",
        "cluster_boot_initrd_ssh_logins": "0",
        "cluster_boot_secure_boot_enabled": "1",
        "cluster_boot_setup_mode": "0",
        "cluster_boot_insecure_optout": "0",
        f'cluster_boot_pcr7_info{{value="{digest}"}}': "1",
    }
    wrong = {k: metrics.get(k) for k, v in want.items() if metrics.get(k) != v}
    control(
        "report-tpm",
        not wrong
        and "cluster_reboot_pending" not in metrics
        and event is not None
        and event["sender"] == "target"
        and event["node"] == "target"
        and event["unlock"] == "tpm"
        and event["tpm_devices"] == len(LUKS_DEVICES)
        and event["initrd_ssh_logins"] == 0
        and event["secure_boot"] == 1
        and event["setup_mode"] == 0
        and event["pcr7"] == digest
        and event["toplevel"] == os.path.basename(booted)[:32]
        and event["generation"] >= 2,
        f"wrong metrics {wrong}; event {event}; refused {refused_requests()}; last email {last_email()!r}\n{metrics}",
    )


def main():
    peer.start()
    peer.wait_for_unit("multi-user.target")
    provision(inspect=installed)

    disks = new_case()
    firmware = new_firmware()

    # ── S3: Setup Mode, passphrase typed ───────────────────────────────────
    boot(disks, firmware=firmware)
    booted = type_until_stage2(target, serial())
    control("first-boot-reaches-stage-2", booted, "no stage 2")
    target.wait_for_unit("multi-user.target")
    status = pool_status()
    secure = secure_boot_status()
    control(
        "first-boot-setup-mode",
        secure.startswith("disabled (setup)")
        and efi_flag("SetupMode") == "1"
        and efi_flag("SecureBoot") == "0"
        and both_legs_online(status),
        f"{secure} SetupMode={efi_flag('SetupMode')} {status}",
    )
    control("default-entry-is-the-generation", booted_closure() == TOPLEVEL, booted_closure())
    journal = target.succeed("journalctl -b -o cat | grep 'volume-identity:' || true")
    control("identity-ok-first-boot", "volume-identity: OK" in journal, journal)
    setup_pcr7 = pcr7()

    for esp in ("/boot", "/boot-fallback"):
        ok, out = sbctl_verified(esp)
        control(f"sbctl-verify{esp.replace('/', '-')}", ok, out)

    # The Setup Mode PCR 7 is the same constant on every machine, so a binding made now
    # would open for anyone who clears the keys. The right passphrase, and still refused.
    rc, out = bind()
    tokens = tpm_tokens()
    control(
        "bind-refused-in-setup-mode",
        rc != 0 and "refusing: SecureBoot=0 SetupMode=1" in out and set(tokens.values()) == {0},
        f"rc={rc} tokens={tokens}\n{out}",
    )

    # ── S4: enroll ─────────────────────────────────────────────────────────
    # The node's own tool, as `avc boot enroll` runs it: option ROMs by hash, no Microsoft
    # keys. The other boot tests enroll Microsoft's as well (enroll_keys), the opt-in.
    rc, out = seal_tool("enroll")
    microsoft = int(target.succeed(f"grep -ac 'Microsoft Corporation' {DB} || true").strip())
    control(
        "enroll-from-os",
        rc == 0 and efi_flag("SetupMode") == "0" and microsoft == 0,
        f"rc={rc} Microsoft entries in db: {microsoft}\n{out}",
    )
    power_off()

    # ── S5: enforcing ──────────────────────────────────────────────────────
    boot(disks, firmware=firmware)
    booted = type_until_stage2(target, serial())
    control("enforcing-reaches-stage-2", booted, "no stage 2 once enrolled")
    target.wait_for_unit("multi-user.target")
    secure = secure_boot_status()
    enforcing_pcr7 = pcr7()
    control(
        "enforcing",
        enforcing() and enforcing_pcr7 != setup_pcr7,
        f"{secure}; PCR 7 {setup_pcr7} then {enforcing_pcr7}",
    )
    control("enforcing-both-legs", both_legs_online(pool_status()), pool_status())
    # One signed chain whichever disk the firmware starts from.
    difference = esps_identical()
    control("both-esps-identical-enforcing", difference == "", difference)

    target.log(f"PCR 7 authority events by data length (48 is a hash, more a certificate):\n{pcr7_authorities()}")

    # ── S6: bind ───────────────────────────────────────────────────────────
    # The passphrase is what authorises a new slot: none, or the wrong one, binds nothing.
    rc, out = bind(passphrase="")
    tokens = tpm_tokens()
    control(
        "bind-refused-without-passphrase",
        rc == 2 and "no passphrase on stdin" in out and set(tokens.values()) == {0},
        f"rc={rc} tokens={tokens}\n{out}",
    )
    rc, out = bind(passphrase=WRONG)
    tokens = tpm_tokens()
    control(
        "bind-wrong-passphrase-binds-nothing",
        rc != 0 and set(tokens.values()) == {0},
        f"rc={rc} tokens={tokens}\n{out}",
    )
    # One TPM slot on each leg, and the TPM opens both here, under the PCR 7 it sealed to.
    rc, out = bind()
    tokens = tpm_tokens()
    rc_tpm, answer = tpm_answer()
    control(
        "bind",
        rc == 0 and set(tokens.values()) == {1} and rc_tpm == 0,
        f"bind rc={rc} tokens={tokens}\n{out}\nTPM rc={rc_tpm}: {answer.strip()[-300:]}",
    )
    # Bound twice is refused, and the slots stay as they were.
    rc, out = bind()
    tokens = tpm_tokens()
    control(
        "bind-twice-refused",
        rc != 0 and "already bound" in out and set(tokens.values()) == {1},
        f"rc={rc} tokens={tokens}\n{out}",
    )

    # ── a new generation, as a deploy installs one ─────────────────────────
    newgen = target.succeed(f"readlink -f {TOPLEVEL}/specialisation/newgen").strip()
    set_generation(newgen)
    rc, out = install_bootloader()
    on_a, on_b = on_esp("/boot", 2), on_esp("/boot-fallback", 2)
    difference = esps_identical()
    control(
        "generation-2-on-both-esps",
        rc == 0 and len(on_a) == 1 and len(on_b) == 1 and difference == "",
        f"rc={rc} {on_a} {on_b} {difference}\n{out}",
    )
    for esp in ("/boot", "/boot-fallback"):
        ok, out = sbctl_verified(esp)
        control(f"sbctl-verify-generation-2{esp.replace('/', '-')}", ok, out)
    power_off()

    # ── S7: nobody types ───────────────────────────────────────────────────
    ok, detail = unattended(disks, firmware)
    control("unattended-both-devices", ok, detail)
    base_kernel = target.succeed("uname -r").strip()
    control(
        "generation-2-is-what-booted",
        booted_closure() == newgen and target.succeed("cat /etc/test-newgen").strip() == "2",
        booted_closure(),
    )
    control("generation-2-keeps-the-same-pcr7", enforcing() and pcr7() == enforcing_pcr7, pcr7())
    target.wait_for_unit("multi-user.target")

    report_tpm()

    failed = target.succeed("systemctl list-units --state=failed,auto-restart --no-legend --plain")
    control("unattended-no-failed-units", failed.strip() == "", failed)
    what_the_next_boot_needs()
    power_off()

    # Nothing about an unattended boot wears out.
    results = []
    for _ in range(2):
        ok, detail = unattended(disks, firmware)
        results.append((ok and pcr7() == enforcing_pcr7, detail))
        power_off()
    control("repeat-boots", all(ok for ok, _ in results), "\n".join(d for _, d in results))

    # The TPM is all an unattended boot asks: the same boot with the cable out from power-on.
    ok, detail = unattended(disks, firmware, unplugged=True)
    carrier = target.succeed(f"cat /sys/class/net/{WAN_INTERFACE}/carrier 2>&1 || true").strip() if ok else ""
    control(
        "unattended-with-no-network",
        ok and carrier == "0" and pcr7() == enforcing_pcr7,
        f"carrier on {WAN_INTERFACE}: {carrier!r}\n{detail}",
    )
    power_off()

    # A kernel update is a new signed entry with the same signer: PCR 7 doesn't move, so the
    # binding holds. The entry is selected through the unsigned loader.conf, as anyone can.
    select_entry(disks, "kernelupdate", generation=1)
    ok, detail = unattended(disks, firmware)
    running = target.succeed("uname -r").strip() if ok else ""
    control(
        "other-kernel-same-pcr7",
        ok and running != base_kernel and pcr7() == enforcing_pcr7 and enforcing(),
        f"kernel {running} (base {base_kernel}), PCR 7 against {enforcing_pcr7}\n{detail}",
    )
    power_off()

    # Last: it takes generation 1, and its kernelupdate entry, off the ESPs.
    booted_entry_kept(disks, firmware)
