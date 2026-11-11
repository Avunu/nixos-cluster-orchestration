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


def vlan_gone(name):
    """The VLAN went with the initrd: no link, no route to Tang, and the audit agrees."""
    rc_link, link = target.execute(f"ip link show {TANG_VLAN} 2>&1")
    rc_ping, ping = target.execute(f"ping -c 1 -W 2 {TANG_ADDRESS} 2>&1")
    present = audit_metric("cluster_tang_vlan_present")
    control(
        name,
        rc_link != 0 and rc_ping != 0 and present == "0",
        f"link rc={rc_link} {link.strip()}; ping rc={rc_ping}; cluster_tang_vlan_present {present}",
    )


def unattended(disks, firmware):
    """A boot nobody types into: both legs from Tang and the TPM, one key recovery each.
    Returns whether it was that, and what happened."""
    before = rec_count()
    booted, took = boot_unattended(disks, firmware)
    recovered = rec_count() - before
    status = pool_status() if booted else ""
    detail = f"stage 2: {booted} after {took:.0f}s, {recovered} key recoveries at Tang\n{status}"
    target.log(detail)
    return booted and recovered == 2 and both_legs_online(status), detail


def forged_adv(adv):
    """The pinned key's public half in the payload, the attacker's key beside it, and a
    signature by the attacker's key alone. Everything a thumbprint check reads is genuine:
    only the signature says this advertisement is not Tang's."""
    path = put_adv(adv, "/run/real-adv.jws")
    target.succeed(
        "jose jwk gen -i '{\"alg\":\"ES512\"}' -o /run/att.jwk",
        "jose jwk pub -i /run/att.jwk -o /run/att.pub",
        f"jose fmt -j- -g payload -y -o- < {path} | jq -c --slurpfile a /run/att.pub '.keys += $a' > /run/forged.json",
        "jose jws sig -I /run/forged.json -k /run/att.jwk -o /run/forged.jws",
    )
    return target.succeed("cat /run/forged.jws").strip()


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


def what_the_next_boot_needs(adv):
    """`avc boot reboot` reads the bindings and the identity secret as they are now, through the
    seal tool, and the audit exports both: a leg left unbound after a disk swap holds the next
    boot at the prompt, and a deleted secret halts it. Both must show before the reboot."""
    legs = sorted(LUKS_DEVICES.items())
    rc, out = seal_tool("check")
    text = audit_all()
    tokens = {n: audit_value(text, f'cluster_boot_clevis_tokens{{device="{d}"}}') for n, d in legs}
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
    slot = target.succeed(f"clevis luks list -d {device} | cut -d: -f1").split()[0]
    target.succeed(f"clevis luks unbind -f -d {device} -s {slot}")
    rc, out = seal_tool("check")
    text = audit_all()
    control(
        "seal-check-sees-unbound-leg",
        rc == 1
        and f"{device} has no Clevis binding" in out
        and audit_value(text, f'cluster_boot_clevis_tokens{{device="{device}"}}') == "0",
        f"rc={rc}\n{out}\n{text}",
    )
    rc, out = bind(adv, "--device", device)
    control("seal-check-rebound-leg", rc == 0 and set(clevis_tokens().values()) == {1}, f"rc={rc}\n{out}")

    # A slot bound to a Tang key nobody pinned, beside the good one: what a node missed in a
    # Tang rotation keeps once the old thumbprint is unpinned. Its TPM share opens and the
    # last boot was clean, so only the advertisement in its header says it is stale. Bound
    # with clevis itself, because cluster-boot-seal refuses this advertisement.
    import json

    foreign = put_adv(foreign_adv(), "/run/foreign-adv.jws")
    pin = json.dumps(
        {
            "t": 2,
            "pins": {
                "tang": [{"url": f"http://{TANG_ADDRESS}:{TANG_PORT}", "adv": foreign}],
                "tpm2": [{"pcr_bank": "sha256", "pcr_ids": "7"}],
            },
        }
    )

    def slots():
        return set(target.succeed(f"clevis luks list -d {device} | cut -d: -f1").split())

    before = slots()
    target.succeed(
        f"printf %s {shlex.quote(PASSPHRASE)} | clevis luks bind -y -k - -d {device} sss {shlex.quote(pin)}",
        timeout=300,
    )
    added = slots() - before
    rc, out = seal_tool("check")
    text = audit_all()
    unpinned = {n: audit_value(text, f'cluster_boot_clevis_unpinned_tokens{{device="{d}"}}') for n, d in legs}
    control(
        "seal-check-sees-unpinned-tang",
        len(added) == 1
        and rc == 4
        and f"{device} token" in out
        and "not pinned" in out
        and unpinned == {n: ("1" if d == device else "0") for n, d in legs},
        f"added={added} rc={rc} unpinned={unpinned}\n{out}\n{text}",
    )
    for s in added:
        target.succeed(f"clevis luks unbind -f -d {device} -s {s}")
    rc, out = seal_tool("check")
    text = audit_all()
    unpinned = {n: audit_value(text, f'cluster_boot_clevis_unpinned_tokens{{device="{d}"}}') for n, d in legs}
    control(
        "seal-check-clean-once-the-stale-slot-goes",
        rc == 0 and set(unpinned.values()) == {"0"} and set(clevis_tokens().values()) == {1},
        f"rc={rc} unpinned={unpinned}\n{out}",
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


def askpass_one_recovery_per_device():
    """Clevis recovers a device's key from Tang once, however often the device asks. On a boot,
    a passphrase answered for one leg lands in the keyring, the other leg drops its question to
    try it, and Clevis's reply to that question is lost; the leg then asks again. Here the same
    loss, made certain: a question whose asker was killed keeps its ask file, and its socket
    refuses, so every reply to it is lost. Then a live question for the same device. One key
    recovery at Tang in all, and the live question gets the key."""
    device = LUKS_DEVICES["crypt-a"]
    ask = "/run/systemd/ask-password"
    vlan_up_by_hand()
    before = rec_count()
    target.succeed(
        f"systemd-run --unit=askpass-dead systemd-ask-password --no-tty --timeout=0 "
        f"--id=cryptsetup:{device} askpass-dead"
    )
    dead = target.wait_until_succeeds(f"grep -lx 'Message=askpass-dead' {ask}/ask.*", timeout=30).strip()
    socket = target.succeed(f"sed -n 's/^Socket=//p' {dead}").strip()
    target.succeed("systemctl kill -s KILL askpass-dead")
    target.wait_until_fails("systemctl is-active askpass-dead", timeout=30)
    target.succeed(f"test -e {dead} && test -S {socket}")

    target.succeed(f"systemd-run --unit=askpass-test {CLEVIS_ASKPASS} -l")
    lost = "journalctl -u askpass-test -o cat --no-pager | grep -c 'with recovered passphrase' || true"
    target.wait_until_succeeds(f"test $({lost}) -ge 3", timeout=120)
    target.succeed(
        "systemd-run --unit=askpass-live -p StandardOutput=file:/run/askpass-live.out "
        f"systemd-ask-password --no-tty --timeout=60 --id=cryptsetup:{device} askpass-live"
    )
    target.wait_until_succeeds("test -s /run/askpass-live.out", timeout=60)
    target.succeed(f"systemctl stop askpass-test; rm -f {dead} {socket}")
    time.sleep(2)
    recovered = rec_count() - before
    journal = target.succeed("journalctl -u askpass-test -o cat --no-pager")
    replies_lost = int(target.succeed(lost).strip())

    slot = target.succeed(f"clevis luks list -d {device} | cut -d: -f1").split()[0]
    real = target.succeed(
        f"clevis luks pass -d {device} -s {slot} | tr -d '\\n' | sha256sum | cut -d' ' -f1"
    ).strip()
    answer = target.succeed("tr -d '\\n' < /run/askpass-live.out | sha256sum | cut -d' ' -f1").strip()
    target.succeed("rm -f /run/askpass-live.out")
    vlan_down_by_hand()
    control(
        "askpass-one-recovery-per-device",
        recovered == 1 and replies_lost >= 3 and answer == real,
        f"{recovered} key recoveries at Tang, {replies_lost} replies lost, "
        f"the live question {'got' if answer == real else 'did not get'} the key\n{journal}",
    )


def report_clevis():
    """What the node says about the boot nobody typed into, and what the Worker stored of it:
    both legs answered by Clevis, under enforcing Secure Boot, nobody in the initrd."""
    metrics = report_metrics()
    bid = this_boot()
    event = delivered_boot_event(bid)
    booted = booted_closure()
    # sysfs prints the digest in capitals; the report writes it as the Worker takes it.
    digest = pcr7().lower()
    want = {
        "cluster_boot_unlock_passphrase": "0",
        "cluster_boot_unlock_clevis_devices": str(len(LUKS_DEVICES)),
        "cluster_boot_unlock_expected_devices": str(len(LUKS_DEVICES)),
        "cluster_unlock_tpm_share_ok": "1",
        "cluster_boot_initrd_ssh_logins": "0",
        "cluster_boot_secure_boot_enabled": "1",
        "cluster_boot_setup_mode": "0",
        "cluster_boot_insecure_optout": "0",
        f'cluster_boot_pcr7_info{{value="{digest}"}}': "1",
    }
    wrong = {k: metrics.get(k) for k, v in want.items() if metrics.get(k) != v}
    control(
        "report-clevis",
        not wrong
        and "cluster_reboot_pending" not in metrics
        and event is not None
        and event["sender"] == "target"
        and event["node"] == "target"
        and event["unlock"] == "clevis"
        and event["clevis_devices"] == len(LUKS_DEVICES)
        and event["initrd_ssh_logins"] == 0
        and event["secure_boot"] == 1
        and event["setup_mode"] == 0
        and event["pcr7"] == digest
        and event["toplevel"] == os.path.basename(booted)[:32]
        and event["generation"] >= 2,
        f"wrong metrics {wrong}; event {event}; refused {refused_requests()}; last email {last_email()!r}\n{metrics}",
    )


def main():
    tang.start()
    tang.wait_for_unit("multi-user.target")
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
    # Every boot tears the VLAN down, bound or not. Checked here, on the first, so that
    # nothing later stands in front of it; and again after an unattended boot below.
    vlan_gone("tang-vlan-gone-in-stage2")

    for esp in ("/boot", "/boot-fallback"):
        ok, out = sbctl_verified(esp)
        control(f"sbctl-verify{esp.replace('/', '-')}", ok, out)

    # The Setup Mode PCR 7 is the same constant on every machine, so a binding made now
    # would open for anyone who clears the keys. A good advertisement, and still refused.
    adv = fetch_adv()
    rc, out = bind(adv)
    tokens = clevis_tokens()
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
    # The pinned key in the payload, and somebody else's signature.
    rc, out = bind(forged_adv(adv))
    tokens = clevis_tokens()
    control(
        "bind-refused-forged-signature",
        rc != 0 and "signature does not verify" in out and set(tokens.values()) == {0},
        f"rc={rc} tokens={tokens}\n{out}",
    )
    # Signed, well formed, and by a key nobody pinned.
    rc, out = bind(foreign_adv())
    tokens = clevis_tokens()
    control(
        "bind-refused-wrong-thumbprint",
        rc != 0 and "not signed by a pinned key" in out and set(tokens.values()) == {0},
        f"rc={rc} tokens={tokens}\n{out}",
    )
    # The Tang VLAN exists only in the initrd, so stage 2 can't reach Tang, and doesn't need
    # to: the advertisement is what the operator delivers.
    rc_ping, ping = target.execute(f"ping -c 1 -W 2 {TANG_ADDRESS} 2>&1")
    rc, out = bind(adv)
    tokens = clevis_tokens()
    control(
        "bind-no-route-to-tang",
        rc_ping != 0 and rc == 0 and set(tokens.values()) == {1},
        f"ping rc={rc_ping} ({ping.strip()}); bind rc={rc} tokens={tokens}\n{out}",
    )
    # Bound twice is refused, and the slots stay as they were.
    rc, out = bind(adv)
    tokens = clevis_tokens()
    control(
        "bind-twice-refused",
        rc != 0 and "already bound" in out and set(tokens.values()) == {1},
        f"rc={rc} tokens={tokens}\n{out}",
    )
    # Bound, and still in the typed boot: Clevis answering a device that asks more than once.
    askpass_one_recovery_per_device()

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

    report_clevis()

    vlan_gone("tang-vlan-gone-after-unattended")

    # WAN and trunk are two NICs: the operator's way in on one, Tang's VLAN on the other, each
    # from its own .network, and Tang answered over the VLAN (above).
    journal = target.succeed("journalctl -b -o cat --no-pager | grep -E 'Configuring with' || true")
    wanted = {
        WAN_INTERFACE: "30-wan.network",
        TRUNK: "35-trunk.network",
        TANG_VLAN: f"50-{TANG_VLAN}.network",
    }
    configured = {
        link: re.search(rf"^{re.escape(link)}: Configuring with \S*/{re.escape(unit)}", journal, re.M) is not None
        for link, unit in wanted.items()
    }
    control("two-nics", WAN_INTERFACE != TRUNK and all(configured.values()), f"{configured}\n{journal}")

    failed = target.succeed("systemctl list-units --state=failed,auto-restart --no-legend --plain")
    control("unattended-no-failed-units", failed.strip() == "", failed)
    what_the_next_boot_needs(adv)
    power_off()

    # Nothing about an unattended boot wears out.
    results = []
    for _ in range(2):
        ok, detail = unattended(disks, firmware)
        results.append((ok and pcr7() == enforcing_pcr7, detail))
        power_off()
    control("repeat-boots", all(ok for ok, _ in results), "\n".join(d for _, d in results))

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
