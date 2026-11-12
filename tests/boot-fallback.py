SLOW_HUMAN_SECONDS = 75
# From power-on. A TPM that refuses says so in the first seconds of the initrd, twice for
# each leg, and the prompt follows: about 5 seconds of kernel time, plus the firmware's.
REFUSED_PROMPT_SECONDS = 20


SSHD_ACCEPTED = "journalctl -b -o cat --no-pager _COMM=sshd-session _COMM=sshd _UID=0 | grep -c '^Accepted ' || true"


def report_initrd_ssh_logins():
    """The operator's logins to the initrd are counted, and told apart from a login after
    it. The report reads both from this boot's journal and keeps those from before stage 2's
    systemd started; so a stage-2 login, by the same key, must not move the count."""
    metrics = report_metrics()
    initrd = int(metrics.get("cluster_boot_initrd_ssh_logins", "-1"))
    before = int(target.succeed(SSHD_ACCEPTED).strip())
    target.wait_for_unit("sshd.service")
    rc, out = peer.execute(
        "ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes "
        f"-o ConnectTimeout=10 -i /root/id root@{STAGE2_ADDRESS} true 2>&1"
    )
    target.wait_until_succeeds(f"test $({SSHD_ACCEPTED}) -gt {before}", timeout=30)
    after = int(target.succeed(SSHD_ACCEPTED).strip())
    again = int(rerun_report().get("cluster_boot_initrd_ssh_logins", "-1"))
    event = delivered_boot_event(this_boot())
    control(
        "report-initrd-ssh-logins",
        initrd >= 2
        and rc == 0
        and after == before + 1
        and again == initrd
        and event is not None
        and event["initrd_ssh_logins"] == initrd,
        f"initrd logins {initrd}, again after a stage-2 login {again}; Accepted lines {before} then {after} "
        f"(stage-2 ssh rc={rc} {out.strip()}); event {event}; refused {refused_requests()}",
    )


def report_passphrase():
    """A bound node whose TPM refused, typed through: the report says passphrase, the TPM
    opened no leg and refused both, and the Worker has the same. Both legs asked the TPM
    on this boot, so a report that counted the asking would call it a TPM unlock."""
    metrics = report_metrics()
    event = delivered_boot_event(this_boot())
    legs = str(len(LUKS_DEVICES))
    want = {
        "cluster_boot_unlock_passphrase": "1",
        "cluster_boot_unlock_tpm_devices": "0",
        "cluster_boot_unlock_expected_devices": legs,
        "cluster_unlock_tpm_ok": "0",
        "cluster_boot_tpm_refusals": legs,
        "cluster_boot_secure_boot_enabled": "1",
        "cluster_boot_setup_mode": "0",
    }
    wrong = {k: metrics.get(k) for k, v in want.items() if metrics.get(k) != v}
    control(
        "report-passphrase",
        not wrong
        and event is not None
        and event["unlock"] == "passphrase"
        and event["tpm_devices"] == 0
        and event["expected_devices"] == len(LUKS_DEVICES),
        f"wrong metrics {wrong}; event {event}; "
        f"refused {refused_requests()}; last email {last_email()!r}\n{metrics}",
    )


def refused_console(bound, firmware):
    """A bound, enforcing node whose firmware came to trust one more signer: PCR 7 is not
    the value the slots are sealed to, the TPM refuses both legs, and the prompt is there
    within seconds. This boot is also the one that checks everything else about a normal
    boot."""
    disks = new_case(base=bound)
    started = boot(disks, firmware=refusing_firmware(firmware))
    found = next_prompt(target, 0, 60)
    elapsed = time.monotonic() - started
    control(
        f"refused-console-prompt-within-{REFUSED_PROMPT_SECONDS}s",
        found is not None and elapsed <= REFUSED_PROMPT_SECONDS,
        f"{elapsed:.1f}s",
    )

    # The prompt is up, so the initrd's network is too, or it never will be.
    control("initrd-ssh-on-the-wan-nic", wait_initrd_ssh(), f"no ssh to {WAN_ADDRESS}")
    rc, scanned = peer.execute(f"ssh-keyscan -p {SSH_PORT} -t ed25519 {WAN_ADDRESS} 2>/dev/null")
    initrd_key = scanned.split()[-2:] if rc == 0 else []

    booted = type_until_stage2(target, serial())
    control("refused-console", booted, "typing on the serial console did not reach stage 2")
    status = pool_status()
    control("refused-console-both-legs", both_legs_online(status) and root_is_the_pool(), status)
    # It was the TPM refusing that brought the prompt, for each leg, and neither opened from
    # its slot. Without this the case could pass on a node that never asked the TPM.
    journal = target.succeed("journalctl -b -o cat --no-pager")
    refused = {name: leg_journal(name).count(TPM_REFUSED) for name in sorted(LUKS_DEVICES)}
    control(
        "refused-console-tpm-refused-both-legs",
        all(n >= 1 for n in refused.values()) and tpm_opened_legs() == [] and TPM_OPENED not in journal,
        f"refusals logged {refused}, legs opened by the TPM {tpm_opened_legs()}",
    )
    rc, answer = tpm_answer()
    control("refused-console-tpm-still-refuses", rc != 0, answer)
    control("passphrase-not-in-the-journal", PASSPHRASE not in journal, "the typed passphrase is in the journal")
    report_passphrase()

    rc, addresses = target.execute(f"ip -4 -o addr show {WAN_INTERFACE}")
    control("flush-leaves-no-initrd-address", rc == 0 and WAN_ADDRESS not in addresses, addresses)

    cmdline = target.succeed("cat /proc/cmdline").split()
    wanted = IOMMU_PARAMS + ["systemd.import_credentials=no", "noresume"]
    control("kernel-params", all(p in cmdline for p in wanted), " ".join(cmdline))

    # What the disko hook left on the root, and that the initrd really has the key it placed.
    mode, digest = target.succeed(f"stat -c %a {IDENTITY_PATH}; sha256sum < {IDENTITY_PATH}").split()[:2]
    control("disko-hook-placed-identity", mode == "400" and digest == IDENTITY_HASH, f"{mode} {digest}")
    mode = target.succeed(f"stat -c %a {HOST_KEY_PATH}").strip()
    placed = target.succeed(f"ssh-keygen -y -f {HOST_KEY_PATH}").split()[:2]
    control(
        "disko-hook-placed-host-key",
        mode == "400" and initrd_key[:2] == placed,
        f"{mode}, initrd {initrd_key}, placed {placed}",
    )
    power_off()


def refused_tty0(bound, firmware):
    """The closest stand-in for a BMC's KVM: PS/2 keystrokes on the first VT."""
    disks = new_case(base=bound)
    boot(disks, firmware=refusing_firmware(firmware))
    booted = type_until_stage2(target, tty0())
    control("refused-tty0", booted and both_legs_online(pool_status()), "typing on tty0 did not reach stage 2")
    power_off()


def refused_ssh(bound, firmware):
    """The TPM refuses and nobody is at a console: the operator answers over initrd SSH, on
    the WAN NIC."""
    disks = new_case(base=bound)
    boot(disks, firmware=refusing_firmware(firmware))
    reachable = wait_initrd_ssh(90)
    opened = ""
    deadline = time.monotonic() + 150
    while reachable and time.monotonic() < deadline:
        answer_over_ssh(PASSPHRASE)
        rc, opened = initrd_ssh("ls /dev/mapper", timeout=20)
        if rc != 0 or ("crypt-a" in opened and "crypt-b" in opened):
            # Gone means switch-root took SSH with it, which is what both legs open leads to.
            break
    booted = reachable and wait_stage2(target, 120)
    control(
        "refused-ssh",
        booted and both_legs_online(pool_status()),
        f"initrd ssh reachable: {reachable}, last /dev/mapper: {opened!r}, stage 2: {booted}",
    )
    report_initrd_ssh_logins()
    power_off()


def wrong_then_right():
    """Each leg keeps its own count of tries and they take turns at the console, so 8 wrong
    answers are what it takes to give both legs more than cryptsetup's default of 3."""
    disks = new_case()
    boot(disks)
    after = 0
    wrong = 0
    for _ in range(8):
        found = next_prompt(target, after, 60)
        if found is None:
            break
        after = found
        time.sleep(0.5)
        serial()(WRONG)
        wrong += 1
    booted = wrong == 8 and type_until_stage2(target, serial(), after)
    online = booted and both_legs_online(pool_status())
    control("wrong-then-right", online, f"{wrong} wrong answers taken, stage 2: {booted}")
    power_off()


def slow_human_gate():
    """Longer than nixpkgs' 60-second import loop. Nothing may give up on the disks."""
    disks = new_case()
    started = boot(disks)
    found = next_prompt(target, 0, 60)
    control("slow-human-prompt", found is not None, "no prompt")
    time.sleep(max(0, SLOW_HUMAN_SECONDS - (time.monotonic() - started)))
    booted = type_until_stage2(target, serial(), timeout=180)
    online = booted and both_legs_online(pool_status())
    control("slow-human-gate", online, f"typed at {SLOW_HUMAN_SECONDS}s, stage 2: {booted}")
    power_off()


ASKED_LEG = re.compile(r"Please enter passphrase for disk \S+ \((crypt-[ab])\)")


def pending_queries() -> list[dict[str, str]] | None:
    """The LUKS password queries waiting in the initrd, read over SSH from systemd's ask
    files (Message, AcceptCached, Id, ...), one dict each, or None if SSH failed. Shell
    builtins only: the initrd has little else. A file that goes between the glob and the
    read is simply not listed."""
    rc, out = initrd_ssh(
        'for f in /run/systemd/ask-password/ask.*; do [ -f "$f" ] || continue; echo "=="; '
        'while IFS= read -r l; do printf "%s\\n" "$l"; done < "$f" 2>/dev/null; done'
    )
    if rc != 0:
        return None
    queries: list[dict[str, str]] = []
    for block in out.split("==\n")[1:]:
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                fields[key] = value
        if fields.get("Id", "").startswith("cryptsetup:"):
            queries.append(fields)
    return queries


def answerable_prompt(after, timeout):
    """(index past the prompt, the leg it names) for the newest prompt that only a typed
    answer can finish, or (None, None).

    A leg's first query also takes a key that turns up in the kernel keyring, and the
    console agent may already be showing it when the other leg's answer lands there. That
    query is then withdrawn, and whatever is typed at it goes nowhere. Seen: WRONG answered
    crypt-a, crypt-b's own first query came up 7 ms later and took the cached WRONG, the
    PASSPHRASE typed at it was lost, and crypt-a's retry, shown 4 s on, was never answered.
    So: the prompt names a leg whose query is waiting with AcceptCached=0, which nothing
    but an answer ends, and no query a cached key could still take is left."""
    deadline = time.monotonic() + timeout
    leg: str | None = None
    while time.monotonic() < deadline:
        # The agent shows one query at a time, the last one it began: always the newest prompt.
        # Found by its leg, which can come out on a later line than the start of the prompt
        # when a kernel record cuts it (tests/lib/boot-harness.py, ConsoleReader).
        found, named = wait_console_match(target, ASKED_LEG, 1, after)
        if found is not None:
            after = found
            leg = named.group(1)
            target.log(f"partial: prompt for {leg} at console line {found}")
            continue
        if leg is None:
            continue
        queries = pending_queries()
        if (
            queries
            and all(q.get("AcceptCached") == "0" for q in queries)
            and any(f"({leg})" in q.get("Message", "") for q in queries)
        ):
            target.log(f"partial: answering {leg}; pending {queries!r}")
            return after, leg
        target.log(f"partial: not yet answering {leg}; pending {queries!r}")
    return None, None


def partial_waits():
    """One wrong answer, then the right one: one leg opens and the other, having failed
    once, won't take the cached key and keeps asking. The pool must wait for it."""
    disks = new_case()
    boot(disks)
    control("partial-initrd-ssh", wait_initrd_ssh(), "no ssh")
    found = next_prompt(target, 0, 60)
    control("partial-first-prompt", found is not None, "no prompt")
    time.sleep(0.5)
    serial()(WRONG)
    found, leg = answerable_prompt(found, 60)
    control("partial-second-prompt", found is not None, "no prompt that only typing can answer")
    time.sleep(0.5)
    serial()(PASSPHRASE)

    def opened():
        # The initrd has ls, and not much else.
        return sorted(set(re.findall(r"crypt-[ab]", initrd_ssh("ls /dev/mapper")[1])))

    deadline = time.monotonic() + 30
    while len(opened()) != 1 and time.monotonic() < deadline:
        time.sleep(1)
    now = opened()
    # One leg, and the one the answer was typed for.
    control("partial-one-leg-open", now == [leg], f"answered {leg}, opened {now}")

    time.sleep(90)
    rc, pools = initrd_ssh("zpool list -H -o name 2>&1")
    now = opened()
    control(
        "partial-waits",
        now == [leg] and "rpool" not in pools and not wait_stage2_now(target),
        f"opened {now} (answered {leg}), pools: {pools!r}",
    )

    booted = type_until_stage2(target, serial(), found)
    status = pool_status() if booted else ""
    control("partial-both-legs-online", booted and both_legs_online(status), status)
    # Never imported DEGRADED, even for a moment on the way here.
    log = target.succeed("journalctl -b -o cat | grep -c 'DEGRADED' || true").strip()
    control("partial-never-degraded", log == "0", log)
    power_off()


def wait_stage2_now(machine):
    # Corrected in WS4: this used to look for a "Welcome to NixOS" line, which the serial
    # console never shows, so it read only `connected`.
    return machine.connected or console_seen(machine, SWITCHED)


def recover_emergency_over_ssh():
    """A failed boot, with nobody at a console. SSH stays up through emergency mode, and
    from there the operator can finish the boot."""
    disks = new_case()
    select_entry(disks, "nogate")
    boot(disks)
    found = wait_console(target, EMERGENCY, 180)
    control("emergency-reached", found is not None, "the import did not fail without a gate")
    control("emergency-ssh-up", wait_initrd_ssh(), "no ssh in emergency mode")
    rc, out = initrd_ssh(
        "systemctl --no-block start 'systemd-cryptsetup@crypt\\x2da.service' 'systemd-cryptsetup@crypt\\x2db.service'"
    )
    control("emergency-start-cryptsetup", rc == 0, out)
    deadline = time.monotonic() + 120
    opened = ""
    while time.monotonic() < deadline:
        answer_over_ssh(PASSPHRASE)
        opened = initrd_ssh("ls /dev/mapper")[1]
        if "crypt-a" in opened and "crypt-b" in opened:
            break
    control("emergency-both-legs-opened", "crypt-a" in opened and "crypt-b" in opened, opened)
    rc, out = initrd_ssh("systemctl restart zfs-import-rpool.service && systemctl --no-block default")
    control("emergency-continue", rc == 0, out)
    booted = wait_stage2(target, 180)
    control(
        "recover-emergency-over-ssh",
        booted and both_legs_online(pool_status()),
        "the boot did not finish from emergency mode",
    )
    power_off()


def emergency_password():
    """The console shell takes the hash's password, and only that. On tty0, where the
    kernel's /dev/console points, with the shell's own output sent to the serial log."""
    disks = new_case()
    select_entry(disks, "nogate")
    boot(disks)
    found = wait_console(target, EMERGENCY, 180)
    control("emergency-password-reached", found is not None, "no emergency mode")
    time.sleep(8)
    send = tty0()
    probe = "echo {}-SHELL-$((40 + 2)) > /dev/ttyS0"
    send("not-the-password")
    time.sleep(5)
    send(probe.format("WRONG"))
    time.sleep(3)
    control(
        "emergency-wrong-password-refused",
        wait_console(target, re.compile("WRONG-SHELL-42"), 5) is None,
        "a shell took the wrong password",
    )
    # The refused probe was itself taken as a password attempt. Let that attempt finish.
    time.sleep(8)
    send(EMERGENCY_PASSWORD)
    time.sleep(5)
    send(probe.format("RIGHT"))
    found = wait_console(target, re.compile("RIGHT-SHELL-42"), 30)
    control("emergency-right-password-opens", found is not None, "\n".join(target.full_console_log[-15:]))
    power_off()


def main():
    peer.start()
    peer.wait_for_unit("multi-user.target")
    ssh_ready()
    provision()
    # A node as it runs: enforcing, and bound to the TPM at its PCR 7. The refused cases
    # boot that node on firmware that trusts one more signer, so its TPM is asked and
    # refuses. The typed cases boot fresh firmware, where the TPM has nothing to give and
    # typing is the only way in.
    sealed, sealed_firmware = sealed_checkpoint()
    bound, bound_firmware, _ = bound_checkpoint(sealed, sealed_firmware)
    # Each named mutant takes out one control for the whole node, so the case it is about
    # runs before any case that leans on that control for something else: partial_waits
    # needs SSH.
    wrong_then_right()
    slow_human_gate()
    refused_ssh(bound, bound_firmware)
    refused_console(bound, bound_firmware)
    refused_tty0(bound, bound_firmware)
    partial_waits()
    recover_emergency_over_ssh()
    emergency_password()
