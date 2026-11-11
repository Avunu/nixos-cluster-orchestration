SLOW_HUMAN_SECONDS = 75
# Held connections time out after --max-time 15 and are retried, so after healing the patched
# client needs one more try: well inside this.
HEALED_SECONDS = 60
# The stock client, stuck on its first connection, must still be stuck this long after.
STOCK_STUCK_SECONDS = 180


SSHD_ACCEPTED = "journalctl -b -o cat --no-pager _COMM=sshd-session _COMM=sshd _UID=0 | grep -c '^Accepted ' || true"


def report_initrd_ssh_logins():
    """The operator's logins to the initrd are counted, and told apart from a login after
    it. The report reads both from this boot's journal and keeps those from before stage 2's
    systemd started; so a stage-2 login, by the same key, must not move the count."""
    metrics = report_metrics()
    initrd = int(metrics.get("cluster_boot_initrd_ssh_logins", "-1"))
    before = int(target.succeed(SSHD_ACCEPTED).strip())
    target.wait_for_unit("sshd.service")
    rc, out = tang.execute(
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
    """A bound node that Tang refused, typed through: the report says passphrase, Clevis
    answered no leg, and the Worker has the same. Clevis tried all the way through this boot,
    so a report that counted its attempts would call it a Clevis unlock."""
    metrics = report_metrics()
    event = delivered_boot_event(this_boot())
    want = {
        "cluster_boot_unlock_passphrase": "1",
        "cluster_boot_unlock_clevis_devices": "0",
        "cluster_unlock_tpm_share_ok": "0",
        "cluster_boot_secure_boot_enabled": "1",
        "cluster_boot_setup_mode": "0",
    }
    wrong = {k: metrics.get(k) for k, v in want.items() if metrics.get(k) != v}
    attempts = target.succeed("journalctl -b -o cat --no-pager _SYSTEMD_UNIT=clevis-luks-askpass.service | wc -l").strip()
    control(
        "report-passphrase",
        not wrong
        and event is not None
        and event["unlock"] == "passphrase"
        and event["clevis_devices"] == 0
        and event["expected_devices"] == len(LUKS_DEVICES),
        f"wrong metrics {wrong}; askpass logged {attempts} lines; event {event}; "
        f"refused {refused_requests()}; last email {last_email()!r}\n{metrics}",
    )


def refused_console(bound, firmware):
    """Tang refusing connections on a bound, enforcing node: Clevis can't get its half, and
    the prompt is there anyway, at once, because it never waited for Clevis. This boot is
    also the one that checks everything else about a normal boot."""
    stop_tang()
    disks = new_case(base=bound)
    started = boot(disks, firmware=new_firmware(firmware))
    found = next_prompt(target, 0, 60)
    elapsed = time.monotonic() - started
    control("refused-console-prompt-within-10s", found is not None and elapsed <= 10, f"{elapsed:.1f}s")

    # The prompt is up, so the initrd's network is too, or it never will be.
    control("initrd-ssh-on-the-wan-nic", wait_initrd_ssh(), f"no ssh to {WAN_ADDRESS}")
    rc, out = tang.execute(f"ping -c 1 -W 5 {TANG_NODE_ADDRESS}")
    control("initrd-tang-vlan-on-the-trunk-nic", rc == 0, out)
    rc, scanned = tang.execute(f"ssh-keyscan -p {SSH_PORT} -t ed25519 {WAN_ADDRESS} 2>/dev/null")
    initrd_key = scanned.split()[-2:] if rc == 0 else []

    booted = type_until_stage2(target, serial())
    control("refused-console", booted, "typing on the serial console did not reach stage 2")
    status = pool_status()
    control("refused-console-both-legs", both_legs_online(status) and root_is_the_pool(), status)
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
    start_tang()


def refused_tty0(bound, firmware):
    """The closest stand-in for a BMC's KVM: PS/2 keystrokes on the first VT."""
    stop_tang()
    disks = new_case(base=bound)
    boot(disks, firmware=new_firmware(firmware))
    booted = type_until_stage2(target, tty0())
    control("refused-tty0", booted and both_legs_online(pool_status()), "typing on tty0 did not reach stage 2")
    power_off()
    start_tang()


def drop_ssh(bound, firmware):
    """Tang's port silently dropped, so every Clevis attempt waits out its timeout, and nobody
    at a console: the operator answers over initrd SSH, on the WAN NIC."""
    stop_tang()
    tang.succeed(f"iptables -I INPUT 1 -i {TANG_VLAN} -p tcp --dport {TANG_PORT} -j DROP")
    disks = new_case(base=bound)
    boot(disks, firmware=new_firmware(firmware))
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
        "drop-ssh",
        booted and both_legs_online(pool_status()),
        f"initrd ssh reachable: {reachable}, last /dev/mapper: {opened!r}, stage 2: {booted}",
    )
    report_initrd_ssh_logins()
    power_off()
    tang.succeed(f"iptables -D INPUT -i {TANG_VLAN} -p tcp --dport {TANG_PORT} -j DROP")
    start_tang()


# ── Tang that accepts and goes silent ─────────────────────────────────────


def tarpit_up():
    stop_tang()
    tang.succeed("rm -f /run/tarpit-heal", "systemctl start tarpit.service")
    tang.wait_until_succeeds(f"ss -ltn | grep -q ':{TANG_PORT} '", timeout=30)


def tarpit_down():
    tang.succeed("systemctl stop tarpit.service", "rm -f /run/tarpit-heal")
    start_tang()


def tarpit_held():
    return int(tang.succeed("journalctl -u tarpit.service -o cat --no-pager | grep -c 'holding a connection' || true").strip())


def tarpit_until_held(seconds=120):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if tarpit_held() > 0:
            return True
        time.sleep(1)
    return False


def tarpit_max_time_recovers(bound, firmware):
    """With --max-time, a client that got no answer gives up and asks again, so once Tang
    heals the node unlocks by itself."""
    tarpit_up()
    disks = new_case(base=bound)
    boot(disks, firmware=new_firmware(firmware))
    stage2 = connecting(target)
    held = tarpit_until_held()
    # Longer than --max-time, so a patched client has already been held and retried.
    time.sleep(30)
    held_before = tarpit_held()
    early = not stage2.is_alive()
    tang.succeed("touch /run/tarpit-heal")
    stage2.join(HEALED_SECONDS)
    booted = not stage2.is_alive()
    control(
        "tarpit-max-time-recovers",
        held and not early and booted and both_legs_online(pool_status()),
        f"held: {held} ({held_before} connections before healing), stage 2 before healing: {early}, "
        f"within {HEALED_SECONDS}s of healing: {booted}",
    )
    power_off()
    tarpit_down()


def tarpit_stock(bound, firmware):
    """The built-in negative control: the same tarpit, and clevis as nixpkgs ships it, with only
    the connect timeout. Its first connection never ends, so it never unlocks, healed or not.
    A person typing still gets in, since the prompt never waited for it."""
    tarpit_up()
    disks = new_case(base=bound)
    select_entry(disks, "stockclevis")
    boot(disks, firmware=new_firmware(firmware))
    stage2 = connecting(target)
    held = tarpit_until_held()
    time.sleep(30)
    tang.succeed("touch /run/tarpit-heal")
    stage2.join(STOCK_STUCK_SECONDS)
    stuck = stage2.is_alive()
    held_total = tarpit_held()
    control(
        "tarpit-stock-hangs",
        held and stuck,
        f"held: {held}, {held_total} connections held in all, no stage 2 {STOCK_STUCK_SECONDS}s after healing: {stuck}",
    )
    booted = type_until_stage2(target, serial(), thread=stage2)
    control("tarpit-stock-typing-works", booted and both_legs_online(pool_status()), "typing did not reach stage 2")
    power_off()
    tarpit_down()


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
    tang.start()
    tang.wait_for_unit("multi-user.target")
    ssh_ready()
    provision()
    # A node as it runs: enforcing, and bound to Tang and PCR 7. The Tang cases only mean
    # something on that, so they boot it with its own firmware. The typed cases boot fresh
    # firmware, where the TPM has nothing to give and typing is the only way in.
    sealed, sealed_firmware = sealed_checkpoint()
    bound, bound_firmware, _, _ = bound_checkpoint(sealed, sealed_firmware)
    # Each named mutant takes out one control for the whole node, so the case it is about
    # runs before any case that leans on that control for something else: the tarpit cases
    # wait longer than the import does without the gate, and partial_waits needs SSH.
    wrong_then_right()
    slow_human_gate()
    drop_ssh(bound, bound_firmware)
    refused_console(bound, bound_firmware)
    refused_tty0(bound, bound_firmware)
    tarpit_max_time_recovers(bound, bound_firmware)
    tarpit_stock(bound, bound_firmware)
    partial_waits()
    recover_emergency_over_ssh()
    emergency_password()
