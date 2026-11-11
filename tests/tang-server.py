# The script of tests/tang-server.nix. The prelude sets MUTANT, the addresses, OUT,
# PINNED, PINNED_KEYS, STOCK_ROTATE and EVAL_REPORT, and splices in tests/lib/control.py.
import base64
import json
import shlex
import time

KEYDIR = "/var/lib/private/tang"
ADV_PRIVATE = f"http://{VPS_PRIVATE}:{PORT}/adv"
ADV_LOOPBACK = f"http://127.0.0.1:{PORT}/adv"
LUKS_PASSPHRASE = "tang-server-test-luks-passphrase"
DEVICE = "/dev/vdb"


# Every control's evidence goes into the log, passing or not, through control.py's.
_control = control


def control(name, ok, detail=""):
    print(f"[{name}] {'ok' if ok else 'NOT OK'}: {detail}", flush=True)
    _control(name, ok, detail)


# ── looking ───────────────────────────────────────────────────────────────


def curl_code(m, url, timeout=10):
    """(curl rc, HTTP code). rc 28 is a timeout, 7 refused, 52 an empty reply."""
    rc, out = m.execute(f"curl -g -s -o /dev/null -w '%{{http_code}}' --max-time {timeout} {shlex.quote(url)}")
    return rc, out.strip()


def key_files(m=None):
    """Every .jwk in the key directory, visible and hidden, sorted."""
    m = m or vps
    rc, out = m.execute(f"cd {KEYDIR} && ls -A")
    return sorted(f for f in out.split() if f.endswith(".jwk")) if rc == 0 else []


def visible(files):
    return [f for f in files if not f.startswith(".")]


def hidden(files):
    return [f for f in files if f.startswith(".")]


def owners(m, files):
    """{file: (uid, gid, mode)} for files in the key directory, and the directory's own."""
    names = " ".join(shlex.quote(f"{KEYDIR}/{f}") for f in files)
    out = m.succeed(f"stat -c '%u %g %a %n' {KEYDIR} {names}")
    result = {}
    for line in out.splitlines():
        uid, gid, mode, name = line.split(" ", 3)
        result[name.rsplit("/", 1)[-1] if name != KEYDIR else "."] = (uid, gid, mode)
    return result


def owned_like_dir(m, files):
    o = owners(m, files)
    d = o["."]
    return all(o[f][:2] == d[:2] and o[f][2] == "440" for f in files), o


def signers(m, url):
    """(verified, thumbprints): /adv's signatures checked against the keys it advertises,
    and the S256 thumbprints of the keys that signed it."""
    rc, out = m.execute(
        f"curl -fsS --max-time 10 {url} > /tmp/adv.jws"
        " && jose fmt -j- -g payload -y -o- < /tmp/adv.jws | jose jwk use -i- -r -u verify -o- > /tmp/sig.jwks"
        " && jose jws ver -i /tmp/adv.jws -k /tmp/sig.jwks -a"
        " && jose jwk thp -i /tmp/sig.jwks -a S256 2>&1"
    )
    return rc == 0, sorted(out.split()) if rc == 0 else out.strip()


def guard_refusals(what):
    return int(vps.succeed(f"journalctl -o cat --no-pager | grep -c {shlex.quote('tang-key-guard: refusing: ' + what)} || true").strip())


def stored(kind=None):
    """What the real Worker stored, oldest first."""
    rc, out = outsider.execute(f"cat {OUT}/audit.jsonl 2>/dev/null")
    events = [json.loads(line)["value"] for line in out.splitlines() if line.strip()]
    return [e for e in events if kind is None or e["kind"] == kind]


def requests():
    rc, out = outsider.execute(f"cat {OUT}/requests.jsonl 2>/dev/null")
    return [json.loads(line) for line in out.splitlines() if line.strip()]


def wait_for(predicate, timeout):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() > deadline:
            return value
        time.sleep(1)


def probe():
    """(rc, journal of this run). The test drives the probe: its timer is stopped."""
    cursor = vps.succeed("journalctl -q -n 1 --show-cursor -o cat | sed -n 's/^-- cursor: //p'").strip()
    rc, _ = vps.execute("systemctl start tang-probe.service")
    log = vps.succeed(f"journalctl -o cat --no-pager -u tang-probe.service --after-cursor={shlex.quote(cursor)}")
    return rc, log


def vps_now():
    return int(vps.succeed("date +%s").strip())


def rec_lines(status="200"):
    out = vps.succeed(f"journalctl -t tangd -o cat --no-pager | grep -E 'POST /rec/.* => {status}' || true")
    return [line for line in out.splitlines() if line.strip()]


# ── the Clevis client ─────────────────────────────────────────────────────


def policy(thp, adv=None):
    tang = {"url": f"http://{VPS_PRIVATE}:{PORT}", "thp": thp}
    if adv:
        tang["adv"] = adv
    return json.dumps({"t": 2, "pins": {"tpm2": {"pcr_bank": "sha256"}, "tang": tang}})


def bind(thp, adv=None):
    return node.execute(
        f"printf %s {LUKS_PASSPHRASE} | timeout 120 clevis luks bind -d {DEVICE} -k - sss {shlex.quote(policy(thp, adv))} 2>&1"
    )


def slots():
    """{slot: config} of every Clevis binding on the device."""
    out = node.succeed(f"clevis luks list -d {DEVICE}")
    result = {}
    for line in out.splitlines():
        if ":" in line:
            slot, rest = line.split(":", 1)
            pin, cfg = rest.strip().split(" ", 1)
            result[slot.strip()] = (pin, json.loads(cfg.strip().strip("'")))
    return result


def unlock(timeout=60):
    """Clevis alone: the TPM's share and Tang's."""
    rc, out = node.execute(f"timeout {timeout} clevis luks unlock -d {DEVICE} -n t2 2>&1")
    if rc == 0:
        node.succeed("cryptsetup close t2")
    return rc, out.strip()


def passphrase_opens():
    rc, _ = node.execute(f"printf %s {LUKS_PASSPHRASE} | cryptsetup open --key-file=- {DEVICE} typed")
    if rc == 0:
        node.succeed("cryptsetup close typed")
    return rc == 0


# ── stock Tang: the hazards the module exists for ─────────────────────────


def stock_hazards():
    """services.tang alone mints keys where the module refuses: on an empty directory, an
    all-hidden one, one of 0-byte files, and after stock tangd-rotate-keys run as root. If
    stock tangd ever stops doing this, the guard's tests below prove less than they claim,
    so this fails loudly."""
    found = {}

    before = key_files(stock)
    _, code = curl_code(stock, ADV_LOOPBACK)
    after = key_files(stock)
    found["empty"] = (before == [] and code == "200" and len(visible(after)) == 2, f"{before} -> {code} {after}")

    stock.succeed(f'cd {KEYDIR} && for k in *.jwk; do mv -- "$k" ".$k"; done')
    before = key_files(stock)
    _, code = curl_code(stock, ADV_LOOPBACK)
    after = key_files(stock)
    found["all-hidden"] = (
        visible(before) == [] and code == "200" and len(visible(after)) == 2,
        f"{before} -> {code} {after}",
    )

    stock.succeed(f'cd {KEYDIR} && rm -f -- .*.jwk && for k in *.jwk; do : > "$k"; done')
    before = key_files(stock)
    _, code = curl_code(stock, ADV_LOOPBACK)
    after = key_files(stock)
    minted = [f for f in visible(after) if f not in before]
    found["zero-length"] = (len(visible(before)) == 2 and code == "200" and len(minted) == 2, f"{before} -> {code} {after}")

    stock.succeed(f"rm -f {KEYDIR}/*.jwk {KEYDIR}/.*.jwk")
    curl_code(stock, ADV_LOOPBACK)
    first = visible(key_files(stock))
    stock.succeed(f"{STOCK_ROTATE} -d {KEYDIR}")
    rotated = [f for f in visible(key_files(stock)) if f not in first]
    o = owners(stock, rotated)
    root_owned = len(rotated) == 2 and all(o[f][0] == "0" for f in rotated)
    _, code = curl_code(stock, ADV_LOOPBACK)
    after = key_files(stock)
    minted = [f for f in visible(after) if f not in first and f not in rotated]
    found["stock-rotate-as-root"] = (
        root_owned and code == "200" and len(minted) == 2,
        f"first {first}, rotated {rotated} owners {o}, then {code} {after}",
    )

    control("stock-hazards", all(ok for ok, _ in found.values()), json.dumps(found))


# ── the module ─────────────────────────────────────────────────────────────


def guard_empty_no_mint():
    """No key yet: the guard refuses, and nothing is minted."""
    _, code = curl_code(node, ADV_PRIVATE)
    _, lo = curl_code(vps, ADV_LOOPBACK)
    files = key_files()
    refused = guard_refusals("0 visible")
    control(
        "guard-empty-no-mint",
        code != "200" and lo != "200" and files == [] and refused >= 2,
        f"/adv over the VLAN {code}, over loopback {lo}; keys {files}; guard refusals {refused}",
    )


def init_thumbprint():
    """`tang-keys init` makes one pair owned like the directory and prints the signing key's
    thumbprint, which is what signs /adv; a second init refuses; the verified probe then
    reaches the Worker."""
    x = vps.succeed("tang-keys init").strip().splitlines()[-1]
    files = key_files()
    owned, o = owned_like_dir(vps, files)
    verified, thps = signers(node, ADV_PRIVATE)
    again, again_out = vps.execute("tang-keys init 2>&1")
    probes = len(stored("tang_probe"))
    rc, log = probe()
    delivered = wait_for(lambda: [e for e in stored("tang_probe")[probes:] if e["sender"] == "tang"], 30)
    timer = vps.succeed("systemctl is-enabled tang-probe.timer").strip()
    control(
        "init-thumbprint",
        f"{x}.jwk" in files
        and len(visible(files)) == 2
        and hidden(files) == []
        and owned
        and verified
        and thps == [x]
        and again != 0
        and "refusing" in again_out
        and rc == 0
        and bool(delivered)
        and timer == "enabled",
        f"printed {x}; keys {files} {o}; /adv signed by {thps} (verified {verified}); second init rc={again} "
        f"{again_out.strip()!r}; probe rc={rc} {log.strip()!r}, delivered {delivered}; timer {timer}",
    )
    return x


def public_side():
    """(rc, code) of /adv from the outsider at the public IPv4, and the same at the public
    NIC's IPv6 link-local address."""
    rc_public, public = curl_code(outsider, f"http://{VPS_PUBLIC}:{PORT}/adv", timeout=5)
    link_local = vps.succeed("ip -6 -o addr show dev eth1 scope link | awk '{print $4}' | cut -d/ -f1").strip()
    rc_v6, v6 = curl_code(outsider, f"http://[{link_local}%25eth1]:{PORT}/adv", timeout=5)
    return (rc_public, public), (rc_v6, v6), link_local


def switch_to(toplevel):
    """Activate a configuration. tangd.socket is restarted by hand, so its IPAddressAllow is
    the new one whatever switch-to-configuration decides about sockets; the probe's timer
    stays stopped, as everywhere in this test."""
    vps.succeed(f"{toplevel}/bin/switch-to-configuration test")
    vps.succeed("systemctl restart tangd.socket", "systemctl stop tang-probe.timer")


def surface():
    """Tang on the private NIC, to allowed clients only; SSH on the public NIC only. Then the
    same host with every address let through IPAddressAllow: the public NIC must still time
    out, which only the firewall can do. Without that half, a Tang port opened on the
    public NIC's firewall would pass (IPAddressAllow alone also drops the outsider's SYN)."""
    _, private = curl_code(node, ADV_PRIVATE)
    (rc_public, public), (rc_v6, v6), link_local = public_side()
    _, ssh_public = outsider.execute(f"timeout 20 ssh-keyscan -T 5 -t ed25519 {VPS_PUBLIC} 2>/dev/null")
    _, ssh_private = node.execute(f"timeout 20 ssh-keyscan -T 5 -t ed25519 {VPS_PRIVATE} 2>/dev/null")
    rc_stranger, stranger = curl_code(stock, ADV_PRIVATE, timeout=5)

    base = vps.succeed("readlink -f /run/current-system").strip()
    switch_to(f"{base}/specialisation/open-clients")
    # The positive control: the address outside the default allowedClients now gets in,
    # so IPAddressAllow really is out of the way for what follows.
    _, opened = curl_code(stock, ADV_PRIVATE, timeout=5)
    (rc_fw, fw), (rc_fw6, fw6), _ = public_side()
    switch_to(base)
    rc_back, back = curl_code(stock, ADV_PRIVATE, timeout=5)
    control(
        "surface",
        private == "200"
        and rc_public == 28
        and rc_v6 == 28
        and "ssh-ed25519" in ssh_public
        and ssh_private.strip() == ""
        and rc_stranger == 28
        and opened == "200"
        and rc_fw == 28
        and rc_fw6 == 28
        and rc_back == 28,
        f"private /adv {private}; public /adv rc={rc_public} {public}; public link-local {link_local} rc={rc_v6} {v6}; "
        f"public ssh {ssh_public.strip()!r}; private ssh {ssh_private.strip()!r}; "
        f"from {STRANGER}, outside allowedClients, rc={rc_stranger} {stranger}; "
        f"every client allowed: from {STRANGER} {opened}, public /adv rc={rc_fw} {fw}, link-local rc={rc_fw6} {fw6}; "
        f"allowedClients back: from {STRANGER} rc={rc_back} {back}",
    )


def core_dumps_off():
    """Tang's private keys stay out of core files: the repo's pipe to nowhere, no dumps
    from setuid processes, a zero core limit, and systemd-coredump keeping nothing."""
    pattern = vps.succeed("cat /proc/sys/kernel/core_pattern").strip()
    suid = vps.succeed("cat /proc/sys/fs/suid_dumpable").strip()
    limit = vps.succeed("systemctl show -p DefaultLimitCORE --value").strip()
    conf = vps.succeed("systemd-analyze cat-config systemd/coredump.conf")
    settings = [line.strip() for line in conf.splitlines() if "=" in line and not line.lstrip().startswith("#")]
    control(
        "core-dumps-off",
        pattern == CORE_PATTERN.strip() and suid == "0" and limit == "0" and "Storage=none" in settings,
        f"core_pattern {pattern!r} (want {CORE_PATTERN.strip()!r}); suid_dumpable {suid}; DefaultLimitCORE {limit}; "
        f"coredump.conf {settings}",
    )


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64url(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def probe_tampered_adv_refused():
    """An advertisement altered after it was signed: its signer is still among the keys it
    carries and still parses, so only `jose jws ver` in the probe can refuse it. No
    heartbeat may reach the Worker."""
    adv = json.loads(vps.succeed(f"curl -fsS {ADV_LOOPBACK}"))
    keys = json.loads(unb64url(adv["payload"]))
    extra = json.loads(vps.succeed("jose jwk gen -i '{\"alg\":\"ECMR\"}' | jose jwk pub -i- -o-"))
    keys["keys"].append(extra)
    adv["payload"] = b64url(json.dumps(keys).encode())
    blob = base64.b64encode(json.dumps(adv).encode()).decode()
    vps.succeed(f"echo {blob} | base64 -d > /root/tampered.jws")
    vps.succeed("systemctl stop tangd.socket", "systemctl start tampered-tang.service")
    vps.wait_until_succeeds(f"curl -fsS --max-time 2 {ADV_LOOPBACK} >/dev/null", timeout=30)
    served = json.loads(unb64url(json.loads(vps.succeed(f"curl -fsS {ADV_LOOPBACK}"))["payload"]))
    probes = len(stored("tang_probe"))
    rc, log = probe()
    time.sleep(2)
    after = len(stored("tang_probe"))
    vps.succeed("systemctl stop tampered-tang.service", "systemctl start tangd.socket")
    rc_back, _ = probe()
    back = wait_for(lambda: len(stored("tang_probe")) > after, 30)
    control(
        "probe-tampered-adv-refused",
        len(served["keys"]) == len(keys["keys"]) and rc != 0 and after == probes and rc_back == 0 and back,
        f"served {len(served['keys'])} keys (one added after signing); probe rc={rc} {log.strip()!r}; "
        f"heartbeats {probes} -> {after}; real Tang back: probe rc={rc_back}, delivered {bool(back)}",
    )


def t2_bind_pinned(x):
    """t=2 of the TPM and Tang, with Tang's thumbprint pinned at bind: a thumbprint this Tang
    doesn't have is refused (clevis asks the URL for /adv/<thumbprint>), the pinned one binds
    and unlocks."""
    node.succeed(
        f"printf %s {LUKS_PASSPHRASE} | cryptsetup luksFormat --type luks2 --batch-mode "
        f"--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file=- {DEVICE}"
    )
    rc_wrong, out_wrong = bind(PINNED)
    after_wrong = slots()
    rc, out = bind(x)
    bound = slots()
    shapes = [
        cfg.get("t") == 2 and sorted(cfg.get("pins", {})) == ["tang", "tpm2"] for pin, cfg in bound.values() if pin == "sss"
    ]
    # A JWE under the same policy, kept for after rotation: it must die with the old key.
    node.succeed(f"echo old-secret | clevis encrypt sss {shlex.quote(policy(x))} > /root/old.jwe")
    rc_unlock, out_unlock = unlock()
    control(
        "t2-bind-pinned",
        rc_wrong != 0 and after_wrong == {} and rc == 0 and len(bound) == 1 and shapes == [True] and rc_unlock == 0,
        f"bind to an unknown thumbprint rc={rc_wrong} {out_wrong!r}, slots after {after_wrong}; "
        f"bind to {x} rc={rc} {out!r}, slots {bound}; unlock rc={rc_unlock} {out_unlock!r}",
    )


def exchange_thumbprints():
    """Every thumbprint, S256 and S1, of every exchange key on the host, hidden or not."""
    out = vps.succeed(
        f"cd {KEYDIR} && for k in *.jwk .*.jwk; do [ -e \"$k\" ] || continue; "
        "[ \"$(jq -r .alg \"$k\")\" = ECMR ] || continue; "
        "jose jwk thp -i \"$k\" -a S256; echo; jose jwk thp -i \"$k\" -a S1; echo; done"
    )
    return set(out.split())


def rec_event_delivered_no_key_material():
    """The unlock's /rec reaches the Worker as a tang_rec: who, which key, what status.
    Nothing that reached the receiver holds a private key of this Tang."""
    line = rec_lines()[-1]
    kid = line.split("POST /rec/", 1)[1].split(" ", 1)[0]
    events = wait_for(lambda: [e for e in stored("tang_rec") if e["kid"] == kid and e["status"] == 200], 60)
    ev = events[0] if events else None
    privates = vps.succeed(
        f'cd {KEYDIR} && for k in *.jwk .*.jwk; do if [ -e "$k" ]; then jq -r .d "$k"; fi; done'
    ).split()
    pattern = " ".join(f"-e {shlex.quote(d)}" for d in privates)
    rc_receiver, leaked = outsider.execute(f"grep -rlF {pattern} {OUT}")
    rc_journal, logged = vps.execute(f"journalctl -o cat --no-pager -u tang-rec-notify.service | grep -F {pattern}")
    bodies = [r for r in requests() if '"tang_rec"' in r["body"]]
    shapes = [sorted(json.loads(r["body"])) == ["at", "ip", "kid", "kind", "status"] and r["status"] == 204 for r in bodies]
    control(
        "rec-event-delivered-no-key-material",
        ev is not None
        and ev["ip"] == NODE
        and ev["sender"] == "tang"
        and kid in exchange_thumbprints()
        and len(privates) == 2
        and rc_receiver == 1
        and rc_journal == 1
        and bodies
        and all(shapes),
        f"tangd: {line!r}; stored {ev}; {len(privates)} private keys looked for: at the receiver rc={rc_receiver} "
        f"{leaked.strip()!r}, in the notifier's journal rc={rc_journal}; tang_rec requests {bodies}",
    )


def rec_odd_paths_reported():
    """tangd routes /rec on `^/+rec/+<kid>$` and logs the path as sent, so `//rec/<kid>` and
    `/rec//<kid>` release the share as `/rec/<kid>` does. Each must reach the Worker as a
    tang_rec with its kid and status, and a POST tangd's route does not take is reported
    too, with kid `unparsed`: the notifier fails closed."""
    kid = vps.succeed(
        f"cd {KEYDIR} && for k in *.jwk; do if [ \"$(jq -r .alg \"$k\")\" = ECMR ]; then jose jwk thp -i \"$k\" -a S256; echo; fi; done"
    ).strip()
    node.succeed("jose jwk gen -i '{\"alg\":\"ECMR\"}' | jose jwk pub -i- -o- > /root/client.pub")
    # Only what arrives from here on: the unlock's own /rec, a second earlier, is in the
    # trail already and must not count for one of these.
    before = len(stored("tang_rec"))
    codes = {}
    for path in (f"//rec/{kid}", f"/rec//{kid}", f"/rec/{kid}/x"):
        _, out = node.execute(
            f"curl -s --path-as-is -o /dev/null -w '%{{http_code}}' --max-time 10 -X POST"
            f" -H 'Content-Type: application/jwk+json' --data-binary @/root/client.pub"
            f" {shlex.quote(f'http://{VPS_PRIVATE}:{PORT}{path}')}"
        )
        codes[path] = out.strip()

    def reported():
        new = [e for e in stored("tang_rec")[before:] if e["ip"] == NODE]
        released = [e for e in new if e["kid"] == kid and e["status"] == 200]
        unparsed = [e for e in new if e["kid"] == "unparsed"]
        return (released, unparsed) if len(released) >= 2 and unparsed else None

    got = wait_for(reported, 60)
    lines = vps.succeed(f"journalctl -t tangd -o cat --no-pager | grep -F {shlex.quote(kid)} | tail -n 4")
    released, unparsed = got if got else ([], [])
    control(
        "rec-odd-paths-reported",
        codes[f"//rec/{kid}"] == "200" and codes[f"/rec//{kid}"] == "200" and len(released) >= 2 and bool(unparsed),
        f"tangd answered {codes}; tangd logged {lines.strip()!r}; stored released {released}, unparsed {unparsed}",
    )


def receiver_down_delays():
    """With the receiver down, a /rec is held, not dropped: across a restart of the notifier
    too, because its journal cursor moves only after delivery."""
    last = max(e["at"] for e in stored("tang_rec"))
    # The notifier sends one event per client, key and status a minute.
    wait = last + 62 - vps_now()
    if wait > 0:
        time.sleep(wait)
    outsider.succeed("systemctl stop audit-stub.service")
    count = len(stored("tang_rec"))
    started = vps_now()
    rc_unlock, _ = unlock()
    retried = vps.wait_until_succeeds(
        "journalctl -o cat --no-pager -u tang-rec-notify.service | grep -c 'tang-rec-notify: retry'", timeout=90
    ).strip()
    vps.succeed("systemctl restart tang-rec-notify.service")
    time.sleep(15)
    held = len(stored("tang_rec")) == count
    outsider.succeed("systemctl start audit-stub.service")
    events = wait_for(lambda: [e for e in stored("tang_rec")[count:] if e["at"] >= started and e["status"] == 200], 120)
    control(
        "receiver-down-delays",
        rc_unlock == 0 and held and len(events) >= 1 and events[0]["ip"] == NODE,
        f"unlock rc={rc_unlock}; retries logged {retried}; nothing stored while down: {held}; after: {events}",
    )


def tang_down_passphrase_works():
    """Tang refusing, then Tang silent: Clevis can't unlock, and the passphrase still can. A
    silent Tang must really hold the client's connection, or the case proves nothing."""
    vps.succeed("systemctl stop tangd.socket")
    started = time.monotonic()
    rc_refused, out_refused = unlock(timeout=60)
    took_refused = time.monotonic() - started
    typed_refused = passphrase_opens()

    vps.succeed("systemctl start silent-tang.service")
    vps.wait_until_succeeds(f"ss -ltn | grep -q ':{PORT} '")
    started = time.monotonic()
    rc_silent, _ = unlock(timeout=30)
    took_silent = time.monotonic() - started
    held = vps.succeed(
        f"journalctl -o cat --no-pager -u silent-tang.service | grep -c 'holding a connection from {NODE}' || true"
    ).strip()
    typed_silent = passphrase_opens()
    vps.succeed("systemctl stop silent-tang.service", "systemctl start tangd.socket")
    rc_back, out_back = unlock()
    control(
        "tang-down-passphrase-works",
        rc_refused != 0
        and typed_refused
        and rc_silent == 124
        and took_silent >= 25
        and int(held) >= 1
        and typed_silent
        and rc_back == 0,
        f"refused: clevis rc={rc_refused} in {took_refused:.0f}s {out_refused!r}, passphrase {typed_refused}; "
        f"silent: clevis rc={rc_silent} in {took_silent:.0f}s, connections held {held}, passphrase {typed_silent}; "
        f"Tang back: rc={rc_back} {out_back!r}",
    )


def rotate_begin(x):
    """New pair visible first, then the old one hidden. /adv is signed by the new key only,
    and the old binding and the old JWE still work: hidden keys still answer /rec."""
    y = vps.succeed("tang-keys rotate-begin").strip().splitlines()[-1]
    files = key_files()
    owned, o = owned_like_dir(vps, visible(files))
    verified, thps = signers(node, ADV_PRIVATE)
    rc_unlock, out_unlock = unlock()
    rc_jwe, _ = node.execute("timeout 60 clevis decrypt < /root/old.jwe")
    control(
        "rotate-begin",
        y != x
        and f"{y}.jwk" in files
        and len(visible(files)) == 2
        and f".{x}.jwk" in files
        and len(hidden(files)) == 2
        and owned
        and verified
        and thps == [y]
        and rc_unlock == 0
        and rc_jwe == 0,
        f"printed {y}; keys {files} {o}; /adv signed by {thps} (verified {verified}); old binding rc={rc_unlock} "
        f"{out_unlock!r}; old JWE rc={rc_jwe}",
    )
    return y


def rebind(x, y):
    """A thumbprint the URL doesn't know is refused, and so is the old thumbprint against an
    advertisement delivered out of band, which only the new key signed. The binding from
    that advertisement, pinned to the new thumbprint, replaces the old one."""
    old = slots()
    rc_unknown, out_unknown = bind(PINNED)
    adv = vps.succeed(f"curl -fsS {ADV_LOOPBACK}")
    node.succeed(f"echo {base64.b64encode(adv.encode()).decode()} | base64 -d > /root/adv.jws")
    rc_old, out_old = bind(x, adv="/root/adv.jws")
    after_wrong = slots()
    rc_new, out_new = bind(y, adv="/root/adv.jws")
    new = {s: c for s, c in slots().items() if s not in old}
    for s in old:
        node.succeed(f"clevis luks unbind -d {DEVICE} -s {s} -f")
    final = slots()
    rc_unlock, out_unlock = unlock()
    control(
        "rebind",
        rc_unknown != 0
        and rc_old != 0
        and after_wrong == old
        and rc_new == 0
        and len(new) == 1
        and sorted(final) == sorted(new)
        and rc_unlock == 0,
        f"bind to {PINNED}, unknown here, rc={rc_unknown} {out_unknown!r}; bind to the old {x} against the "
        f"delivered adv rc={rc_old} {out_old!r}; bind to {y} from it rc={rc_new} {out_new!r}; "
        f"slots {old} -> {final}; unlock rc={rc_unlock} {out_unlock!r}",
    )


def rotate_finish_kills_old(x, y):
    """The hidden keys go: the new binding unlocks, the old JWE gets a 404, and the Worker
    hears of the refusal."""
    # Only this case's 404s: `rec-odd-paths-reported` left one of its own in the trail.
    started = vps_now()
    out = vps.succeed("tang-keys rotate-finish")
    files = key_files()
    rc_unlock, out_unlock = unlock()
    rc_old, _ = node.execute("timeout 60 clevis decrypt < /root/old.jwe")
    refused = rec_lines("404")
    events = wait_for(
        lambda: [
            e
            for e in stored("tang_rec")
            if e["status"] == 404 and e["ip"] == NODE and e["at"] >= started and e["kid"] != "unparsed"
        ],
        60,
    )
    control(
        "rotate-finish-kills-old",
        hidden(files) == []
        and f"deleted .{x}.jwk" in out
        and f"{y}.jwk" in files
        and rc_unlock == 0
        and rc_old != 0
        and len(refused) >= 1
        and bool(events),
        f"rotate-finish: {out.strip()!r}; keys {files}; new binding rc={rc_unlock} {out_unlock!r}; old JWE rc={rc_old}; "
        f"tangd 404s {refused}; stored {events}",
    )


def guard_hidden_no_mint():
    """Every key hidden: the guard refuses, and nothing is minted."""
    vps.succeed(f'cd {KEYDIR} && for k in *.jwk; do mv -- "$k" ".$k"; done')
    before = key_files()
    refusals = guard_refusals("0 visible")
    _, code = curl_code(node, ADV_PRIVATE)
    after = key_files()
    refused = guard_refusals("0 visible") - refusals
    vps.succeed(f'cd {KEYDIR} && for k in .*.jwk; do mv -- "$k" "${{k#.}}"; done')
    _, back = curl_code(node, ADV_PRIVATE)
    control(
        "guard-hidden-no-mint",
        visible(before) == [] and code != "200" and after == before and refused >= 1 and back == "200",
        f"all hidden {before}: /adv {code}, keys after {after}, guard refusals {refused}; unhidden: /adv {back}",
    )


def probe_fails_wiped():
    """No keys: the probe fails and sends no heartbeat, so the Worker's dead-man fires.
    Nothing is minted. With the keys back, the probe reports again."""
    probes = len(stored("tang_probe"))
    vps.succeed(f"rm -rf /root/keys-aside && mkdir /root/keys-aside && mv {KEYDIR}/*.jwk /root/keys-aside/")
    rc_wiped, log_wiped = probe()
    files = key_files()
    time.sleep(2)
    during = len(stored("tang_probe"))
    vps.succeed(f"mv /root/keys-aside/*.jwk {KEYDIR}/")
    rc_back, log_back = probe()
    after = wait_for(lambda: len(stored("tang_probe")) > probes, 30)
    control(
        "probe-fails-wiped",
        rc_wiped != 0 and files == [] and during == probes and rc_back == 0 and after,
        f"wiped: probe rc={rc_wiped} {log_wiped.strip()!r}, keys {files}, heartbeats {probes} -> {during}; "
        f"restored: probe rc={rc_back}, heartbeats {len(stored('tang_probe'))}",
    )


def guard_zero_length():
    """The keys' names, owners and modes, and 0 bytes each: what a crash in the journal
    commit window leaves. Existence would pass them; the guard parses them, and refuses."""
    vps.succeed(f"rm -rf /root/keys-aside && mkdir /root/keys-aside && cp -a {KEYDIR}/*.jwk /root/keys-aside/")
    vps.succeed(f'cd {KEYDIR} && for k in *.jwk; do : > "$k"; done')
    before = key_files()
    sizes = vps.succeed(f"stat -c %s {KEYDIR}/*.jwk").split()
    refusals = guard_refusals("")
    _, code = curl_code(node, ADV_PRIVATE)
    after = key_files()
    corrupt = int(
        vps.succeed("journalctl -o cat --no-pager | grep -c 'tang-key-guard: refusing: .* is unreadable or corrupt' || true")
    )
    refused = guard_refusals("") - refusals
    vps.succeed(f"cp -a /root/keys-aside/*.jwk {KEYDIR}/")
    _, back = curl_code(node, ADV_PRIVATE)
    control(
        "guard-zero-length",
        sizes == ["0", "0"] and code != "200" and after == before and refused >= 1 and corrupt >= 1 and back == "200",
        f"0-byte keys {before} (sizes {sizes}): /adv {code}, keys after {after}, guard refusals {refused} "
        f"({corrupt} for a corrupt key so far); restored: /adv {back}",
    )


def reboot_keeps_key(y):
    """After a reboot: the same key files, byte for byte, /adv signed by the same key, the
    binding unlocks, the notifier resumes and the probe reports."""
    sums = vps.succeed(f"cd {KEYDIR} && find . -type f -exec sha256sum {{}} + | sort")
    vps.shutdown()
    vps.start()
    vps.wait_for_unit("multi-user.target")
    vps.succeed("systemctl stop tang-probe.timer")
    vps.wait_for_unit("tang-rec-notify.service")
    node.wait_until_succeeds(f"curl -fsS --max-time 5 {ADV_PRIVATE} >/dev/null", timeout=60)
    again = vps.succeed(f"cd {KEYDIR} && find . -type f -exec sha256sum {{}} + | sort")
    verified, thps = signers(node, ADV_PRIVATE)
    booted = vps_now()
    rc_unlock, _ = unlock()
    events = wait_for(lambda: [e for e in stored("tang_rec") if e["at"] >= booted and e["status"] == 200], 60)
    rc_probe, _ = probe()
    control(
        "reboot-keeps-key",
        sums == again and verified and thps == [y] and rc_unlock == 0 and bool(events) and rc_probe == 0,
        f"keys before {sums!r}, after {again!r}; /adv signed by {thps} (verified {verified}); unlock rc={rc_unlock}; "
        f"notifier after the reboot {events}; probe rc={rc_probe}",
    )


# ── a pinned host (beyond the named subtests) ─────────────────────────────


def pinned_host(y):
    """The same host with a signing key pinned: the guard needs that key, the probe needs it
    to sign /adv, and rotate-finish won't delete it while it is pinned."""
    vps.succeed("/run/current-system/specialisation/pinned/bin/switch-to-configuration test")
    vps.succeed("systemctl stop tang-probe.timer")

    refusals = guard_refusals(f"pinned key {PINNED} is absent")
    _, code = curl_code(node, ADV_PRIVATE)
    refused = guard_refusals(f"pinned key {PINNED} is absent") - refusals
    control(
        "guard-pinned-absent",
        code != "200" and refused >= 1,
        f"keys {key_files()}, pinned {PINNED} nowhere: /adv {code}, guard refusals {refused}",
    )

    vps.succeed(
        f"for f in {PINNED_KEYS}/*.jwk; do install -m 0440 -o $(stat -c %u {KEYDIR}) -g $(stat -c %g {KEYDIR}) "
        f'"$f" "{KEYDIR}/.$(basename "$f")"; done'
    )
    _, code = curl_code(node, ADV_PRIVATE)
    probes = len(stored("tang_probe"))
    rc_probe, log = probe()
    time.sleep(2)
    control(
        "probe-unpinned-signer-refused",
        code == "200" and rc_probe != 0 and "not signed by a pinned key" in log and len(stored("tang_probe")) == probes,
        f"pinned key present but hidden: /adv {code}; probe rc={rc_probe} {log.strip()!r}",
    )

    rc_finish, out_finish = vps.execute("tang-keys rotate-finish 2>&1")
    files = key_files()
    control(
        "rotate-finish-refuses-pinned",
        rc_finish != 0 and f".{PINNED}.jwk" in files and len(hidden(files)) == 2,
        f"rotate-finish rc={rc_finish} {out_finish.strip()!r}; keys {files}",
    )

    vps.succeed(f'cd {KEYDIR} && for k in .*.jwk; do mv -- "$k" "${{k#.}}"; done')
    verified, thps = signers(node, ADV_PRIVATE)
    rc_probe, log = probe()
    delivered = wait_for(lambda: len(stored("tang_probe")) > probes, 30)
    control(
        "probe-pinned-signer",
        verified and thps == sorted([PINNED, y]) and rc_probe == 0 and delivered,
        f"/adv signed by {thps} (verified {verified}); probe rc={rc_probe} {log.strip()!r}",
    )


def main():
    print("module evaluation: " + "; ".join(EVAL_REPORT))
    start_all()
    for m in (outsider, vps, node, stock):
        m.wait_for_unit("multi-user.target")
    outsider.wait_for_unit("audit-stub.service")
    outsider.wait_for_open_port(8080)
    # The test drives the probe, so a timer firing mid-case can't blur a count.
    vps.succeed("systemctl stop tang-probe.timer")
    vps.wait_for_unit("tang-rec-notify.service")
    node.wait_until_succeeds(f"ping -c 1 -W 1 {VPS_PRIVATE}", timeout=60)

    stock_hazards()
    guard_empty_no_mint()
    x = init_thumbprint()
    surface()
    core_dumps_off()
    probe_tampered_adv_refused()
    t2_bind_pinned(x)
    rec_event_delivered_no_key_material()
    rec_odd_paths_reported()
    receiver_down_delays()
    tang_down_passphrase_works()
    y = rotate_begin(x)
    rebind(x, y)
    rotate_finish_kills_old(x, y)
    guard_hidden_no_mint()
    probe_fails_wiped()
    guard_zero_length()
    reboot_keeps_key(y)
    pinned_host(y)
