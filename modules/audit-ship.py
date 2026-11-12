# cluster-audit: the node's half of the off-host audit trail (design 1.19).
#
#   cluster-audit send               spool -> the Worker's POST /event, for ever
#   cluster-audit follow-journal     SSH logins and deploy outcomes -> spool
#   cluster-audit follow-nomad-acl   Nomad's ACL event stream -> spool (nomad-leader only)
#
# Everything goes through one directory, the spool. A producer writes an event whole and
# renames it in; only then does it move its own cursor on, so an event it has read is
# never lost to a crash. The sender deletes a file only once the Worker has taken it
# (2xx). So a receiver that is down delays the trail and drops nothing.
#
# What a producer puts in an event is only ever the fields the Worker's allowlist names
# (workers/cluster-watchdog/src/index.js, SCHEMAS), each cut to the characters it takes.
# A free-text field has no way in: a message is parsed into fields or dropped.
#
# Settings, from the units' environment:
#   SPOOL_DIR, REJECTED_DIR, STATE_DIR, METRICS_DIR, NODE
#   AUDIT_URL, CA_FILE, and the token as the systemd credential `token`         (send)
#   NOMAD_ADDR, NOMAD_CACERT, NOMAD_CLIENT_CERT, NOMAD_CLIENT_KEY, and the
#   management token as the credential `nomad-token`                           (follow-nomad-acl)
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

SPOOL = os.environ.get("SPOOL_DIR", "/var/lib/cluster-audit/spool")
REJECTED = os.environ.get("REJECTED_DIR", "/var/lib/cluster-audit/rejected")
STATE = os.environ.get("STATE_DIR", "/var/lib/cluster-audit")
METRICS = os.environ.get("METRICS_DIR", "/var/lib/prometheus-node-exporter-text")
NODE = os.environ.get("NODE") or os.uname().nodename
# Identical events inside this window are one event (design 1.19: the sender coalesces).
COALESCE_S = 60
# How often a producer's heartbeat metric is rewritten.
HEARTBEAT_S = 30

ID_CHARS = re.compile(r"[^A-Za-z0-9._:@=/+-]")


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def ident(v):
    """A value for one of the Worker's ID fields: its characters only, 1 to 128 of them."""
    v = ID_CHARS.sub("_", str(v))[:128]
    return v or "unknown"


def credential(name):
    with open(os.path.join(os.environ["CREDENTIALS_DIRECTORY"], name)) as f:
        return f.read().strip()


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_atomic(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fsync_dir(os.path.dirname(path))


def spool(event):
    os.makedirs(SPOOL, mode=0o700, exist_ok=True)
    name = "%d-%s-%d.json" % (time.time_ns(), event["kind"], os.getpid())
    write_atomic(os.path.join(SPOOL, name), json.dumps(event))


class Coalescer:
    def __init__(self):
        self.seen = {}

    def fresh(self, event):
        key = json.dumps({k: v for k, v in event.items() if k != "at"}, sort_keys=True)
        now = time.monotonic()
        self.seen = {k: t for k, t in self.seen.items() if now - t < COALESCE_S}
        if key in self.seen:
            return False
        self.seen[key] = now
        return True


# ── liveness ──────────────────────────────────────────────────────────────
# The daemons restart for ever (Restart=always, no start limit), so a dead or looping one
# never reaches "failed", and an event that never reached the spool trips no spool
# alert: a follower that cannot read, a stream refused with 403, or a sender that never
# started would all look like a quiet cluster. So each one says it is working, in its own
# textfile, and lib/alert-rules.nix fires on a heartbeat that stops (AuditProducerStale),
# on the Nomad stream's last HTTP status (AuditNomadStreamRefused), and on units that keep
# restarting (UnitRestartLoop).


def liveness(producer, state):
    """A thread that rewrites audit_<producer>.prom every HEARTBEAT_S: the last time the
    producer was seen working (state["ok_at"], set by the producer itself), and any extra
    lines state["extra"] holds. The heartbeat is only ever the producer's own claim, so a
    producer that stops claiming goes stale."""
    path = os.path.join(METRICS, "audit_%s.prom" % producer)

    def run():
        while True:
            lines = list(state.get("extra", ()))
            if state.get("ok_at"):
                lines.append(
                    'cluster_audit_producer_heartbeat_timestamp_seconds{producer="%s"} %d' % (producer, state["ok_at"])
                )
            try:
                os.makedirs(METRICS, exist_ok=True)
                with open(path + ".tmp", "w") as f:
                    f.write("".join(line + "\n" for line in lines))
                os.replace(path + ".tmp", path)
            except OSError as e:
                log("cluster-audit: cannot write", path, e)
            time.sleep(HEARTBEAT_S)

    threading.Thread(target=run, daemon=True).start()


# ── send ──────────────────────────────────────────────────────────────────


def spooled():
    try:
        return sorted(f for f in os.listdir(SPOOL) if f.endswith(".json"))
    except FileNotFoundError:
        return []


def write_metrics(state, cache={}):
    """Rewritten only when something changed: this runs every few seconds."""
    files = spooled()
    lines = ["cluster_audit_spool_files %d" % len(files)]
    if files:
        oldest = min(os.stat(os.path.join(SPOOL, f)).st_mtime for f in files)
        lines.append("cluster_audit_spool_oldest_timestamp_seconds %d" % oldest)
    try:
        rejected = len([f for f in os.listdir(REJECTED) if f.endswith(".json")])
    except FileNotFoundError:
        rejected = 0
    lines.append("cluster_audit_rejected_files %d" % rejected)
    if state.get("delivered"):
        lines.append("cluster_audit_last_delivery_timestamp_seconds %d" % state["delivered"])
    text = "\n".join(lines) + "\n"
    if cache.get("text") == text:
        return
    os.makedirs(METRICS, exist_ok=True)
    tmp = os.path.join(METRICS, "audit.prom.tmp")
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, os.path.join(METRICS, "audit.prom"))
    cache["text"] = text


def post(url, token, context, body):
    """HTTP status, or None if the Worker could not be reached at all."""
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(req, timeout=20, context=context) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        log("cluster-audit: cannot reach the audit endpoint:", e)
        return None


def send():
    url = os.environ["AUDIT_URL"]
    token = credential("token")
    context = ssl.create_default_context(cafile=os.environ.get("CA_FILE") or None)
    os.makedirs(SPOOL, mode=0o700, exist_ok=True)
    os.makedirs(REJECTED, mode=0o700, exist_ok=True)
    state = {}
    alive = {}
    liveness("send", alive)
    backoff = 0
    while True:
        alive["ok_at"] = int(time.time())
        write_metrics(state)
        files = spooled()
        if not files:
            time.sleep(2)
            continue
        failed = False
        for name in files:
            path = os.path.join(SPOOL, name)
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                continue
            status = post(url, token, context, body)
            if status is not None and 200 <= status < 300:
                os.unlink(path)
                state["delivered"] = int(time.time())
                log(f"cluster-audit: delivered {name}")
                continue
            if status in (400, 413, 422):
                # The Worker will never take this body: keep it for a human, out of the way
                # of the events behind it. AuditEventRejected says it is there.
                os.replace(path, os.path.join(REJECTED, name))
                log(f"cluster-audit: REFUSED {name} with HTTP {status}; moved to {REJECTED}")
                continue
            if status == 403:
                # This token may not send this kind, or for this node: a configuration
                # error in AUDIT_TOKENS. Keep it, and let the other events through.
                log(f"cluster-audit: HTTP 403 for {name}; kept, retried later")
                failed = True
                continue
            log(f"cluster-audit: HTTP {status} for {name}; kept, retried later")
            failed = True
            break
        write_metrics(state)
        if failed:
            backoff = min(max(backoff * 2, 5), 60)
            time.sleep(backoff)
        else:
            backoff = 0


# ── follow-journal ────────────────────────────────────────────────────────

ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<from>\S+) port \d+(?: [^\s:]+)?(?:: (?P<keytype>\S+) (?P<key>\S+))?"
)
DEPLOY_SWITCH = re.compile(r"^cluster-upgrade: (?P<cur>/nix/store/\S+) -> (?P<new>/nix/store/\S+)$")
DEPLOY_RC = re.compile(r"^cluster-upgrade: switch rc=(?P<rc>\d+) attempt=(?P<attempt>\d+)$")
DEPLOY_REFUSED = re.compile(r"^cluster-upgrade: REFUSING (?P<new>/nix/store/\S+): boot contract")
DEPLOY_DENYLIST = re.compile(r"^cluster-upgrade: (?P<new>/nix/store/\S+) is on the rollback denylist")
DEPLOY_BUILD = re.compile(r"^cluster-upgrade: build failed$")


def message(e):
    m = e.get("MESSAGE") or ""
    return bytes(m).decode("utf-8", "replace") if isinstance(m, list) else m


def generation_of(closure):
    profiles = "/nix/var/nix/profiles"
    best = -1
    try:
        for name in os.listdir(profiles):
            m = re.fullmatch(r"system-(\d+)-link", name)
            if m and os.path.realpath(os.path.join(profiles, name)) == closure:
                best = max(best, int(m[1]))
    except OSError:
        pass
    return best


def toplevel_id(closure):
    return ident(os.path.basename(closure)[:32]) if closure else "unknown"


def event_from_entry(e, pending):
    """The audit event for one journal entry, or None. `pending` carries a tick's
    "cur -> new" line to the "switch rc=" line that follows it."""
    msg = message(e)
    at = int(e.get("__REALTIME_TIMESTAMP", time.time() * 1e6)) // 1_000_000
    if e.get("_SYSTEMD_UNIT") == "cluster-upgrade.service":
        inv = e.get("_SYSTEMD_INVOCATION_ID", "")
        m = DEPLOY_SWITCH.match(msg)
        if m:
            pending[inv] = m["new"]
            return None
        result, closure, attempts = None, None, 0
        m = DEPLOY_RC.match(msg)
        if m:
            closure = pending.pop(inv, None)
            result = "ok" if m["rc"] == "0" else "activation_failed"
            attempts = int(m["attempt"])
        elif (m := DEPLOY_REFUSED.match(msg)) is not None:
            result, closure = "contract_blocked", m["new"]
        elif (m := DEPLOY_DENYLIST.match(msg)) is not None:
            result, closure = "rollback_held", m["new"]
        elif DEPLOY_BUILD.match(msg):
            result = "build_failed"
        if result is None:
            return None
        return {
            "kind": "deploy",
            "node": NODE,
            "generation": generation_of(closure) if closure else -1,
            "toplevel": toplevel_id(closure),
            "result": result,
            "attempts": attempts,
            "at": at,
        }
    m = ACCEPTED.match(msg)
    if m and e.get("_UID") == "0":
        key = m["key"] if m["method"] == "publickey" and m["key"] else m["method"]
        return {
            "kind": "ssh_login",
            "node": NODE,
            "user": ident(m["user"]),
            "from": ident(m["from"]),
            "key": ident(key),
            "at": at,
        }
    return None


def follow_journal():
    cursor_file = os.path.join(STATE, "journal.cursor")
    # Root's sshd only (any user can name a process sshd-session), and the pull loop's
    # own unit. _SYSTEMD_UNIT and _UID are set by journald, not by the sender.
    matches = ["_UID=0", "_COMM=sshd-session", "_COMM=sshd", "+", "_SYSTEMD_UNIT=cluster-upgrade.service"]
    coalesce = Coalescer()
    pending = {}
    alive = {}
    liveness("journal", alive)
    proc = None

    # Working means a journalctl is following: refreshed while it runs, whether or not
    # anything is logged.
    def watch():
        while True:
            if proc is not None and proc.poll() is None:
                alive["ok_at"] = int(time.time())
            time.sleep(HEARTBEAT_S / 2)

    threading.Thread(target=watch, daemon=True).start()
    while True:
        try:
            with open(cursor_file) as f:
                cursor = f.read().strip()
        except FileNotFoundError:
            cursor = ""
        # No cursor yet: this boot, not the whole history.
        where = ["--after-cursor=" + cursor] if cursor else ["-b"]
        proc = subprocess.Popen(
            ["journalctl", "-f", "-o", "json", "--no-pager", *where, *matches],
            stdout=subprocess.PIPE,
            text=True,
        )
        got = 0
        for line in proc.stdout:
            if not line.strip():
                continue
            e = json.loads(line)
            ev = event_from_entry(e, pending)
            if ev is not None and coalesce.fresh(ev):
                spool(ev)
                log(f"cluster-audit: spooled {ev['kind']}")
            # Only once the event is on disk: a crash before this line replays the entry.
            write_atomic(cursor_file, e["__CURSOR"])
            got += 1
        rc = proc.wait()
        if cursor and got == 0 and rc != 0:
            # The journal no longer has that entry (vacuumed): start again from this boot,
            # and say so, since whatever was between is not in the trail.
            log(f"cluster-audit: journalctl rc={rc} at the saved cursor; restarting from this boot")
            os.unlink(cursor_file)
        else:
            log(f"cluster-audit: journalctl exited rc={rc}")
        time.sleep(5)


# ── follow-nomad-acl ──────────────────────────────────────────────────────

TOPICS = ("ACLToken", "ACLPolicy", "ACLRole")


def acl_events(frame):
    """Audit events for one frame of Nomad's event stream. The key and a name only: the
    payload's SecretID is empty in the stream anyway, and a policy's rules stay out."""
    out = []
    for ev in frame.get("Events") or []:
        topic = ev.get("Topic")
        if topic not in TOPICS:
            continue
        payload = (ev.get("Payload") or {}).get(topic) or {}
        out.append(
            {
                "kind": "nomad_acl",
                "node": NODE,
                "topic": topic,
                "type": ident(ev.get("Type", "")),
                "accessor": ident(ev.get("Key", "")),
                "name": ident(payload.get("Name", "")),
                "at": int(time.time()),
            }
        )
    return out


def follow_nomad_acl():
    index_file = os.path.join(STATE, "nomad-acl.index")
    addr = urllib.parse.urlparse(os.environ["NOMAD_ADDR"])
    coalesce = Coalescer()
    # Working means the stream answered 200 and is delivering frames (Nomad sends an
    # empty one every 10 s). The last status is reported too, 0 for no answer at all, so a
    # 403 after the management token changed is visible as itself.
    alive = {"extra": ["cluster_audit_nomad_stream_status 0"]}
    liveness("nomad_acl", alive)
    while True:
        token = credential("nomad-token")
        # Built for every connection, not once: a rotated client certificate or CA is
        # read again on the next reconnect instead of failing until a restart.
        try:
            context = ssl.create_default_context(cafile=os.environ["NOMAD_CACERT"])
            context.load_cert_chain(os.environ["NOMAD_CLIENT_CERT"], os.environ["NOMAD_CLIENT_KEY"])
        except (OSError, ssl.SSLError) as e:
            log("cluster-audit: Nomad TLS material:", e)
            alive["extra"] = ["cluster_audit_nomad_stream_status 0"]
            time.sleep(10)
            continue
        try:
            with open(index_file) as f:
                index = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            index = 0
        query = urllib.parse.urlencode([("topic", t) for t in TOPICS] + [("index", str(index + 1 if index else 0))])
        conn = http.client.HTTPSConnection(addr.hostname, addr.port, context=context, timeout=120)
        try:
            # The token in a header, never on a command line another user could read.
            conn.request("GET", "/v1/event/stream?" + query, headers={"X-Nomad-Token": token})
            resp = conn.getresponse()
            alive["extra"] = ["cluster_audit_nomad_stream_status %d" % resp.status]
            if resp.status != 200:
                log(f"cluster-audit: Nomad event stream: HTTP {resp.status}: {resp.read(300)!r}")
            else:
                while True:
                    line = resp.readline()
                    if not line:
                        break
                    alive["ok_at"] = int(time.time())
                    line = line.strip()
                    if not line:
                        continue
                    frame = json.loads(line)
                    # {} is the stream's heartbeat.
                    for ev in acl_events(frame):
                        if coalesce.fresh(ev):
                            spool(ev)
                            log(f"cluster-audit: spooled nomad_acl {ev['type']} {ev['accessor']}")
                    if frame.get("Index"):
                        write_atomic(index_file, str(frame["Index"]))
        except (OSError, http.client.HTTPException, json.JSONDecodeError) as e:
            log("cluster-audit: Nomad event stream:", e)
            alive["extra"] = ["cluster_audit_nomad_stream_status 0"]
        finally:
            conn.close()
        time.sleep(10)


if __name__ == "__main__":
    {"send": send, "follow-journal": follow_journal, "follow-nomad-acl": follow_nomad_acl}[sys.argv[1]]()
