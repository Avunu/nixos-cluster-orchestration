"""cluster-state — an app's local state, on whichever node Nomad runs the app.

The design is in modules/app-state.nix. In short: each app with `localState` has a ZFS
dataset of its own, <state>/apps/<app>, mounted at /state/clients/<app> on the one node
that runs the app (its holder) and kept as an unmounted, read-only replica on the others.

    acquire <app>     container@<app>'s ExecStartPre: stop the app wherever else it
                      runs, bring the newest copy here, mount it read-write
    release <app>     its ExecStopPost: a last snapshot, unmount, read-only
    replicate         the timer: snapshot what this node holds, pull what it doesn't
    serve             one request from a peer, on the mesh (socket-activated)
    status            what this node and its peers hold
    where <app>       the peers running the app; fails when one cannot be asked
    init <app>        an empty dataset for a new app, when a peer cannot be asked
    orphans           copies set aside because another node's history replaced them
    drop-orphan <name> [--yes]

Only the standard library, and `zfs`, `systemctl` and `findmnt` on PATH.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import pathlib
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

CFG = json.loads(pathlib.Path(os.environ["STATE_CONFIG"]).read_text())
ME: str = CFG["node"]
APPS: dict[str, dict] = CFG["apps"]
PEERS: dict[str, str] = CFG["peers"]
RUN = pathlib.Path(os.environ.get("STATE_RUN_DIR", "/run/cluster-state"))
METRICS = pathlib.Path(os.environ.get("STATE_METRICS_DIR", "/var/lib/prometheus-node-exporter-text"))
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")

# `cluster:holder` on a dataset says whose history its newest data is:
#   <this node>   it is, or was when the node died, the app's live data
#   released      it was, and was stopped cleanly: its last snapshot may be one no peer has
#   -             a replica: everything in it was received from a peer
HOLDER = "cluster:holder"
RELEASED = "released"
REPLICA = "-"


class Refused(Exception):
    """Said to whoever asked; the app does not start."""


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def run(*argv: str, check: bool = True, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(argv)}: exit {p.returncode}: {p.stderr.strip()[-400:]}")
    return p


def zfs(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run("zfs", *args, check=check)


# ── what is on this node ─────────────────────────────────────────────────────


def root() -> str:
    """The dataset mounted at /state, whatever the pool is called."""
    return run("findmnt", "-n", "-o", "SOURCE", CFG["stateMount"]).stdout.strip()


def ds(app: str) -> str:
    return f"{root()}/apps/{app}"


def exists(name: str) -> bool:
    return zfs("list", "-H", "-o", "name", name, check=False).returncode == 0


def prop(name: str, key: str) -> str:
    return zfs("get", "-H", "-p", "-o", "value", key, name).stdout.strip()


def group(name: str) -> None:
    """A dataset that only holds others."""
    if not exists(name):
        zfs("create", "-o", "mountpoint=none", "-o", "canmount=off", "-o", "com.sun:auto-snapshot=false", name)


def snaps(name: str) -> list[list]:
    """[name, guid, creation], oldest first. The guid and the creation time are the
    sender's, on every node that received the snapshot."""
    out = zfs("list", "-H", "-p", "-t", "snapshot", "-d", "1", "-o", "name,guid,creation", "-s", "createtxg", name)
    rows = []
    for line in out.stdout.splitlines():
        full, guid, created = line.split("\t")
        rows.append([full.split("@", 1)[1], guid, int(created)])
    return rows


def unit_state(app: str) -> str:
    return run("systemctl", "show", "-p", "ActiveState", "--value", f"container@{app}.service", check=False).stdout.strip()


def running(app: str) -> bool:
    """Starting and stopping count: the first is about to write, the second still is."""
    return unit_state(app) not in ("inactive", "failed", "")


def legacy(app: str) -> bool:
    """The app's state as a plain directory of /state, from before it had a dataset."""
    path = pathlib.Path(APPS[app]["mount"])
    if exists(ds(app)) or not path.is_dir() or path.is_mount():
        return False
    return any(files for _dir, _dirs, files in os.walk(path))


def snapshot(d: str) -> None:
    zfs("snapshot", f"{d}@repl-{int(time.time())}")


def local_status() -> dict:
    apps = {}
    for app in APPS:
        d = ds(app)
        have = exists(d)
        apps[app] = {
            "running": running(app),
            "snaps": snaps(d) if have else [],
            "holder": prop(d, HOLDER) if have else None,
            "legacy": legacy(app),
        }
    return {"node": ME, "apps": apps}


@contextlib.contextmanager
def locked(app: str, wait: bool = True):
    """One decision about an app's dataset at a time, on this node."""
    RUN.mkdir(parents=True, exist_ok=True)
    with open(RUN / f"{app}.lock", "w") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        yield True


# ── peers ────────────────────────────────────────────────────────────────────


def connect(peer: str, timeout: float = 5) -> socket.socket:
    s = socket.create_connection((PEERS[peer], CFG["port"]), timeout=timeout)
    # A peer that dies in the middle of a stream is noticed, in about a minute.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    return s


def line(s: socket.socket) -> str:
    """One line and not a byte more: what follows may be a stream for `zfs receive`."""
    out = bytearray()
    while not out.endswith(b"\n"):
        b = s.recv(1)
        if not b:
            break
        out += b
        if len(out) > 4 << 20:
            raise RuntimeError("answer too long")
    return out.decode().strip()


def ask(peer: str, request: dict, timeout: float = 15) -> dict | None:
    """A peer's answer, or None when it gave none: off, cut off, or not yet deployed."""
    try:
        with connect(peer) as s:
            s.settimeout(timeout)
            s.sendall(json.dumps(request).encode() + b"\n")
            answer = json.loads(line(s))
        return answer if "apps" in answer else None
    except (OSError, ValueError, RuntimeError):
        return None


def poll() -> dict[str, dict | None]:
    out: dict[str, dict | None] = {}

    def one(peer: str) -> None:
        out[peer] = ask(peer, {"do": "status"})

    threads = [threading.Thread(target=one, args=(p,)) for p in PEERS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    note_reachable(out)
    return out


def note_reachable(st: dict[str, dict | None]) -> dict[str, float]:
    """When each silent peer was first found silent, by this node, since this boot."""
    RUN.mkdir(parents=True, exist_ok=True)
    path = RUN / "unreachable.json"
    with open(RUN / "unreachable.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            seen = json.loads(path.read_text())
        except (OSError, ValueError):
            seen = {}
        now = time.time()
        seen = {p: seen.get(p, now) for p, s in st.items() if s is None}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(seen))
        tmp.replace(path)
    return seen


def receive(app: str, peer: str, since: str | None, to: str) -> None:
    d = ds(app)
    with connect(peer) as s:
        s.settimeout(60)
        s.sendall(json.dumps({"do": "send", "app": app, "from": since, "to": to}).encode() + b"\n")
        first = line(s)
        if first != "ok":
            raise RuntimeError(f"{peer} would not send {app}@{to}: {first or 'no answer'}")
        s.settimeout(None)
        argv = ["zfs", "receive", "-u"]
        if since is None:
            # Never mounted by anything but `acquire`, and never written to as a replica.
            argv += ["-o", "readonly=on", "-o", "canmount=noauto", "-o", f"mountpoint={APPS[app]['mount']}"]
        p = subprocess.run([*argv, d], stdin=s.fileno(), capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"zfs receive {d} from {peer}: {p.stderr.strip()[-400:]}")


def orphan(app: str, why: str) -> None:
    """Set this node's copy aside, whole. Nothing here deletes one."""
    d = ds(app)
    parent = f"{root()}/orphans"
    group(parent)
    stamp = int(time.time())
    if prop(d, "mounted") == "yes":
        zfs("unmount", "-f", d)
    if int(prop(d, "written")) > 0:
        zfs("snapshot", f"{d}@orphaned-{stamp}")
    name = f"{parent}/{app}-{stamp}"
    zfs("rename", d, name)
    zfs("set", "readonly=on", "canmount=noauto", "mountpoint=none", name)
    log(f"{app}: this node's copy is set aside as {name}: {why}. It holds writes no other node has; see `cluster-state orphans`.")


def ahead(mine: list[list] | None, theirs: list[list]) -> bool:
    """Whether a peer's copy has history this node's has not, and newer than it."""
    if not theirs:
        return False
    if not mine:
        return True
    if theirs[-1][1] in {g for _n, g, _c in mine}:
        return False
    return theirs[-1][2] > mine[-1][2]


def pull(app: str, peer: str, theirs: list[list]) -> bool:
    """Make this node's copy the peer's, up to the peer's newest snapshot."""
    d = ds(app)
    head = theirs[-1]
    since = None
    if exists(d):
        mine = snaps(d)
        if head[1] in {g for _n, g, _c in mine}:
            return False
        known = {g for _n, g, _c in theirs}
        common = max((i for i, (_n, g, _c) in enumerate(mine) if g in known), default=None)
        holder = prop(d, HOLDER)
        own = common is None or common < len(mine) - 1 or int(prop(d, "written")) > 0
        if holder == REPLICA and common is not None:
            # A replica has nothing of its own: what it has past the common snapshot
            # the sender had too, and has since destroyed.
            if own:
                zfs("rollback", "-r", f"{d}@{mine[common][0]}")
            since = mine[common][0]
        elif holder == REPLICA and zfs("destroy", "-r", d, check=False).returncode == 0:
            # So far behind that the sender kept nothing it has: a whole copy again.
            log(f"{app}: this node's replica shared no snapshot with {peer} any more; receiving it whole")
        elif own:
            orphan(app, f"{peer} has run the app since, from an earlier snapshot")
        else:
            since = mine[common][0]
    group(f"{root()}/apps")
    receive(app, peer, since, head[0])
    zfs("set", f"{HOLDER}={REPLICA}", "readonly=on", f"cluster:source={peer}", d)
    # What the sender no longer keeps, this node need not either.
    kept = {g for _n, g, _c in theirs}
    for name, guid, _c in snaps(d):
        if guid not in kept:
            zfs("destroy", f"{d}@{name}", check=False)  # a preview's clone keeps one alive
    return True


def source(app: str, st: dict[str, dict | None]) -> tuple[str, list[list]] | None:
    """The peer to take the app's state from: the one running it, else the newest ahead."""
    d = ds(app)
    mine = snaps(d) if exists(d) else None
    best = None
    for peer, s in st.items():
        info = (s or {}).get("apps", {}).get(app)
        if not info or not ahead(mine, info["snaps"]):
            continue
        if info["running"]:
            return peer, info["snaps"]
        if best is None or info["snaps"][-1][2] > best[1][-1][2]:
            best = (peer, info["snaps"])
    return best


# ── the verbs ────────────────────────────────────────────────────────────────


def create(app: str) -> None:
    d = ds(app)
    group(f"{root()}/apps")
    zfs("create", "-o", "canmount=noauto", "-o", f"mountpoint={APPS[app]['mount']}", "-o", f"{HOLDER}={ME}", d)
    snapshot(d)


def adopt(app: str) -> None:
    """The app's directory from before datasets, copied into one. The directory is kept."""
    mount = pathlib.Path(APPS[app]["mount"])
    old = mount.with_name(f".{mount.name}.before-datasets")
    d = ds(app)
    if exists(d):  # an adoption this node did not finish
        zfs("destroy", "-r", d)
    if not old.exists():
        mount.rename(old)
    log(f"{app}: copying {old} into a dataset of its own; this takes as long as the data is large")
    group(f"{root()}/apps")
    zfs("create", "-o", "canmount=noauto", "-o", f"mountpoint={mount}", "-o", "cluster:adopting=1", d)
    zfs("mount", d)
    run("cp", "-a", "--reflink=auto", f"{old}/.", f"{mount}/")
    snapshot(d)
    zfs("set", f"{HOLDER}={ME}", d)
    zfs("inherit", "cluster:adopting", d)
    log(f"{app}: done. {old} is the copy from before and is not used again; remove it once the app is seen to work.")


def unfinished_adoption(app: str) -> bool:
    mount = pathlib.Path(APPS[app]["mount"])
    d = ds(app)
    return mount.with_name(f".{mount.name}.before-datasets").exists() and (
        not exists(d) or prop(d, "cluster:adopting") == "1"
    )


def fence(app: str, st: dict[str, dict | None]) -> dict[str, dict | None]:
    """A peer that does not answer may be running the app, cut off. Nomad makes such a
    node stop its apps by itself (disconnect.stop_on_client_after), and `fence` seconds
    after this node first found it silent, it has."""
    seen = note_reachable(st)
    wait = max((seen[p] + APPS[app]["fence"] - time.time() for p in seen), default=0)
    if wait <= 0:
        return st
    log(f"{app}: {', '.join(sorted(seen))} not answering; waiting {int(wait)}s for it to have stopped its apps")
    time.sleep(wait)
    return poll()


def stop_elsewhere(app: str, st: dict[str, dict | None]) -> None:
    for peer, s in st.items():
        if not (s or {}).get("apps", {}).get(app, {}).get("running"):
            continue
        log(f"{app}: running on {peer}; Nomad placed it here, so stopping it there")
        st[peer] = ask(peer, {"do": "release", "app": app}, timeout=APPS[app]["fence"] + 60)
        if st[peer] is None or st[peer]["apps"][app]["running"]:
            raise Refused(f"{app} is running on {peer} and did not stop there")


def handed_over(app: str, st: dict[str, dict | None]) -> bool:
    """Whether this node's copy ends at the snapshot a peer took as it stopped the app."""
    head = snaps(ds(app))[-1][1]
    for s in st.values():
        info = (s or {}).get("apps", {}).get(app) or {}
        if info.get("holder") == RELEASED and info.get("snaps") and info["snaps"][-1][1] == head:
            return True
    return False


def acquire(app: str) -> None:
    with locked(app):
        d = ds(app)
        if unfinished_adoption(app):
            adopt(app)
        st = poll()
        stop_elsewhere(app, st)
        st = fence(app, st)
        stop_elsewhere(app, st)
        src = source(app, st)
        if src:
            log(f"{app}: taking its state from {src[0]}, up to {src[1][-1][0]}")
            pull(app, *src)
        elif not exists(d):
            silent = sorted(p for p, s in st.items() if s is None)
            elsewhere = sorted(p for p, s in st.items() if s and s["apps"].get(app, {}).get("legacy"))
            if legacy(app):
                adopt(app)
            elif elsewhere:
                raise Refused(
                    f"{app}'s data is a directory on {', '.join(elsewhere)}, from before apps had datasets; "
                    "it has to start there once, which copies it into one"
                )
            elif silent:
                raise Refused(
                    f"no copy of {app}'s state on this node, and {', '.join(silent)} cannot be asked for one. "
                    f"If the app is new, `cluster-state init {app}` on this node says so."
                )
            else:
                log(f"{app}: no node has state for it; starting it empty")
                create(app)
        if prop(d, HOLDER) == REPLICA and not handed_over(app, st):
            # Said once, where the operator of the app will look for why it restarted.
            log(
                f"{app}: starting from a replicated snapshot ({snaps(d)[-1][0]}), not from a clean stop: whatever the "
                "node that ran it wrote after that is not here. An archived database has to start a new generation "
                "(`db-archive next-generation`): the archive holds changes this copy never made."
            )
        zfs("set", "readonly=off", f"{HOLDER}={ME}", d)
        if prop(d, "mounted") != "yes":
            zfs("mount", d)


def release(app: str) -> None:
    with locked(app):
        d = ds(app)
        if not exists(d) or prop(d, HOLDER) != ME:
            return
        if int(prop(d, "written")) > 0:
            snapshot(d)
        zfs("set", f"{HOLDER}={RELEASED}", d)
        zfs("unmount", d, check=False)
        zfs("set", "readonly=on", d)


def thin(d: str) -> None:
    """Every snapshot of the last `recentMinutes`, then one an hour, then one a day."""
    keep = CFG["keep"]
    now = time.time()
    seen: set[tuple[str, int]] = set()
    rows = [r for r in snaps(d) if r[0].startswith("repl-")]
    for name, _guid, created in rows[:-1]:
        age = now - created
        if age <= keep["recentMinutes"] * 60:
            continue
        if age <= keep["hourly"] * 3600:
            bucket = ("h", created // 3600)
        elif age <= keep["daily"] * 86400:
            bucket = ("d", created // 86400)
        else:
            bucket = None
        if bucket and bucket not in seen:
            seen.add(bucket)
            continue
        zfs("destroy", f"{d}@{name}", check=False)


def replicate() -> int:
    st = poll()
    failed = 0
    lag: dict[str, int] = {}
    holding: dict[str, int] = {}
    for app in APPS:
        with locked(app, wait=False) as mine:
            if not mine:
                continue  # being acquired or released right now
            try:
                d = ds(app)
                state = unit_state(app)
                held = exists(d) and prop(d, HOLDER) == ME
                holding[app] = int(state == "active" and held)
                if state == "active" and held:
                    if int(prop(d, "written")) > 0:
                        snapshot(d)
                    thin(d)
                    continue
                if state not in ("inactive", "failed", ""):
                    continue
                src = source(app, st)
                if src:
                    pull(app, *src)
                runner = next((s for s in st.values() if s and s["apps"].get(app, {}).get("running")), None)
                if runner and runner["apps"][app]["snaps"]:
                    have = snaps(d)[-1][2] if exists(d) else 0
                    lag[app] = max(0, runner["apps"][app]["snaps"][-1][2] - have)
            except Exception as e:  # noqa: BLE001 — one app's failure is not the others'
                failed += 1
                log(f"{app}: {e}")
    write_metrics(st, lag, holding, failed)
    return 1 if failed else 0


def orphans() -> list[list]:
    parent = f"{root()}/orphans"
    if not exists(parent):
        return []
    out = zfs("list", "-H", "-p", "-d", "1", "-o", "name,used,creation", parent).stdout
    return [r.split("\t") for r in out.splitlines() if r.split("\t")[0] != parent]


def write_metrics(st: dict, lag: dict[str, int], holding: dict[str, int], failed: int) -> None:
    lines = [
        f"cluster_state_last_run_timestamp_seconds {int(time.time())}",
        f"cluster_state_failed_apps {failed}",
        f"cluster_state_orphans {len(orphans())}",
        f"cluster_state_peers_unreachable {sum(1 for s in st.values() if s is None)}",
    ]
    lines += [f'cluster_state_holder{{app="{a}"}} {v}' for a, v in sorted(holding.items())]
    lines += [f'cluster_state_replica_lag_seconds{{app="{a}"}} {v}' for a, v in sorted(lag.items())]
    METRICS.mkdir(parents=True, exist_ok=True)
    tmp = METRICS / "cluster_state.prom.tmp"
    tmp.write_text("\n".join(lines) + "\n")
    tmp.replace(METRICS / "cluster_state.prom")


def serve() -> None:
    """One request, from a peer on the mesh: WireGuard is what says it is a node."""
    request = json.loads(sys.stdin.buffer.readline())
    do, app = request.get("do"), request.get("app")
    if do == "status":
        print(json.dumps(local_status()), flush=True)
        return
    if app not in APPS:
        print(f"no app {app!r} here", flush=True)
        return
    if do == "release":
        if running(app):
            log(f"{app}: stopped at a peer's request (Nomad placed it there)")
            run("systemctl", "stop", f"container@{app}.service", check=False, timeout=APPS[app]["fence"] + 30)
        print(json.dumps(local_status()), flush=True)
    elif do == "send":
        since, to = request.get("from"), request.get("to")
        if not NAME.match(to or "") or (since is not None and not NAME.match(since)):
            print("bad snapshot name", flush=True)
            return
        d = ds(app)
        if not exists(f"{d}@{to}") or (since and not exists(f"{d}@{since}")):
            print("no such snapshot any more", flush=True)
            return
        print("ok", flush=True)
        # Large blocks, embedded data and compressed records go as they are on disk.
        argv = ["zfs", "send", "-L", "-e", "-c"] + (["-I", f"@{since}"] if since else []) + [f"{d}@{to}"]
        os.execvp("zfs", argv)
    else:
        print("unknown request", flush=True)


def show() -> None:
    st = {ME: local_status(), **poll()}
    now = time.time()
    for app in APPS:
        print(app)
        for node, s in sorted(st.items()):
            if s is None:
                print(f"  {node:<12} no answer")
                continue
            a = s["apps"].get(app)
            if not a or (not a["snaps"] and not a["legacy"]):
                print(f"  {node:<12} nothing")
                continue
            role = "running" if a["running"] else {REPLICA: "replica", RELEASED: "stopped here"}.get(a["holder"], "held, not running")
            if a["legacy"]:
                role = "a directory, from before datasets"
            age = f"newest snapshot {int(now - a['snaps'][-1][2])}s ago" if a["snaps"] else "no snapshot"
            print(f"  {node:<12} {role:<20} {age}")
    for name, used, created in orphans():
        print(f"orphan {name}  {int(used) >> 20} MiB  set aside {time.strftime('%Y-%m-%d %H:%M', time.localtime(int(created)))}")


def main() -> int:
    args = sys.argv[1:]
    verb = args[0] if args else "status"
    try:
        if verb == "serve":
            serve()
        elif verb == "status":
            show()
        elif verb == "replicate":
            return replicate()
        elif verb == "where" and len(args) == 2 and args[1] in APPS:
            # The peers running the app, for a caller that must not act beside them.
            st = poll()
            silent = sorted(p for p, v in st.items() if v is None)
            if silent:
                raise Refused(f"{', '.join(silent)} not answering, so whether {args[1]} runs there is not known")
            print(" ".join(sorted(p for p, v in st.items() if v["apps"].get(args[1], {}).get("running"))))
        elif verb == "orphans":
            for name, used, _created in orphans():
                print(f"{name}\t{int(used) >> 20} MiB")
        elif verb == "drop-orphan" and len(args) >= 2:
            name = args[1]
            if not name.startswith(f"{root()}/orphans/") or not exists(name):
                raise Refused(f"{name} is not an orphan on this node (`cluster-state orphans`)")
            if "--yes" not in args:
                print(f"would destroy {name} and its snapshots; add --yes")
            else:
                zfs("destroy", "-r", name)
        elif verb in ("acquire", "release", "init") and len(args) == 2 and args[1] in APPS:
            app = args[1]
            if verb == "acquire":
                acquire(app)
            elif verb == "release":
                release(app)
            else:
                with locked(app):
                    if exists(ds(app)) or legacy(app):
                        raise Refused(f"{app} has state on this node already")
                    create(app)
                    zfs("set", f"{HOLDER}={RELEASED}", "readonly=on", ds(app))
        else:
            print(__doc__, file=sys.stderr)
            return 2
    except Refused as e:
        log(f"cluster-state: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
