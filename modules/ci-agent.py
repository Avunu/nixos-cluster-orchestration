"""cluster-ci-agent: this node's half of the pipeline (modules/ci-agent.nix).

It asks the cluster-ci Worker (workers/cluster-ci) what this node should run, and says
what it runs. Nothing reaches a node from outside, so the asking is the node's: one
request, held open by the Worker until something changes.

Two things come back:

  deploySeq   counts pushes to the branch this node rebuilds from. When it moves, the
              pull deploy's tick starts now; the timer stays, as the fallback.
  previews    one per app and branch with an open pull request. Each takes one of the
              app's preview slots, containers this node already declares with every
              mount, limit and firewall rule fixed (lib/mk-app-container.nix). What is
              made here is what runs in one:

                build   the site's flake, with the app's project input at the branch's
                        commit, for that slot's container
                seed    a ZFS clone of the state dataset and a JuiceFS clone of the
                        app's files, so the copy costs nothing until it diverges
                start   the container on that closure, whose own units migrate the copy
                        before the app starts
                probe   the preview's hostname, through its own tunnel

State is in STATE_DIR/state.json: which slot holds which preview, at which commit. The
tunnel's secret is not: it arrives with every answer and lives in RUN_DIR.

What it reports of a failure is a build's last lines, which are code, and the names of
units. Never a guest's log: that is a copy of production speaking, and a pull request's
comment is no place for it. Those logs are where every app's are.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

CFG = json.loads(pathlib.Path(os.environ["CI_CONFIG"]).read_text())
STATE_DIR = pathlib.Path(os.environ.get("STATE_DIR", "/var/lib/cluster-ci"))
RUN_DIR = pathlib.Path(os.environ.get("RUN_DIR", "/run/cluster-preview"))
METRICS_DIR = os.environ.get("METRICS_DIR")
PROFILES = pathlib.Path(os.environ.get("PROFILES_DIR", "/nix/var/nix/profiles/per-container"))
ROOTS = pathlib.Path(os.environ.get("CONTAINERS_DIR", "/var/lib/nixos-containers"))

STATES = ("queued", "building", "seeding", "starting", "live", "failed", "no-capacity")
# A guest gets this long to come up, which includes migrating its database.
START_TIMEOUT = int(CFG.get("startTimeoutSeconds", 45 * 60))
PROBE_SECONDS = int(CFG.get("probeSeconds", 180))


class Failed(Exception):
    """A step did not work. Its text goes to the pull request."""


class Superseded(Exception):
    """The branch moved, or the preview is no longer wanted, while a step ran."""


def log(msg: str) -> None:
    print(f"cluster-ci-agent: {msg}", flush=True)


def tail(text: str, lines: int = 25, chars: int = 3000) -> str:
    return "\n".join(text.strip().splitlines()[-lines:])[-chars:]


def run(*argv: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise Failed(f"`{' '.join(argv[:3])}` did not finish in {timeout} s") from e
    if check and p.returncode != 0:
        raise Failed(f"`{' '.join(argv[:3])}` failed:\n{tail(p.stderr, 8, 800)}")
    return p


def token() -> str:
    d = os.environ.get("CREDENTIALS_DIRECTORY", "")
    return pathlib.Path(d, "token").read_text().strip()


class Agent:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.work = threading.Event()
        self.want: dict[str, dict] = {}
        self.waiting: list[dict] = []
        self.version = 0
        self.state_file = STATE_DIR / "state.json"
        saved = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self.deploy_seq: int | None = saved.get("deploySeq")
        # slot name -> {} when free, or {id, app, sha, seed, host, state, detail, and
        # once made: path, seeded, done}
        self.slots: dict[str, dict] = {
            s["name"]: saved.get("slots", {}).get(s["name"], {}) for a in CFG["apps"].values() for s in a["slots"]
        }
        self.slot_cfg = {s["name"]: {**s, "app": name} for name, a in CFG["apps"].items() for s in a["slots"]}
        # A run that was cut off is started again.
        for s in self.slots.values():
            if s.get("state") in ("building", "seeding", "starting"):
                s["state"] = "queued"

    # ── state ────────────────────────────────────────────────────────────────

    def save(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"deploySeq": self.deploy_seq, "slots": self.slots}, sort_keys=True))
        tmp.replace(self.state_file)
        if METRICS_DIR:
            counts = {st: 0 for st in STATES}
            for s in self.slots.values():
                if s.get("state") in counts:
                    counts[s["state"]] += 1
            counts["no-capacity"] = len(self.waiting)
            body = "".join(f'cluster_ci_previews{{state="{k}"}} {v}\n' for k, v in counts.items())
            body += f"cluster_ci_last_sync_timestamp_seconds {int(time.time())}\n"
            pathlib.Path(METRICS_DIR).mkdir(parents=True, exist_ok=True)
            out = pathlib.Path(METRICS_DIR, "cluster_ci.prom")
            out.with_suffix(".tmp").write_text(body)
            out.with_suffix(".tmp").replace(out)

    def set(self, name: str, state: str, detail: str = "") -> None:
        with self.lock:
            self.slots[name].update(state=state, detail=detail)
            self.save()
        log(f"{name}: {state}{': ' + detail.splitlines()[0] if detail else ''}")
        # Said at once, without waiting for the held request to come back.
        try:
            self.post(-1)
        except OSError as e:
            log(f"could not report: {e}")

    def target(self, name: str) -> tuple[str, int] | None:
        s = self.slots[name]
        if not s.get("id") or s.get("release"):
            return None
        return (s["sha"], s["seed"])

    def check(self, name: str, target: tuple[str, int]) -> None:
        with self.lock:
            if self.target(name) != target:
                raise Superseded

    # ── the Worker ───────────────────────────────────────────────────────────

    def report(self) -> list[dict]:
        held = [
            {"id": s["id"], "sha": s["sha"], "seed": s["seed"], "state": s["state"], "detail": s.get("detail", ""), "slot": n}
            for n, s in self.slots.items()
            if s.get("id")
        ]
        full = "Every preview slot of this app is in use. It starts when a pull request on another branch closes."
        return held + [
            {"id": p["id"], "sha": p["sha"], "seed": p["seed"], "state": "no-capacity", "detail": full} for p in self.waiting
        ]

    def post(self, version: int) -> dict:
        with self.lock:
            body = {
                "version": version,
                "flake": CFG["flake"],
                "apps": [{"app": n, "repo": a["repo"], "slots": len(a["slots"])} for n, a in CFG["apps"].items()],
                "previews": self.report(),
            }
        req = urllib.request.Request(
            CFG["url"],
            data=json.dumps(body).encode(),
            headers={"Authorization": f"Bearer {token()}", "Content-Type": "application/json", "User-Agent": "cluster-ci-agent"},
        )
        with urllib.request.urlopen(req, timeout=90) as res:
            return json.load(res)

    def apply(self, answer: dict) -> None:
        with self.lock:
            self.version = answer["version"]
            seq = answer["deploySeq"]
            deploy = self.deploy_seq is not None and seq > self.deploy_seq
            self.deploy_seq = seq
            self.want = {p["id"]: p for p in answer["previews"]}
            for s in self.slots.values():
                if s.get("id") and s["id"] not in self.want:
                    s["release"] = True
            self.waiting = []
            for p in answer["previews"]:
                held = next((s for s in self.slots.values() if s.get("id") == p["id"]), None)
                if held is None:
                    free = [s["name"] for s in CFG["apps"].get(p["app"], {}).get("slots", []) if not self.slots[s["name"]]]
                    if not free:
                        self.waiting.append(p)
                        continue
                    held = self.slots[free[0]]
                    held.update(id=p["id"], app=p["app"])
                held.pop("release", None)
                if (held.get("sha"), held.get("seed")) != (p["sha"], p["seed"]):
                    held.update(sha=p["sha"], seed=p["seed"], state="queued", detail="")
                held["host"] = p["host"]
            self.save()
        self.work.set()
        if deploy:
            log(f"the deploy branch moved (#{seq}): starting cluster-upgrade")
            run("systemctl", "start", "--no-block", "cluster-upgrade.service", check=False)

    def poll(self) -> None:
        while True:
            try:
                self.apply(self.post(self.version))
            except (OSError, ValueError, KeyError) as e:
                log(f"sync failed: {e}")
                time.sleep(15)

    # ── the work, one slot at a time ─────────────────────────────────────────

    def next_job(self) -> tuple[str, str] | None:
        with self.lock:
            for n, s in self.slots.items():
                if s.get("release"):
                    return ("release", n)
            for n, s in self.slots.items():
                t = self.target(n)
                if t and s.get("done") != list(t) and s.get("gaveup") != list(t) and s["id"] in self.want:
                    return ("deploy", n)
            live = [n for n, s in self.slots.items() if s.get("state") == "live" and s.get("id") in self.want]
        # After a reboot nothing starts a preview but this: no slot is a Nomad job.
        for n in live:
            if run("systemctl", "is-active", "--quiet", f"container@{n}.service", check=False).returncode != 0:
                return ("start", n)
        return None

    def loop(self) -> None:
        while True:
            self.work.wait(30)
            self.work.clear()
            while job := self.next_job():
                kind, name = job
                try:
                    getattr(self, kind)(name)
                except Superseded:
                    log(f"{name}: superseded")
                except Exception as e:  # noqa: BLE001  a bug must not stop the other slots
                    if not isinstance(e, Failed):
                        e = Failed(f"The agent itself failed: {type(e).__name__}: {e}")
                    if kind == "release":
                        # Still held, so still reported, and tried again at the next wake.
                        log(f"{name}: could not be released: {e}")
                        break
                    with self.lock:
                        t = self.target(name)
                        if t:
                            self.slots[name]["gaveup"] = list(t)
                    self.set(name, "failed", str(e))

    def deploy(self, name: str) -> None:
        with self.lock:
            t = self.target(name)
            if t is None:
                raise Superseded
            p = self.want[self.slots[name]["id"]]
        self.set(name, "building")
        path = self.build(name, p, t)
        self.check(name, t)
        if self.slots[name].get("seeded") != t[1]:
            self.set(name, "seeding")
            self.seed(name)
            with self.lock:
                self.slots[name]["seeded"] = t[1]
                self.save()
        self.check(name, t)
        with self.lock:
            self.slots[name]["path"] = path
        self.start(name, t)

    def build(self, name: str, p: dict, t: tuple[str, int]) -> str:
        app = CFG["apps"][p["app"]]
        url = app["inputUrl"].replace("{rev}", p["sha"]).replace("{ref}", urllib.parse.quote(p["branch"], safe=""))
        attr = f"nixosConfigurations.{CFG['host']}.config.containers.{name}.config.system.build.toplevel"
        argv = ["nix", "build", "--refresh", "--no-link", "--print-out-paths", "--override-input", app["input"], url,
                f"{CFG['flake']}#{attr}"]  # fmt: skip
        with tempfile.TemporaryFile("w+") as out, tempfile.TemporaryFile("w+") as err:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, text=True)
            # A push while this builds makes the result worthless: stop, and build that.
            while proc.poll() is None:
                try:
                    self.check(name, t)
                except Superseded:
                    proc.terminate()
                    proc.wait()
                    raise
                time.sleep(1)
            out.seek(0)
            err.seek(0)
            if proc.returncode != 0:
                raise Failed(f"The build failed:\n{tail(err.read())}")
            return out.read().strip().splitlines()[-1]

    def clone_names(self, name: str) -> tuple[str, str, str]:
        src = run("findmnt", "-n", "-o", "SOURCE", CFG["stateMount"]).stdout.strip()
        parent = f"{src.split('/')[0]}/preview"
        return (f"{src}@preview-{name}", parent, f"{parent}/{name}")

    def unseed(self, name: str) -> None:
        """The slot's copy of everything, gone. The container is stopped first."""
        run("systemctl", "stop", f"container@{name}.service", timeout=START_TIMEOUT)
        snap, _parent, clone = self.clone_names(name)
        for ds in (clone, snap):
            if run("zfs", "list", "-H", "-o", "name", ds, check=False).returncode == 0:
                run("zfs", "destroy", ds)
        files = pathlib.Path(CFG["jfsMount"], "previews", name)
        if files.exists():
            run("juicefs", "rmr", str(files), timeout=3600)
        # The guest's own root: its journal and whatever else it wrote outside its mounts.
        shutil.rmtree(ROOTS / name, ignore_errors=True)

    def seed(self, name: str) -> None:
        self.unseed(name)
        snap, parent, clone = self.clone_names(name)
        if run("zfs", "list", "-H", "-o", "name", parent, check=False).returncode != 0:
            run("zfs", "create", "-o", "mountpoint=none", "-o", "com.sun:auto-snapshot=false", parent)
        # One instant for every file of the database, so it comes up as after a power
        # cut: recovered, and consistent. The clone shares its blocks with production
        # until either side writes.
        run("zfs", "snapshot", snap)
        run("zfs", "clone", "-o", f"mountpoint={CFG['cloneRoot']}/{name}", "-o", "com.sun:auto-snapshot=false", snap, clone)
        base = pathlib.Path(CFG["jfsMount"], "clients", self.slot_cfg[name]["app"])
        if base.exists():
            dst = pathlib.Path(CFG["jfsMount"], "previews", name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            run("juicefs", "clone", str(base), str(dst), timeout=3600)

    def start(self, name: str, t: tuple[str, int] | None = None) -> None:
        with self.lock:
            s = self.slots[name]
            t = t or self.target(name)
            p = self.want.get(s.get("id", ""))
            if t is None or p is None:
                raise Superseded
            path = s["path"]
        self.set(name, "starting")
        self.tunnel_files(name, p)
        (PROFILES / name).mkdir(parents=True, exist_ok=True)
        run("nix-env", "-p", str(PROFILES / name / "system"), "--set", path)
        _snap, _parent, clone = self.clone_names(name)
        run("zfs", "mount", clone, check=False)  # already mounted, unless this is after a reboot
        unit = f"container@{name}.service"
        run("systemctl", "restart", unit, timeout=START_TIMEOUT)
        up = run("nixos-container", "run", name, "--", "systemctl", "is-system-running", "--wait",
                 check=False, timeout=START_TIMEOUT).stdout.strip()  # fmt: skip
        if up != "running":
            failed = run("nixos-container", "run", name, "--", "systemctl", "list-units", "--failed", "--plain",
                         "--no-legend", check=False).stdout  # fmt: skip
            units = " ".join(line.split()[0] for line in failed.splitlines() if line.strip()) or "(none listed)"
            raise Failed(
                f"The container started but is {up or 'not answering'}. Failed units: {units}\n"
                f"Their logs are with the cluster's, under app={name}."
            )
        self.check(name, t)
        self.probe(name, p)
        with self.lock:
            self.slots[name]["done"] = list(t)
        self.set(name, "live")

    def tunnel_files(self, name: str, p: dict) -> None:
        d = RUN_DIR / name
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o700)
        tun = p["tunnel"]
        creds = {"AccountTag": tun["account"], "TunnelID": tun["id"], "TunnelSecret": tun["secret"]}
        # JSON is YAML. The credentials path is where the guest's unit is handed the file.
        config = {
            "tunnel": tun["id"],
            "credentials-file": "/run/credentials/preview-tunnel.service/credentials.json",
            "ingress": [{"hostname": p["host"], "service": self.slot_cfg[name]["origin"]}, {"service": "http_status:404"}],
        }
        for file, content in (("credentials.json", creds), ("config.yml", config)):
            f = d / file
            f.touch(mode=0o600)
            f.write_text(json.dumps(content))

    def probe(self, name: str, p: dict) -> None:
        base = CFG.get("probeBase") or f"https://{p['host']}"
        url = base + CFG["apps"][p["app"]]["healthPath"]
        deadline = time.monotonic() + PROBE_SECONDS
        last = "no answer"
        while True:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "cluster-ci-agent"})
                with urllib.request.urlopen(req, timeout=20) as res:
                    code = res.status
            except urllib.error.HTTPError as e:
                code = e.code
            except OSError as e:
                code, last = None, str(e)
            if code is not None and code < 500:
                return
            if code is not None:
                last = f"HTTP {code}"
            if time.monotonic() >= deadline:
                raise Failed(f"The container is up, but {url} did not answer through its tunnel: {last}")
            time.sleep(5)

    def release(self, name: str) -> None:
        self.unseed(name)
        shutil.rmtree(RUN_DIR / name, ignore_errors=True)
        # No profile, no root for the closure: the next collection takes it.
        for link in (PROFILES / name).glob("system*"):
            link.unlink(missing_ok=True)
        with self.lock:
            s = self.slots[name]
            # Wanted again while this ran (a pull request reopened): the slot stays the
            # branch's, with nothing left of its copy.
            again = not s.get("release")
            if again:
                for k in ("seeded", "done", "gaveup", "path"):
                    s.pop(k, None)
            else:
                self.slots[name] = {}
            self.save()
        log(f"{name}: released")
        if again:
            self.work.set()
            return
        try:
            self.post(-1)
        except OSError as e:
            log(f"could not report: {e}")


def main() -> None:
    agent = Agent()
    threading.Thread(target=agent.loop, daemon=True).start()
    agent.poll()


if __name__ == "__main__":
    main()
