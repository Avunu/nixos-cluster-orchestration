"""The pipeline's agent (modules/ci-agent.py), run for real against a stand-in Worker
and stand-in commands (checks.ci-agent in flake.nix).

Usage: ci-agent.py AGENT

The agent is a process of its own here, as on a node: what is checked is what it asks of
nix, zfs, juicefs and systemd, in which order, and what it tells the Worker. What those
commands then do is the VM tests' and the tools' own business.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

AGENT = sys.argv.pop(1)

FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
d = pathlib.Path(os.environ["FAKE_DIR"])
name, argv = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with open(d / "log", "a") as f:
    f.write(json.dumps([name, *argv]) + "\n")
have = d / "zfs"
sets = set(have.read_text().split()) if have.exists() else set()
if name == "nix":
    if (d / "build-fail").exists():
        sys.exit("error: attribute 'boom' missing\nerror: build of the preview failed")
    print("/nix/store/built-" + argv[argv.index("--override-input") + 2].rsplit("/", 1)[-1][-8:])
elif name == "findmnt":
    print("rpool/state")
elif name == "zfs":
    if argv[0] == "list":
        sys.exit(0 if argv[-1] in sets else 1)
    if argv[0] in ("snapshot", "clone", "create"):
        sets.add(argv[-1])
    if argv[0] == "destroy":
        sets.discard(argv[-1])
    have.write_text("\n".join(sorted(sets)))
elif name == "juicefs":
    if argv[0] == "clone":
        shutil.copytree(argv[1], argv[2])
    if argv[0] == "rmr":
        shutil.rmtree(argv[1])
elif name == "systemctl":
    unit = d / ("active-" + argv[-1])
    if argv[0] == "is-active":
        sys.exit(0 if unit.exists() else 3)
    if argv[0] == "restart":
        unit.touch()
    if argv[0] == "stop":
        unit.unlink(missing_ok=True)
elif name == "nixos-container":
    if "is-system-running" in argv:
        state = d / "guest"
        print(state.read_text() if state.exists() else "running")
    elif "list-units" in argv:
        print("odoo-migrate.service loaded failed failed Migrate")
'''

SHA_A, SHA_B = "a" * 40, "b" * 40


class Worker(http.server.BaseHTTPRequestHandler):
    """Answers /agent/sync with what the test wants run, and keeps what it was told."""

    lock = threading.Lock()
    version = 1
    deploy_seq = 0
    previews: list[dict] = []
    reports: list[dict] = []
    health = 200

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(Worker.health)
        self.end_headers()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.headers["Authorization"] == "Bearer t0ken"
        with Worker.lock:
            Worker.reports.append(body)
            held = body["version"] == Worker.version
        if held:
            time.sleep(0.1)
        with Worker.lock:
            answer = {"version": Worker.version, "deploySeq": Worker.deploy_seq, "previews": Worker.previews}
        data = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def preview(branch: str, sha: str, seed: int = 1) -> dict:
    return {
        "id": f"shop/{branch}", "app": "shop", "repo": "acme/shop", "branch": branch, "sha": sha, "seed": seed,
        "host": f"{branch}-shop.preview.example.com",
        "tunnel": {"id": f"tun-{branch}", "account": "acct", "secret": "c2VjcmV0"},
    }  # fmt: skip


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        bin_ = self.tmp / "bin"
        bin_.mkdir()
        (bin_ / "fake").write_text(FAKE.replace("#!/usr/bin/env python3", f"#!{sys.executable}"))
        (bin_ / "fake").chmod(0o755)
        for c in ("nix", "nix-env", "zfs", "juicefs", "systemctl", "nixos-container", "findmnt"):
            (bin_ / c).symlink_to("fake")
        self.fake = self.tmp / "fake"
        self.fake.mkdir()
        (self.tmp / "creds").mkdir()
        (self.tmp / "creds/token").write_text("t0ken\n")
        files = self.tmp / "jfs/clients/shop/odoo"
        files.mkdir(parents=True)
        (files / "filestore").write_text("production's")

        Worker.version, Worker.deploy_seq, Worker.previews, Worker.reports, Worker.health = 1, 0, [], [], 200
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Worker)
        # An agent killed in mid-request is this test's doing, not a failure to print.
        self.server.handle_error = lambda *_: None
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{self.server.server_port}"
        self.cfg = {
            "node": "node1", "host": "node1", "url": f"{base}/agent/sync", "flake": "github:acme/cluster",
            "stateMount": "/state", "cloneRoot": "/state-preview", "jfsMount": str(self.tmp / "jfs"),
            "probeBase": base, "probeSeconds": 1,
            "apps": {"shop": {
                "repo": "acme/shop", "input": "shop-src", "inputUrl": "github:acme/shop/{rev}", "healthPath": "/web/health",
                "slots": [{"name": "shop-pv1", "origin": "unix:/run/odoo-shop-pv1/nginx.sock"}],
            }},
        }  # fmt: skip
        self.proc = None

    def tearDown(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait()
        self.server.shutdown()
        self.server.server_close()

    def start(self):
        (self.tmp / "config.json").write_text(json.dumps(self.cfg))
        env = {
            "PATH": f"{self.tmp / 'bin'}:{os.environ['PATH']}",
            "FAKE_DIR": str(self.fake),
            "CI_CONFIG": str(self.tmp / "config.json"),
            "CREDENTIALS_DIRECTORY": str(self.tmp / "creds"),
            "STATE_DIR": str(self.tmp / "state"),
            "RUN_DIR": str(self.tmp / "run"),
            "METRICS_DIR": str(self.tmp / "metrics"),
            "PROFILES_DIR": str(self.tmp / "profiles"),
            "CONTAINERS_DIR": str(self.tmp / "roots"),
        }
        self.proc = subprocess.Popen([sys.executable, AGENT], env=env)

    def want(self, *previews: dict, deploy: int | None = None):
        with Worker.lock:
            Worker.previews = list(previews)
            Worker.version += 1
            if deploy is not None:
                Worker.deploy_seq = deploy

    def said(self, pid: str) -> dict | None:
        with Worker.lock:
            last = Worker.reports[-1] if Worker.reports else {"previews": []}
        return next((p for p in last["previews"] if p["id"] == pid), None)

    def until(self, what, seconds: float = 20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if got := what():
                return got
            time.sleep(0.05)
        self.fail(f"timed out; the agent ran: {self.ran()}, last said: {Worker.reports[-1:]}")

    def state(self, pid: str, state: str, sha: str):
        return self.until(lambda: (p := self.said(pid)) and p["state"] == state and p["sha"] == sha and p)

    def ran(self, clear: bool = False) -> list[str]:
        log = self.fake / "log"
        lines = [" ".join(json.loads(line)) for line in log.read_text().splitlines()] if log.exists() else []
        if clear:
            log.unlink(missing_ok=True)
        return lines

    def test_a_preview_is_built_seeded_started_and_followed(self):
        self.start()
        self.until(lambda: Worker.reports)
        self.assertEqual(Worker.reports[0]["apps"], [{"app": "shop", "repo": "acme/shop", "slots": 1}])
        self.assertEqual(Worker.reports[0]["flake"], "github:acme/cluster")

        self.want(preview("feat-x", SHA_A))
        self.assertEqual(self.state("shop/feat-x", "live", SHA_A)["slot"], "shop-pv1")
        ran = self.ran(clear=True)
        built = "nixosConfigurations.node1.config.containers.shop-pv1.config.system.build.toplevel"
        self.assertIn(
            f"nix build --refresh --no-link --print-out-paths --override-input shop-src github:acme/shop/{SHA_A}"
            f" github:acme/cluster#{built}",
            ran,
        )
        order = [
            "nix build",
            "systemctl stop container@shop-pv1.service",
            "zfs create -o mountpoint=none -o com.sun:auto-snapshot=false rpool/preview",
            "zfs snapshot rpool/state@preview-shop-pv1",
            "zfs clone -o mountpoint=/state-preview/shop-pv1 -o com.sun:auto-snapshot=false"
            " rpool/state@preview-shop-pv1 rpool/preview/shop-pv1",
            f"juicefs clone {self.tmp}/jfs/clients/shop {self.tmp}/jfs/previews/shop-pv1",
            f"nix-env -p {self.tmp}/profiles/shop-pv1/system --set /nix/store/built-aaaaaaaa",
            "systemctl restart container@shop-pv1.service",
            "nixos-container run shop-pv1 -- systemctl is-system-running --wait",
        ]
        at = [next(i for i, line in enumerate(ran) if line.startswith(step)) for step in order]
        self.assertEqual(at, sorted(at), ran)
        self.assertEqual((self.tmp / "jfs/previews/shop-pv1/odoo/filestore").read_text(), "production's")
        run = self.tmp / "run/shop-pv1"
        self.assertEqual(
            json.loads((run / "credentials.json").read_text()),
            {"AccountTag": "acct", "TunnelID": "tun-feat-x", "TunnelSecret": "c2VjcmV0"},
        )
        self.assertEqual(
            json.loads((run / "config.yml").read_text())["ingress"],
            [
                {"hostname": "feat-x-shop.preview.example.com", "service": "unix:/run/odoo-shop-pv1/nginx.sock"},
                {"service": "http_status:404"},
            ],
        )
        self.assertEqual((run / "credentials.json").stat().st_mode & 0o777, 0o600)

        # A push: the new commit on the same copy. Built and restarted, not seeded again.
        self.want(preview("feat-x", SHA_B))
        self.state("shop/feat-x", "live", SHA_B)
        ran = self.ran(clear=True)
        self.assertTrue(any(f"github:acme/shop/{SHA_B}" in line for line in ran))
        self.assertIn("systemctl restart container@shop-pv1.service", ran)
        self.assertFalse([line for line in ran if line.startswith(("zfs snapshot", "zfs destroy", "juicefs"))], ran)

        # /preview reset: the same commit on a fresh copy.
        (self.tmp / "jfs/previews/shop-pv1/odoo/filestore").write_text("the preview's")
        self.want(preview("feat-x", SHA_B, seed=2))
        self.until(lambda: (p := self.said("shop/feat-x")) and p["seed"] == 2 and p["state"] == "live")
        ran = self.ran(clear=True)
        self.assertIn("zfs destroy rpool/preview/shop-pv1", ran)
        self.assertIn("zfs destroy rpool/state@preview-shop-pv1", ran)
        self.assertEqual((self.tmp / "jfs/previews/shop-pv1/odoo/filestore").read_text(), "production's")

        # A second branch finds the app's one slot taken, and says so.
        self.want(preview("feat-x", SHA_B, seed=2), preview("feat-y", SHA_A))
        self.assertIn("slot", self.state("shop/feat-y", "no-capacity", SHA_A)["detail"])
        self.assertEqual(self.said("shop/feat-x")["state"], "live")
        self.ran(clear=True)

        # The first closes: everything of it goes, the Worker hears no more of it, and
        # the slot is the second branch's.
        self.want(preview("feat-y", SHA_A))
        self.state("shop/feat-y", "live", SHA_A)
        self.assertIsNone(self.said("shop/feat-x"))
        ran = self.ran(clear=True)
        self.assertLess(ran.index("zfs destroy rpool/preview/shop-pv1"), ran.index("zfs snapshot rpool/state@preview-shop-pv1"))
        self.assertEqual(json.loads((run / "credentials.json").read_text())["TunnelID"], "tun-feat-y")

        self.want()
        self.until(lambda: Worker.reports[-1]["previews"] == [])
        self.until(lambda: not (self.tmp / "jfs/previews/shop-pv1").exists() and not run.exists())
        self.assertFalse((self.fake / "active-container@shop-pv1.service").exists())
        self.assertEqual((self.fake / "zfs").read_text().split(), ["rpool/preview"])

    def test_a_failed_build_is_reported_once_and_a_push_tries_again(self):
        (self.fake / "build-fail").touch()
        self.start()
        self.want(preview("feat-x", SHA_A))
        said = self.state("shop/feat-x", "failed", SHA_A)
        self.assertIn("The build failed", said["detail"])
        self.assertIn("attribute 'boom' missing", said["detail"])
        time.sleep(0.5)
        ran = self.ran(clear=True)
        self.assertEqual(len([line for line in ran if line.startswith("nix build")]), 1, ran)
        self.assertFalse([line for line in ran if line.startswith(("zfs", "systemctl restart"))], ran)
        (self.fake / "build-fail").unlink()
        self.want(preview("feat-x", SHA_B))
        self.state("shop/feat-x", "live", SHA_B)

    def test_a_guest_that_does_not_come_up_names_its_units_and_nothing_else(self):
        (self.fake / "guest").write_text("degraded")
        self.start()
        self.want(preview("feat-x", SHA_A))
        detail = self.state("shop/feat-x", "failed", SHA_A)["detail"]
        self.assertIn("odoo-migrate.service", detail)
        self.assertIn("app=shop-pv1", detail)
        self.assertNotIn("Migrate", detail)

    def test_a_preview_nothing_answers_for_is_not_live(self):
        Worker.health = 502
        self.start()
        Worker.health = 502
        self.want(preview("feat-x", SHA_A))
        self.assertIn("HTTP 502", self.state("shop/feat-x", "failed", SHA_A)["detail"])

    def test_the_deploy_branch_moving_starts_the_tick_once(self):
        self.start()
        self.until(lambda: Worker.reports)
        time.sleep(0.3)
        self.assertEqual(self.ran(), [])  # the first answer is where it starts counting
        self.want(deploy=1)
        self.until(lambda: "systemctl start --no-block cluster-upgrade.service" in self.ran())
        time.sleep(0.5)
        self.assertEqual(self.ran().count("systemctl start --no-block cluster-upgrade.service"), 1)
        # Counted across a restart: a push while the agent was down is not lost.
        self.proc.kill()
        self.proc.wait()
        self.ran(clear=True)
        self.want(deploy=2)
        self.start()
        self.until(lambda: "systemctl start --no-block cluster-upgrade.service" in self.ran())

    def test_a_live_preview_is_started_again_after_a_reboot(self):
        self.start()
        self.want(preview("feat-x", SHA_A))
        self.state("shop/feat-x", "live", SHA_A)
        self.proc.kill()
        self.proc.wait()
        (self.fake / "active-container@shop-pv1.service").unlink()
        shutil.rmtree(self.tmp / "run")
        self.ran(clear=True)
        self.start()
        self.until(lambda: (self.fake / "active-container@shop-pv1.service").exists())
        self.state("shop/feat-x", "live", SHA_A)
        ran = self.ran()
        self.assertFalse([line for line in ran if line.startswith(("nix build", "zfs snapshot", "zfs destroy"))], ran)
        self.assertIn("zfs mount rpool/preview/shop-pv1", ran)
        self.assertTrue((self.tmp / "run/shop-pv1/config.yml").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
