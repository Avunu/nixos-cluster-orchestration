"""A node's read access to GitHub (modules/github-access.py), run for real against a
stand-in Worker, and its credential helper asked by git itself (checks.github-access in
flake.nix).

Usage: github-access.py TOOL

What is checked is what a node ends up holding: which files, whole and root's alone,
what a refresh that fails leaves behind, and which token git is answered with for which
repository. That the Worker hands out the right tokens is workers/cluster-ci's tests;
that Nix's `github:` fetcher takes the longest matching `access-tokens` prefix is Nix's
own code (libfetchers/github.cc), and here only that the file written parses as that
setting, with the nix on PATH when there is one.
"""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

TOOL = sys.argv.pop(1)


def iso(seconds_from_now: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds_from_now))


def answer(*tokens: dict, uncovered: list[str] | None = None, errors: list[dict] | None = None) -> dict:
    return {"site": "acme/cluster", "ref": "main", "tokens": list(tokens), "uncovered": uncovered or [], "errors": errors or []}


def token(owner: str, value: str, repos: list[str], left: float = 3600) -> dict:
    return {"owner": owner, "token": value, "expires_at": iso(left), "repositories": repos}


class Worker(http.server.BaseHTTPRequestHandler):
    """Answers /agent/token with what the test set, and keeps who asked and what."""

    status = 200
    body: dict | str = {}
    asked: list[tuple[str, str, bytes]] = []

    def log_message(self, *_):
        pass

    def do_POST(self):
        sent = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Worker.asked.append((self.path, self.headers.get("Authorization", ""), sent))
        data = (Worker.body if isinstance(Worker.body, str) else json.dumps(Worker.body)).encode()
        self.send_response(Worker.status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class AccessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        (self.tmp / "creds").mkdir()
        (self.tmp / "creds/token").write_text("t0ken\n")
        self.run_dir = self.tmp / "run/cluster-github"
        Worker.status, Worker.body, Worker.asked = 200, answer(), []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Worker)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.env = {
            "PATH": os.environ["PATH"],
            "GITHUB_ACCESS_URL": f"http://127.0.0.1:{self.server.server_port}/agent/token",
            "CREDENTIALS_DIRECTORY": str(self.tmp / "creds"),
            "RUN_DIR": str(self.run_dir),
            "METRICS_DIR": str(self.tmp / "metrics"),
            "GITHUB_ACCESS_PAUSE": "0",
        }

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self.tmp)

    def refresh(self, body=None, status: int = 200) -> subprocess.CompletedProcess[str]:
        if body is not None:
            Worker.body = body
        Worker.status = status
        return subprocess.run([sys.executable, TOOL, "refresh"], env=self.env, capture_output=True, text=True)

    def conf(self) -> str:
        return (self.run_dir / "nix.conf").read_text()

    def access_tokens(self) -> dict[str, str]:
        lines = [line for line in self.conf().splitlines() if line.startswith("access-tokens = ")]
        self.assertLessEqual(len(lines), 1)
        return dict(pair.split("=", 1) for pair in lines[0].removeprefix("access-tokens = ").split()) if lines else {}

    def metrics(self) -> dict[str, int]:
        text = (self.tmp / "metrics/cluster_github_token.prom").read_text()
        return {k: int(v) for k, v in (line.split() for line in text.splitlines())}

    def helper(self, request: str) -> str:
        p = subprocess.run([sys.executable, TOOL, "credential", "get"], env=self.env, input=request, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def git_fill(self, url: str) -> dict[str, str] | None:
        """What git itself makes of the helper, configured as modules/github-access.nix
        configures it: None when git is left with nothing and would have to ask."""
        env = {
            **self.env,
            "HOME": str(self.tmp),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "2",
            "GIT_CONFIG_KEY_0": "credential.https://github.com.useHttpPath",
            "GIT_CONFIG_VALUE_0": "true",
            "GIT_CONFIG_KEY_1": "credential.https://github.com.helper",
            "GIT_CONFIG_VALUE_1": f"{sys.executable} {TOOL} credential",
        }
        p = subprocess.run(["git", "credential", "fill"], env=env, input=f"url={url}\n\n", capture_output=True, text=True)
        if p.returncode != 0:
            return None
        return dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)

    # ── refresh ──────────────────────────────────────────────────────────────

    def test_what_a_refresh_writes_is_whole_and_roots_alone(self):
        p = self.refresh(
            answer(
                token("acme", "ghs_acme", ["acme/cluster", "acme/shop"]),
                token("Customer", "ghs_cust", ["Customer/content"]),
                uncovered=["NixOS/nixpkgs"],
            )
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        # Asked as the pipeline's agent asks, and with nothing that names a repository.
        self.assertEqual(Worker.asked, [("/agent/token", "Bearer t0ken", b"{}")])
        self.assertEqual(stat.S_IMODE(self.run_dir.stat().st_mode), 0o700)
        self.assertEqual(sorted(f.name for f in self.run_dir.iterdir()), ["nix.conf", "tokens.json"])
        for f in self.run_dir.iterdir():
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600, f)
        # One entry per repository, spelled as the site spells it: Nix compares exactly.
        self.assertEqual(
            self.access_tokens(),
            {
                "github.com/acme/cluster": "ghs_acme",
                "github.com/acme/shop": "ghs_acme",
                "github.com/Customer/content": "ghs_cust",
            },
        )
        held = json.loads((self.run_dir / "tokens.json").read_text())
        self.assertEqual([t["token"] for t in held["tokens"]], ["ghs_acme", "ghs_cust"])
        self.assertEqual(held["uncovered"], ["NixOS/nixpkgs"])
        m = self.metrics()
        self.assertAlmostEqual(m["cluster_github_token_last_success_timestamp_seconds"], time.time(), delta=30)
        self.assertAlmostEqual(m["cluster_github_token_expiry_timestamp_seconds"], time.time() + 3600, delta=30)
        self.assertEqual(m["cluster_github_token_repositories"], 3)
        self.assertEqual(m["cluster_github_token_uncovered_repositories"], 1)
        self.assertIn("no installation covers: NixOS/nixpkgs", p.stderr)
        self.assertNotIn("ghs_", p.stdout + p.stderr)

    def test_each_file_is_replaced_by_rename(self):
        self.refresh(answer(token("acme", "ghs_one", ["acme/cluster"])))
        before = {f.name: f.stat().st_ino for f in self.run_dir.iterdir()}
        # A reader that opened the old file keeps the old file, whole.
        with open(self.run_dir / "nix.conf") as reader:
            self.refresh(answer(token("acme", "ghs_two", ["acme/cluster"])))
            self.assertIn("ghs_one", reader.read())
        after = {f.name: f.stat().st_ino for f in self.run_dir.iterdir()}
        self.assertEqual(sorted(after), ["nix.conf", "tokens.json"])
        self.assertTrue(all(before[n] != after[n] for n in before), (before, after))
        self.assertEqual(self.access_tokens(), {"github.com/acme/cluster": "ghs_two"})

    def test_a_refresh_that_fails_keeps_the_tokens_that_are_still_good(self):
        self.refresh(answer(token("acme", "ghs_acme", ["acme/cluster"]), token("customer", "ghs_old", ["customer/app"], left=30)))
        first = self.metrics()["cluster_github_token_last_success_timestamp_seconds"]
        for body, status in (({"error": "GitHub is away"}, 502), ({"error": "unauthorized"}, 401), ("<html>not json", 200)):
            Worker.asked = []
            p = self.refresh(body, status)
            self.assertEqual(p.returncode, 1, p.stderr)
            # Tried again within the run, and then left for the timer.
            self.assertEqual(len(Worker.asked), 3)
            # The one with an hour left stays. The one about to expire goes: sent to
            # GitHub it would be refused, where no token reads a public repository.
            self.assertEqual(self.access_tokens(), {"github.com/acme/cluster": "ghs_acme"})
            self.assertEqual([t["token"] for t in json.loads((self.run_dir / "tokens.json").read_text())["tokens"]], ["ghs_acme"])
            self.assertEqual(self.metrics()["cluster_github_token_last_success_timestamp_seconds"], first)
        # The Worker not there at all.
        self.server.shutdown()
        self.server.server_close()
        p = self.refresh()
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.access_tokens(), {"github.com/acme/cluster": "ghs_acme"})
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Worker)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def test_a_node_that_never_got_an_answer_says_so_and_holds_nothing(self):
        p = self.refresh({"error": "SITE_FLAKE is not set"}, 502)
        self.assertEqual(p.returncode, 1)
        self.assertIn("SITE_FLAKE is not set", p.stderr)
        self.assertEqual(self.access_tokens(), {})
        self.assertEqual(self.metrics()["cluster_github_token_last_success_timestamp_seconds"], 0)
        self.assertEqual(self.metrics()["cluster_github_token_expiry_timestamp_seconds"], 0)

    def test_an_owner_github_refused_the_worker_keeps_its_old_token(self):
        self.refresh(answer(token("acme", "ghs_acme", ["acme/cluster"]), token("customer", "ghs_cust", ["customer/app"])))
        p = self.refresh(answer(token("acme", "ghs_new", ["acme/cluster"]), errors=[{"owner": "customer", "error": "HTTP 500"}]))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.access_tokens(), {"github.com/acme/cluster": "ghs_new", "github.com/customer/app": "ghs_cust"})
        # An owner that is simply no longer in the answer left the site: its token goes.
        self.refresh(answer(token("acme", "ghs_new", ["acme/cluster"])))
        self.assertEqual(self.access_tokens(), {"github.com/acme/cluster": "ghs_new"})

    def test_an_answer_that_is_not_tokens_and_names_is_not_written(self):
        self.refresh(answer(token("acme", "ghs_acme", ["acme/cluster"])))
        for bad in (
            token("acme", "ghs_x\nextra-substituters = https://evil.example.net", ["acme/cluster"]),
            token("acme", "ghs_x github.com=ghs_y", ["acme/cluster"]),
            token("acme", "ghs_x", ["acme/cluster github.com/other"]),
            token("acme", "ghs_x", ["acme"]),
            {"owner": "acme", "token": "ghs_x", "repositories": ["acme/cluster"]},
        ):
            p = self.refresh(answer(bad))
            self.assertEqual(p.returncode, 1, bad)
            self.assertEqual(self.conf().count("\n"), 2, self.conf())
            self.assertEqual(self.access_tokens(), {"github.com/acme/cluster": "ghs_acme"})

    def test_a_site_whose_repositories_need_no_token_is_a_success(self):
        p = self.refresh(answer(uncovered=["acme/cluster", "NixOS/nixpkgs"]))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.access_tokens(), {})
        self.assertNotIn("access-tokens", self.conf())

    def test_the_fragment_is_a_setting_nix_reads(self):
        nix = shutil.which("nix")
        if not nix:
            # The check has the nodes' nix (flake.nix); a bare `python3` run may not.
            self.assertNotIn("REQUIRE_NIX", os.environ)
            self.skipTest("no nix on PATH")
        self.refresh(answer(token("acme", "ghs_acme", ["acme/cluster", "acme/shop"]), token("Customer", "ghs_cust", ["Customer/content"])))
        conf = self.tmp / "etc"
        conf.mkdir()
        env = {
            **self.env, "HOME": str(self.tmp), "NIX_CONF_DIR": str(conf), "NIX_USER_CONF_FILES": "/dev/null",
            "NIX_STATE_DIR": str(self.tmp / "state"), "NIX_STORE_DIR": str(self.tmp / "store"),
        }  # fmt: skip
        show = [nix, "--extra-experimental-features", "nix-command", "config", "show", "access-tokens"]
        # As modules/github-access.nix includes it; and a file that is not there is not an error.
        (conf / "nix.conf").write_text(f"!include {self.run_dir}/nix.conf\n!include {self.run_dir}/absent.conf\n")
        p = subprocess.run(show, env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(
            sorted(p.stdout.split()),
            ["github.com/Customer/content=ghs_cust", "github.com/acme/cluster=ghs_acme", "github.com/acme/shop=ghs_acme"],
        )
        shutil.rmtree(self.run_dir)
        p = subprocess.run(show, env=env, capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout.strip()), (0, ""), p.stderr)

    # ── git's credential helper ──────────────────────────────────────────────

    def test_git_is_answered_with_the_token_of_the_repository_it_names(self):
        self.refresh(
            answer(
                token("acme", "ghs_acme", ["acme/cluster", "acme/shop"]),
                token("Customer", "ghs_cust", ["Customer/content"]),
                token("late", "ghs_late", ["late/app"], left=30),
            )
        )
        acme = {"username": "x-access-token", "password": "ghs_acme"}
        for url in (
            "https://github.com/acme/shop.git",
            "https://github.com/acme/shop",
            "https://github.com/Acme/Shop.git",
            "https://github.com/acme/cluster.git/info/refs",
        ):
            got = self.git_fill(url)
            self.assertIsNotNone(got, url)
            self.assertEqual({k: got[k] for k in acme}, acme, url)
        self.assertEqual(self.git_fill("https://github.com/customer/content.git")["password"], "ghs_cust")
        # Nothing for an owner the node holds no token for, for a repository of an owner
        # it does hold one for that the token does not name, or for one about to expire.
        for url in (
            "https://github.com/mallory/secret.git",
            "https://github.com/acme/other.git",
            "https://github.com/acme/shop-private.git",
            "https://github.com/late/app.git",
            "https://github.com/acme",
        ):
            self.assertIsNone(self.git_fill(url), url)
        # And for no other host: the token is GitHub's.
        self.assertEqual(self.helper("protocol=https\nhost=github.com.example.net\npath=acme/shop.git\n"), "")
        self.assertEqual(self.helper("protocol=http\nhost=github.com\npath=acme/shop.git\n"), "")
        self.assertEqual(self.helper("protocol=https\nhost=github.com\n"), "")
        self.assertEqual(
            self.helper("protocol=https\nhost=github.com\npath=acme/shop.git\n"), "username=x-access-token\npassword=ghs_acme\n"
        )

    def test_the_helper_has_nothing_for_whoever_cannot_read_the_tokens(self):
        # Before the first refresh, and for any user but root: no file to read.
        self.assertEqual(self.helper("protocol=https\nhost=github.com\npath=acme/shop.git\n"), "")
        self.assertIsNone(self.git_fill("https://github.com/acme/shop.git"))
        self.refresh(answer(token("acme", "ghs_acme", ["acme/shop"])))
        (self.run_dir / "tokens.json").write_text("not json")
        self.assertEqual(self.helper("protocol=https\nhost=github.com\npath=acme/shop.git\n"), "")
        # git's other two questions are not this helper's to answer.
        for op in ("store", "erase"):
            p = subprocess.run([sys.executable, TOOL, "credential", op], env=self.env, input="password=x\n", capture_output=True, text=True)
            self.assertEqual((p.returncode, p.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
