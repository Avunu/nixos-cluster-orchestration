"""cluster-github-access: this node's read access to the site's GitHub repositories
(modules/github-access.nix).

No node holds the GitHub App's key. The cluster-ci Worker does (workers/cluster-ci), and
a node asks it, with the bearer token it already has for the pipeline's agent, for
installation tokens GitHub has narrowed to reading the site's repositories. They last
an hour, so this runs on a timer and before every pull.

  refresh             ask the Worker, and write under RUN_DIR (a tmpfs), each file whole
                      or not at all, root's and nobody else's:

                        tokens.json   what was handed out, and until when
                        nix.conf      `access-tokens`, one entry per repository, which
                                      Nix's own `github:` fetcher reads (`!include`)

                      A refresh that fails keeps every token that is still good and
                      drops the ones that are not: an expired token sent to GitHub is
                      refused even for a public repository, where no token is not.

  credential get      git's credential helper, for `git+https://` inputs and
                      builtins.fetchGit, where Nix runs `git fetch`. git says which
                      repository it wants (credential.useHttpPath); the answer is that
                      repository's token from tokens.json, or nothing.

Nothing here decides which repositories: the Worker reads that from the site's
repository, and what this node asks for is not part of the question.
"""

from __future__ import annotations

import calendar
import json
import os
import pathlib
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request

RUN_DIR = pathlib.Path(os.environ.get("RUN_DIR", "/run/cluster-github"))
TOKENS = RUN_DIR / "tokens.json"
NIX_CONF = RUN_DIR / "nix.conf"
METRICS_DIR = os.environ.get("METRICS_DIR")

# A token with less than this left is not used: the fetch it starts may outlive it.
MARGIN = 60
ATTEMPTS = int(os.environ.get("GITHUB_ACCESS_ATTEMPTS", "3"))
PAUSE = float(os.environ.get("GITHUB_ACCESS_PAUSE", "5"))

TOKEN = re.compile(r"^[A-Za-z0-9_.~+/=-]+$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def log(msg: str) -> None:
    print(f"cluster-github-access: {msg}", file=sys.stderr, flush=True)


def write(path: pathlib.Path, text: str) -> None:
    """The whole file or the old one, never part of it, and never readable by others."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        pathlib.Path(tmp).unlink(missing_ok=True)
        raise


def held() -> dict:
    try:
        got = json.loads(TOKENS.read_text())
        return got if isinstance(got, dict) else {}
    except (OSError, ValueError):
        return {}


def good(t: dict, now: float) -> bool:
    return t.get("expires_at", 0) - now > MARGIN


def parse(answer: dict) -> tuple[list[dict], list[str], list[str]]:
    """The Worker's answer, held to its shape: what is written into nix.conf is a
    token and repository names, and nothing else it might have said."""
    tokens = []
    for t in answer["tokens"]:
        repos = [r for r in t["repositories"] if isinstance(r, str) and REPO.match(r)]
        if not isinstance(t["token"], str) or not TOKEN.match(t["token"]) or repos != t["repositories"]:
            raise ValueError("the Worker's answer is not tokens and repository names")
        when = time.strptime(t["expires_at"][:19], "%Y-%m-%dT%H:%M:%S")
        tokens.append(
            {"owner": str(t["owner"]), "token": t["token"], "expires_at": calendar.timegm(when), "repositories": repos}
        )
    uncovered = [r for r in answer.get("uncovered", []) if isinstance(r, str) and REPO.match(r)]
    failed = [str(e.get("owner", "")) for e in answer.get("errors", [])]
    return tokens, uncovered, failed


def ask() -> dict:
    token = pathlib.Path(os.environ["CREDENTIALS_DIRECTORY"], "token").read_text().strip()
    req = urllib.request.Request(
        os.environ["GITHUB_ACCESS_URL"],
        data=b"{}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "cluster-github-access"},
    )
    with urllib.request.urlopen(req, timeout=60) as res:
        return json.load(res)


def nix_conf(tokens: list[dict]) -> str:
    # Per repository, not per owner: Nix takes the longest prefix (libfetchers/github.cc,
    # getAccessToken), so a repository of the same owner that the token does not name,
    # a public one, is fetched with no token at all.
    pairs = [f"github.com/{r}={t['token']}" for t in tokens for r in t["repositories"]]
    head = "# Written by cluster-github-token.service (modules/github-access.nix). Good for an hour.\n"
    return head + (f"access-tokens = {' '.join(pairs)}\n" if pairs else "")


def metrics(last_success: float, tokens: list[dict], uncovered: int) -> None:
    if not METRICS_DIR:
        return
    expiry = min((t["expires_at"] for t in tokens), default=0)
    body = (
        f"cluster_github_token_last_success_timestamp_seconds {int(last_success)}\n"
        f"cluster_github_token_expiry_timestamp_seconds {int(expiry)}\n"
        f"cluster_github_token_repositories {sum(len(t['repositories']) for t in tokens)}\n"
        f"cluster_github_token_uncovered_repositories {uncovered}\n"
    )
    out = pathlib.Path(METRICS_DIR, "cluster_github_token.prom")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".prom.tmp")
    tmp.write_text(body)
    tmp.replace(out)


def refresh() -> int:
    old = held()
    now = time.time()
    kept = [t for t in old.get("tokens", []) if good(t, now)]
    error = None
    for attempt in range(ATTEMPTS):
        try:
            tokens, uncovered, failed = parse(ask())
            break
        except urllib.error.HTTPError as e:
            error = f"HTTP {e.code} {e.read(300).decode(errors='replace').strip()}"
        except (OSError, ValueError, KeyError, TypeError) as e:
            error = f"{type(e).__name__}: {e}"
        if attempt + 1 < ATTEMPTS:
            time.sleep(PAUSE)
    else:
        log(f"no answer from the Worker: {error}")
        log(f"keeping {len(kept)} token(s) that are still good" if kept else "and no token is held")
        write(TOKENS, json.dumps({**old, "tokens": kept}, sort_keys=True))
        write(NIX_CONF, nix_conf(kept))
        metrics(old.get("fetched_at", 0), kept, len(old.get("uncovered", [])))
        return 1

    # GitHub refused the Worker a new token for an owner: the one held is used out.
    have = {t["owner"].lower() for t in tokens}
    tokens += [t for t in kept if t["owner"].lower() in {f.lower() for f in failed} - have]
    write(TOKENS, json.dumps({"fetched_at": int(now), "tokens": tokens, "uncovered": uncovered}, sort_keys=True))
    write(NIX_CONF, nix_conf(tokens))
    metrics(now, tokens, len(uncovered))
    for owner in failed:
        log(f"GitHub gave the Worker no new token for {owner}")
    names = [r for t in tokens for r in t["repositories"]]
    log(f"read access to {len(names)} repositories: {' '.join(names) or '(none)'}")
    if uncovered:
        # Public ones need no token. A private one waits for its owner to install the App.
        log(f"no installation covers: {' '.join(uncovered)}")
    return 0


def credential(op: str) -> int:
    if op != "get":
        return 0  # nothing here is git's to store or erase
    want = dict(line.rstrip("\n").split("=", 1) for line in sys.stdin if "=" in line)
    if want.get("protocol") != "https" or want.get("host") != "github.com":
        return 0
    parts = want.get("path", "").strip("/").split("/")
    if len(parts) < 2:
        return 0
    repo = f"{parts[0]}/{parts[1].removesuffix('.git')}".lower()
    now = time.time()
    for t in held().get("tokens", []):
        if good(t, now) and repo in (r.lower() for r in t["repositories"]):
            sys.stdout.write(f"username=x-access-token\npassword={t['token']}\n")
            return 0
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["refresh"]:
        return refresh()
    if argv[:1] == ["credential"] and len(argv) == 2:
        return credential(argv[1])
    print("usage: cluster-github-access refresh | credential get|store|erase", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
