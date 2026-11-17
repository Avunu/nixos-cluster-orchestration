"""Pipeline: what the cluster-ci Worker needs from the site (modules/ci-agent.nix,
modules/github-access.nix, workers/cluster-ci), and who has installed the GitHub App.

Everything the Worker is given is printed here and pushed by `wrangler secret put`,
which reads it on stdin: avc holds no Cloudflare credential for it.

  tokens          AGENT_TOKENS, from every node's own `ci/token`. One YubiKey touch per
                  node: each token is a file of its own.
  app <value>     one of the GitHub App's values (`github-app`, modules/vars.nix):
                  `private-key` and `webhook-secret` are one touch each, `app-id` is
                  public and costs none.
  repos           writes github-repos.json, the repositories the site fetches that its
                  flake.lock does not name, from the flake's own account of them
                  (lib/github-repos.nix). No touch. The merge gate holds the file to it.
  installations   who has installed the App, and which of the site's repositories no
                  installation covers: what onboarding an app from another organization
                  waits for. Signs in as the App with its private key, here, on the
                  operator's machine: one touch. Asks GitHub and changes nothing.

A node never holds the App's key. It asks the Worker, which hands it read-only tokens
for the repositories this module lists as covered.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

from avc import ui
from avc.actions import Arg, action
from avc.core import secretstore
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

APP_VALUES = ("app-id", "private-key", "webhook-secret")
REPOS_FILE = "github-repos.json"
# Where GitHub's API is. The tests stand it in.
API_ENV = "AVC_GITHUB_API"

_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_URL = re.compile(r"^(?:git\+)?(?:https|ssh|git)://(?:[^@/]+@)?(?:github\.com|api\.github\.com/repos)/([^/?#]+)/([^/?#]+)")
_SCP = re.compile(r"^(?:[^@/]+@)?github\.com:([^/?#]+)/([^/?#]+)")


def agent_tokens(ctx: Ctx) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, node in sorted(ctx.index.nodes.items()):
        if not (node.get("ci") or {}).get("enabled"):
            continue
        token = secretstore.get_value(ctx.root, name, "ci/token").strip()
        if not token:
            raise AvcError(f"{name}: ci/token is empty; run `avc secrets provision`")
        if token in out:
            raise AvcError(f"{name} and {out[token]} have the same ci/token")
        out[token] = name
    if not out:
        raise AvcError("no node runs the pipeline's agent: topology.ci.url is not set")
    return out


@action("ci", "tokens", "Print AGENT_TOKENS for the cluster-ci Worker")
def tokens(ctx: Ctx) -> None:
    ui.out(json.dumps(agent_tokens(ctx), sort_keys=True))


def app_value(ctx: Ctx, value: str) -> str:
    if value not in APP_VALUES:
        raise AvcError(f"the GitHub App has no {value!r}: one of {', '.join(APP_VALUES)}")
    got = secretstore.get_value(ctx.root, ctx.index.reference, f"github-app/{value}").strip()
    if not got:
        raise AvcError(f"github-app/{value} is empty; run `avc secrets provision`")
    return got


@action(
    "ci",
    "app",
    "Print one of the GitHub App's values for the cluster-ci Worker",
    Arg("value", "Which value", choices=lambda ctx: list(APP_VALUES)),
)
def app(ctx: Ctx, value: str) -> None:
    ui.out(app_value(ctx, value))


# ── which repositories the site uses ─────────────────────────────────────────
# The same reading as the Worker's (workers/cluster-ci/src/access.js, siteRepos); both
# are held to workers/cluster-ci/test/site-repos.json.


def _named(owner: Any, repo: Any) -> str | None:
    if not isinstance(owner, str) or not isinstance(repo, str):
        return None
    repo = repo.removesuffix(".git")
    if not _NAME.match(owner) or not _NAME.match(repo) or repo in (".", ".."):
        return None
    return f"{owner}/{repo}"


def github_repo(ref: Any) -> str | None:
    """The github.com repository a lock node's `locked` or `original` names, or None."""
    if not isinstance(ref, dict):
        return None
    if ref.get("type") == "github":
        return _named(ref.get("owner"), ref.get("repo")) if ref.get("host", "github.com") == "github.com" else None
    if ref.get("type") not in ("git", "tarball"):
        return None
    url = ref.get("url") or ""
    m = _URL.match(url) or _SCP.match(url)
    return _named(m.group(1), m.group(2)) if m else None


def site_repos(site: str, lock: dict[str, Any], extra: list[Any]) -> list[str]:
    out: dict[str, str] = {}

    def add(name: str | None) -> None:
        if name and name.lower() not in out:
            out[name.lower()] = name

    add(_named(*site.split("/")) if site.count("/") == 1 else None)
    for node in (lock.get("nodes") or {}).values():
        add(github_repo(node.get("locked")))
        add(github_repo(node.get("original")))
    for name in extra:
        if isinstance(name, str) and name.count("/") == 1:
            add(_named(*name.split("/")))
    return sorted(out.values(), key=str.lower)


def site_of(flake_url: str) -> str:
    m = re.match(r"^github:([^/?#]+)/([^/?#]+)", flake_url)
    if not m:
        raise AvcError(f"deploy.flakeUrl is {flake_url!r}: the cluster-ci Worker reads a site at github:OWNER/name")
    return f"{m.group(1)}/{m.group(2)}"


def committed_repos(ctx: Ctx) -> list[str]:
    path = ctx.root / REPOS_FILE
    return sorted(json.loads(path.read_text())) if path.exists() else []


@action("ci", "repos", f"Write {REPOS_FILE}: what the site fetches from GitHub outside flake.lock")
def repos(ctx: Ctx) -> None:
    want = sorted(ctx.index.github_repos)
    path = ctx.root / REPOS_FILE
    if committed_repos(ctx) == want:
        ui.ok(f"{REPOS_FILE} is current: {', '.join(want) or 'nothing outside the lock'}")
        return
    if want:
        path.write_text(json.dumps(want, indent=2) + "\n")
    else:
        path.unlink()
    ui.ok(f"{REPOS_FILE}: {', '.join(want) or 'removed, nothing outside the lock'}")
    ui.say("Commit it with the change that needs it (`git add`, then `avc deploy ship`): the merge gate")
    ui.say("holds it to the flake, and the Worker reads it from the deploy branch once that has merged.")


# ── the App, asked from here ─────────────────────────────────────────────────


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def app_jwt(app_id: str, private_key: str, now: float | None = None) -> str:
    """The App's own sign-in: RS256, good for nine minutes, issued a minute ago for a
    clock that runs ahead of GitHub's."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    at = int(now if now is not None else time.time())
    signed = ".".join(
        _b64(json.dumps(part, separators=(",", ":")).encode())
        for part in ({"alg": "RS256", "typ": "JWT"}, {"iat": at - 60, "exp": at + 540, "iss": str(app_id)})
    )
    try:
        key = serialization.load_pem_private_key(private_key.encode(), password=None)
    except (ValueError, TypeError) as e:
        raise AvcError("github-app/private-key is not a PEM private key: paste the .pem as GitHub downloads it") from e
    return f"{signed}.{_b64(key.sign(signed.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


def github(jwt: str, path: str) -> Any:
    """GET one path as the App. None for 404."""
    base = os.environ.get(API_ENV, "https://api.github.com").rstrip("/")
    req = urllib.request.Request(
        base + path,
        headers={
            "Authorization": f"Bearer {jwt}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "avc",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.load(res)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise AvcError(f"GitHub GET {path}: HTTP {e.code} {e.read(200).decode(errors='replace')}") from e
    except OSError as e:
        raise AvcError(f"GitHub GET {path}: {e}") from e


def coverage(ctx: Ctx) -> dict[str, Any]:
    """Who has installed the App, and for each repository the site uses, whether an
    installation covers it. One decryption: the private key."""
    site = site_of(ctx.index.flake_url)
    lock_file = ctx.root / "flake.lock"
    lock = json.loads(lock_file.read_text()) if lock_file.exists() else {}
    wanted = site_repos(site, lock, list(ctx.index.github_repos))
    jwt = app_jwt(app_value(ctx, "app-id"), app_value(ctx, "private-key"))
    me = github(jwt, "/app")
    if me is None:
        raise AvcError("GitHub knows no App by this id and key: check github-app/app-id")
    installs: list[dict[str, Any]] = []
    page = 1
    while True:
        got = github(jwt, f"/app/installations?per_page=100&page={page}") or []
        installs += got
        if len(got) < 100:
            break
        page += 1
    by_owner = {(i.get("account") or {}).get("login", "").lower(): i for i in installs}
    rows = []
    for repo in wanted:
        inst = by_owner.get(repo.split("/")[0].lower())
        if inst is None:
            state = "no installation"
        elif inst.get("suspended_at"):
            state = "suspended"
        elif github(jwt, f"/repos/{repo}/installation") is None:
            state = "not selected"
        else:
            state = "covered"
        rows.append((repo, state))
    used = {r.split("/")[0].lower() for r in wanted}
    return {
        "app": {"slug": me.get("slug", ""), "name": me.get("name", ""), "url": me.get("html_url", "")},
        "installations": [
            {
                "account": (i.get("account") or {}).get("login", ""),
                "id": i.get("id"),
                "selection": i.get("repository_selection", ""),
                "suspended": bool(i.get("suspended_at")),
                "used": (i.get("account") or {}).get("login", "").lower() in used,
            }
            for i in sorted(installs, key=lambda i: (i.get("account") or {}).get("login", "").lower())
        ],
        "repositories": rows,
    }


_MEANS = {
    "covered": "the nodes are given read access",
    "no installation": "its owner has not installed the App. Public: nothing to do",
    "not selected": "its owner installed the App on other repositories only",
    "suspended": "its owner suspended the App",
}


@action("ci", "installations", "Who installed the GitHub App, and which of the site's repositories are not covered")
def installations(ctx: Ctx) -> None:
    if committed_repos(ctx) != sorted(ctx.index.github_repos):
        ui.warn(f"{REPOS_FILE} is not what the flake says: run `avc ci repos`. The Worker reads the committed file.")
    got = coverage(ctx)
    ui.table(
        f"Installations of {got['app']['name'] or got['app']['slug']}",
        ["Account", "Repositories", "Id", ""],
        [
            [
                i["account"],
                i["selection"],
                str(i["id"]),
                ("suspended" if i["suspended"] else "") if i["used"] else "not this site's: the Worker gives it nothing",
            ]
            for i in got["installations"]
        ],
    )
    ui.table("The site's repositories", ["Repository", "", ""], [[r, s, _MEANS[s]] for r, s in got["repositories"]])
    waiting = [r for r, s in got["repositories"] if s != "covered"]
    if waiting:
        ui.say("A private repository that is not covered cannot be fetched by a node. Its owner installs the App at")
        ui.say(f"{got['app']['url'] or 'https://github.com/apps/<the app>'}/installations/new and selects it.")
