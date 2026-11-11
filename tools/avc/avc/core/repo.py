"""git, as the rest of the tool needs it: what changed, commit, push a branch
for a pull request, and whether the branch pull-deploy follows has what we have."""

from __future__ import annotations

import functools
import re
import time
from dataclasses import dataclass
from pathlib import Path

from avc.core import proc
from avc.errors import AvcError

# Pull-deploy builds topology.deploy.flakeUrl with no ref, i.e. the default
# branch. Only this branch ever reaches a node, and avc never pushes to it: a change
# gets there by a pull request from a branch under PR_PREFIX (avc/core/ship.py).
DEPLOY_BRANCH = "main"
PR_PREFIX = "avc/"


@dataclass(frozen=True)
class Change:
    status: str  # porcelain XY, e.g. " M", "??", "A "
    path: str

    @property
    def untracked(self) -> bool:
        return self.status == "??"


def git(root: Path, *args: str, timeout: float | None = None) -> str:
    return proc.out(["git", *args], cwd=root, timeout=timeout)


def repo_slug(flake_url: str) -> str | None:
    """`owner/repo` of a flake URL: `github:owner/repo[/ref]`, or a
    `git+https://host/owner/repo.git?...` or `git+ssh://` one. None when the
    URL names no such repository (a path, say)."""
    scheme, _, rest = flake_url.partition(":")
    rest = rest.split("?", 1)[0]
    if scheme in ("github", "gitlab", "sourcehut"):
        parts = rest.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    if scheme.startswith("git+"):
        parts = rest.rstrip("/").removesuffix(".git").split("/")
        return "/".join(parts[-2:]) if len(parts) >= 2 else None
    return None


@functools.cache
def deploy_repo(root: Path) -> str | None:
    """The repository the nodes pull (topology.deploy.flakeUrl, through the
    flake's opsIndex). None when it cannot be told, e.g. offline with no eval
    cache: the caller falls back to `origin`."""
    p = proc.run(["nix", "eval", "--raw", ".#opsIndex.flakeUrl"], cwd=root, check=False)
    return repo_slug(p.stdout.strip()) if p.returncode == 0 else None


@functools.cache
def remote(root: Path) -> str:
    """The remote nodes deploy from, whatever it is called in this clone
    (`origin` in a fresh clone, `upstream` in a fork-style setup)."""
    slug = deploy_repo(root)
    if slug:
        for line in git(root, "remote", "-v").splitlines():
            name, url, *_ = line.split()
            if slug.lower() in url.lower().removesuffix(".git"):
                return name
    return "origin"


def slug(root: Path) -> str | None:
    """`owner/repo` of the repository the nodes pull, for the forge's CLI: from
    the flake URL, or failing that from the remote's own URL."""
    found = deploy_repo(root)
    if found:
        return found
    p = proc.run(["git", "remote", "get-url", remote(root)], cwd=root, check=False)
    parts = re.split(r"[/:]", p.stdout.strip().removesuffix(".git"))
    return "/".join(parts[-2:]) if p.returncode == 0 and len(parts) >= 2 else None


def deploy_ref(root: Path) -> str:
    return f"{remote(root)}/{DEPLOY_BRANCH}"


def is_pr_branch(name: str) -> bool:
    return name.startswith(PR_PREFIX)


def pr_branch_name(message: str) -> str:
    """A new branch for one shipped change: sortable, and readable in the forge."""
    words = re.sub(r"[^a-z0-9]+", "-", message.lower()).strip("-")[:40].strip("-")
    return f"{PR_PREFIX}{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{words or 'change'}"


def branch(root: Path) -> str:
    return git(root, "rev-parse", "--abbrev-ref", "HEAD")


def head(root: Path) -> str:
    return git(root, "rev-parse", "HEAD")


def changes(root: Path) -> list[Change]:
    out = proc.run(["git", "status", "--porcelain=v1", "-uall"], cwd=root).stdout
    return [Change(line[:2], line[3:]) for line in out.splitlines() if line]


def fetch(root: Path) -> bool:
    """Best effort: the overview should still render offline."""
    return proc.run(["git", "fetch", "--quiet", remote(root), DEPLOY_BRANCH], cwd=root, check=False, timeout=20).returncode == 0


def ahead_behind(root: Path) -> tuple[int, int]:
    """Commits on HEAD not on the deploy branch, and the reverse."""
    out = proc.run(
        ["git", "rev-list", "--left-right", "--count", f"HEAD...{deploy_ref(root)}"], cwd=root, check=False
    ).stdout.split()
    return (int(out[0]), int(out[1])) if len(out) == 2 else (0, 0)


def diff_stat(root: Path, paths: list[str]) -> str:
    return proc.run(["git", "diff", "HEAD", "--stat", "--", *paths], cwd=root, check=False).stdout


def commit(root: Path, paths: list[str], message: str) -> str:
    # `add -A -- paths` stages deletions as well as edits for exactly these paths.
    proc.run(["git", "add", "-A", "--", *paths], cwd=root)
    proc.run(["git", "commit", "--quiet", "-m", message, "--", *paths], cwd=root)
    return head(root)


def changed_since_fork(root: Path) -> list[str]:
    """The files HEAD's own commits touch: the diff from where it left the
    deploy branch, so what merged there since does not count."""
    base = git(root, "merge-base", "HEAD", deploy_ref(root))
    return [line for line in git(root, "diff", "--name-only", base, "HEAD").splitlines() if line]


def landed(root: Path) -> bool:
    """Whether everything HEAD's commits changed is on the deploy branch, byte
    for byte. True after any kind of merge (merge commit, squash, rebase) and
    false while a local commit is not there yet. Also false if the deploy branch
    has since changed the same files again, which the caller must not read as
    "merged"."""
    paths = changed_since_fork(root)
    if not paths:
        return True
    return proc.run(["git", "diff", "--quiet", "HEAD", deploy_ref(root), "--", *paths], cwd=root, check=False).returncode == 0


def in_pull_request(root: Path, number: int) -> bool | None:
    """Whether HEAD is part of pull request `number` as the forge has it: GitHub
    keeps `refs/pull/N/head` at the pull request's last commit, also once it has
    merged and its branch is gone. Exact where `landed` is a comparison of
    content. None when there is no such ref to fetch."""
    if proc.run(["git", "fetch", "--quiet", remote(root), f"refs/pull/{number}/head"], cwd=root, check=False, timeout=60).returncode != 0:
        return None
    return proc.run(["git", "merge-base", "--is-ancestor", "HEAD", "FETCH_HEAD"], cwd=root, check=False).returncode == 0


def start_pr_branch(root: Path, name: str) -> None:
    """Move to a new branch at HEAD, taking the working tree along, and leave
    the local deploy branch where the remote's is: commits made on it by hand
    travel with the new branch instead of sitting on a branch avc never pushes."""
    was = branch(root)
    proc.run(["git", "switch", "--quiet", "-c", name], cwd=root)
    if was == DEPLOY_BRANCH:
        proc.run(["git", "branch", "--quiet", "-f", DEPLOY_BRANCH, deploy_ref(root)], cwd=root)


def remote_head(root: Path, name: str) -> str | None:
    """The commit `name` is at on the remote, or None when it is not there."""
    out = proc.run(["git", "ls-remote", "--heads", remote(root), name], cwd=root, check=False, timeout=30).stdout.split()
    return out[0] if out else None


def push_branch(root: Path, name: str) -> None:
    """Push HEAD to a pull-request branch. Never to the deploy branch: that is
    the merge gate's to write, and this is the only push avc has."""
    if not is_pr_branch(name):
        raise AvcError(f"refusing to push to {name}: avc only pushes branches under {PR_PREFIX}")
    proc.run(["git", "push", "--quiet", remote(root), f"HEAD:refs/heads/{name}"], cwd=root, timeout=120)


def return_to_deploy_branch(root: Path, name: str) -> None:
    """After `name` has merged: back on the deploy branch at the remote's
    commit, and the merged branch gone here and (best effort) there. One
    checkout straight to the merged commit, so uncommitted work in files the
    merge did not touch comes along."""
    ref = deploy_ref(root)
    if proc.run(["git", "merge-base", "--is-ancestor", DEPLOY_BRANCH, ref], cwd=root, check=False).returncode != 0:
        raise AvcError(
            f"local {DEPLOY_BRANCH} has commits {ref} does not, so it is not moved: put them on a branch of their own "
            f"(`git branch <name> {DEPLOY_BRANCH}`), then `avc deploy ship` again"
        )
    proc.run(["git", "switch", "--quiet", "-C", DEPLOY_BRANCH, ref], cwd=root)
    proc.run(["git", "branch", "--quiet", "-D", name], cwd=root, check=False)
    proc.run(["git", "push", "--quiet", remote(root), "--delete", name], cwd=root, check=False, timeout=60)


def last_change(root: Path, path: str) -> str | None:
    """ISO date of the last commit touching `path` (a secret's age)."""
    out = proc.run(["git", "log", "-1", "--format=%cI", "--", path], cwd=root, check=False).stdout.strip()
    return out or None
