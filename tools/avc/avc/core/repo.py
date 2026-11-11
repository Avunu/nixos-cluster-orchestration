"""git, as the rest of the tool needs it: what changed, commit, push, and
whether the branch pull-deploy follows has what we have."""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path

from avc.core import proc

# Pull-deploy builds topology.deploy.flakeUrl with no ref, i.e. the default
# branch. Only this branch ever reaches a node.
DEPLOY_BRANCH = "main"


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


def deploy_ref(root: Path) -> str:
    return f"{remote(root)}/{DEPLOY_BRANCH}"


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


def outgoing_paths(root: Path) -> list[str]:
    """The files a push of HEAD would change on the deploy branch."""
    out = git(root, "diff", "--name-only", deploy_ref(root), "HEAD")
    return [line for line in out.splitlines() if line]


def push(root: Path) -> None:
    proc.run(["git", "push", "--quiet", remote(root), f"HEAD:{DEPLOY_BRANCH}"], cwd=root, timeout=120)


def last_change(root: Path, path: str) -> str | None:
    """ISO date of the last commit touching `path` (a secret's age)."""
    out = proc.run(["git", "log", "-1", "--format=%cI", "--", path], cwd=root, check=False).stdout.strip()
    return out or None
