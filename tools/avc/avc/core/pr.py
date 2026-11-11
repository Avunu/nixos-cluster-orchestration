"""Pull requests on the repository the nodes pull, through the GitHub CLI.

avc never writes the deploy branch. A change gets there as a pull request that the
site's merge gate has passed (templates/cluster/README.md, "Merging safely"), and this
is the part that opens it, asks for auto-merge and reads how it is doing. Anything gh
cannot do here (no login, a forge that is not GitHub) is `Unavailable`, and the caller
falls back to telling the operator which branch to open a pull request from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from avc.core import proc, repo
from avc.errors import AvcError

# The same method templates/cluster/.github/workflows/flake-update.yml asks for, so a site
# needs one merge method allowed. A squash leaves the branch's commits off the deploy
# branch's history, which is why avc.core.repo.landed compares content, not ancestry.
MERGE_METHOD = "--squash"

# A check that ended like this will not turn green by waiting.
_FAILED = {"FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE"}

_FIELDS = "number,state,url,headRefOid,mergeStateStatus,autoMergeRequest,statusCheckRollup"


class Unavailable(AvcError):
    """gh cannot work with this repository."""


@dataclass(frozen=True)
class PullRequest:
    number: int
    state: str  # OPEN | MERGED | CLOSED
    url: str
    head: str  # the commit the pull request is at
    merge_state: str  # GitHub's mergeStateStatus: BEHIND, BLOCKED, CLEAN, DIRTY, ...
    failed: tuple[str, ...]  # checks that ended red
    auto: bool = False  # auto-merge already asked for

    @property
    def merged(self) -> bool:
        return self.state == "MERGED"


def _gh(root: Path, *args: str, check: bool = True) -> str:
    target = repo.slug(root)
    if not target:
        raise Unavailable("cannot tell which repository the nodes pull, so no pull request can be opened in it")
    try:
        p = proc.run(["gh", *args, "--repo", target], cwd=root, check=False, timeout=60)
    except AvcError as e:  # gh missing, or it hung
        raise Unavailable(str(e)) from e
    if p.returncode != 0:
        detail = (p.stderr or p.stdout).strip()
        if check:
            raise Unavailable(f"gh {' '.join(args[:2])} failed ({p.returncode}): {detail}")
        return ""
    return p.stdout.strip()


def _failed(rollup: list[dict]) -> tuple[str, ...]:
    # Check runs carry `conclusion`, commit statuses carry `state`.
    return tuple(
        str(c.get("name") or c.get("context") or "?")
        for c in rollup or []
        if (c.get("conclusion") or c.get("state") or "").upper() in _FAILED
    )


def find(root: Path, branch: str) -> PullRequest | None:
    """The newest pull request from `branch`, in any state, or None."""
    found = json.loads(_gh(root, "pr", "list", "--head", branch, "--state", "all", "--limit", "1", "--json", _FIELDS) or "[]")
    if not found:
        return None
    d = found[0]
    return PullRequest(
        number=d["number"],
        state=d["state"],
        url=d["url"],
        head=d["headRefOid"],
        merge_state=d.get("mergeStateStatus") or "",
        failed=_failed(d.get("statusCheckRollup") or []),
        auto=bool(d.get("autoMergeRequest")),
    )


def open_(root: Path, branch: str, title: str) -> PullRequest:
    body = "Opened by `avc`. It merges once the merge gate passes, and the nodes apply it within their pull interval."
    _gh(root, "pr", "create", "--base", repo.DEPLOY_BRANCH, "--head", branch, "--title", title, "--body", body)
    created = find(root, branch)
    if created is None:
        raise Unavailable(f"opened a pull request from {branch}, but cannot find it")
    return created


def request_merge(root: Path, number: int) -> bool:
    """Ask for auto-merge: GitHub merges once the required checks pass, and never
    on a red or skipped run. False when it would not take the request (auto-merge
    not allowed in the repository's settings, say)."""
    try:
        _gh(root, "pr", "merge", str(number), "--auto", MERGE_METHOD)
    except Unavailable:
        return False
    return True


def update_branch(root: Path, number: int) -> None:
    """Bring the pull request up to date with the deploy branch (required when
    the protection asks for it and something else merged first). Best effort."""
    _gh(root, "pr", "update-branch", str(number), check=False)
