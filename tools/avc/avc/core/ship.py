"""The one way a change reaches the cluster: commit → pull request → merge →
deploy → post-actions.

Every mutating flow ends here instead of printing "now commit, push and wait".
The steps mirror how the cluster really works: a node only ever builds
origin/main (modules/pull-deploy.nix), and nothing reaches origin/main but a
pull request the site's merge gate has passed (templates/cluster/README.md,
"Merging safely"). So avc commits on a branch of its own, pushes that branch,
opens the pull request, asks for auto-merge and waits. It has no push to the
deploy branch at all, and needs no place on a bypass list. "Deployed" is then
checked, not assumed — the node's /run/current-system must equal the toplevel
evaluated from the exact merged commit.

Post-actions (restart a job, revoke an old credential) only run once that is
confirmed. Revoking before the new credential is live is an outage, so a
post-action that cannot run yet is saved to .avc/pending.json and surfaced by
the status overview until it does.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING

from avc import ui
from avc.core import pr, proc, repo
from avc.core.node import HOLD, Node
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

# Paths a flow writes; anything else in the working tree is left unticked when
# choosing what to commit, so a stray scratch file is never swept in.
OPS_PATHS = ("apps/", "vars/", "secrets/", "cluster/", "hosts/", "topology.nix", "machines/", "inventory.json")

# Waiting for a pull request to merge: how often to look, and when to stop looking and
# leave the rest to `avc deploy ship`. An hour covers the gate's boot tests and every
# node's build with room to spare; on a runner that keeps its Nix store, a change that
# leaves flake.lock alone reuses the boot tests' results and is through in minutes.
MERGE_POLL = 15
MERGE_TIMEOUT = 60 * 60


@dataclass(frozen=True)
class PostAction:
    """Something to do on a node once the deploy it depends on is live."""

    node: str
    label: str
    kind: str  # "nomad-restart" (arg = job) | "shell" (arg = command)
    arg: str

    def run(self, ctx: Ctx) -> bool:
        node = ctx.node(self.node)
        p = node.nomad(f"job restart -yes {self.arg}") if self.kind == "nomad-restart" else node.run(self.arg, check=False, timeout=None)
        if p.returncode == 0:
            ui.ok(self.label)
            return True
        ui.err(f"{self.label}: {(p.stderr or p.stdout).strip()}")
        return False


def restart(app_job: str, node: str) -> PostAction:
    return PostAction(node=node, label=f"restart {app_job} on {node}", kind="nomad-restart", arg=app_job)


# ── pending post-actions ─────────────────────────────────────────────────────


def _pending_file(ctx: Ctx):  # noqa: ANN202
    return ctx.state_dir / "pending.json"


def pending(ctx: Ctx) -> list[PostAction]:
    f = _pending_file(ctx)
    if not f.exists():
        return []
    return [PostAction(**p) for p in json.loads(f.read_text())]


def _save_pending(ctx: Ctx, actions: list[PostAction]) -> None:
    f = _pending_file(ctx)
    if actions:
        f.write_text(json.dumps([asdict(a) for a in actions], indent=2) + "\n")
    elif f.exists():
        f.unlink()


def defer(ctx: Ctx, actions: list[PostAction]) -> None:
    current = pending(ctx)
    _save_pending(ctx, current + [a for a in actions if a not in current])


def run_pending(ctx: Ctx) -> None:
    actions = pending(ctx)
    if not actions:
        ui.ok("no pending post-actions")
        return
    left = [a for a in actions if not a.run(ctx)]
    _save_pending(ctx, left)


# ── deploy ───────────────────────────────────────────────────────────────────


def expected_toplevel(ctx: Ctx, node: str, rev: str) -> str:
    """The system a node will build from commit `rev` — evaluated from that
    exact commit, so uncommitted edits in the working tree cannot skew it."""
    url = f"git+file://{ctx.root}?rev={rev}#nixosConfigurations.{node}.config.system.build.toplevel.outPath"
    with ui.spin(f"{node}: evaluating the system for {rev[:8]}"):
        return proc.out(["nix", "eval", "--raw", url], cwd=ctx.root)


def converge(ctx: Ctx, node: Node, rev: str) -> bool:
    """Make `node` run origin/main's `rev` now, and prove it did."""
    h = node.health()
    if not h.reachable:
        ui.err(f"{node.name}: unreachable ({h.error})")
        return False
    if h.automated_holds:
        ui.warn(f"{node.name}: held by {', '.join(h.automated_holds)} (a backup or restore is running) — try again when it finishes")
        return False
    if h.manual_hold:
        ui.warn(f"{node.name}: has a manual break-glass hold ({HOLD})")
        if not ui.confirm("Release it? (only if the break-glass change has merged)"):
            return False
        node.release()

    want = expected_toplevel(ctx, node.name, rev)
    if h.current_system == want:
        ui.ok(f"{node.name}: already running {rev[:8]}")
        return True

    for attempt in (1, 2):
        with ui.spin(f"{node.name}: pulling and switching (cluster-upgrade)"):
            p = node.upgrade()
        if p.returncode != 0:
            ui.err(f"{node.name}: cluster-upgrade failed")
            ui.out(node.journal("cluster-upgrade.service"))
            return False
        if node.current_system() == want:
            ui.ok(f"{node.name}: running {rev[:8]}")
            return True
        if attempt == 1:
            # `nix build --refresh` can still see GitHub's previous archive for
            # a few seconds after a push.
            ui.warn(f"{node.name}: switched, but not to {rev[:8]} yet — GitHub may lag; retrying in 30s")
            time.sleep(30)
    ui.err(f"{node.name}: still not on {rev[:8]}")
    ui.out(node.journal("cluster-upgrade.service"))
    return False


def deploy(ctx: Ctx, nodes: list[str] | None = None) -> bool:
    """Bring every installed node (or `nodes`) to origin/main, now."""
    repo.fetch(ctx.root)
    rev = repo.git(ctx.root, "rev-parse", repo.deploy_ref(ctx.root))
    targets = nodes or ctx.installed
    results = [converge(ctx, ctx.node(n), rev) for n in targets]
    return all(results)


# ── the pipeline ─────────────────────────────────────────────────────────────


def _choose_paths(ctx: Ctx, preselect: list[str] | None) -> list[str]:
    changed = repo.changes(ctx.root)
    if not changed:
        return []

    def ticked(c: repo.Change) -> bool:
        if preselect is not None:
            return any(c.path == p or c.path.startswith(p.rstrip("/") + "/") for p in preselect)
        return not c.untracked or c.path.startswith(OPS_PATHS)

    choices = [(f"{c.status} {c.path}", c.path, ticked(c)) for c in changed]
    if ui.assume_yes:
        return [path for _, path, on in choices if on]
    return ui.checkbox("Include in the commit", choices)


def _nothing_left_behind(ctx: Ctx, found: pr.PullRequest, branch: str) -> None:
    """A merged pull request took everything on `branch` here with it, or this
    raises: the branch is about to be deleted, and a commit made after the merge
    would go with it and never reach a node."""
    root = ctx.root
    if found.head == repo.head(root):
        return
    # The heads differ after the forge brought the branch up to date, which is fine, and
    # after a commit here that the pull request never had, which is not.
    inside = repo.in_pull_request(root, found.number)
    if inside or (inside is None and repo.landed(root)):
        return
    raise AvcError(
        f"{found.url} has merged, but branch {branch} here has a commit it did not have. "
        f"Look at `git diff {repo.deploy_ref(root)} HEAD`. If nothing of yours is missing, "
        f"`git switch {repo.DEPLOY_BRANCH} && git pull --ff-only`; otherwise put what is missing on a new branch off "
        f"{repo.deploy_ref(root)} and `avc deploy ship` again."
    )


def _merged(ctx: Ctx, branch: str) -> bool:
    """Whether the pull request from `branch` has merged, and everything this
    checkout has on that branch went with it."""
    root = ctx.root
    if not repo.ahead_behind(root)[0]:
        return True  # the branch holds nothing the deploy branch lacks
    try:
        found = pr.find(root, branch)
    except pr.Unavailable:
        # No forge to ask. The content on the deploy branch is the evidence.
        return repo.landed(root)
    if found is None or not found.merged:
        return False
    repo.fetch(root)  # it may have merged since the fetch that started this run
    _nothing_left_behind(ctx, found, branch)
    return True


def await_merge(ctx: Ctx, found: pr.PullRequest, branch: str) -> pr.PullRequest | None:
    """Wait for the pull request to merge, and return it merged. None when it is
    not going to by waiting (a red check, a conflict), or the wait ran out or
    was interrupted: in every such case nothing has reached the deploy branch."""
    root = ctx.root
    deadline = time.monotonic() + MERGE_TIMEOUT
    updated: str | None = None
    try:
        with ui.spin(f"waiting for {found.url} to pass the merge gate and merge (Ctrl-C stops waiting, not the merge)"):
            while True:
                now = pr.find(root, branch)
                if now is None:
                    raise AvcError(f"the pull request from {branch} is gone")
                if now.merged:
                    ui.ok(f"merged: {now.url}")
                    return now
                if now.state != "OPEN":
                    raise AvcError(f"{now.url} was closed without merging. Reopen it, or `avc deploy ship` to open another.")
                if now.failed:
                    ui.err(f"{now.url}: failed {', '.join(now.failed)}. Nothing merged. Fix it and `avc deploy ship` again.")
                    return None
                if now.merge_state == "DIRTY":
                    ui.err(f"{now.url} conflicts with {repo.DEPLOY_BRANCH}. Nothing merged. Rebase {branch} and `avc deploy ship` again.")
                    return None
                if now.merge_state == "BEHIND" and updated != now.head:
                    pr.update_branch(root, now.number)
                    updated = now.head
                if time.monotonic() >= deadline:
                    ui.warn(f"{now.url} has not merged after {MERGE_TIMEOUT // 60} minutes")
                    return None
                time.sleep(MERGE_POLL)
    except KeyboardInterrupt:
        ui.warn("stopped waiting; the pull request is still open and merges on its own if auto-merge is on")
        return None


def _propose(ctx: Ctx, branch: str, title: str) -> pr.PullRequest | None:
    """Push `branch`, open its pull request, ask for auto-merge, wait. The pull
    request once it has merged, and None if it has not."""
    root = ctx.root
    if repo.remote_head(root, branch) != repo.head(root):
        ahead = repo.ahead_behind(root)[0]
        if not ui.confirm(
            f"Open a pull request for {ahead} commit(s) into {repo.DEPLOY_BRANCH}? Once it merges, every node applies it within 10 minutes.",
            default=True,
        ):
            ui.warn(f"not pushed; the commit(s) are on branch {branch} — `avc deploy ship` resumes")
            return None
        repo.push_branch(root, branch)
        ui.ok(f"pushed {branch}")
    try:
        found = pr.find(root, branch)
        if found is None or found.state == "CLOSED":
            found = pr.open_(root, branch, title)
            ui.ok(f"opened {found.url}")
        if not found.merged and not found.auto and not pr.request_merge(root, found.number):
            ui.warn(f'could not ask for auto-merge (is "Allow auto-merge" on?): merge {found.url} yourself once its checks pass')
    except pr.Unavailable as e:
        ui.warn(str(e))
        ui.warn(
            f"open a pull request from {branch} into {repo.DEPLOY_BRANCH} yourself; once it has merged, `avc deploy ship` again"
        )
        return None
    return found if found.merged else await_merge(ctx, found, branch)


def _land(ctx: Ctx, message: str, paths: list[str] | None) -> bool | None:
    """Everything up to the merge. True: the deploy branch has the change (now,
    or from an earlier run). False: it does not yet. None: there was nothing to
    land."""
    root = ctx.root
    repo.fetch(root)
    branch = repo.branch(root)
    resumed = False
    if repo.is_pr_branch(branch) and _merged(ctx, branch):
        # An earlier run's pull request merged while nobody was waiting.
        repo.return_to_deploy_branch(root, branch)
        ui.ok(f"{branch} has merged; back on {repo.DEPLOY_BRANCH}")
        branch, resumed = repo.DEPLOY_BRANCH, True

    if branch == repo.DEPLOY_BRANCH and repo.ahead_behind(root)[1]:
        behind = repo.ahead_behind(root)[1]
        raise AvcError(f"{repo.DEPLOY_BRANCH} is {behind} commit(s) behind {repo.deploy_ref(root)} — pull (rebase) first, then `avc deploy ship`")

    selected = _choose_paths(ctx, paths)
    if selected:
        ui.console.print(repo.diff_stat(root, selected) or "  (new files only)")
        message = ui.text("Commit message", default=message) if not ui.assume_yes else message
        if branch == repo.DEPLOY_BRANCH:
            branch = repo.pr_branch_name(message)
            repo.start_pr_branch(root, branch)
        sha = repo.commit(root, selected, message)
        ui.ok(f"committed {sha[:8]} on {branch}  {message}")
    elif branch == repo.DEPLOY_BRANCH and repo.ahead_behind(root)[0]:
        # Commits made on the deploy branch by hand: they go by pull request like the rest.
        branch = repo.pr_branch_name(repo.git(root, "log", "-1", "--format=%s"))
        repo.start_pr_branch(root, branch)
        ui.info(f"moved the unpushed commit(s) from {repo.DEPLOY_BRANCH} to {branch}")

    if repo.is_pr_branch(branch):
        merged = _propose(ctx, branch, repo.git(root, "log", "-1", "--format=%s"))
        if merged is None:
            return False
        repo.fetch(root)
        _nothing_left_behind(ctx, merged, branch)
        repo.return_to_deploy_branch(root, branch)
        return True
    if branch != repo.DEPLOY_BRANCH:
        ui.warn(f"on branch {branch}, not {repo.DEPLOY_BRANCH}: nodes only build {repo.DEPLOY_BRANCH}. Merge it, then `avc deploy ship`.")
        return False
    return True if resumed else None


def ship(
    ctx: Ctx,
    message: str,
    post: list[PostAction] | None = None,
    paths: list[str] | None = None,
) -> bool:
    """Commit what a flow changed, get it merged by pull request, deploy it,
    then run `post`. Returns True once everything, post-actions included, is
    done. Run again (`avc deploy ship`), it picks up wherever the last run
    stopped: a pull request still open, or one that merged since."""
    post = post or []
    ui.header("Ship")
    try:
        landed = _land(ctx, message, paths)
    except AvcError:
        # Whatever stopped it, a post-action is not lost: it waits in .avc/pending.json.
        defer(ctx, post)
        raise
    if landed is False:
        defer(ctx, post)
        if post:
            ui.warn(f"{len(post)} post-action(s) saved; `avc deploy ship` runs them once the change has merged and deployed")
        return False
    if landed is None and not post:
        ui.ok(f"nothing to ship: no changes, and {repo.deploy_ref(ctx.root)} is up to date")
        return True

    now = ui.assume_yes or ui.choose(
        "Deploy",
        [
            ("Now — trigger pull-deploy on each node and wait for it", True),
            ("Later — let the 10-minute timer pick it up", False),
        ],
    )
    if not now:
        defer(ctx, post)
        if post:
            ui.warn(f"{len(post)} post-action(s) saved; run them after the deploy with `avc deploy pending`")
        return False
    if not deploy(ctx):
        defer(ctx, post)
        ui.warn("deploy not confirmed on every node; post-actions saved for `avc deploy pending`")
        return False

    left = [a for a in post if not a.run(ctx)]
    _save_pending(ctx, [a for a in pending(ctx) if a not in post] + left)
    return not left
