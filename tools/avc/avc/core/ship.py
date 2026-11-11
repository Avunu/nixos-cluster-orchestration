"""The one way a change reaches the cluster: commit → push → deploy →
post-actions.

Every mutating flow ends here instead of printing "now commit, push and wait".
The steps mirror how the cluster really works: a node only ever builds
origin/main (modules/pull-deploy.nix), so "deployed" is checked, not assumed —
the node's /run/current-system must equal the toplevel evaluated from the
exact pushed commit.

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
from avc.core import proc, repo
from avc.core.node import HOLD, Node
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

# Paths a flow writes; anything else in the working tree is left unticked when
# choosing what to commit, so a stray scratch file is never swept in.
OPS_PATHS = ("apps/", "vars/", "secrets/", "cluster/", "hosts/", "topology.nix", "machines/", "inventory.json")

# What avc never pushes straight to the deploy branch: the lock and the inputs, which is
# where a nixpkgs, kernel, clan, Lanzaboote or library bump comes from. Those reach main
# only through a pull request and the site's merge gate (templates/cluster/README.md,
# "Merging safely"). Everything else avc ships (vars, secrets, topology, apps, a
# break-glass fix) is pushed directly, by an operator the branch protection lets bypass
# the pull-request rule: a rotation or a fix at 3am must not wait twenty minutes behind a
# runner that may be down.
GATED_PATHS = ("flake.lock", "flake.nix")


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
        if not ui.confirm("Release it? (only if the break-glass change has been pushed)"):
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


def ship(
    ctx: Ctx,
    message: str,
    post: list[PostAction] | None = None,
    paths: list[str] | None = None,
) -> bool:
    """Commit what a flow changed, push it, deploy it, then run `post`.
    Returns True once everything, post-actions included, is done."""
    post = post or []
    ui.header("Ship")
    root = ctx.root

    selected = _choose_paths(ctx, paths)
    if selected:
        ui.console.print(repo.diff_stat(root, selected) or "  (new files only)")
        message = ui.text("Commit message", default=message) if not ui.assume_yes else message
        sha = repo.commit(root, selected, message)
        ui.ok(f"committed {sha[:8]}  {message}")

    branch = repo.branch(root)
    repo.fetch(root)
    ahead, behind = repo.ahead_behind(root)
    if branch != repo.DEPLOY_BRANCH:
        ui.warn(f"on branch {branch}, not {repo.DEPLOY_BRANCH}: nodes only build {repo.DEPLOY_BRANCH}. Merge it, then `avc deploy ship`.")
        defer(ctx, post)
        return False
    if behind:
        raise AvcError(f"{repo.DEPLOY_BRANCH} is {behind} commit(s) behind {repo.deploy_ref(root)} — pull (rebase) first, then `avc deploy ship`")
    if ahead:
        gated = [p for p in repo.outgoing_paths(root) if p in GATED_PATHS]
        if gated:
            defer(ctx, post)
            raise AvcError(
                f"{', '.join(gated)} changed: the lock and the inputs reach {repo.DEPLOY_BRANCH} only through a pull "
                "request and the merge gate, never a direct push. Push a branch "
                f"(`git push {repo.remote(root)} HEAD:refs/heads/<branch>`), open a pull request, and once it has merged, "
                f"`git pull --rebase` and `avc deploy ship`. Post-actions are saved."
            )
        if not ui.confirm(f"Push {ahead} commit(s) to {repo.deploy_ref(root)}? Every node applies it within 10 minutes.", default=True):
            defer(ctx, post)
            ui.warn("not pushed; post-actions saved — `avc deploy ship` resumes")
            return False
        repo.push(root)
        ui.ok(f"pushed to {repo.deploy_ref(root)}")
    elif not selected and not post:
        ui.ok(f"nothing to ship: no changes, and {repo.deploy_ref(root)} is up to date")
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
    defer(ctx, left)
    return not left
