"""The overview: everything that answers "where are things?" on one screen.

`quick` is what the menu shows on every return: git, nodes (one ssh round
trip each, in parallel) and what is pending. `full` adds what costs an eval —
whether each node runs origin/main, and whether its secrets are generated and rekeyed.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

from avc import ui
from avc.actions import Arg, action
from avc.core import repo, secretstore, ship
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx
    from avc.core.node import Health


def _git(ctx: Ctx) -> None:
    root = ctx.root
    online = repo.fetch(root)
    ahead, behind = repo.ahead_behind(root)
    changed = repo.changes(root)
    parts = [f"branch [bold]{repo.branch(root)}[/]"]
    parts.append(f"{len(changed)} uncommitted" if changed else "clean")
    if ahead and repo.is_pr_branch(repo.branch(root)):
        parts.append(f"[yellow]{ahead} commit(s) waiting on a pull request (`avc deploy ship` resumes)[/]")
    elif ahead:
        parts.append(f"[yellow]{ahead} unpushed[/]")
    if behind:
        parts.append(f"[yellow]{behind} behind {repo.deploy_ref(root)}[/]")
    if not online:
        parts.append(f"[dim](offline: {repo.remote(root)} not fetched)[/]")
    ui.console.print("[bold]repo[/]   " + " · ".join(parts))


def _health_row(name: str, h: Health) -> list[str]:
    if not h.reachable:
        return [name, "[red]unreachable[/]", h.error, "", ""]
    holds = []
    if h.manual_hold:
        holds.append("[yellow]manual[/]")
    holds += [f"[yellow]{x}[/]" for x in h.automated_holds]
    last = "[cyan]running[/]" if h.upgrade_active else (
        "[green]ok[/]" if h.upgrade_result == "success" else f"[red]{h.upgrade_result or '?'}[/]"
    )
    failed = f"[red]{' '.join(h.failed_units)}[/]" if h.failed_units else "[green]none[/]"
    return [name, "[green]up[/]", f"{last} {h.upgrade_finished}", " ".join(holds) or "none", failed]


def _nodes(ctx: Ctx) -> dict[str, Health]:
    nodes = ctx.installed_nodes()
    with ThreadPoolExecutor(max_workers=max(1, len(nodes))) as pool:
        healths = dict(zip([n.name for n in nodes], pool.map(lambda n: n.health(), nodes)))
    ui.table(
        None,
        ["node", "ssh", "last pull-deploy", "holds", "failed units"],
        [_health_row(n, h) for n, h in healths.items()],
    )
    return healths


def _pending(ctx: Ctx) -> None:
    for a in ship.pending(ctx):
        ui.warn(f"pending post-action: {a.label}  (`avc deploy pending`)")
    state = ctx.root / ".site-provisioner"
    for f in sorted(state.glob("*.state.json")) if state.exists() else []:
        try:
            steps = json.loads(f.read_text()).get("steps", {})
        except json.JSONDecodeError:
            continue
        slug = f.name.removesuffix(".state.json")
        app = ctx.index.apps.get(slug)
        if app is None or not app.tunnel:
            ui.warn(f"site {slug}: provisioning in progress ({len(steps)} steps done) — `avc site status {slug}`")


def _hygiene(ctx: Ctx) -> None:
    """Leftovers the README says should go, surfaced rather than removed."""
    if (ctx.root / "tmp" / "cloud-storage.json").exists():
        ui.warn("tmp/cloud-storage.json holds plaintext S3 credentials — delete it once they are stored (`avc secrets set`)")


def quick(ctx: Ctx) -> None:
    ui.header("cluster")
    _git(ctx)
    _nodes(ctx)
    _pending(ctx)
    _hygiene(ctx)


def _converged(ctx: Ctx, healths: dict[str, Health]) -> None:
    rev = repo.git(ctx.root, "rev-parse", repo.deploy_ref(ctx.root))
    for name, h in healths.items():
        if not h.reachable:
            continue
        want = ship.expected_toplevel(ctx, name, rev)
        if h.current_system == want:
            ui.ok(f"{name}: running {repo.deploy_ref(ctx.root)} ({rev[:8]})")
        else:
            ui.warn(f"{name}: NOT on {repo.deploy_ref(ctx.root)} {rev[:8]} — `avc deploy now`, or wait for the timer")


def _secrets(ctx: Ctx) -> None:
    for name in ctx.installed:
        with ui.spin(f"{name}: checking secrets"):
            try:
                s = secretstore.status(ctx.root, name)
                r = secretstore.readiness(ctx.root, name)
            except AvcError as e:
                ui.err(str(e))
                continue
        if s.clean and r.ok:
            ui.ok(f"{name}: every secret is generated, current and rekeyed")
        for v in s.missing:
            ui.warn(f"{name}: missing {v}  (`avc secrets provision`)")
        if s.unfixed:
            ui.warn(f"{name}: {len(s.unfixed)} secret(s) need re-encryption  (master recipients changed; `avc secrets fix`)")
        for g in s.outdated:
            ui.warn(f"{name}: outdated generator {g}  (what it is made from changed; `avc secrets provision`)")
        for v in r.unrekeyed:
            ui.warn(f"{name}: {v} is not rekeyed for it  (`avc secrets rekey`)")


@action("status", "show", "Overview (repo, nodes, pending work)", Arg("full", "Also check deploy convergence and secrets", flag=True))
def show(ctx: Ctx, full: bool) -> None:
    ui.header("cluster")
    _git(ctx)
    healths = _nodes(ctx)
    if full:
        _converged(ctx, healths)
        _secrets(ctx)
    _pending(ctx)
    _hygiene(ctx)


@action("status", "full", "Full check (+ convergence with origin/main, secrets)")
def full(ctx: Ctx) -> None:
    show(ctx, full=True)
