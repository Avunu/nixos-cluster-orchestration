"""Deploy: ship pending changes, force a pull, holds, and break-glass push."""

from __future__ import annotations

from typing import TYPE_CHECKING

from avc import ui
from avc.actions import Arg, action
from avc.core import proc, repo, ship
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx


def _nodes(ctx: Ctx) -> list[str]:
    return ctx.installed


@action("deploy", "ship", "Ship changes (commit → pull request → merge → deploy → post-actions)")
def ship_changes(ctx: Ctx) -> None:
    ship.ship(ctx, "chore: update cluster configuration", post=ship.pending(ctx))


@action("deploy", "now", "Deploy origin/main now (trigger pull-deploy, wait, verify)")
def now(ctx: Ctx) -> None:
    if ship.deploy(ctx):
        ui.ok("every node runs origin/main")


@action("deploy", "pending", "Run pending post-actions")
def pending(ctx: Ctx) -> None:
    ship.run_pending(ctx)


@action("deploy", "watch", "Follow a node's pull-deploy log", Arg("node", "Node", choices=_nodes))
def watch(ctx: Ctx, node: str) -> None:
    ui.say("Ctrl-C to stop")
    ctx.node(node).stream("journalctl -fu cluster-upgrade.service")


@action("deploy", "hold", "Hold pull-deploys on a node", Arg("node", "Node", choices=_nodes))
def hold(ctx: Ctx, node: str) -> None:
    ctx.node(node).hold()
    ui.ok(f"{node}: held — clears on reboot, or `avc deploy release {node}`")


@action("deploy", "release", "Release a node's manual hold", Arg("node", "Node", choices=_nodes))
def release(ctx: Ctx, node: str) -> None:
    ctx.node(node).release()
    ui.ok(f"{node}: released")


@action("deploy", "retry", "Clear a node's failed attempts so the next pull-deploy tries again", Arg("node", "Node", choices=_nodes))
def retry(ctx: Ctx, node: str) -> None:
    ctx.node(node).deploy_retry()
    ui.ok(f"{node}: attempts cleared — the next tick tries again, or `avc deploy now`")


@action("deploy", "break-glass", "Break-glass push from this working tree", Arg("node", "Node", choices=_nodes))
def break_glass(ctx: Ctx, node: str) -> None:
    """README "break-glass": hold → clan machines update → pull request → release.

    The hold stops the timer from reverting the pushed build to what the deploy
    branch has; it is only released once the same change has merged there, so
    the next pull builds the same thing."""
    ui.header(f"Break-glass deploy to {node}")
    ui.warn("this builds the WORKING TREE (uncommitted edits included) and activates it directly")
    if not ui.confirm(f"Hold {node}, then `clan machines update {node}`?"):
        return
    n = ctx.node(node)
    n.hold()
    ui.ok(f"{node}: held")
    rc = proc.run(["clan", "machines", "update", node], cwd=ctx.root, check=False, capture=False).returncode
    if rc != 0:
        ui.err(f"clan machines update failed ({rc}); {node} stays HELD so the timer cannot revert a partial state")
        ui.say(f"fix and re-run, or `avc deploy release {node}` to go back to pull-deploy")
        return
    ui.ok(f"{node}: updated")
    ui.info("now get the same change merged, so the timer builds what is running")
    try:
        shipped = ship.ship(ctx, "fix: break-glass change", paths=None)
    except AvcError:
        # The pull request was closed, say: the timer would revert the build until main
        # has the change, so the hold stays.
        ui.warn(f"{node}: still held; release it once main has the change (`avc deploy release {node}`)")
        raise
    if shipped or (repo.branch(ctx.root) == repo.DEPLOY_BRANCH and repo.ahead_behind(ctx.root)[0] == 0):
        n.release()
        ui.ok(f"{node}: hold released — pull-deploy resumes")
    else:
        ui.warn(
            f"{node}: still held, so the timer cannot revert it while the pull request is open. `avc deploy ship` once it "
            f"has merged, then `avc deploy release {node}`. A hold does not survive a reboot."
        )
