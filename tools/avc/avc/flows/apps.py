"""Apps: what runs where, and the everyday operations on one app — status,
logs, restart, backup, restore — without knowing which node Nomad put it on,
which job name, or the nomad ACL incantation."""

from __future__ import annotations

import json
import shlex
from typing import TYPE_CHECKING

from avc import ui
from avc.actions import Arg, action
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx
    from avc.core.node import Node


def app_names(ctx: Ctx) -> list[str]:
    return sorted(ctx.index.apps)


def _app(ctx: Ctx, app: str):  # noqa: ANN202
    a = ctx.index.apps.get(app)
    if a is None:
        raise AvcError(f"unknown app {app!r}")
    return a


def _any(ctx: Ctx, app: str) -> Node:
    """A node to ask Nomad about the app: any would do."""
    _app(ctx, app)
    return ctx.node(ctx.index.leader)


def running_nodes(allocs_json: str) -> list[str]:
    """The nodes with a running allocation, from `nomad job allocs -json`."""
    try:
        allocs = json.loads(allocs_json or "[]")
    except ValueError:
        return []
    return sorted({a["NodeName"] for a in allocs or [] if a.get("ClientStatus") == "running" and a.get("NodeName")})


def placement(ctx: Ctx, app: str) -> list[str]:
    p = _any(ctx, app).nomad(f"job allocs -json {_app(ctx, app).job}")
    return [n for n in running_nodes(p.stdout) if n in ctx.index.nodes]


def _where(ctx: Ctx, app: str, *, or_any: bool = False) -> Node:
    """The node the app is running on: Nomad's choice, asked of Nomad each time."""
    nodes = placement(ctx, app)
    if nodes:
        return ctx.node(nodes[0])
    if or_any:
        ui.info(f"{app} is not running on any node; using {ctx.index.leader}")
        return ctx.node(ctx.index.leader)
    raise AvcError(f"{app} is not running on any node (`avc app status {app}`)")


@action("app", "list", "List apps")
def list_apps(ctx: Ctx) -> None:
    rows = [
        [a.name, a.kind or "-", ", ".join(placement(ctx, a.name)) or "-", ", ".join(a.hostnames) or "-", "yes" if a.tunnel else "[yellow]no[/]"]
        for a in sorted(ctx.index.apps.values(), key=lambda a: a.name)
    ]
    ui.table("apps", ["app", "kind", "running on", "hostnames", "tunnel"], rows)


@action("app", "status", "Job status", Arg("app", "App", choices=app_names))
def status(ctx: Ctx, app: str) -> None:
    p = _any(ctx, app).nomad(f"job status {ctx.index.apps[app].job}")
    ui.out(p.stdout or p.stderr)


@action("app", "logs", "Recent logs", Arg("app", "App", choices=app_names), Arg("follow", "Follow", flag=True))
def logs(ctx: Ctx, app: str, follow: bool) -> None:
    # The container's own journal (machine name == app name), which is where
    # the app, its tunnel and its units log.
    cmd = f"journalctl -M {shlex.quote(app)} --no-pager " + ("-f" if follow else "-n 200")
    _where(ctx, app).stream(cmd)


@action("app", "restart", "Restart (nomad job restart)", Arg("app", "App", choices=app_names))
def restart(ctx: Ctx, app: str) -> None:
    job = ctx.index.apps[app].job
    if not ui.confirm(f"Restart {job}? The site is briefly down while its container restarts."):
        return
    node = _any(ctx, app)
    with ui.spin(f"restarting {job}"):
        p = node.nomad(f"job restart -yes {job}", timeout=600)
    if p.returncode != 0:
        raise AvcError((p.stderr or p.stdout).strip())
    ui.ok(f"{job} restarted")


@action("app", "backup", "Back up now", Arg("app", "App", choices=app_names))
def backup(ctx: Ctx, app: str) -> None:
    rc = _where(ctx, app).stream(f"cluster-backup {shlex.quote(app)}")
    (ui.ok if rc == 0 else ui.err)(f"backup of {app} {'done' if rc == 0 else f'failed ({rc})'}")


@action("app", "snapshots", "List backup snapshots", Arg("app", "App", choices=app_names))
def snapshots(ctx: Ctx, app: str) -> None:
    _any(ctx, app).stream(f"cluster-backup-list {shlex.quote(app)}")


@action(
    "app",
    "restore",
    "Restore from a backup",
    Arg("app", "App", choices=app_names),
    Arg("snapshot", "Snapshot ID (blank = latest)", optional=True),
)
def restore(ctx: Ctx, app: str, snapshot: str | None) -> None:
    # A stopped app is restored on any node, which takes its state for the duration.
    node = _where(ctx, app, or_any=True)
    if snapshot is None and not ui.assume_yes:
        snapshot = ui.text("Snapshot ID (blank = latest; see `avc app snapshots`)") or None
    scope = ui.choose(
        "What to restore",
        [("Database and files", ""), ("Database only", "--db-only"), ("Files only", "--files-only")],
    ) if not ui.assume_yes else ""
    args = [shlex.quote(app)] + ([f"--snapshot {shlex.quote(snapshot)}"] if snapshot else []) + ([scope] if scope else [])
    # Without --yes, cluster-restore prints its plan and touches nothing.
    ui.header("Restore plan")
    node.stream("cluster-restore " + " ".join(args))
    ui.type_to_confirm(f"This overwrites {app}'s live data on {node.name}", app)
    rc = node.stream("cluster-restore " + " ".join([*args, "--yes"]))
    (ui.ok if rc == 0 else ui.err)(f"restore of {app} {'done' if rc == 0 else f'failed ({rc})'}")
