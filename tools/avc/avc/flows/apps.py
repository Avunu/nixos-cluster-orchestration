"""Apps: what runs where, and the everyday operations on one app — status,
logs, restart, backup, restore — without remembering which node, which job
name, or the nomad ACL incantation."""

from __future__ import annotations

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


def _home(ctx: Ctx, app: str) -> Node:
    a = ctx.index.apps.get(app)
    if a is None:
        raise AvcError(f"unknown app {app!r}")
    node = a.home_node or ctx.index.leader
    return ctx.node(node)


@action("app", "list", "List apps")
def list_apps(ctx: Ctx) -> None:
    rows = [
        [a.name, a.kind or "-", a.home_node or "-", ", ".join(a.hostnames) or "-", "yes" if a.tunnel else "[yellow]no[/]"]
        for a in sorted(ctx.index.apps.values(), key=lambda a: a.name)
    ]
    ui.table("apps", ["app", "kind", "home", "hostnames", "tunnel"], rows)


@action("app", "status", "Job status", Arg("app", "App", choices=app_names))
def status(ctx: Ctx, app: str) -> None:
    p = _home(ctx, app).nomad(f"job status {ctx.index.apps[app].job}")
    ui.out(p.stdout or p.stderr)


@action("app", "logs", "Recent logs", Arg("app", "App", choices=app_names), Arg("follow", "Follow", flag=True))
def logs(ctx: Ctx, app: str, follow: bool) -> None:
    # The container's own journal (machine name == app name), which is where
    # the app, its tunnel and its units log.
    cmd = f"journalctl -M {shlex.quote(app)} --no-pager " + ("-f" if follow else "-n 200")
    _home(ctx, app).stream(cmd)


@action("app", "restart", "Restart (nomad job restart)", Arg("app", "App", choices=app_names))
def restart(ctx: Ctx, app: str) -> None:
    job = ctx.index.apps[app].job
    if not ui.confirm(f"Restart {job}? The site is briefly down while its container restarts."):
        return
    node = _home(ctx, app)
    with ui.spin(f"restarting {job}"):
        p = node.nomad(f"job restart -yes {job}", timeout=600)
    if p.returncode != 0:
        raise AvcError((p.stderr or p.stdout).strip())
    ui.ok(f"{job} restarted")


@action("app", "backup", "Back up now", Arg("app", "App", choices=app_names))
def backup(ctx: Ctx, app: str) -> None:
    rc = _home(ctx, app).stream(f"cluster-backup {shlex.quote(app)}")
    (ui.ok if rc == 0 else ui.err)(f"backup of {app} {'done' if rc == 0 else f'failed ({rc})'}")


@action("app", "snapshots", "List backup snapshots", Arg("app", "App", choices=app_names))
def snapshots(ctx: Ctx, app: str) -> None:
    _home(ctx, app).stream(f"cluster-backup-list {shlex.quote(app)}")


@action(
    "app",
    "restore",
    "Restore from a backup",
    Arg("app", "App", choices=app_names),
    Arg("snapshot", "Snapshot ID (blank = latest)", optional=True),
)
def restore(ctx: Ctx, app: str, snapshot: str | None) -> None:
    node = _home(ctx, app)
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
