"""Entry point: `avc` (guided) or `avc <group> <action> [args]` (direct)."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from avc import actions, flows, ui  # noqa: F401 — flows registers the actions
from avc.context import Ctx, find_root
from avc.errors import Aborted, AvcError
from avc.flows import status


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="avc",
        description="Day-to-day operations for a nixos-cluster-orchestration cluster. Run without arguments for the guided menu.",
    )
    p.add_argument("-y", "--yes", action="store_true", help="answer yes to confirmations (non-interactive use)")
    groups = p.add_subparsers(dest="group", metavar="<group>")
    for g in sorted(actions.GROUPS.values(), key=lambda g: g.order):
        gp = groups.add_parser(g.key, help=g.title)
        sub = gp.add_subparsers(dest="action", metavar="<action>", required=True)
        for a in actions.in_group(g.key):
            ap = sub.add_parser(a.name, help=a.title, description=a.title)
            for arg in a.args:
                if arg.flag:
                    ap.add_argument(f"--{arg.name}", action="store_true", help=arg.help)
                elif arg.option:
                    ap.add_argument(f"--{arg.name}", help=arg.help)
                else:
                    # Positionals are optional on the command line: a missing
                    # one is asked for, the same as in the menu.
                    ap.add_argument(arg.name, nargs="?", help=arg.help)
            ap.set_defaults(_action=a)
    return p


def _run(ctx: Ctx, a: actions.Action, given: dict[str, Any] | None = None) -> None:
    try:
        a.run(ctx, given)
    except (Aborted, KeyboardInterrupt):
        ui.warn("aborted")
    except AvcError as e:
        ui.err(str(e))


def menu(ctx: Ctx) -> None:
    status.quick(ctx)
    groups = sorted((g for g in actions.GROUPS.values() if g.key != "status"), key=lambda g: g.order)
    while True:
        try:
            choice = ui.choose(
                "What do you want to do?",
                [(g.title, g.key) for g in groups]
                + [("Full status check", "full"), ("Refresh overview", "refresh"), ("Quit", "quit")],
            )
        except Aborted:
            return
        if choice == "quit":
            return
        if choice == "refresh":
            ctx.forget()
            status.quick(ctx)
            continue
        if choice == "full":
            _run(ctx, actions.find("status", "full"))
            continue
        try:
            a = ui.choose(
                actions.GROUPS[choice].title,
                [(x.title, x) for x in actions.in_group(choice)] + [("← Back", "back")],
            )
        except Aborted:
            continue
        if a != "back":
            _run(ctx, a)
            ctx.forget()


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    ui.assume_yes = args.yes
    try:
        ctx = Ctx(find_root())
        if args.group is None:
            if not sys.stdin.isatty():
                raise AvcError("the guided menu needs a terminal; use `avc <group> <action>` (see --help)")
            menu(ctx)
            return
        a: actions.Action = args._action
        given = {arg.name: getattr(args, arg.name, None) for arg in a.args}
        a.run(ctx, given)
    except Aborted:
        ui.warn("aborted")
        sys.exit(130)
    except AvcError as e:
        ui.err(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
