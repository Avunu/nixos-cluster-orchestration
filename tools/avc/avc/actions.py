"""The action registry: one declaration per operation, from which both the
guided menu and the `avc <group> <action>` subcommands are generated.

An action is a plain function `fn(ctx, **args)`. Its arguments are declared
with `Arg`; on the command line they are positionals or flags, and in the menu
any that are missing are asked for — chosen from `choices(ctx)` when there is
a fixed set (apps, nodes, generators), typed otherwise.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from avc import ui
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx


@dataclass(frozen=True)
class Arg:
    name: str
    help: str
    choices: Callable[[Ctx], list[str]] | None = None
    flag: bool = False  # a boolean --switch instead of a value
    optional: bool = False  # positional that may be left out (default None)


@dataclass(frozen=True)
class Group:
    key: str
    title: str
    order: int


@dataclass(frozen=True)
class Action:
    group: str
    name: str
    title: str
    fn: Callable[..., Any]
    args: tuple[Arg, ...] = field(default=())

    def collect(self, ctx: Ctx, given: dict[str, Any]) -> dict[str, Any]:
        """Fill in what the command line left out, by asking."""
        values = dict(given)
        for a in self.args:
            if values.get(a.name) is not None:
                continue
            if a.flag:
                values[a.name] = bool(values.get(a.name))
            elif a.optional:
                values[a.name] = None
            elif a.choices is not None:
                options = a.choices(ctx)
                if not options:
                    raise AvcError(f"nothing to choose for {a.name}")
                values[a.name] = ui.choose(a.help, options)
            else:
                values[a.name] = ui.text(a.help)
        return values

    def run(self, ctx: Ctx, given: dict[str, Any] | None = None) -> Any:
        return self.fn(ctx, **self.collect(ctx, given or {}))


GROUPS: dict[str, Group] = {}
ACTIONS: list[Action] = []


def group(key: str, title: str, order: int) -> None:
    GROUPS[key] = Group(key, title, order)


def action(group_key: str, name: str, title: str, *args: Arg) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def register(fn: Callable[..., Any]) -> Callable[..., Any]:
        if group_key not in GROUPS:
            raise KeyError(f"unknown group {group_key}")
        if any(a.group == group_key and a.name == name for a in ACTIONS):
            raise KeyError(f"duplicate action {group_key} {name}")
        ACTIONS.append(Action(group_key, name, title, fn, tuple(args)))
        return fn

    return register


def in_group(key: str) -> list[Action]:
    return [a for a in ACTIONS if a.group == key]


def find(group_key: str, name: str) -> Action:
    for a in ACTIONS:
        if a.group == group_key and a.name == name:
            return a
    raise KeyError(f"{group_key} {name}")
