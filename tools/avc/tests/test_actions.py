from __future__ import annotations

import pytest

from avc import actions, ui
from avc.cli import build_parser
from avc.core.vars import GeneratorInfo, dependents


def test_every_action_is_a_subcommand():
    parser = build_parser()
    for a in actions.ACTIONS:
        args = parser.parse_args([a.group, a.name])
        assert args._action is a


def test_every_group_has_actions():
    for key in actions.GROUPS:
        assert actions.in_group(key), key


def test_missing_args_are_asked_for(ctx):
    calls = []

    def fn(ctx, app, follow):
        calls.append((app, follow))

    a = actions.Action("app", "x", "x", fn, (actions.Arg("app", "App", choices=lambda c: sorted(c.index.apps)), actions.Arg("follow", "f", flag=True)))
    with ui.scripted(["blog"]):
        a.run(ctx, {"app": None, "follow": False})
    assert calls == [("blog", False)]


def test_given_args_are_not_asked(ctx):
    a = actions.Action("app", "x", "x", lambda ctx, app: app, (actions.Arg("app", "App", choices=lambda c: []),))
    with ui.scripted([]):
        assert a.run(ctx, {"app": "demo-erp"}) == "demo-erp"


def test_dependents_are_transitive():
    def g(name, *deps):
        return GeneratorInfo(name, True, (), (), tuple(deps))

    gens = [g("root"), g("mid", "root"), g("leaf", "mid"), g("other")]
    assert dependents(gens, "root") == ["leaf", "mid"]
    assert dependents(gens, "other") == []


def test_type_to_confirm_refuses_a_wrong_answer():
    with ui.scripted(["nope"]), pytest.raises(ui.Aborted):
        ui.type_to_confirm("Delete blog", "blog")
