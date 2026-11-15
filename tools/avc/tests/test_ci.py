"""`avc ci`: the Worker's AGENT_TOKENS, from each node's own vars."""

from __future__ import annotations

import dataclasses
import json

import pytest

from avc.core import vars as clanvars
from avc.errors import AvcError
from avc.flows import ci


def fleet(ctx, index, monkeypatch, enabled, value=lambda machine: f"tok-{machine}\n"):
    base = index.nodes["node1"]
    nodes = {n: {**base, "ci": {"enabled": on}} for n, on in enabled.items()}
    ctx.__dict__["index"] = dataclasses.replace(index, nodes=nodes)
    asked = []

    def get_value(root, machine, var_id):
        asked.append((machine, var_id))
        return value(machine)

    monkeypatch.setattr(clanvars, "get_value", get_value)
    return asked


def test_each_node_with_an_agent_is_known_by_its_own_token(ctx, index, monkeypatch, capsys):
    asked = fleet(ctx, index, monkeypatch, {"node1": True, "node2": True, "node3": False})
    assert ci.agent_tokens(ctx) == {"tok-node1": "node1", "tok-node2": "node2"}
    assert asked == [("node1", "ci/token"), ("node2", "ci/token")]
    ci.tokens(ctx)
    assert json.loads(capsys.readouterr().out) == {"tok-node1": "node1", "tok-node2": "node2"}


def test_two_nodes_with_one_token_are_refused(ctx, index, monkeypatch):
    fleet(ctx, index, monkeypatch, {"node1": True, "node2": True}, value=lambda _: "same\n")
    with pytest.raises(AvcError, match="same ci/token"):
        ci.agent_tokens(ctx)


def test_a_site_without_the_pipeline_says_so(ctx, index, monkeypatch):
    fleet(ctx, index, monkeypatch, {"node1": False})
    with pytest.raises(AvcError, match="topology.ci.url"):
        ci.agent_tokens(ctx)
