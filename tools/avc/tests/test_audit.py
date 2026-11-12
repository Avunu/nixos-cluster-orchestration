"""`avc audit`: the Worker's AUDIT_TOKENS, from each node's own vars."""

from __future__ import annotations

import dataclasses
import json

import pytest

from avc import actions
from avc.core import vars as clanvars
from avc.errors import AvcError
from avc.flows import audit


@pytest.fixture
def fleet(ctx, index, monkeypatch):
    base = index.nodes["node1"]
    nodes = {
        "node1": {**base, "audit": {"enabled": True, "nomadAcl": True}},
        "node2": {**base, "tags": [], "audit": {"enabled": True, "nomadAcl": False}},
        # Opted out with no URL: it ships nothing and has no token.
        "node3": {**base, "tags": [], "audit": {"enabled": False, "nomadAcl": False}},
    }
    ctx.__dict__["index"] = dataclasses.replace(index, nodes=nodes)
    asked = []

    def get_value(root, machine, var_id):
        asked.append((machine, var_id))
        return f"tok-{machine}\n"

    monkeypatch.setattr(clanvars, "get_value", get_value)
    return ctx, asked


def test_each_node_is_known_by_its_own_token(fleet):
    ctx, asked = fleet
    data = audit.audit_tokens(ctx)
    assert data == {
        "tok-node1": {"sender": "node1", "kinds": ["boot", "deploy", "ssh_login", "canary", "nomad_acl"]},
        "tok-node2": {"sender": "node2", "kinds": ["boot", "deploy", "ssh_login", "canary"]},
    }
    # Per machine, and never for a node that ships nothing.
    assert asked == [("node1", "audit/token"), ("node2", "audit/token")]


def test_the_printed_json_is_only_the_tokens(fleet, capsys):
    ctx, _ = fleet
    audit.tokens(ctx)
    out = capsys.readouterr()
    # stdout is what `wrangler secret put` reads: the whole of it is the secret, as it is.
    assert json.loads(out.out) == audit.audit_tokens(ctx)
    assert out.err == ""


def test_tokens_is_the_only_audit_command():
    assert [a.name for a in actions.in_group("audit")] == ["tokens"]


def test_two_nodes_with_one_token_are_refused(fleet, monkeypatch):
    ctx, _ = fleet
    monkeypatch.setattr(clanvars, "get_value", lambda root, m, v: "same")
    with pytest.raises(AvcError, match="same audit/token"):
        audit.audit_tokens(ctx)


def test_an_empty_token_is_refused(fleet, monkeypatch):
    ctx, _ = fleet
    monkeypatch.setattr(clanvars, "get_value", lambda root, m, v: "\n")
    with pytest.raises(AvcError, match="empty"):
        audit.audit_tokens(ctx)
