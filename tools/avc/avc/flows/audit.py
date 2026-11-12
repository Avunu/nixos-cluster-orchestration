"""Audit: what the watchdog Worker needs to know about each node for the off-host audit
trail (modules/audit-ship.nix, workers/cluster-watchdog). Prints the JSON for its
AUDIT_TOKENS secret, which names every node by its own `audit/token`; pushing it is
`wrangler secret put`, which reads it on stdin.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from avc import ui
from avc.actions import action
from avc.core import vars as clanvars
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

# What a node may send. The nomad-leader node adds nomad_acl.
NODE_KINDS = ("boot", "deploy", "ssh_login", "canary")


def audit_tokens(ctx: Ctx) -> dict[str, dict[str, object]]:
    out: dict[str, dict[str, object]] = {}
    for name, node in sorted(ctx.index.nodes.items()):
        audit = node.get("audit") or {}
        if not audit.get("enabled"):
            continue
        token = clanvars.get_value(ctx.root, name, "audit/token").strip()
        if not token:
            raise AvcError(f"{name}: audit/token is empty; run `avc secrets provision`")
        if token in out:
            raise AvcError(f"{name} and {out[token]['sender']} have the same audit/token")
        kinds = [*NODE_KINDS, *(["nomad_acl"] if audit.get("nomadAcl") else [])]
        out[token] = {"sender": name, "kinds": kinds}
    if not out:
        raise AvcError("no node ships audit events: topology.alerting.auditUrl is null")
    return out


@action("audit", "tokens", "Print AUDIT_TOKENS for the watchdog Worker")
def tokens(ctx: Ctx) -> None:
    ui.out(json.dumps(audit_tokens(ctx), sort_keys=True))
