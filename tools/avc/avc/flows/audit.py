"""Audit: what the watchdog Worker needs to know about each node for the off-host audit
trail (modules/audit-ship.nix, workers/cluster-watchdog). Prints the JSON for its two
secrets; pushing them is `wrangler secret put`, which reads them on stdin.

AUDIT_TOKENS names every node by its own `audit/token`. The Tang host's entry is not in
this repository (Tang's configuration lives in its own), so it is printed as a reminder,
not as part of the JSON: add it by hand before pushing, or the Tang host's events are
refused.
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

# What a node may send. The nomad-leader node adds nomad_acl; Tang's kinds are its own.
NODE_KINDS = ("boot", "deploy", "ssh_login", "canary")
TANG_ENTRY = {"sender": "tang", "kinds": ["tang_rec", "tang_probe"]}


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
    data = audit_tokens(ctx)
    ui.warn(
        "Add the Tang host's entry from the Tang repo before pushing: "
        f'"<its token>": {json.dumps(TANG_ENTRY)}. Then: wrangler secret put AUDIT_TOKENS'
    )
    ui.out(json.dumps(data, sort_keys=True))


@action("audit", "tang-clients", "Print TANG_CLIENTS for the watchdog Worker")
def tang_clients(ctx: Ctx) -> None:
    data = {a["tangIp"]: name for name, n in sorted(ctx.index.nodes.items()) if (a := n.get("audit") or {}).get("tangIp")}
    ui.out(json.dumps(data, sort_keys=True))
