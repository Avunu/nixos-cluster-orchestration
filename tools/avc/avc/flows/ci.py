"""Pipeline: what the cluster-ci Worker needs to know each node's agent by
(modules/ci-agent.nix, workers/cluster-ci). Prints the JSON for its AGENT_TOKENS secret,
from every node's own `ci/token`; pushing it is `wrangler secret put`, which reads it on
stdin.
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


def agent_tokens(ctx: Ctx) -> dict[str, str]:
    out: dict[str, str] = {}
    for name, node in sorted(ctx.index.nodes.items()):
        if not (node.get("ci") or {}).get("enabled"):
            continue
        token = clanvars.get_value(ctx.root, name, "ci/token").strip()
        if not token:
            raise AvcError(f"{name}: ci/token is empty; run `avc secrets provision`")
        if token in out:
            raise AvcError(f"{name} and {out[token]} have the same ci/token")
        out[token] = name
    if not out:
        raise AvcError("no node runs the pipeline's agent: topology.ci.url is not set")
    return out


@action("ci", "tokens", "Print AGENT_TOKENS for the cluster-ci Worker")
def tokens(ctx: Ctx) -> None:
    ui.out(json.dumps(agent_tokens(ctx), sort_keys=True))
