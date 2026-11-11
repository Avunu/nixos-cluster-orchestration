"""The flake's `opsIndex` output (lib/ops-index.nix): nodes, apps, and which
vars generators each app consumes. One eval; nix's own eval cache makes the
repeat cheap."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from avc.core import proc


@dataclass(frozen=True)
class App:
    name: str
    kind: str | None
    home_node: str | None
    job: str
    tunnel: str
    hostnames: list[str]
    generators: list[str]


@dataclass(frozen=True)
class Index:
    leader: str
    flake_url: str
    nodes: dict[str, dict[str, Any]]
    apps: dict[str, App]

    def apps_using(self, generator: str) -> list[App]:
        return [a for a in self.apps.values() if generator in a.generators]


def parse_index(data: dict[str, Any]) -> Index:
    apps = {
        name: App(
            name=name,
            kind=a.get("kind"),
            home_node=a.get("homeNode"),
            job=a["job"],
            tunnel=a.get("tunnel", ""),
            hostnames=a.get("hostnames", []),
            generators=a.get("generators", []),
        )
        for name, a in data["apps"].items()
    }
    return Index(leader=data["leader"], flake_url=data["flakeUrl"], nodes=data["nodes"], apps=apps)


def load_index(root: Path) -> Index:
    return parse_index(json.loads(proc.out(["nix", "eval", "--json", f"{root}#opsIndex"], cwd=root)))
