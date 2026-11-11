"""What every action receives: where the repository is, and lazy, memoized
access to the things that cost an eval or a round trip."""

from __future__ import annotations

import functools
import json
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

from avc.core.index import Index, load_index
from avc.core.node import Node
from avc.errors import AvcError


def find_root(start: Path | None = None) -> Path:
    env = os.environ.get("AVC_REPO")
    if env:
        return Path(env).resolve()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start or Path.cwd(),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise AvcError("not inside a cluster repository (or set AVC_REPO)") from e
    root = Path(out)
    if not (root / "flake.nix").exists():
        raise AvcError(f"{root} is not a cluster repository (no flake.nix)")
    return root


@dataclass
class Ctx:
    root: Path
    _memo: dict[str, Any] = field(default_factory=dict, repr=False)

    def memo(self, key: str, compute: Callable[[], Any]) -> Any:
        """Compute once per run (per menu visit: the menu loop forgets)."""
        if key not in self._memo:
            self._memo[key] = compute()
        return self._memo[key]

    def forget(self) -> None:
        """Drop everything derived from the repository; a flow may have changed it."""
        self._memo.clear()
        for cached in ("index", "installed"):
            self.__dict__.pop(cached, None)

    @functools.cached_property
    def index(self) -> Index:
        return load_index(self.root)

    def node(self, name: str) -> Node:
        if name not in self.index.nodes:
            raise AvcError(f"unknown node {name!r} (known: {', '.join(self.index.nodes)})")
        return Node(name, self.index.nodes[name])

    @functools.cached_property
    def installed(self) -> list[str]:
        """Nodes that actually exist: clan records an install in inventory.json.
        topology.nix also carries placeholders (node2, node3) that must never be
        ssh'd into or waited on."""
        try:
            machines = json.loads((self.root / "inventory.json").read_text()).get("machines", {})
        except FileNotFoundError:
            machines = {}
        return [n for n in self.index.nodes if machines.get(n, {}).get("installedAt")]

    def installed_nodes(self) -> list[Node]:
        return [self.node(n) for n in self.installed]

    @property
    def state_dir(self) -> Path:
        d = self.root / ".avc"
        d.mkdir(exist_ok=True)
        ignore = d / ".gitignore"
        if not ignore.exists():
            # Local state, never part of a commit, whatever the site's own .gitignore says.
            ignore.write_text("*\n")
        return d
