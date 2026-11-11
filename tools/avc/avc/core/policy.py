"""secrets/policy.toml: which generators may be regenerated, and how."""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from avc.core.index import Index


@dataclass(frozen=True)
class Rule:
    match: str | None = None
    kind: str | None = None
    suffix: str = ""
    never: tuple[str, ...] = ()
    manual: bool = False
    via: str | None = None
    reason: str = ""

    def applies(self, generator: str, index: Index) -> bool:
        if self.match is not None and fnmatch.fnmatchcase(generator, self.match):
            return True
        if self.kind is not None:
            return any(a.kind == self.kind and generator == a.name + self.suffix for a in index.apps.values())
        return False


@dataclass(frozen=True)
class Verdict:
    """What the policy says about regenerating one generator."""

    allowed: bool
    never: tuple[str, ...] = ()
    manual: bool = False
    via: str | None = None
    reasons: tuple[str, ...] = field(default=())

    @property
    def label(self) -> str:
        if self.never:
            return f"[red]never[/] ({', '.join(self.never)})"
        if self.manual:
            return "[yellow]manual[/]"
        if self.via:
            return f"[cyan]via {self.via}[/]"
        return "[green]safe[/]"


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    max_age_days: int = 365

    def verdict(self, generator: str, index: Index) -> Verdict:
        hits = [r for r in self.rules if r.applies(generator, index)]
        never = tuple(sorted({f for r in hits for f in r.never}))
        manual = any(r.manual for r in hits)
        via = next((r.via for r in hits if r.via), None)
        return Verdict(
            allowed=not (never or manual or via),
            never=never,
            manual=manual,
            via=via,
            reasons=tuple(r.reason for r in hits if r.reason),
        )


def parse(data: dict) -> Policy:
    rules = tuple(
        Rule(
            match=r.get("match"),
            kind=r.get("kind"),
            suffix=r.get("suffix", ""),
            never=tuple(r.get("never", ())),
            manual=bool(r.get("manual", False)),
            via=r.get("via"),
            reason=r.get("reason", ""),
        )
        for r in data.get("rule", [])
    )
    return Policy(rules=rules, max_age_days=int(data.get("defaults", {}).get("max_age_days", 365)))


def load(root: Path) -> Policy:
    f = root / "secrets" / "policy.toml"
    if not f.exists():
        return Policy(rules=())
    return parse(tomllib.loads(f.read_text()))
