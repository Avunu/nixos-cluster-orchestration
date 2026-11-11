"""The only module that imports clan_lib.

clan-core is pinned by rev and bumped alone (flake.nix), but clan_lib is not a
stable API: keeping every call behind these few functions means a bump that
moves something breaks one file, not the tool.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from avc.errors import AvcError


@dataclass(frozen=True)
class VarsSummary:
    missing: list[str]  # generator/file with no value in the store
    unfixed: list[str]  # present, but its recipients no longer match (re-encrypt)
    outdated: list[str]  # generators whose validation hash changed (regenerate)

    @property
    def clean(self) -> bool:
        return not (self.missing or self.unfixed or self.outdated)


def _flake(root: Path):  # noqa: ANN202 — clan_lib type, imported lazily
    try:
        from clan_lib.flake import Flake
    except ImportError as e:
        raise AvcError("clan_lib is not importable — run avc from `nix run .#avc` or the devShell") from e
    # clan_lib reports every missing var at INFO; the summary says it once.
    logging.getLogger("clan_lib").setLevel(logging.WARNING)
    return Flake(str(root))


def status(root: Path, machine: str) -> VarsSummary:
    from clan_lib.errors import ClanError
    from clan_lib.vars.check import vars_status

    try:
        s = vars_status(machine, _flake(root))
    except ClanError as e:
        raise AvcError(f"vars status for {machine}: {e}") from e
    return VarsSummary(
        missing=sorted(v.id for v in [*s.missing_secret_vars, *s.missing_public_vars]),
        unfixed=sorted(v.id for v in s.unfixed_secret_vars),
        outdated=sorted(s.invalid_generators),
    )


@dataclass(frozen=True)
class VarFile:
    name: str
    secret: bool
    deploy: bool


@dataclass(frozen=True)
class GeneratorInfo:
    name: str
    share: bool
    files: tuple[VarFile, ...]
    prompts: tuple[str, ...]  # prompted (operator-supplied) values, e.g. issued tokens
    dependencies: tuple[str, ...]

    def path(self, root: Path, file: VarFile, machine: str | None = None) -> Path:
        """Where the value lives in the repository (age backend layout). A per-machine
        generator's values are under the machine's name, so it needs one."""
        if self.share:
            scope = Path("shared")
        elif machine is None:
            raise ValueError(f"{self.name} is per machine: say which machine")
        else:
            scope = Path("per-machine") / machine
        if file.secret:
            return root / "secrets" / "clan-vars" / scope / self.name / file.name / f"{file.name}.age"
        return root / "vars" / scope / self.name / file.name / "value"


def generators(root: Path, machine: str) -> list[GeneratorInfo]:
    from clan_lib.errors import ClanError
    from clan_lib.vars.generator import get_machine_generators

    try:
        gens = get_machine_generators([machine], _flake(root))
    except ClanError as e:
        raise AvcError(f"listing generators for {machine}: {e}") from e
    return sorted(
        (
            GeneratorInfo(
                name=g.name,
                share=g.share,
                files=tuple(VarFile(f.name, f.secret, f.deploy) for f in g.files),
                prompts=tuple(p.name for p in g.prompts),
                dependencies=tuple(sorted(d.name for d in g.dependencies)),
            )
            for g in gens
        ),
        key=lambda g: g.name,
    )


def dependents(gens: list[GeneratorInfo], name: str) -> list[str]:
    """Everything regenerated along with `name` (clan regenerates the
    transitive dependents of a requested generator)."""
    out: list[str] = []
    frontier = [name]
    while frontier:
        current = frontier.pop()
        for g in gens:
            if current in g.dependencies and g.name not in out:
                out.append(g.name)
                frontier.append(g.name)
    return sorted(out)


# Writes go through the clan CLI rather than clan_lib: it owns the interactive
# prompts (hidden input, previous value as default). clan commits what it
# writes itself, so the ship pipeline then finds commits on the deploy branch
# rather than a dirty tree, and moves them to a pull-request branch.


def _clan(root: Path, *args: str, input: str | None = None, capture: bool = False) -> str:
    from avc.core import proc

    return proc.run(["clan", "vars", *args], cwd=root, input=input, capture=capture).stdout or ""


def generate(root: Path, machine: str, generator: str | None = None, regenerate: bool = False) -> None:
    args = ["generate", machine]
    if generator:
        args += ["--generator", generator]
    if regenerate:
        args.append("--regenerate")
    _clan(root, *args)


def set_value(root: Path, machine: str, var_id: str, value: str) -> None:
    _clan(root, "set", machine, var_id, input=value, capture=True)


def get_value(root: Path, machine: str, var_id: str) -> str:
    return _clan(root, "get", machine, var_id, capture=True)


def fix(root: Path, machine: str) -> None:
    _clan(root, "fix", machine)
