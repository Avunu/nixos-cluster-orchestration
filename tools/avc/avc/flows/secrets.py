"""Secrets: one inventory, and provisioning and rotation that know what each
secret feeds.

Every secret here is a clan var. A rotation is gated by secrets/policy.toml,
shows what else regenerates with it (clan's dependent closure), and ends in
the ship pipeline with a restart of every app that consumes any of it — a new
value reaches a container as a bind mount, which a reload does not refresh.

Shared generators have one value for the fleet, read and written through the
nomad leader. Per-machine ones (the boot secrets, a node's own certificates and
keys) have one value per node, so every command that touches them goes machine
by machine. A per-machine var is named `<machine>:<generator>/<file>`.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from avc import ui
from avc.actions import Arg, action
from avc.core import policy as policy_mod
from avc.core import repo, ship
from avc.core import vars as clanvars
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx
    from avc.core.vars import GeneratorInfo

# Bound to an installed node's disks: the LUKS passphrase opens them and the identity check
# compares the secret on them with the hash in the signed initrd. Regenerating either locks
# the node out, whatever secrets/policy.toml says, so these are refused here as well.
BOUND_TO_DISKS = {
    "luks": "the disks' LUKS passphrase: a new one opens nothing",
    "volume-identity": "compared with the secret on the root at every boot: a new one halts the node",
}

# Held on an installed node as well as in the repository, and a new value reaches only the
# repository. The disko hook placed the initrd's host key on the root once, at install, and
# each new generation's initrd is built from that file; `avc boot unlock` checks the host key
# against the repository's. Every signed initrd carries the emergency password's hash, and
# the generations already on the ESP keep the old one. These have a manual procedure.
HELD_ON_THE_NODE = {
    "initrd-ssh": (
        "the initrd's SSH host key, placed on each node at install and never again: a new one changes only the "
        "repository's copy, and `avc boot unlock` then refuses every node's initrd as the wrong host. By hand: "
        "`clan vars generate <node> --generator initrd-ssh --regenerate`, then "
        "`clan vars get <node> initrd-ssh/ssh_host_ed25519_key | ssh root@<node> install -m 0400 /dev/stdin "
        "/var/lib/initrd-ssh/ssh_host_ed25519_key`, then deploy. Generations already on the ESP keep the old key"
    ),
    "emergency-access": (
        "the initrd emergency shell's password, whose hash is in every signed initrd: generations already on the "
        "ESP keep the old hash, and `clan vars get` then gives only the new password. By hand, keeping the old "
        "password until those generations are gone"
    ),
}

# Bound to data that already exists: the value is what opens it, and a new one opens
# nothing. Refused here in code, like the disk-bound ones, so the protection does not hang
# on a site's own secrets/policy.toml (a site without one used to see these as "safe").
BOUND_TO_DATA = {
    "juicefs-rsa": (
        "the JuiceFS volume's key: its PEM is in the volume's metadata, encrypted with this passphrase, and every "
        "mount after the next restart could not open it. Changing it means a new volume"
    ),
    "restic": (
        "every app's restic repository password: a new one opens none of the existing repositories (rc 12). "
        "Per repository, `restic key add` / `restic key remove` instead"
    ),
}

# What must not be generated anew on an installed node, by any command.
NOT_ON_INSTALLED = BOUND_TO_DISKS | HELD_ON_THE_NODE | BOUND_TO_DATA


@dataclass(frozen=True)
class Scoped:
    """A generator and the machines its values belong to: the one machine that holds a shared
    generator's value, or every machine that has a per-machine one."""

    gen: GeneratorInfo
    machines: tuple[str, ...]


def _machine(ctx: Ctx) -> str:
    # Shared generators have one value for every node, so any machine reads and writes
    # them; the nomad leader always exists.
    return ctx.index.leader


def _machines(ctx: Ctx) -> list[str]:
    # Placeholders too: their per-machine vars are generated before they are installed.
    return list(ctx.index.nodes)


def _scoped(ctx: Ctx) -> dict[str, Scoped]:
    def read() -> dict[str, Scoped]:
        found: dict[str, tuple[GeneratorInfo, list[str]]] = {}
        with ui.spin("reading generators"):
            for m in _machines(ctx):
                for g in clanvars.generators(ctx.root, m):
                    found.setdefault(g.name, (g, []))[1].append(m)
        out = {}
        for name, (g, machines) in sorted(found.items()):
            if g.share:
                owner = _machine(ctx) if _machine(ctx) in machines else machines[0]
                out[name] = Scoped(g, (owner,))
            else:
                out[name] = Scoped(g, tuple(machines))
        return out

    return ctx.memo("generators", read)


def _gens(ctx: Ctx) -> list[GeneratorInfo]:
    return [s.gen for s in _scoped(ctx).values()]


def _gen_names(ctx: Ctx) -> list[str]:
    return [g.name for g in _gens(ctx)]


def _var_ids(ctx: Ctx) -> list[str]:
    ids = []
    for s in _scoped(ctx).values():
        for f in s.gen.files:
            if s.gen.share:
                ids.append(f"{s.gen.name}/{f.name}")
            else:
                ids.extend(f"{m}:{s.gen.name}/{f.name}" for m in s.machines)
    return ids


def parse_var(ctx: Ctx, var: str) -> tuple[str, str]:
    """(machine, generator/file) for a var id: shared through the leader, per-machine
    through the machine it names."""
    machine, sep, rest = var.partition(":")
    if sep:
        if machine not in ctx.index.nodes:
            raise AvcError(f"unknown machine {machine!r} in {var!r}")
        return machine, rest
    scoped = _scoped(ctx).get(var.partition("/")[0])
    if scoped is not None and not scoped.gen.share:
        raise AvcError(f"{var} is per machine: name it as <machine>:{var}")
    return _machine(ctx), var


def _age_days(root: Path, s: Scoped) -> int | None:
    dates = []
    for m in s.machines:
        for f in s.gen.files:
            d = repo.last_change(root, str(s.gen.path(root, f, m).relative_to(root)))
            if d:
                dates.append(d)
    if not dates:
        return None
    newest = max(dt.datetime.fromisoformat(d) for d in dates)
    return (dt.datetime.now(dt.UTC) - newest).days


def _restarts(ctx: Ctx, generators: list[str]) -> list[ship.PostAction]:
    seen: dict[str, ship.PostAction] = {}
    for g in generators:
        for app in ctx.index.apps_using(g):
            seen.setdefault(app.job, ship.restart(app.job, app.home_node or ctx.index.leader))
    return list(seen.values())


def _statuses(ctx: Ctx, machines: list[str]) -> dict[str, clanvars.VarsSummary]:
    with ui.spin("checking vars status"):
        return {m: clanvars.status(ctx.root, m) for m in machines}


@action("secrets", "inventory", "Inventory (age, consumers, rotation policy)")
def inventory(ctx: Ctx) -> None:
    scoped = _scoped(ctx)
    pol = policy_mod.load(ctx.root)
    statuses = _statuses(ctx, _machines(ctx))
    rows = []
    for name, s in scoped.items():
        age = _age_days(ctx.root, s)
        age_s = "-" if age is None else (f"[yellow]{age}d[/]" if age > pol.max_age_days else f"{age}d")
        missing = [m for m in s.machines if name in {v.split("/")[0] for v in statuses[m].missing}]
        outdated = [m for m in s.machines if name in statuses[m].outdated]
        where = "" if s.gen.share else f" on {', '.join(missing or outdated)}"
        state = "[red]missing[/]" + where if missing else "[yellow]outdated[/]" + where if outdated else "ok"
        users = ", ".join(a.name for a in ctx.index.apps_using(name)) or "[dim]host[/]"
        kind = "prompted" if s.gen.prompts else "generated"
        scope = "shared" if s.gen.share else f"per machine ({len(s.machines)})"
        if name in BOUND_TO_DISKS:
            verdict = "[red]never[/] (bound to the disks)"
        elif name in BOUND_TO_DATA:
            verdict = "[red]never[/] (bound to existing data)"
        elif name in HELD_ON_THE_NODE:
            verdict = "[yellow]manual[/] (held on the node)"
        else:
            verdict = pol.verdict(name, ctx.index).label
        rows.append([name, scope, kind, users, age_s, verdict, state])
    ui.table("secrets", ["generator", "scope", "source", "used by", "age", "rotation", "state"], rows)

    known = set(scoped)
    for base in (ctx.root / "secrets" / "clan-vars" / "shared", ctx.root / "vars" / "shared"):
        for d in sorted(base.iterdir()) if base.exists() else []:
            if d.is_dir() and d.name not in known:
                ui.say(f"orphaned: {d.relative_to(ctx.root)} (no generator declares it any more)")


def _needing(st: clanvars.VarsSummary) -> set[str]:
    return {v.split("/")[0] for v in st.missing} | set(st.outdated)


@action("secrets", "provision", "Provision missing secrets")
def provision(ctx: Ctx) -> None:
    statuses = _statuses(ctx, _machines(ctx))
    # `clan vars generate <machine>` makes every missing or outdated generator on that
    # machine anew, so one of these on an installed node means nothing is generated there:
    # a lost var file comes back from git, and a library change to one of these
    # generators has its own procedure.
    held = {m: sorted(_needing(st) & NOT_ON_INSTALLED.keys()) for m, st in statuses.items() if m in ctx.installed}
    held = {m: g for m, g in held.items() if g}
    todo = [m for m, st in statuses.items() if (st.missing or st.outdated) and m not in held]
    if not todo and not held and not any(st.unfixed for st in statuses.values()):
        ui.ok("every secret is present and current, on every machine")
        return
    gens: set[str] = set()
    for m, st in statuses.items():
        for v in st.missing:
            ui.info(f"{m}: missing {v}")
        for g in st.outdated:
            ui.info(f"{m}: outdated {g}")
        if st.unfixed:
            ui.warn(f"{m}: {len(st.unfixed)} need re-encryption — `avc secrets fix`")
        if m not in held:
            gens |= _needing(st)
    for m, names in held.items():
        for g in names:
            ui.err(f"{m} is installed, and {g} is {NOT_ON_INSTALLED[g]}")
        ui.say(f"{m}: nothing generated there. Restore a lost var file from git; anything else is by hand.")
    if todo:
        if not ui.confirm(
            f"Generate them now, on {', '.join(todo)}? Prompted values (issued tokens) are asked for.", default=True
        ):
            return
        for m in todo:
            clanvars.generate(ctx.root, m)
        names = sorted(gens)
        ship.ship(ctx, f"feat(secrets): provision {', '.join(names)}", paths=["vars/", "secrets/"], post=_restarts(ctx, names))
    if held:
        raise AvcError(f"not provisioned on {', '.join(held)}: see above")


def rotation_targets(ctx: Ctx, generator: str) -> tuple[str, ...]:
    """The machines a rotation regenerates on: the leader for a shared generator, every
    machine that has it for a per-machine one."""
    scoped = _scoped(ctx).get(generator)
    if scoped is None:
        raise AvcError(f"no generator {generator!r}")
    return scoped.machines


@action("secrets", "rotate", "Rotate a secret", Arg("generator", "Generator", choices=_gen_names))
def rotate(ctx: Ctx, generator: str) -> None:
    gens = _gens(ctx)
    by_name = {g.name: g for g in gens}
    targets = rotation_targets(ctx, generator)
    pol = policy_mod.load(ctx.root)
    closure = [generator, *clanvars.dependents(gens, generator)]

    ui.header(f"Rotate {generator}")
    for name in closure:
        if name in NOT_ON_INSTALLED:
            ui.err(f"{name} is {NOT_ON_INSTALLED[name]}" + (" (regenerated as a dependent)" if name != generator else ""))
            raise AvcError(f"refusing to regenerate {generator}")
        v = pol.verdict(name, ctx.index)
        if v.via:
            ui.info(f"{name} rotates through `avc {v.via}`: {' '.join(v.reasons)}")
            if name.startswith("wp-") and name.endswith("-api"):
                from avc.flows import sites

                if ui.confirm(f"Run `avc {v.via}` now?", default=True):
                    sites.r2_rotate(ctx, name.removeprefix("wp-").removesuffix("-api"))
            return
        if not v.allowed:
            what = f"never-rotate files {', '.join(v.never)}" if v.never else "a manual rotation procedure"
            ui.err(f"{name} has {what}" + (" (regenerated as a dependent)" if name != generator else ""))
            for r in v.reasons:
                ui.say(r)
            raise AvcError(f"refusing to regenerate {generator}")

    if len(closure) > 1:
        ui.warn(f"also regenerated (they derive from it): {', '.join(closure[1:])}")
    g = by_name[generator]
    files = ", ".join(f.name for f in g.files)
    ui.say(f"files: {files}")
    if not g.share:
        ui.say(f"one value per machine, regenerated on each: {', '.join(targets)}")
    if g.prompts:
        ui.say(f"you will be asked for: {', '.join(g.prompts)} (issue the new value first; the old one stays valid until you revoke it)")
    post = _restarts(ctx, closure)
    for p in post:
        ui.say(f"then: {p.label}")
    if not ui.confirm(f"Regenerate {generator}?"):
        return
    for m in targets:
        clanvars.generate(ctx.root, m, generator, regenerate=True)
    if ship.ship(ctx, f"chore(secrets): rotate {generator}", paths=["vars/", "secrets/"], post=post) and g.prompts:
        ui.info("deployed and restarted — now revoke the old credential at its issuer")


@action("secrets", "set", "Set a value by hand", Arg("var", "Secret (generator/file, or machine:generator/file)", choices=_var_ids))
def set_var(ctx: Ctx, var: str) -> None:
    machine, var_id = parse_var(ctx, var)
    generator, _, file = var_id.partition("/")
    if generator in NOT_ON_INSTALLED:
        ui.err(f"{generator} is {NOT_ON_INSTALLED[generator]}")
        ui.type_to_confirm(f"Overwrite {var} anyway", file)
    v = policy_mod.load(ctx.root).verdict(generator, ctx.index)
    if file in v.never:
        ui.err(f"{var} is marked never-rotate")
        for r in v.reasons:
            ui.say(r)
        ui.type_to_confirm(f"Overwrite {var} anyway", file)
    source = ui.choose("Value from", [("Type or paste it (hidden)", "prompt"), ("A file", "file")])
    if source == "file":
        path = Path(ui.text("Path")).expanduser()
        value = path.read_text()
    else:
        value = ui.secret(f"New value for {var}")
    clanvars.set_value(ctx.root, machine, var_id, value)
    ui.ok(f"{var} stored (encrypted)")
    ship.ship(ctx, f"chore(secrets): set {var}", paths=["vars/", "secrets/"], post=_restarts(ctx, [generator]))


@action("secrets", "reveal", "Reveal a value", Arg("var", "Secret (generator/file, or machine:generator/file)", choices=_var_ids))
def reveal(ctx: Ctx, var: str) -> None:
    machine, var_id = parse_var(ctx, var)
    if not ui.confirm(f"Print {var} in clear on this terminal?"):
        return
    ui.out(clanvars.get_value(ctx.root, machine, var_id))


@action("secrets", "fix", "Re-encrypt for the current recipients")
def fix(ctx: Ctx) -> None:
    """After an operator key is added to or removed from
    vars.settings.recipients (flake.nix), every secret is re-encrypted."""
    statuses = _statuses(ctx, _machines(ctx))
    todo = {m: st.unfixed for m, st in statuses.items() if st.unfixed}
    if not todo:
        ui.ok("every secret is encrypted for the current recipients")
        return
    for m, unfixed in todo.items():
        for v in unfixed:
            ui.info(f"{m}: re-encrypt {v}")
    ui.warn("re-encrypting grants every listed recipient access — check flake.nix recipients first")
    if not ui.confirm(f"Re-encrypt {sum(len(u) for u in todo.values())} secret(s)?"):
        return
    for m in todo:
        clanvars.fix(ctx.root, m)
    ship.ship(ctx, "chore(secrets): re-encrypt for current recipients", paths=["vars/", "secrets/"])
