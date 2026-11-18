"""Secrets: one inventory, and provisioning and rotation that know what each
secret feeds.

Every secret here is a file of a generator the flake declares (modules/secrets.nix),
made and kept by avc/core/secretstore.py. A rotation is gated by secrets/policy.toml,
shows what else regenerates with it (the generators that read its files), and ends in
the ship pipeline with a restart of every app that consumes any of it — a new
value reaches a container as a bind mount, which a reload does not refresh.

Whatever changes a source ends in `rekey`: a node is given the files under
secrets/rekeyed/<node>/ and nothing else, so a new value that was not rekeyed is a
value no node has. `avc secrets check` says whether a deploy of this tree would give
every node everything it declares.

Shared generators have one value for the fleet, read and written through one
machine. Per-machine ones (the boot secrets, a node's own certificates and
keys) have one value per node, so every command that touches them goes machine
by machine. A per-machine value is named `<machine>:<generator>/<file>`.
"""

from __future__ import annotations

import datetime as dt
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from avc import ui
from avc.actions import Arg, action
from avc.core import policy as policy_mod
from avc.core import repo, secretstore, ship
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx
    from avc.core.secretstore import GeneratorInfo

# Bound to an installed node's disks: `luks/passphrase` is the node's recovery key, with a
# slot on each leg, and the identity check compares the secret on them with the hash in the
# signed initrd. Regenerating either locks
# the node out, whatever secrets/policy.toml says, so these are refused here as well.
BOUND_TO_DISKS = {
    "luks": "the disks' recovery key: a new one opens nothing",
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
        "a new pair from `ssh-keygen -t ed25519`, each half stored with "
        "`avc secrets set <node>:initrd-ssh/ssh_host_ed25519_key` (and `.pub`), which asks you to confirm, then "
        "`avc -y secrets reveal <node>:initrd-ssh/ssh_host_ed25519_key | ssh root@<node> install -m 0400 /dev/stdin "
        "/var/lib/initrd-ssh/ssh_host_ed25519_key`, then deploy. Generations already on the ESP keep the old key"
    ),
    "emergency-access": (
        "the initrd emergency shell's password, whose hash is in every signed initrd: generations already on the "
        "ESP keep the old hash, and `avc secrets reveal` then gives only the new password. By hand, keeping the old "
        "password until those generations are gone"
    ),
}

# Bound to data that already exists: the value is what opens it, and a new one opens
# nothing. Refused here in code, like the disk-bound ones, so the protection does not hang
# on a site's own secrets/policy.toml (a site without one used to see these as "safe").
BOUND_TO_DATA = {
    "juicefs-rsa": (
        "the JuiceFS volume's key: its PEM is in the volume's metadata, encrypted with this passphrase, and every "
        "mount after the next restart could not open it. Changing it means a new volume: "
        "`avc secrets replace juicefs-rsa`, by the README's Recovery, 'A node left your control'"
    ),
    "restic": (
        "every app's restic repository password: a new one opens none of the existing repositories (rc 12). "
        "Per repository, `restic key add` / `restic key remove` instead; after a lost node, new repositories: "
        "`avc secrets replace restic`, by the README's Recovery, 'A node left your control'"
    ),
}

# What must not be generated anew on an installed node, by any command.
NOT_ON_INSTALLED = BOUND_TO_DISKS | HELD_ON_THE_NODE | BOUND_TO_DATA

# One app's JuiceFS volume key (<volume>-jfs): as juicefs-rsa, for that app's files.
APP_VOLUME_KEY = "-jfs"
APP_VOLUME_KEY_WHY = (
    "one app's JuiceFS volume key: its PEM is in the volume's metadata, encrypted with this passphrase, and a "
    "new one reads none of the app's files. Changing it means a new volume for that app (`avc secrets replace`)"
)


def bound_to_data(name: str) -> str | None:
    return APP_VOLUME_KEY_WHY if name.endswith(APP_VOLUME_KEY) else BOUND_TO_DATA.get(name)


def not_on_installed(name: str) -> str | None:
    return APP_VOLUME_KEY_WHY if name.endswith(APP_VOLUME_KEY) else NOT_ON_INSTALLED.get(name)


@dataclass(frozen=True)
class Scoped:
    """A generator and the machines its values belong to: the one machine that holds a shared
    generator's value, or every machine that has a per-machine one."""

    gen: GeneratorInfo
    machines: tuple[str, ...]


def _machine(ctx: Ctx) -> str:
    # Shared generators have one value for every node, so any machine that declares
    # them reads and writes them; the index names a Nomad server, which declares all.
    return ctx.index.reference


def _machines(ctx: Ctx) -> list[str]:
    # Placeholders too: their per-machine secrets are generated before they are installed.
    return list(ctx.index.nodes)


def _scoped(ctx: Ctx) -> dict[str, Scoped]:
    def read() -> dict[str, Scoped]:
        found: dict[str, tuple[GeneratorInfo, list[str]]] = {}
        with ui.spin("reading generators"):
            for m in _machines(ctx):
                for g in secretstore.generators(ctx.root, m):
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
    """(machine, generator/file) for a var id: shared through one machine, per-machine
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
        # Each machine's own declaration: a per-machine file is kept under its name.
        for g in secretstore.generators(root, m):
            for f in g.files if g.name == s.gen.name else ():
                d = repo.last_change(root, f.stored_as)
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
            seen.setdefault(app.job, ship.restart(app.job, ctx.contact().name))
    return list(seen.values())


def _statuses(ctx: Ctx, machines: list[str]) -> dict[str, secretstore.Summary]:
    with ui.spin("checking what is generated"):
        return {m: secretstore.status(ctx.root, m) for m in machines}


def _stored(ctx: Ctx) -> None:
    """After anything that wrote a source: what the nodes are given must follow it."""
    secretstore.rekey(ctx.root)


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
        elif bound_to_data(name):
            verdict = "[red]never[/] (bound to existing data)"
        elif name in HELD_ON_THE_NODE:
            verdict = "[yellow]manual[/] (held on the node)"
        else:
            verdict = pol.verdict(name, ctx.index).label
        rows.append([name, scope, kind, users, age_s, verdict, state])
    ui.table("secrets", ["generator", "scope", "source", "used by", "age", "rotation", "state"], rows)

    bases = {ctx.root / "secrets" / "shared": {n for n, s in scoped.items() if s.gen.share}}
    for m in _machines(ctx):
        bases[ctx.root / "secrets" / "per-machine" / m] = {n for n, s in scoped.items() if not s.gen.share and m in s.machines}
    for base, known in bases.items():
        for d in sorted(base.iterdir()) if base.exists() else []:
            if d.is_dir() and d.name not in known:
                ui.say(f"orphaned: {d.relative_to(ctx.root)} (no generator declares it any more)")


def cloud_issued(ctx: Ctx) -> set[str]:
    from avc.flows import cloud

    return cloud.issued(ctx)


def _needing(ctx: Ctx, machine: str, st: secretstore.Summary) -> set[str]:
    """The generators a provision would run on `machine`: those with a file missing or
    made from other inputs, and those that read their files."""
    names = {v.split("/")[0] for v in st.missing} | set(st.outdated)
    gens = secretstore.generators(ctx.root, machine)
    return names | {d for n in names for d in secretstore.dependents(gens, n)}


@action("secrets", "provision", "Provision missing secrets")
def provision(ctx: Ctx) -> None:
    statuses = _statuses(ctx, _machines(ctx))
    needing = {m: _needing(ctx, m, st) for m, st in statuses.items()}
    # One of these on an installed node is never made anew, whether it is missing, was
    # made from other inputs, or reads a generator that is: a lost file comes back from
    # git, and a library change to one of these generators has its own procedure.
    # Nothing else is generated for that node either, so that what is wrong with it is
    # looked at before anything about it changes.
    # A key pair `avc cloud apply` issues is not one to ask for: before the first apply
    # nobody has it. Only while it is missing; one that is stored is treated as any other.
    absent = {v.split("/")[0] for st in statuses.values() for v in st.missing}
    left = sorted(absent & cloud_issued(ctx)) if absent else []
    for m in needing:
        needing[m] -= set(left)
    held = {m: sorted(g for g in needing[m] if not_on_installed(g)) for m in statuses if m in ctx.installed}
    held = {m: g for m, g in held.items() if g}
    # A shared one is every node's: an installed node holding it keeps the others from
    # making a new one for the fleet.
    shared = {n for n, s in _scoped(ctx).items() if s.gen.share}
    held_shared = {g for names in held.values() for g in names if g in shared}
    todo = [m for m in statuses if needing[m] - held_shared and m not in held]
    later = f"{', '.join(left)}: issued by the provider, and written by `avc cloud apply`"
    if not todo and not held and not any(st.unfixed for st in statuses.values()):
        if left:
            ui.info(later)
            ui.ok("every other secret is present and current, on every machine")
        else:
            ui.ok("every secret is present and current, on every machine")
        return
    if left:
        ui.info(later)
    for m, st in statuses.items():
        for v in st.missing:
            if v.split("/")[0] in left:
                continue
            ui.info(f"{m}: missing {v}")
        for g in st.outdated:
            ui.info(f"{m}: outdated {g}")
        if st.unfixed:
            ui.warn(f"{m}: {len(st.unfixed)} need re-encryption — `avc secrets fix`")
    for m, names in held.items():
        for g in names:
            ui.err(f"{m} is installed, and {g} is {not_on_installed(g)}")
        ui.say(
            f"{m}: nothing of its own is generated (what reads a shared secret that is made again still follows it). "
            "Restore a lost file from git; anything else is by hand."
        )
    if todo:
        if not ui.confirm(
            f"Generate them now, on {', '.join(todo)}? Prompted values (issued tokens) are asked for.", default=True
        ):
            return
        targets = sorted((m, g) for m in todo for g in needing[m] - held_shared)
        secretstore.generate(ctx.root, targets, reference=_machine(ctx))
        _stored(ctx)
        names = sorted({g for _, g in targets})
        ship.ship(ctx, f"feat(secrets): provision {', '.join(names)}", paths=["secrets/"], post=_restarts(ctx, names))
    if held:
        raise AvcError(f"not provisioned on {', '.join(held)}: see above")


def rotation_targets(ctx: Ctx, generator: str) -> tuple[str, ...]:
    """The machines a rotation regenerates on: one machine for a shared generator, every
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
    closure = [generator, *secretstore.dependents(gens, generator)]

    ui.header(f"Rotate {generator}")
    for name in closure:
        if not_on_installed(name):
            ui.err(f"{name} is {not_on_installed(name)}" + (" (regenerated as a dependent)" if name != generator else ""))
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
    prompts = ", ".join(p.name for p in g.prompts)
    if not g.share:
        ui.say(f"one value per machine, regenerated on each: {', '.join(targets)}")
    if g.prompts:
        ui.say(f"you will be asked for: {prompts} (issue the new value first; the old one stays valid until you revoke it)")
    post = _restarts(ctx, closure)
    for p in post:
        ui.say(f"then: {p.label}")
    if not ui.confirm(f"Regenerate {generator}?"):
        return
    secretstore.generate(ctx.root, [(m, generator) for m in targets], regenerate=True, reference=_machine(ctx))
    _stored(ctx)
    if ship.ship(ctx, f"chore(secrets): rotate {generator}", paths=["secrets/"], post=post) and g.prompts:
        ui.info("deployed and restarted — now revoke the old credential at its issuer")


def replaceable(ctx: Ctx) -> list[str]:
    return [n for n in _gen_names(ctx) if bound_to_data(n)]


@action(
    "secrets",
    "replace",
    "Replace a data-bound key (a new JuiceFS volume, new restic repositories), after a node left your control",
    Arg("generator", "Generator", choices=replaceable),
)
def replace(ctx: Ctx, generator: str) -> None:
    """The one way to a new `juicefs-rsa`, `restic` or `<app>-jfs`. `rotate` and
    `provision` refuse them on an installed node, because a new value opens nothing that
    exists. After a lost node that is the purpose (README, Recovery: 'A node left your
    control'): the old value is disclosed, so the data moves to a new volume, or to new
    repositories, under a key the lost machine never held. This makes that key and
    nothing else: the steps before and after it are the README's, and they are what keep
    the data."""
    why = bound_to_data(generator)
    if why is None:
        raise AvcError(f"{generator} is not bound to data: `avc secrets rotate {generator}`")
    gens = _gens(ctx)
    closure = [generator, *secretstore.dependents(gens, generator)]
    for name in closure[1:]:
        if not_on_installed(name):
            raise AvcError(f"{name} derives from {generator} and is {not_on_installed(name)}: not replaced")
    ui.header(f"Replace {generator}")
    ui.err(f"{generator} is {why}")
    ui.say("After this the repository holds the old value only in its history. Before going on:")
    ui.say("  - the old value is in the offline kit, and compares equal to `avc secrets reveal` of it;")
    if generator == "restic":
        ui.say("  - every app has been restored or backed up as far as it will be from the old repositories;")
        ui.say("  - this commit also changes `backup.repoSalt`, so that every app moves to a new, empty repository.")
    else:
        ui.say("  - every app on the volume has a backup you have looked at (`cluster-backup-list <app>`);")
        ui.say("  - every node is held, the apps and the mounts are stopped;")
        ui.say("  - this commit also names a new, empty bucket, and the volume's metadata database is emptied before the nodes are released.")
    if len(closure) > 1:
        ui.warn(f"also regenerated (they derive from it): {', '.join(closure[1:])}")
    # Typed, and never taken as given: `-y` answers confirmations, and this is not one.
    if ui.assume_yes and not ui.is_scripted():
        raise AvcError(f"replacing {generator} is not something `-y` answers: run it at a terminal and type the name")
    ui.type_to_confirm(f"Make a new {generator}, which opens nothing that exists", f"replace {generator}")
    targets = rotation_targets(ctx, generator)
    secretstore.generate(ctx.root, [(m, generator) for m in targets], regenerate=True, reference=_machine(ctx))
    _stored(ctx)
    ui.ok(f"{generator} is new. It is on no node yet: commit it with the change it belongs to (the bucket, or the salt)")
    ui.say("`avc deploy ship` ships the working tree; put the new value in the offline kit, with a new bundle.")


@action("secrets", "set", "Set a value by hand", Arg("var", "Secret (generator/file, or machine:generator/file)", choices=_var_ids))
def set_var(ctx: Ctx, var: str) -> None:
    machine, var_id = parse_var(ctx, var)
    generator, _, file = var_id.partition("/")
    if not_on_installed(generator):
        ui.err(f"{generator} is {not_on_installed(generator)}")
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
    secretstore.set_value(ctx.root, machine, var_id, value)
    ui.ok(f"{var} stored")
    _stored(ctx)
    ship.ship(ctx, f"chore(secrets): set {var}", paths=["secrets/"], post=_restarts(ctx, [generator]))


@action("secrets", "reveal", "Reveal a value", Arg("var", "Secret (generator/file, or machine:generator/file)", choices=_var_ids))
def reveal(ctx: Ctx, var: str) -> None:
    machine, var_id = parse_var(ctx, var)
    if not ui.confirm(f"Print {var} in clear on this terminal?"):
        return
    value = secretstore.get_value(ctx.root, machine, var_id)
    # The bytes as they are, so that a pipe gets the key and not the key and a newline.
    sys.stdout.write(value)
    if sys.stdout.isatty() and not value.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()


@action("secrets", "fix", "Re-encrypt for the current master recipients")
def fix(ctx: Ctx) -> None:
    """After an operator's key is added to or removed from masterIdentities or
    extraRecipients (flake.nix), every source is encrypted again, and rekeyed: a node's
    files are named by the source they came from."""
    statuses = _statuses(ctx, _machines(ctx))
    todo = sorted({f"{m}: {v}" if ":" not in v else v for m, st in statuses.items() for v in st.unfixed})
    if not todo:
        ui.ok("every secret is encrypted for the current master recipients")
        return
    ui.info(f"{len(todo)} declared secret(s) are not known to be encrypted for the flake's master recipients")
    ui.warn("re-encrypting grants every listed recipient access — check masterIdentities and extraRecipients in flake.nix first")
    ui.say("every source is decrypted once: with a YubiKey, one touch for each")
    if not ui.confirm("Re-encrypt every secret in the repository?"):
        return
    count = secretstore.fix(ctx.root)
    ui.ok(f"{count} file(s) re-encrypted")
    _stored(ctx)
    ship.ship(ctx, "chore(secrets): re-encrypt for current recipients", paths=["secrets/"])


@action("secrets", "rekey", "Rekey: give each node what it reads, encrypted to its own key")
def rekey(ctx: Ctx) -> None:
    """After a node's recipient is added (an install), or a source changed outside avc."""
    _stored(ctx)
    ship.ship(ctx, "chore(secrets): rekey", paths=["secrets/"])


def readiness_problems(ctx: Ctx, machines: list[str], strict: bool) -> list[str]:
    """Why a deploy of this tree would leave a node short of a secret, one line each.
    `strict`: a node with no recipient is one, too; otherwise it is a node not installed
    yet (Ctx.installed), which needs its secrets generated and nothing rekeyed."""
    problems = []
    for m in machines:
        r = secretstore.readiness(ctx.root, m)
        problems += [f"{m}: {v} is not generated (`avc secrets provision`)" for v in r.missing]
        problems += [f"{m}: {g} was made from other inputs than it declares now (`avc secrets provision`)" for g in r.outdated]
        problems += [f"{m}: {v} is not rekeyed for it, or was rekeyed from an older value (`avc secrets rekey`)" for v in r.unrekeyed]
        if not r.recipient and strict:
            problems.append(f"{m}: no recipient (secrets/recipients/{m}.pub): nothing can be rekeyed for it, and it would decrypt nothing")
        elif not r.recipient:
            ui.say(f"{m}: no recipient yet (not installed): nothing is rekeyed for it")
        for rel in r.orphaned:
            ui.warn(f"{m}: secrets/rekeyed/{m}/{rel} is named by nothing (`avc secrets rekey` removes it)")
    return problems


@action(
    "secrets",
    "check",
    "Check that a deploy would give every node its secrets",
    Arg("node", "Node (every node when left out)", choices=lambda ctx: list(ctx.index.nodes), optional=True),
)
def check(ctx: Ctx, node: str | None = None) -> None:
    """A node builds and switches without a secret that was never generated or never
    rekeyed, and then runs short of it. So this is asked before a deploy, and refuses."""
    if node is not None and node not in ctx.index.nodes:
        raise AvcError(f"unknown node {node!r} (known: {', '.join(ctx.index.nodes)})")
    machines = [node] if node else _machines(ctx)
    with ui.spin("checking sources and rekeyed files"):
        problems = readiness_problems(ctx, machines, strict=node is not None)
    for p in problems:
        ui.err(p)
    if problems:
        raise AvcError(f"{len(problems)} secret(s) would not reach their node: do not deploy this tree")
    ui.ok(f"{', '.join(machines)}: every declared secret is generated, and rekeyed where there is a recipient")
