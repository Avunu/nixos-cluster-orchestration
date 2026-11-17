"""The site's secrets, on the operator's machine: the generator runner, and every read
and write of a value.

What a secret is, is declared in the flake (modules/secrets.nix), and this module reads
it as data: `nix eval --json .#clusterSecrets`, one entry per machine. Where a value is
kept is lib/secrets-layout.nix: a secret is one age file, encrypted to the operators'
master recipients and to nothing else; a public file is beside it in the clear.

Making a value. A generator is a script that writes its files to $out, reading what the
operator was asked from $prompts and the files of the generators it depends on from $in.
It runs here and nowhere else:

  * in a directory of its own (mode 0700) on a tmpfs, $XDG_RUNTIME_DIR or else /dev/shm,
    removed when the script ends, however it ends. A machine with neither is refused:
    plaintext is never written to a disk.
  * under bubblewrap: no network, a new PID, IPC and user namespace, an empty
    environment, a user of its own, the Nix store read-only, $in and $prompts read-only, and $out the one
    place it can write that outlives it.
  * and then held to its declaration: every declared file, as a regular file, and
    nothing else.

Nothing reaches the repository until every generator of the run has done that. Then each
secret is encrypted, and only ciphertext and public files are written, each by rename.
A run that fails leaves the repository as it was.

Reading a value is `age -d` with the master identities: a YubiKey, through
age-plugin-yubikey, which wants a touch for every file. So a file is decrypted at most
once per run, and what this run made or wrote is never decrypted at all.

A node reads none of the above. What it is given is `secrets/rekeyed/<node>/`: each
secret it holds, encrypted to its own recipient, under the name agenix-rekey computes
from the recipient and the source. `rekey` writes those that are missing from plaintext
this run already has (one decryption per source, however many nodes read it), removes
the ones nothing names any more, and then runs the flake's own `agenix rekey`, which is
the authority and finds nothing left to do.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from avc import ui
from avc.core import proc
from avc.errors import AvcError

# lib/secrets-layout.nix.
SECRETS = "secrets"
MASTER_RECIPIENTS = f"{SECRETS}/.master-recipients"
# Every directory that holds master-encrypted files: the generators' two, and the nodes'
# identity files, which an install writes (`set_node_identity`).
SOURCE_SCOPES = (f"{SECRETS}/shared", f"{SECRETS}/per-machine", f"{SECRETS}/identities")

# An identity file used before the flake's master identities, for a key the flake names
# only as a recipient: the offline one. Several, separated by `:`.
IDENTITY_ENV = "AVC_AGE_IDENTITY"
# agenix-rekey's own: the recipient of the YubiKey that is plugged in, so that age asks
# for that one first and not for the other operator's.
PRIMARY_ENV = "AGENIX_REKEY_PRIMARY_IDENTITY"
# `none` runs a generator without bubblewrap, for a machine that cannot make a user
# namespace. Everything else about a run is the same.
SANDBOX_ENV = "AVC_SANDBOX"


@dataclass(frozen=True)
class SecretFile:
    name: str
    secret: bool = True
    deploy: bool = True
    needed_for: str = "services"
    stored_as: str = ""

    @property
    def lowered(self) -> bool:
        """Whether a node is given it by agenix (modules/secrets.nix, `deployed`)."""
        return self.secret and self.deploy and self.needed_for == "services"

    @property
    def age_name(self) -> str:
        """agenix's name for it: its path below /run/secrets."""
        return self.stored_as.removeprefix(f"{SECRETS}/").removesuffix(".age")


@dataclass(frozen=True)
class Prompt:
    name: str
    description: str = ""
    type: str = "line"  # hidden | line | multiline | multiline-hidden
    persist: bool = False


@dataclass(frozen=True)
class GeneratorInfo:
    """One generator as one machine declares it."""

    name: str
    share: bool
    files: tuple[SecretFile, ...]
    prompts: tuple[Prompt, ...] = ()
    dependencies: tuple[str, ...] = ()
    validation_hash: str | None = None
    validation_stored_as: str = ""
    script: str = ""
    script_drv: str = ""

    def file(self, name: str) -> SecretFile:
        for f in self.files:
            if f.name == name:
                return f
        raise AvcError(f"{self.name} has no file {name!r} (it has: {', '.join(f.name for f in self.files)})")

    def path(self, root: Path, file: SecretFile) -> Path:
        return root / file.stored_as


@dataclass(frozen=True)
class Summary:
    missing: list[str]  # generator/file with nothing in the repository
    unfixed: list[str]  # present, but not known to be encrypted to the current master recipients
    outdated: list[str]  # generators whose validation hash is not the one they were made with

    @property
    def clean(self) -> bool:
        return not (self.missing or self.unfixed or self.outdated)


@dataclass(frozen=True)
class Unit:
    """A generator to run: once for the fleet when it is shared, through `machine`'s
    declaration of it; once per machine otherwise."""

    machine: str
    gen: GeneratorInfo

    @property
    def key(self) -> tuple[str | None, str]:
        return (None if self.gen.share else self.machine, self.gen.name)

    @property
    def label(self) -> str:
        return self.gen.name if self.gen.share else f"{self.machine}:{self.gen.name}"


@dataclass(frozen=True)
class Readiness:
    """Whether a node would get every secret it declares from a deploy of this tree."""

    machine: str
    recipient: bool
    missing: tuple[str, ...]  # declared, not generated
    outdated: tuple[str, ...]  # generated from other inputs than it declares now
    unrekeyed: tuple[str, ...]  # generated, and no current rekeyed file for this node
    orphaned: tuple[str, ...]  # rekeyed files nothing names: an old value's, or a removed secret's

    @property
    def ok(self) -> bool:
        return self.recipient and not (self.missing or self.outdated or self.unrekeyed)


# ── the tmpfs a generator runs on ────────────────────────────────────────────

RAM_FILESYSTEMS = {"tmpfs", "ramfs"}


def filesystem(path: Path) -> str | None:
    """The type of the filesystem `path` is on, from the mount table."""
    target = os.path.realpath(path)
    best, kind = "", None
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        left, _, right = line.partition(" - ")
        mount = left.split()[4].replace("\\040", " ")
        if (target == mount or target.startswith(mount.rstrip("/") + "/")) and len(mount) >= len(best):
            best, kind = mount, right.split()[0]
    return kind


def runtime_dir() -> Path:
    """Where plaintext may be while a generator runs: memory, and nowhere a disk backs."""
    tried = []
    for candidate in (os.environ.get("XDG_RUNTIME_DIR"), "/dev/shm"):
        if not candidate:
            continue
        p = Path(candidate)
        kind = filesystem(p) if p.is_dir() else None
        if kind in RAM_FILESYSTEMS and os.access(p, os.W_OK | os.X_OK):
            return p
        tried.append(f"{candidate} ({kind or 'not a directory'})")
    raise AvcError(
        "no tmpfs to run a generator on: plaintext is never written to a disk. Tried " + (", ".join(tried) or "nothing")
    )


def _private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _replace(path: Path, data: bytes) -> None:
    """Never plaintext: ciphertext, or a file its generator declares public."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".tmp-avc-{path.name}")
    tmp.write_bytes(data)
    os.replace(tmp, path)


SANDBOX_UID = 1000


def sandbox_argv(script: str, work: Path) -> list[str]:
    """A generator's command line: its script, with nothing of this machine but the Nix
    store, and no network."""
    env = {"out": str(work / "out"), "in": str(work / "in"), "prompts": str(work / "prompts")}
    if os.environ.get(SANDBOX_ENV) == "none":
        return ["env", "-i", *(f"{k}={v}" for k, v in env.items()), "HOME=/var/empty", script]
    argv = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv"]
    argv += ["--uid", str(SANDBOX_UID), "--gid", str(SANDBOX_UID)]
    argv += ["--ro-bind", "/nix/store", "/nix/store", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp"]
    # ssh-keygen and its like ask who they are.
    for name in ("passwd", "group"):
        argv += ["--ro-bind", str(work / name), f"/etc/{name}"]
    if not script.startswith("/nix/store/"):
        argv += ["--ro-bind", script, script]
    argv += ["--dir", str(work)]
    argv += ["--bind", env["out"], env["out"], "--ro-bind", env["in"], env["in"], "--ro-bind", env["prompts"], env["prompts"]]
    for k, v in env.items():
        argv += ["--setenv", k, v]
    argv += ["--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp", "--chdir", "/tmp", "--", script]
    return argv


def ask_prompt(label: str, p: Prompt) -> str:
    question = f"{label}/{p.name}: {p.description}" if p.description and p.description != p.name else f"{label}/{p.name}"
    if p.type == "hidden":
        return ui.secret(question)
    if p.type == "line":
        return ui.text(question)
    return ui.multiline(question, hidden=p.type == "multiline-hidden")


def rekeyed_name(recipient: str, source: bytes, age_name: str) -> str:
    """Where agenix-rekey keeps one secret for one host, below its localStorageDir
    (its apps/rekey.nix): a hash of the host's recipient and of the source, then the
    secret's name."""
    pubkey_hash = hashlib.sha256(recipient.encode()).hexdigest()
    ident = hashlib.sha256((pubkey_hash + hashlib.sha256(source).hexdigest()).encode()).hexdigest()[:32]
    return f"{ident}-{age_name}.age"


def _generator(name: str, data: dict[str, Any]) -> GeneratorInfo:
    return GeneratorInfo(
        name=name,
        share=bool(data["share"]),
        files=tuple(
            SecretFile(n, bool(f["secret"]), bool(f["deploy"]), f["neededFor"], f["storedAs"])
            for n, f in sorted(data["files"].items())
        ),
        prompts=tuple(
            Prompt(n, p.get("description", n), p.get("type", "line"), bool(p.get("persist")))
            for n, p in sorted(data.get("prompts", {}).items())
        ),
        dependencies=tuple(sorted(data.get("dependencies", ()))),
        validation_hash=data.get("validationHash"),
        validation_stored_as=data.get("validationStoredAs", ""),
        script=data.get("script", ""),
        script_drv=data.get("scriptDrv", ""),
    )


class Store:
    """One repository's secrets. `export` is `.#clusterSecrets`; given, nothing is evaluated."""

    def __init__(self, root: Path, export: dict[str, Any] | None = None) -> None:
        self.root = Path(root)
        self._export = export
        self._plain: dict[Path, bytes] = {}
        self._gens: dict[str, dict[str, GeneratorInfo]] = {}

    # ── what is declared ─────────────────────────────────────────────────────

    @property
    def export(self) -> dict[str, Any]:
        if self._export is None:
            with ui.spin("evaluating the site's secrets"):
                out = proc.out(["nix", "eval", "--json", f"{self.root}#clusterSecrets"], cwd=self.root)
            self._export = json.loads(out)
        return self._export

    def reload(self) -> None:
        """The flake changed (a new app, say): evaluate again. What was decrypted is kept."""
        self._export = None
        self._gens.clear()

    def machines(self) -> list[str]:
        return sorted(self.export)

    def _machine(self, machine: str) -> dict[str, GeneratorInfo]:
        if machine not in self._gens:
            if machine not in self.export:
                raise AvcError(f"unknown machine {machine!r} (known: {', '.join(self.machines())})")
            self._gens[machine] = {n: _generator(n, g) for n, g in self.export[machine]["generators"].items()}
        return self._gens[machine]

    def generators(self, machine: str) -> list[GeneratorInfo]:
        return sorted(self._machine(machine).values(), key=lambda g: g.name)

    def generator(self, machine: str, name: str) -> GeneratorInfo:
        gens = self._machine(machine)
        if name not in gens:
            raise AvcError(f"{machine} declares no generator {name!r}")
        return gens[name]

    def find(self, machine: str, var_id: str) -> tuple[GeneratorInfo, SecretFile]:
        name, sep, file = var_id.partition("/")
        if not sep or not file:
            raise AvcError(f"{var_id!r} is not <generator>/<file>")
        if name not in self._machine(machine):
            # Declared since the last evaluation: an app that has just been given a tunnel.
            self.reload()
        gen = self.generator(machine, name)
        return gen, gen.file(file)

    # ── age ──────────────────────────────────────────────────────────────────

    def _any(self) -> dict[str, Any]:
        export = self.export
        if not export:
            raise AvcError("the flake's clusterSecrets names no machine")
        return export[sorted(export)[0]]

    def _identity_path(self, identity: str) -> Path:
        return Path(identity) if os.path.isabs(identity) else self.root / identity

    def _identity_recipient(self, identity: dict[str, Any]) -> str | None:
        """An identity's recipient: named beside it, or in the comment the plugin wrote
        into the file (as agenix-rekey reads it)."""
        if identity.get("pubkey"):
            return str(identity["pubkey"]).strip()
        try:
            text = self._identity_path(identity["identity"]).read_text()
        except OSError:
            return None
        found = []
        for line in text.splitlines():
            for marker in ("Recipient: ", "public key: "):
                if line.startswith("#") and marker in line:
                    found.append(line.split(marker, 1)[1].strip())
        return found[0] if len(found) == 1 else None

    def master_recipient_args(self) -> list[str]:
        """age's arguments to encrypt to the operators and to the extra recipients."""
        cfg = self._any()
        args: list[str] = []
        for identity in cfg.get("masterIdentities", []):
            recipient = self._identity_recipient(identity)
            args += ["-r", recipient] if recipient else ["-i", str(self._identity_path(identity["identity"]))]
        for extra in cfg.get("extraRecipients", []):
            # agenix-rekey's rule: an absolute path is a recipients file.
            args += ["-R", extra] if os.path.isabs(extra) else ["-r", extra]
        if not args:
            raise AvcError("the flake names no master identity and no extra recipient: there is nobody to encrypt to")
        return args

    def master_recipients(self) -> list[str]:
        """The same, as the list kept in secrets/.master-recipients."""
        out = []
        args = self.master_recipient_args()
        for flag, value in zip(args[::2], args[1::2]):
            if flag == "-r":
                out.append(value)
            elif flag == "-R":
                out += [ln.strip() for ln in Path(value).read_text().splitlines() if ln.strip() and not ln.startswith("#")]
            else:
                out.append(f"identity:{os.path.relpath(value, self.root) if value.startswith(str(self.root)) else value}")
        return sorted(set(out))

    def recorded_recipients(self) -> list[str] | None:
        f = self.root / MASTER_RECIPIENTS
        return f.read_text().split() if f.exists() else None

    def _identity_args(self) -> list[str]:
        cfg = self._any()
        primary = os.environ.get(PRIMARY_ENV)
        identities = sorted(
            cfg.get("masterIdentities", []),
            key=lambda i: 0 if primary and self._identity_recipient(i) == primary else 1,
        )
        paths = [p for p in os.environ.get(IDENTITY_ENV, "").split(":") if p]
        paths += [str(self._identity_path(i["identity"])) for i in identities]
        if not paths:
            raise AvcError(f"the flake names no master identity to decrypt with (and {IDENTITY_ENV} is not set)")
        return [a for p in paths for a in ("-i", p)]

    def _age(self, args: list[str], data: bytes | None, what: str) -> bytes:
        # age and its plugins talk to the operator (PIN, "touch your YubiKey") on the
        # terminal itself, so stderr is theirs when there is one.
        quiet = not sys.stderr.isatty()
        try:
            feed: dict[str, Any] = {"stdin": subprocess.DEVNULL} if data is None else {"input": data}
            p = subprocess.run(["age", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE if quiet else None, **feed)
        except FileNotFoundError as e:
            raise AvcError("age: not found on PATH; run avc from `nix run .#avc` or the devShell") from e
        if p.returncode != 0:
            detail = (p.stderr or b"").decode(errors="replace").strip() if quiet else ""
            raise AvcError(f"age could not {what} ({p.returncode})" + (f":\n{detail}" if detail else ""))
        return p.stdout

    def encrypt(self, data: bytes, recipient_args: list[str]) -> bytes:
        return self._age(["-e", *recipient_args], data, "encrypt")

    def decrypt(self, path: Path) -> bytes:
        """A source's plaintext, with the master identities. Once per run for each file."""
        path = Path(path)
        if path not in self._plain:
            if not path.exists():
                raise AvcError(f"{self._rel(path)} is not in the repository: its generator has not run")
            self._plain[path] = self._age(["-d", *self._identity_args(), str(path)], None, f"decrypt {self._rel(path)}")
        return self._plain[path]

    def _rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    # ── state ────────────────────────────────────────────────────────────────

    def recorded_hash(self, gen: GeneratorInfo) -> str | None:
        f = self.root / gen.validation_stored_as if gen.validation_stored_as else None
        return f.read_text().strip() if f is not None and f.exists() else None

    def missing(self, gen: GeneratorInfo) -> list[SecretFile]:
        return [f for f in gen.files if not gen.path(self.root, f).exists()]

    def outdated(self, gen: GeneratorInfo) -> bool:
        """Made from other inputs than it declares now. One with no record of what it was
        made from counts: nothing says it is current."""
        if gen.validation_hash is None or len(self.missing(gen)) == len(gen.files):
            return False
        return self.recorded_hash(gen) != gen.validation_hash

    def needs(self, gen: GeneratorInfo) -> bool:
        return bool(self.missing(gen)) or self.outdated(gen)

    def sources(self) -> list[Path]:
        """Every master-encrypted file in the repository, declared now or not."""
        return sorted(p for scope in SOURCE_SCOPES for p in (self.root / scope).rglob("*.age") if p.is_file())

    def recipients_current(self) -> bool:
        recorded = self.recorded_recipients()
        if recorded is None:
            return not self.sources()
        return recorded == self.master_recipients()

    def status(self, machine: str) -> Summary:
        gens = self.generators(machine)
        stale = not self.recipients_current()
        return Summary(
            missing=sorted(f"{g.name}/{f.name}" for g in gens for f in self.missing(g)),
            unfixed=sorted(
                f"{g.name}/{f.name}" for g in gens for f in g.files if stale and f.secret and g.path(self.root, f).exists()
            ),
            outdated=sorted(g.name for g in gens if self.outdated(g)),
        )

    # ── values ───────────────────────────────────────────────────────────────

    def get(self, machine: str, var_id: str) -> bytes:
        gen, file = self.find(machine, var_id)
        path = gen.path(self.root, file)
        if not path.exists():
            raise AvcError(f"{var_id} has no value for {machine}: `avc secrets provision` makes it")
        return self.decrypt(path) if file.secret else path.read_bytes()

    def set(self, machine: str, var_id: str, value: bytes) -> str:
        """Write one file's value, as given. Returns where, relative to the repository."""
        gen, file = self.find(machine, var_id)
        had = bool(self.sources())
        path = gen.path(self.root, file)
        _replace(path, self.encrypt(value, self.master_recipient_args()) if file.secret else value)
        if file.secret:
            self._plain[path] = value
        # Set file by file, a generator is whole once its last file is: say what it was made for.
        if not self.missing(gen):
            self._record_hash(gen)
        self._record_recipients(had)
        return file.stored_as

    def _record_hash(self, gen: GeneratorInfo) -> None:
        if not gen.validation_stored_as:
            return
        f = self.root / gen.validation_stored_as
        if gen.validation_hash is None:
            f.unlink(missing_ok=True)
        else:
            _replace(f, (gen.validation_hash + "\n").encode())

    def _record_recipients(self, had_sources: bool) -> None:
        """The record is true of every source or it is not written: a new file among older
        ones encrypted to other keys leaves it as it was, for `fix`."""
        if self.recorded_recipients() is None and not had_sources and self.sources():
            _replace(self.root / MASTER_RECIPIENTS, ("\n".join(self.master_recipients()) + "\n").encode())

    # ── the runner ───────────────────────────────────────────────────────────

    def units(self, reference: str | None = None) -> dict[tuple[str | None, str], Unit]:
        """Every generator of the site, a shared one once: through `reference` when it
        declares it, else through the first machine that does."""
        out: dict[tuple[str | None, str], Unit] = {}
        machines = self.machines()
        if reference in machines:
            machines = [reference, *(m for m in machines if m != reference)]
        for m in machines:
            for g in self.generators(m):
                out.setdefault(Unit(m, g).key, Unit(m, g))
        return out

    def _deps(self, unit: Unit, units: dict[tuple[str | None, str], Unit]) -> list[Unit]:
        out = []
        for name in unit.gen.dependencies:
            dep = self.generator(unit.machine, name)
            out.append(units[Unit(unit.machine, dep).key])
        return out

    def plan(
        self,
        targets: Iterable[tuple[str, str]] | None = None,
        regenerate: bool = False,
        reference: str | None = None,
    ) -> list[Unit]:
        """What to run, in order. `targets` are (machine, generator); none means every
        generator with a file missing or its validation changed. A generator is run when
        one it depends on is: its files were derived from the old ones."""
        units = self.units(reference)
        if targets is None:
            wanted = {k for k, u in units.items() if self.needs(u.gen)}
        else:
            wanted = set()
            for machine, name in targets:
                unit = units[Unit(machine, self.generator(machine, name)).key]
                if regenerate or self.needs(unit.gen):
                    wanted.add(unit.key)
        grew = True
        while grew:
            grew = False
            for k, u in units.items():
                if k not in wanted and any(d.key in wanted for d in self._deps(u, units)):
                    wanted.add(k)
                    grew = True

        order: list[Unit] = []
        done: set[tuple[str | None, str]] = set()

        def visit(k: tuple[str | None, str], path: tuple[tuple[str | None, str], ...]) -> None:
            if k in done:
                return
            if k in path:
                raise AvcError("generators depend on each other in a circle: " + " -> ".join(n for _, n in (*path, k)))
            for d in self._deps(units[k], units):
                if d.key in wanted:
                    visit(d.key, (*path, k))
            done.add(k)
            order.append(units[k])

        for k in sorted(wanted, key=lambda k: (k[0] or "", k[1])):
            visit(k, ())
        return order

    def realise(self, units: list[Unit]) -> None:
        """Build the scripts that are not in the store yet."""
        drvs = []
        for u in units:
            if os.path.exists(u.gen.script):
                continue
            if not u.gen.script_drv:
                raise AvcError(f"{u.label}: its script {u.gen.script!r} does not exist and the flake names no derivation for it")
            drvs.append(f"{u.gen.script_drv}^out")
        if drvs:
            with ui.spin(f"building {len(drvs)} generator script(s)"):
                proc.run(["nix", "build", "--no-link", *sorted(set(drvs))], cwd=self.root)

    def run(self, units: list[Unit], ask: Callable[[str, Prompt], str] = ask_prompt) -> list[str]:
        """Run `units` in the order given and store what they make. Returns the files
        written, relative to the repository. All of them or none."""
        if not units:
            return []
        self.realise(units)
        base = runtime_dir()
        args = self.master_recipient_args()
        units_by_key = self.units()
        units_by_key.update({u.key: u for u in units})
        answers = {u.key: {p.name: ask(u.label, p) for p in u.gen.prompts} for u in units}

        made: dict[str, bytes] = {}
        for u in units:
            with ui.spin(f"generating {u.label}"):
                made.update(self._run_one(u, self._deps(u, units_by_key), answers[u.key], made, base))

        # Every script has run and kept to its declaration. Encrypt it all, then write.
        stored = {
            f.stored_as: self.encrypt(made[f.stored_as], args) if f.secret else made[f.stored_as]
            for u in units
            for f in u.gen.files
        }
        had = bool(self.sources())
        for rel, data in stored.items():
            _replace(self.root / rel, data)
        for u in units:
            self._record_hash(u.gen)
            for f in u.gen.files:
                if f.secret:
                    self._plain[self.root / f.stored_as] = made[f.stored_as]
        self._record_recipients(had)
        return sorted(stored)

    def _input(self, gen: GeneratorInfo, f: SecretFile, made: dict[str, bytes]) -> bytes:
        if f.stored_as in made:
            return made[f.stored_as]
        path = gen.path(self.root, f)
        if not path.exists():
            raise AvcError(f"{gen.name}/{f.name} is needed as an input and has not been generated")
        return self.decrypt(path) if f.secret else path.read_bytes()

    def _run_one(self, unit: Unit, deps: list[Unit], answers: dict[str, str], made: dict[str, bytes], base: Path) -> dict[str, bytes]:
        gen = unit.gen
        work = Path(tempfile.mkdtemp(prefix="avc-secrets-", dir=base))  # 0700
        try:
            out, inputs, prompts = work / "out", work / "in", work / "prompts"
            for d in (out, inputs, prompts):
                d.mkdir(mode=0o700)
            (work / "passwd").write_text(f"generator:x:{SANDBOX_UID}:{SANDBOX_UID}::/tmp:/bin/sh\n")
            (work / "group").write_text(f"generator:x:{SANDBOX_UID}:\n")
            for name, value in answers.items():
                _private(prompts / name, value.encode())
            for dep in deps:
                (inputs / dep.gen.name).mkdir(mode=0o700)
                for f in dep.gen.files:
                    _private(inputs / dep.gen.name / f.name, self._input(dep.gen, f, made))
            try:
                p = subprocess.run(sandbox_argv(gen.script, work), stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
            except FileNotFoundError as e:
                raise AvcError(f"{e.filename}: not found on PATH; run avc from `nix run .#avc` or the devShell") from e
            if p.returncode != 0:
                tail = "\n".join((p.stderr or p.stdout or "").strip().splitlines()[-20:])
                raise AvcError(f"generator {unit.label} failed ({p.returncode})" + (f":\n{tail}" if tail else ""))
            declared = {f.name for f in gen.files}
            found = {e.name: e for e in os.scandir(out)}
            problems = [f"did not write {n}" for n in sorted(declared - set(found))]
            problems += [f"wrote {n}, which it does not declare" for n in sorted(set(found) - declared)]
            problems += [f"{n} is not a regular file" for n, e in sorted(found.items()) if not e.is_file(follow_symlinks=False)]
            if problems:
                raise AvcError(f"generator {unit.label} did not keep to its declaration: " + "; ".join(problems))
            return {f.stored_as: (out / f.name).read_bytes() for f in gen.files}
        finally:
            shutil.rmtree(work, ignore_errors=True)
            if work.exists():
                raise AvcError(f"could not remove {work}: it may hold plaintext; remove it by hand")

    # ── master recipients ────────────────────────────────────────────────────

    def fix(self) -> int:
        """Encrypt every source again, to the master recipients as the flake names them now."""
        args = self.master_recipient_args()
        again = {p: self.encrypt(self.decrypt(p), args) for p in self.sources()}
        for p, data in again.items():
            _replace(p, data)
        _replace(self.root / MASTER_RECIPIENTS, ("\n".join(self.master_recipients()) + "\n").encode())
        return len(again)

    # ── what a node is given ─────────────────────────────────────────────────

    def recipient(self, machine: str) -> str | None:
        f = self.root / SECRETS / "recipients" / f"{machine}.pub"
        return f.read_text().removesuffix("\n") if f.exists() else None

    def _stored_as(self, machine: str, key: str, default: str) -> Path:
        if machine not in self.export:
            raise AvcError(f"unknown machine {machine!r} (known: {', '.join(self.machines())})")
        return self.root / self.export[machine].get(key, default)

    def node_identity(self, machine: str) -> str | None:
        """The node's age identity file as its last install left it in the repository: a
        handle to a key in that machine's TPM, encrypted to the operators like any source."""
        f = self._stored_as(machine, "identityStoredAs", f"{SECRETS}/identities/{machine}.age")
        return self.decrypt(f).decode() if f.exists() else None

    def set_node_identity(self, machine: str, identity: str, recipient: str) -> list[str]:
        """A node's new identity: the recipient in the clear, the identity file encrypted
        to the master recipients. What was rekeyed to the old recipient is named by it, so
        `rekey` after this makes all of it again and removes the old."""
        had = bool(self.sources())
        rec = self._stored_as(machine, "recipientStoredAs", f"{SECRETS}/recipients/{machine}.pub")
        ident = self._stored_as(machine, "identityStoredAs", f"{SECRETS}/identities/{machine}.age")
        _replace(ident, self.encrypt(identity.encode(), self.master_recipient_args()))
        self._plain[ident] = identity.encode()
        _replace(rec, (recipient.strip() + "\n").encode())
        self._record_recipients(had)
        return [self._rel(rec), self._rel(ident)]

    def rekeyed_dir(self, machine: str) -> Path:
        return self.root / SECRETS / "rekeyed" / machine

    def expected_rekeyed(self, machine: str) -> dict[str, tuple[GeneratorInfo, SecretFile]]:
        """The rekeyed files a node's closure names, relative to its rekeyed directory:
        one per secret it is given that has been generated."""
        recipient = self.recipient(machine)
        if recipient is None:
            return {}
        out = {}
        for g in self.generators(machine):
            for f in g.files:
                source = g.path(self.root, f)
                if f.lowered and source.exists():
                    out[rekeyed_name(recipient, source.read_bytes(), f.age_name)] = (g, f)
        return out

    def _rekeyed_present(self, machine: str) -> set[str]:
        d = self.rekeyed_dir(machine)
        return {str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()} if d.is_dir() else set()

    def readiness(self, machine: str) -> Readiness:
        gens = self.generators(machine)
        expected = self.expected_rekeyed(machine)
        present = self._rekeyed_present(machine)
        return Readiness(
            machine=machine,
            recipient=self.recipient(machine) is not None,
            missing=tuple(sorted(f"{g.name}/{f.name}" for g in gens for f in self.missing(g))),
            outdated=tuple(sorted(g.name for g in gens if self.outdated(g))),
            unrekeyed=tuple(sorted(f"{g.name}/{f.name}" for rel, (g, f) in expected.items() if rel not in present)),
            orphaned=tuple(sorted(present - set(expected))),
        )

    def fill_rekeyed(self) -> list[str]:
        """Write each rekeyed file that is missing, and remove the ones nothing names.
        A source is decrypted once for all the nodes that read it, and not at all when
        this run made it. Returns what was written, relative to the repository."""
        written = []
        for machine in self.machines():
            recipient = self.recipient(machine)
            if recipient is None:
                continue
            d = self.rekeyed_dir(machine)
            expected = self.expected_rekeyed(machine)
            present = self._rekeyed_present(machine)
            for rel, (g, f) in sorted(expected.items()):
                if rel not in present:
                    _replace(d / rel, self.encrypt(self.decrypt(g.path(self.root, f)), ["-r", recipient]))
                    written.append(self._rel(d / rel))
            for rel in sorted(present - set(expected)):
                (d / rel).unlink()
            for sub in sorted((p for p in d.rglob("*") if p.is_dir()), reverse=True) if d.is_dir() else []:
                if not any(sub.iterdir()):
                    sub.rmdir()
        return written

    def rekey(self) -> None:
        self.fill_rekeyed()
        if not any(self.recipient(m) for m in self.machines()):
            ui.info("no node has a recipient yet (secrets/recipients/): nothing to rekey")
            return
        agenix_rekey(self.root)


def agenix_rekey(root: Path) -> None:
    """The flake's own `agenix rekey`: what a node's closure is built from is what it
    wrote or left alone. It evaluates the flake as git has it, so the sources are staged
    first; `-a` stages what it writes."""
    if (root / ".git").exists():
        proc.run(["git", "add", "--", SECRETS], cwd=root)
    cmd = ["agenix"] if shutil.which("agenix") else ["nix", "run", f"{root}#agenix", "--"]
    ui.info("agenix rekey")
    try:
        rc = subprocess.run([*cmd, "rekey", "-a"], cwd=root).returncode
    except FileNotFoundError as e:
        raise AvcError(f"{cmd[0]}: not found on PATH; run avc from `nix run .#avc` or the devShell") from e
    if rc != 0:
        raise AvcError(f"agenix rekey failed ({rc}): secrets/rekeyed/ may not match the sources; run `avc secrets rekey` again")


# ── one store per repository, for the flows ─────────────────────────────────

_stores: dict[Path, Store] = {}


def store(root: Path) -> Store:
    root = Path(root)
    if root not in _stores:
        _stores[root] = Store(root)
    return _stores[root]


def forget() -> None:
    """Drop every evaluation and every decrypted value (the menu loop, between actions)."""
    _stores.clear()


def status(root: Path, machine: str) -> Summary:
    return store(root).status(machine)


def generators(root: Path, machine: str) -> list[GeneratorInfo]:
    return store(root).generators(machine)


def dependents(gens: list[GeneratorInfo], name: str) -> list[str]:
    """Everything regenerated along with `name`: the generators that read its files,
    and those that read theirs."""
    out: list[str] = []
    frontier = [name]
    while frontier:
        current = frontier.pop()
        for g in gens:
            if current in g.dependencies and g.name not in out:
                out.append(g.name)
                frontier.append(g.name)
    return sorted(out)


def generate(
    root: Path,
    targets: list[tuple[str, str]] | None = None,
    regenerate: bool = False,
    reference: str | None = None,
) -> list[str]:
    """Run the generators `targets` name ((machine, generator); none: whatever is missing
    or outdated) and what derives from them. Returns the files written."""
    s = store(root)
    return s.run(s.plan(targets, regenerate, reference))


def set_value(root: Path, machine: str, var_id: str, value: str) -> None:
    store(root).set(machine, var_id, value.encode())


def get_value(root: Path, machine: str, var_id: str) -> str:
    return store(root).get(machine, var_id).decode()


def fix(root: Path) -> int:
    return store(root).fix()


def rekey(root: Path) -> None:
    store(root).rekey()


def readiness(root: Path, machine: str) -> Readiness:
    return store(root).readiness(machine)
