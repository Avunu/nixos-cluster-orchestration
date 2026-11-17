"""The generator runner, for real: scripts run, age encrypts and decrypts, files land.

The master key here is a plain age key in a file, where a site's is a YubiKey; node1's
recipient is a plain age key too, where a node's is its TPM's. Everything else is what an
operator's machine does: the export is the shape `nix eval --json .#clusterSecrets` gives
(modules/secrets.nix), and each script is a file, as a built `finalScript` is.
"""

from __future__ import annotations

import dataclasses
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from avc import actions, ui
from avc.context import Ctx
from avc.core import secretstore
from avc.core.secretstore import Store
from avc.errors import AvcError
from avc.flows import secrets as secrets_flow

BASH = shutil.which("bash") or "/bin/sh"
TOKEN = "tok-PLAINTEXT-7f3a"
CREDENTIALS = '{"TunnelSecret": "PLAINTEXT-multi"}\n'


def _bwrap_works() -> bool:
    if shutil.which("bwrap") is None:
        return False
    probe = ["bwrap", "--unshare-all", "--ro-bind", "/nix/store", "/nix/store", "--dev", "/dev", "--proc", "/proc", "--", BASH, "-c", "exit 0"]
    return subprocess.run(probe, capture_output=True).returncode == 0


BWRAP = _bwrap_works()


@pytest.fixture(autouse=True)
def sandbox(monkeypatch):
    """bubblewrap where this machine can make a user namespace (a Nix build's sandbox
    may not let it); the same run without it otherwise."""
    if not BWRAP:
        monkeypatch.setenv(secretstore.SANDBOX_ENV, "none")
    secretstore.forget()
    yield
    secretstore.forget()


@pytest.fixture
def scratch(monkeypatch):
    """The tmpfs the generators run on, in a directory of its own, so that what a run
    leaves behind can be listed."""
    d = Path(tempfile.mkdtemp(prefix="avc-test-", dir=secretstore.runtime_dir()))
    monkeypatch.setattr(secretstore, "runtime_dir", lambda: d)
    yield d
    shutil.rmtree(d, ignore_errors=True)


def keygen(path: Path) -> str:
    subprocess.run(["age-keygen", "-o", str(path)], check=True, capture_output=True)
    return subprocess.run(["age-keygen", "-y", str(path)], check=True, capture_output=True, text=True).stdout.strip()


SCRIPTS = {
    # A key nothing is given, and its public half.
    "ca": 'head -c 16 /dev/urandom | od -An -tx1 | tr -d " \\n" > "$out/key"\necho "cert-of-$(sha256sum < "$out/key" | cut -c1-16)" > "$out/cert"',
    # Reads both through $in.
    "tls": 'echo "signed-by:$(cat "$in/ca/key"):$(cat "$in/ca/cert")" > "$out/key"',
    # What modules/secrets.nix puts before a script for a persisted prompt, then the script.
    "token": 'cat "$prompts/token" > "$out/token"\necho "note=$(cat "$prompts/note")" > "$out/derived"',
    "tunnel": 'cat "$prompts/cloudflared" > "$out/cloudflared"',
    "mesh": 'head -c 8 /dev/urandom | od -An -tx1 | tr -d " \\n" > "$out/private"\necho "pub-of-$(cat "$out/private")" > "$out/public"',
    "luks": 'head -c 8 /dev/urandom | od -An -tx1 | tr -d " \\n" > "$out/passphrase"',
}


def write_script(root: Path, name: str, body: str) -> str:
    d = root / "scripts"
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text(f"#!{BASH}\nset -euo pipefail\nPATH={os.environ['PATH']}\n{body}\n")
    f.chmod(0o755)
    return str(f)


def declare(root: Path, machine: str, name: str, files: dict, share=False, prompts=None, deps=(), validation=None, body=None) -> dict:
    rel = "shared" if share else f"per-machine/{machine}"
    return {
        "share": share,
        "dependencies": list(deps),
        "validationHash": validation,
        "validationStoredAs": f"secrets/{rel}/{name}/.validation-hash",
        "script": write_script(root, name, body or SCRIPTS[name]),
        "scriptDrv": "",
        "runtimeInputs": [],
        "prompts": prompts or {},
        "files": {
            n: {
                "secret": f.get("secret", True),
                "deploy": f.get("deploy", True),
                "neededFor": f.get("neededFor", "services"),
                "storedAs": f"secrets/{rel}/{name}/{n}" + (".age" if f.get("secret", True) else ""),
            }
            for n, f in files.items()
        },
    }


def machine_export(root: Path, machine: str, identities: list, mesh_hash="h1", extra=None) -> dict:
    gens = {
        "ca": declare(root, machine, "ca", {"key": {"deploy": False}, "cert": {"secret": False}}, share=True),
        "tls": declare(root, machine, "tls", {"key": {}}, deps=["ca"]),
        "token": declare(
            root, machine, "token", {"token": {}, "derived": {}}, share=True,
            prompts={"token": {"description": "the issued token", "type": "hidden", "persist": True},
                     "note": {"description": "a note", "type": "line", "persist": False}},
        ),
        "tunnel": declare(
            root, machine, "tunnel", {"cloudflared": {}}, share=True,
            prompts={"cloudflared": {"description": "credentials JSON", "type": "multiline-hidden", "persist": True}},
        ),
        "mesh": declare(root, machine, "mesh", {"private": {}, "public": {"secret": False}}, validation=mesh_hash),
        "luks": declare(root, machine, "luks", {"passphrase": {"neededFor": "partitioning"}}),
    }
    gens.update(extra or {})
    return {"machine": machine, "recipient": None, "masterIdentities": identities, "extraRecipients": [], "generators": gens}


@dataclasses.dataclass
class Site:
    root: Path
    master: Path
    master_pub: str
    node_key: Path
    node_pub: str

    def export(self, **kw) -> dict:
        identities = kw.pop("identities", [{"identity": str(self.master), "pubkey": self.master_pub}])
        return {m: machine_export(self.root, m, identities, **kw) for m in ("node1", "node2")}

    def store(self, **kw) -> Store:
        return Store(self.root, self.export(**kw))

    def plain(self, rel: str, key: Path | None = None) -> str:
        return subprocess.run(["age", "-d", "-i", str(key or self.master), str(self.root / rel)], check=True, capture_output=True, text=True).stdout

    def snapshot(self) -> dict[str, bytes]:
        d = self.root / "secrets"
        return {str(p.relative_to(d)): p.read_bytes() for p in sorted(d.rglob("*")) if p.is_file()}


@pytest.fixture
def site(tmp_path, scratch) -> Site:
    root = tmp_path / "site"
    keys = tmp_path / "keys"
    (root / "secrets" / "recipients").mkdir(parents=True)
    keys.mkdir()
    master_pub = keygen(keys / "master.txt")
    node_pub = keygen(keys / "node1.txt")
    # node1 is installed: it has a recipient. node2 is a placeholder.
    (root / "secrets" / "recipients" / "node1.pub").write_text(node_pub + "\n")
    return Site(root, keys / "master.txt", master_pub, keys / "node1.txt", node_pub)


# token/note, token/token, tunnel/cloudflared: in the order asked.
ANSWERS = ["hello", TOKEN, CREDENTIALS]


def provision(store: Store) -> list[str]:
    plan = store.plan(None, reference="node1")
    with ui.scripted(ANSWERS):
        return store.run(plan)


def decryptions(store: Store, monkeypatch) -> list[str]:
    """The files the master identity is asked to decrypt from here on: each is a touch."""
    seen: list[str] = []
    real = store._age

    def counted(args, data, what):
        if args[0] == "-d":
            seen.append(Path(args[-1]).name)
        return real(args, data, what)

    monkeypatch.setattr(store, "_age", counted)
    return seen


# ── a fresh site ─────────────────────────────────────────────────────────────


def test_the_order_is_the_dependencies_and_a_shared_generator_is_one_unit(site):
    plan = site.store().plan(None, reference="node1")
    labels = [u.label for u in plan]
    # Shared ones once, not once per node; per-machine ones on each.
    assert sorted(labels) == sorted(
        ["ca", "token", "tunnel", *(f"{m}:{g}" for m in ("node1", "node2") for g in ("tls", "mesh", "luks"))]
    )
    assert labels.index("ca") < labels.index("node1:tls") and labels.index("ca") < labels.index("node2:tls")


def test_a_fresh_site_is_generated_encrypted_and_never_decrypted(site, scratch, monkeypatch):
    store = site.store()
    touches = decryptions(store, monkeypatch)
    written = provision(store)
    assert "secrets/shared/ca/key.age" in written and "secrets/per-machine/node2/tls/key.age" in written

    # Secrets are age files to the master key; public files are as the script wrote them.
    for rel in written:
        data = (site.root / rel).read_bytes()
        assert data.startswith(b"age-encryption.org/v1") == rel.endswith(".age"), rel
    ca_key = site.plain("secrets/shared/ca/key.age")
    assert len(ca_key) == 32
    cert = (site.root / "secrets/shared/ca/cert").read_text()
    assert cert.startswith("cert-of-") and len(cert) == 25

    # $in: a secret and a public file of the dependency, and the one CA for both nodes.
    for m in ("node1", "node2"):
        assert site.plain(f"secrets/per-machine/{m}/tls/key.age") == f"signed-by:{ca_key}:{cert}"
    # Each node its own.
    assert site.plain("secrets/per-machine/node1/mesh/private.age") != site.plain("secrets/per-machine/node2/mesh/private.age")

    # What the files were made from, and who they are encrypted to.
    assert (site.root / "secrets/per-machine/node1/mesh/.validation-hash").read_text() == "h1\n"
    assert not (site.root / "secrets/shared/ca/.validation-hash").exists()
    assert (site.root / "secrets/.master-recipients").read_text() == site.master_pub + "\n"

    # Nothing was decrypted: every input of this run was made in it.
    assert touches == []
    # Nothing is left on the tmpfs, and no plaintext is in the repository.
    assert list(scratch.iterdir()) == []
    everything = b"".join(p.read_bytes() for p in site.root.rglob("*") if p.is_file() and "scripts" not in p.parts)
    for secret in (ca_key, TOKEN, "PLAINTEXT-multi", site.plain("secrets/per-machine/node1/luks/passphrase.age")):
        assert secret.encode() not in everything

    # And then there is nothing to do.
    assert store.plan(None) == []
    assert all(store.status(m).clean for m in ("node1", "node2"))


def test_prompts_are_asked_by_type_and_a_persisted_one_is_its_file(site, monkeypatch):
    store = site.store()
    asked = []

    def ask(label, p):
        asked.append((label, p.name, p.type, p.persist))
        return {"token": TOKEN, "note": "hello", "cloudflared": CREDENTIALS}[p.name]

    store.run(store.plan(None, reference="node1"), ask=ask)
    assert asked == [
        ("token", "note", "line", False),
        ("token", "token", "hidden", True),
        ("tunnel", "cloudflared", "multiline-hidden", True),
    ]
    assert site.plain("secrets/shared/token/token.age") == TOKEN  # the bytes typed, no newline added
    assert site.plain("secrets/shared/token/derived.age") == "note=hello\n"
    assert site.plain("secrets/shared/tunnel/cloudflared.age") == CREDENTIALS
    # A prompt that is not persisted is nowhere but in what the script made of it.
    assert not (site.root / "secrets/shared/token/note.age").exists()

    # Through the terminal's own prompts: hidden, a line, and several hidden lines.
    kinds = []
    monkeypatch.setattr(ui, "secret", lambda q: kinds.append("secret") or "x")
    monkeypatch.setattr(ui, "text", lambda q, **k: kinds.append("text") or "x")
    monkeypatch.setattr(ui, "multiline", lambda q, hidden=False: kinds.append(f"multiline hidden={hidden}") or "x")
    for unit in store.plan([("node1", "token"), ("node1", "tunnel")], regenerate=True):
        for p in unit.gen.prompts:
            secretstore.ask_prompt(unit.label, p)
    assert kinds == ["text", "secret", "multiline hidden=True"]


# ── making again ─────────────────────────────────────────────────────────────


def test_a_changed_validation_hash_makes_the_generator_again(site):
    provision(site.store())
    before = site.plain("secrets/per-machine/node1/mesh/private.age")
    tls = site.plain("secrets/per-machine/node1/tls/key.age")

    store = site.store(mesh_hash="h2")
    assert store.status("node1").outdated == ["mesh"]
    plan = store.plan(None)
    assert [u.label for u in plan] == ["node1:mesh", "node2:mesh"]
    store.run(plan)
    assert site.plain("secrets/per-machine/node1/mesh/private.age") != before
    assert (site.root / "secrets/per-machine/node1/mesh/.validation-hash").read_text() == "h2\n"
    assert site.plain("secrets/per-machine/node1/tls/key.age") == tls
    assert store.plan(None) == []


def test_files_with_no_record_of_what_they_were_made_from_are_not_called_current(site):
    provision(site.store())
    (site.root / "secrets/per-machine/node1/mesh/.validation-hash").unlink()
    assert site.store().status("node1").outdated == ["mesh"]


def test_what_reads_a_regenerated_generator_is_regenerated_with_it(site, monkeypatch):
    provision(site.store())
    store = site.store()
    touches = decryptions(store, monkeypatch)
    plan = store.plan([("node1", "ca")], regenerate=True)
    assert [u.label for u in plan] == ["ca", "node1:tls", "node2:tls"]
    store.run(plan)
    ca_key = site.plain("secrets/shared/ca/key.age")
    assert site.plain("secrets/per-machine/node2/tls/key.age") == f"signed-by:{ca_key}:{(site.root / 'secrets/shared/ca/cert').read_text()}"
    # The new CA went to both from this run, not from the repository.
    assert touches == []


def test_an_input_from_the_repository_is_decrypted_once_for_every_generator_that_reads_it(site, monkeypatch):
    provision(site.store())
    store = site.store()
    touches = decryptions(store, monkeypatch)
    store.run(store.plan([("node1", "tls"), ("node2", "tls")], regenerate=True))
    assert touches == ["key.age"]
    # A target that needs nothing is not run without `regenerate`.
    assert store.plan([("node1", "tls")]) == []


def test_a_generator_that_reads_one_never_generated_is_refused(site):
    store = site.store()
    with pytest.raises(AvcError, match="ca/cert is needed as an input and has not been generated"):
        # Not through plan(): that would have put the CA first.
        store.run([u for u in store.plan(None) if u.label == "node1:tls"])
    assert site.snapshot() == {"recipients/node1.pub": site.node_pub.encode() + b"\n"}


# ── a run that fails ─────────────────────────────────────────────────────────

BROKEN = {
    "fails": ('echo -n half-a-PLAINTEXT-secret > "$out/a"\necho "it broke" >&2\nexit 3', "generator node1:broken failed \\(3\\)"),
    "missing": ('echo x > "$out/a"', "did not write b"),
    "extra": ('echo x > "$out/a"; echo x > "$out/b"; echo x > "$out/c"', "wrote c, which it does not declare"),
    "symlink": ('echo x > "$out/a"; ln -s /etc/passwd "$out/b"', "b is not a regular file"),
    "directory": ('echo x > "$out/a"; mkdir "$out/b"', "b is not a regular file"),
}


@pytest.mark.parametrize("how", sorted(BROKEN))
def test_a_failing_generator_leaves_nothing_behind(site, scratch, how):
    body, message = BROKEN[how]
    provision(site.store())
    before = site.snapshot()

    def extra(m):
        # After `ca` in the order, and `ca` is regenerated in the same run.
        return {"broken": declare(site.root, m, "broken", {"a": {}, "b": {}}, deps=["ca"], body=body)}

    export = {m: machine_export(site.root, m, [{"identity": str(site.master), "pubkey": site.master_pub}], extra=extra(m)) for m in ("node1", "node2")}
    store = Store(site.root, export)
    plan = store.plan([("node1", "ca")], regenerate=True)
    assert [u.label for u in plan][:1] == ["ca"] and "node1:broken" in [u.label for u in plan]
    with pytest.raises(AvcError, match=message):
        store.run(plan)
    # Not the CA that had already run, not half of the broken one, no stray temporary file.
    assert site.snapshot() == before
    assert list(scratch.iterdir()) == []


def test_plaintext_is_refused_a_disk(monkeypatch):
    monkeypatch.setattr(secretstore, "filesystem", lambda p: "ext4")
    with pytest.raises(AvcError, match="no tmpfs to run a generator on"):
        secretstore.runtime_dir()


def test_a_generator_runs_on_a_tmpfs_in_a_directory_of_its_own(site, scratch):
    assert secretstore.filesystem(scratch) in secretstore.RAM_FILESYSTEMS
    body = 'stat -c "%a %n" "$out/.." > "$out/where"'
    export = site.export(extra=None)
    export["node1"]["generators"]["where"] = declare(site.root, "node1", "where", {"where": {"secret": False}}, body=body)
    store = Store(site.root, export)
    store.run(store.plan([("node1", "where")]))
    mode, where = (site.root / "secrets/per-machine/node1/where/where").read_text().split()
    assert Path(where).resolve().parent == scratch and not Path(where).resolve().exists()
    if BWRAP:
        # Inside the sandbox the directory is a mount point of the sandbox's own.
        assert mode in ("700", "755")
    else:
        assert mode == "700"


@pytest.mark.skipif(not BWRAP, reason="this machine cannot make a user namespace for bubblewrap")
def test_the_sandbox_has_no_network_no_environment_and_one_place_to_write(site, monkeypatch):
    monkeypatch.setenv("LEAKED", "from-the-operators-shell")
    body = "\n".join([
        'grep -c : /proc/net/dev > "$out/interfaces"',
        'id -u > "$out/uid"; ssh-keygen -q -t ed25519 -N "" -f /tmp/k 2>/dev/null && echo yes > "$out/has-a-name" || echo no > "$out/has-a-name"',
        'echo "${LEAKED:-unset}" > "$out/env"',
        '(echo x > "$in/ca/cert") 2>/dev/null && echo yes > "$out/wrote-in" || echo no > "$out/wrote-in"',
        '(ls /home /root /etc) >/dev/null 2>&1 && echo yes > "$out/sees-host" || echo no > "$out/sees-host"',
    ])
    files = {n: {"secret": False} for n in ("interfaces", "env", "wrote-in", "sees-host", "uid", "has-a-name")}
    export = site.export()
    for m in export:
        export[m]["generators"]["probe"] = declare(site.root, m, "probe", files, deps=["ca"], body=body)
    store = Store(site.root, export)
    with ui.scripted([]):
        store.run(store.plan([("node1", "ca"), ("node1", "probe")], regenerate=True))
    got = {n: (site.root / f"secrets/per-machine/node1/probe/{n}").read_text().strip() for n in files}
    # Loopback and nothing else; nothing of the operator's shell; $in read-only; no host
    # files; a user of its own, with a passwd entry (ssh-keygen refuses to run without one).
    has_name = "yes" if shutil.which("ssh-keygen") else "no"
    assert got == {"interfaces": "1", "env": "unset", "wrote-in": "no", "sees-host": "no", "uid": "1000", "has-a-name": has_name}


# ── values ───────────────────────────────────────────────────────────────────


def test_set_and_get_and_a_value_is_decrypted_once(site, monkeypatch):
    store = site.store()
    touches = decryptions(store, monkeypatch)
    store.set("node1", "token/token", b"issued-PLAINTEXT")
    assert site.plain("secrets/shared/token/token.age") == "issued-PLAINTEXT"
    assert store.get("node1", "token/token") == b"issued-PLAINTEXT"
    assert touches == []  # what this run wrote, it knows

    again = site.store()
    touches = decryptions(again, monkeypatch)
    assert again.get("node1", "token/token") == b"issued-PLAINTEXT"
    assert again.get("node2", "token/token") == b"issued-PLAINTEXT"
    assert touches == ["token.age"]
    # A public file is read, not decrypted; a value that is not there is said plainly.
    again.set("node1", "mesh/public", b"pub\n")
    assert again.get("node1", "mesh/public") == b"pub\n" and (site.root / "secrets/per-machine/node1/mesh/public").read_bytes() == b"pub\n"
    with pytest.raises(AvcError, match="has no value for node2"):
        again.get("node2", "mesh/private")
    with pytest.raises(AvcError, match="has no file 'nope'"):
        again.get("node1", "mesh/nope")


def test_a_generator_set_by_hand_is_whole_once_its_last_file_is(site):
    store = site.store()
    store.set("node1", "mesh/private", b"k")
    assert not (site.root / "secrets/per-machine/node1/mesh/.validation-hash").exists()
    store.set("node1", "mesh/public", b"p")
    assert (site.root / "secrets/per-machine/node1/mesh/.validation-hash").read_text() == "h1\n"
    assert "mesh" not in store.status("node1").outdated and not [v for v in store.status("node1").missing if v.startswith("mesh/")]


def test_an_identity_file_names_its_recipient_as_the_plugin_wrote_it(site):
    stub = site.root / "secrets" / "master" / "yubikey.pub"
    stub.parent.mkdir()
    stub.write_text("#       Serial: 1, Slot: 1\n#    Recipient: age1yubikey1qexample\nAGE-PLUGIN-YUBIKEY-1EXAMPLE\n")
    store = site.store(identities=[{"identity": "secrets/master/yubikey.pub", "pubkey": None}, {"identity": str(site.master), "pubkey": site.master_pub}])
    assert store.master_recipient_args() == ["-r", "age1yubikey1qexample", "-r", site.master_pub]
    # Relative to the repository, and the key that is plugged in first.
    assert store._identity_args() == ["-i", str(stub), "-i", str(site.master)]
    os.environ[secretstore.PRIMARY_ENV] = site.master_pub
    try:
        assert store._identity_args() == ["-i", str(site.master), "-i", str(stub)]
    finally:
        del os.environ[secretstore.PRIMARY_ENV]


def test_new_master_recipients_are_seen_and_fixed(site, tmp_path, monkeypatch):
    provision(site.store())
    second = tmp_path / "keys" / "second.txt"
    second_pub = keygen(second)
    both = [{"identity": str(site.master), "pubkey": site.master_pub}, {"identity": str(second), "pubkey": second_pub}]

    store = site.store(identities=both)
    assert "ca/key" in store.status("node1").unfixed and "ca/cert" not in store.status("node1").unfixed
    # A new file among the old ones does not make the record say more than is true.
    store.set("node1", "token/token", b"new")
    assert (site.root / "secrets/.master-recipients").read_text() == site.master_pub + "\n"
    with pytest.raises(subprocess.CalledProcessError):
        site.plain("secrets/shared/ca/key.age", second)

    ca_key = site.plain("secrets/shared/ca/key.age")
    touches = decryptions(store, monkeypatch)
    count = store.fix()
    assert count == len(store.sources()) and len(touches) == count - 1  # token/token was written by this run
    assert site.plain("secrets/shared/ca/key.age", second) == ca_key == site.plain("secrets/shared/ca/key.age")
    assert (site.root / "secrets/.master-recipients").read_text().split() == sorted([site.master_pub, second_pub])
    assert site.store(identities=both).status("node1").unfixed == []


# ── what a node is given ─────────────────────────────────────────────────────


def test_rekeyed_names_are_agenix_rekeys():
    """The committed fixture site (tests/fixtures/agenix): its rekeyed files were written
    by agenix-rekey's own app, and tests/secrets-tpm.nix holds that app to these names."""
    fixture = os.environ.get("AVC_AGENIX_FIXTURE")
    root = Path(fixture) if fixture else Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "agenix"
    if not (root / "secrets").exists():
        pytest.skip("tests/fixtures/agenix is not here: not a checkout, and AVC_AGENIX_FIXTURE is not set")
    recipient = (root / "secrets/recipients/node1.pub").read_text().removesuffix("\n")
    committed = {str(p.relative_to(root / "secrets/rekeyed/node1")) for p in (root / "secrets/rekeyed/node1").rglob("*.age")}
    ours = {
        secretstore.rekeyed_name(recipient, (root / f"secrets/{name}.age").read_bytes(), name)
        for name in ("shared/canary/value", "per-machine/node1/wg-ctrl/private")
    }
    assert ours == committed and len(committed) == 2


def test_a_node_is_given_what_it_reads_and_nothing_else(site, monkeypatch):
    store = site.store()
    provision(store)
    touches = decryptions(store, monkeypatch)
    written = store.fill_rekeyed()
    d = site.root / "secrets/rekeyed/node1"
    names = sorted(str(p.relative_to(d)).split("-", 1)[1] for p in d.rglob("*.age"))
    # Not the CA's key (deploy = false), not the LUKS passphrase (read at install), no public file.
    assert names == [
        "per-machine/node1/mesh/private.age",
        "per-machine/node1/tls/key.age",
        "shared/token/derived.age",
        "shared/token/token.age",
        "shared/tunnel/cloudflared.age",
    ]
    assert len(written) == 5 and touches == []
    # node2 has no recipient: nothing is encrypted to nobody.
    assert not (site.root / "secrets/rekeyed/node2").exists()
    # node1's own key opens them, to the values the master key opens; the master key does not.
    token = next(p for p in d.rglob("*.age") if p.name == "token.age")
    assert site.plain(str(token), site.node_key) == TOKEN == site.plain("secrets/shared/token/token.age")
    with pytest.raises(subprocess.CalledProcessError):
        site.plain(str(token))
    assert store.fill_rekeyed() == []

    # A new value: its rekeyed file is new, and the old value's is gone.
    store.set("node1", "token/token", b"rotated")
    r = store.readiness("node1")
    assert r.unrekeyed == ("token/token",) and len(r.orphaned) == 1 and not r.ok
    store.fill_rekeyed()
    assert not token.exists()
    token = next(p for p in d.rglob("*.age") if p.name == "token.age")
    assert site.plain(str(token), site.node_key) == "rotated"
    assert store.readiness("node1").ok and touches == []

    # From a cold start a source is decrypted once, whatever number of files is missing.
    shutil.rmtree(d)
    cold = site.store()
    touches = decryptions(cold, monkeypatch)
    assert len(cold.fill_rekeyed()) == 5 and len(touches) == 5


# ── the commands ─────────────────────────────────────────────────────────────


@pytest.fixture
def cluster(site, index, monkeypatch):
    """A Ctx over the site, with the runner's store given the export instead of an
    evaluation, the flake's `agenix rekey` recorded, and the ship pipeline stubbed."""
    ctx = Ctx(site.root)
    ctx.__dict__["index"] = dataclasses.replace(index, nodes={n: dict(index.nodes["node1"]) for n in ("node1", "node2")})
    store = site.store()
    secretstore._stores[site.root] = store
    calls = {"agenix": 0, "shipped": []}
    monkeypatch.setattr(secretstore, "agenix_rekey", lambda root: calls.__setitem__("agenix", calls["agenix"] + 1))
    monkeypatch.setattr(secrets_flow.ship, "ship", lambda ctx, message, **k: calls["shipped"].append((message, k.get("paths"))) or True)
    return ctx, store, calls


def provision_before_install(ctx: Ctx, site: Site) -> None:
    """As a site is made: every node's secrets first, then node1 is installed and its
    recipient committed. (Its LUKS passphrase is never generated after that.)"""
    recipient = site.root / "secrets/recipients/node1.pub"
    recipient.unlink()
    ctx.__dict__.pop("installed", None)
    with ui.scripted([True, *ANSWERS]):
        actions.find("secrets", "provision").run(ctx, {})
    recipient.write_text(site.node_pub + "\n")
    ctx.__dict__.pop("installed", None)


def test_installed_is_having_a_recipient(cluster):
    ctx, _store, _calls = cluster
    assert ctx.installed == ["node1"]


def test_check_refuses_until_everything_is_generated_and_rekeyed(cluster, site):
    ctx, store, calls = cluster
    check = actions.find("secrets", "check")
    with pytest.raises(AvcError, match="would not reach their node"):
        check.run(ctx, {"node": "node1"})

    # Generated but not rekeyed: a node would build, switch, and have none of them.
    provision(store)
    with pytest.raises(AvcError, match="5 secret\\(s\\) would not reach"):
        check.run(ctx, {"node": "node1"})
    problems = secrets_flow.readiness_problems(ctx, ["node1"], strict=True)
    assert any("token/token is not rekeyed" in p for p in problems)

    actions.find("secrets", "rekey").run(ctx, {})
    assert calls["agenix"] == 1 and calls["shipped"] == [("chore(secrets): rekey", ["secrets/"])]
    check.run(ctx, {"node": "node1"})
    # Every node: node2 has no recipient, which is a node not installed yet.
    check.run(ctx, {})
    # Asked for by name, a node that could decrypt nothing is refused.
    with pytest.raises(AvcError, match="would not reach"):
        check.run(ctx, {"node": "node2"})

    # One source changed behind avc's back (a merge, `agenix edit`): stale.
    src = site.root / "secrets/shared/token/token.age"
    src.write_bytes(subprocess.run(["age", "-e", "-r", site.master_pub], input=b"edited", capture_output=True, check=True).stdout)
    with pytest.raises(AvcError, match="1 secret\\(s\\) would not reach"):
        check.run(ctx, {})
    # And one that was never generated, on the node with no recipient.
    (site.root / "secrets/per-machine/node2/tls/key.age").unlink()
    assert secrets_flow.readiness_problems(ctx, ["node2"], strict=False) == ["node2: tls/key is not generated (`avc secrets provision`)"]


def test_provision_generates_and_ships_and_an_install_is_followed_by_a_rekey(cluster, site):
    ctx, store, calls = cluster
    provision_before_install(ctx, site)
    # No node had a recipient: there was nothing to rekey, and the flake's app was not run.
    assert calls["agenix"] == 0 and calls["shipped"][0][1] == ["secrets/"]
    assert all(store.status(m).clean for m in ("node1", "node2"))
    assert ctx.installed == ["node1"]
    with pytest.raises(AvcError, match="would not reach"):
        actions.find("secrets", "check").run(ctx, {})
    actions.find("secrets", "rekey").run(ctx, {})
    assert calls["agenix"] == 1 and store.readiness("node1").ok
    actions.find("secrets", "check").run(ctx, {})
    # Nothing is left to provision.
    actions.find("secrets", "provision").run(ctx, {})
    assert len(calls["shipped"]) == 2


def test_provision_holds_what_an_installed_node_holds(cluster, site):
    ctx, store, calls = cluster
    provision_before_install(ctx, site)
    actions.find("secrets", "rekey").run(ctx, {})
    before = site.snapshot()
    # node1 is installed, and its LUKS passphrase is gone from the working tree; node2's too.
    for m in ("node1", "node2"):
        (site.root / f"secrets/per-machine/{m}/luks/passphrase.age").unlink()
    with ui.scripted([True]), pytest.raises(AvcError, match="not provisioned on node1"):
        actions.find("secrets", "provision").run(ctx, {})
    after = site.snapshot()
    assert "per-machine/node1/luks/passphrase.age" not in after
    assert "per-machine/node2/luks/passphrase.age" in after
    assert {k: v for k, v in after.items() if "luks" not in k} == {k: v for k, v in before.items() if "luks" not in k}


def test_rotate_regenerates_what_derives_from_it_and_refuses_what_must_not_change(cluster, site):
    ctx, store, calls = cluster
    provision_before_install(ctx, site)
    before = site.snapshot()

    with pytest.raises(AvcError, match="refusing to regenerate luks"):
        actions.find("secrets", "rotate").run(ctx, {"generator": "luks"})
    assert site.snapshot() == before

    # secrets/policy.toml: a file marked never, and a generator a dependent of which is.
    (site.root / "secrets/policy.toml").write_text('[[rule]]\nmatch = "tls"\nnever = ["key"]\nreason = "pinned by peers"\n')
    for generator in ("tls", "ca"):
        with pytest.raises(AvcError, match=f"refusing to regenerate {generator}"):
            actions.find("secrets", "rotate").run(ctx, {"generator": generator})
    assert {k: v for k, v in site.snapshot().items() if k != "policy.toml"} == before

    (site.root / "secrets/policy.toml").unlink()
    old = site.plain("secrets/shared/ca/key.age")
    with ui.scripted([True]):
        actions.find("secrets", "rotate").run(ctx, {"generator": "ca"})
    new = site.plain("secrets/shared/ca/key.age")
    assert new != old
    assert site.plain("secrets/per-machine/node1/tls/key.age") == f"signed-by:{new}:{(site.root / 'secrets/shared/ca/cert').read_text()}"
    assert calls["shipped"][-1] == ("chore(secrets): rotate ca", ["secrets/"])
    # The nodes were given the new certificates' keys before anything shipped.
    assert store.readiness("node1").ok and calls["agenix"] == 1


def test_set_and_reveal_through_the_commands(cluster, site, capsys):
    ctx, store, calls = cluster
    with ui.scripted(["prompt", "issued-by-hand"]):
        actions.find("secrets", "set").run(ctx, {"var": "token/token"})
    assert site.plain("secrets/shared/token/token.age") == "issued-by-hand"
    assert calls["agenix"] == 1 and calls["shipped"][-1] == ("chore(secrets): set token/token", ["secrets/"])
    with ui.scripted([True]):
        actions.find("secrets", "reveal").run(ctx, {"var": "token/token"})
    assert capsys.readouterr().out == "issued-by-hand"  # the bytes, for a pipe
    with pytest.raises(AvcError, match="per machine"):
        actions.find("secrets", "reveal").run(ctx, {"var": "mesh/private"})
    # The disk-bound ones ask for the name back before anything is written.
    with ui.scripted(["no"]), pytest.raises(Exception) as refused:
        actions.find("secrets", "set").run(ctx, {"var": "node1:luks/passphrase"})
    assert refused.type.__name__ == "Aborted"
    assert not (site.root / "secrets/per-machine/node1/luks/passphrase.age").exists()
