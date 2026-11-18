"""Shared generators go through one machine; per-machine ones, machine by machine."""

from __future__ import annotations

import dataclasses

import pytest

from avc import actions, ui
from avc.core import secretstore
from avc.core.secretstore import GeneratorInfo, SecretFile, Summary
from avc.errors import AvcError
from avc.flows import secrets

SHARED = GeneratorInfo("nomad-ca", True, (SecretFile("ca.crt", False, True),), (), ())
PER_MACHINE = GeneratorInfo("wg-ctrl", False, (SecretFile("private", True, True),), (), ())
INITRD_SSH = GeneratorInfo("initrd-ssh", False, (SecretFile("ssh_host_ed25519_key", True, True),), (), ())
EMERGENCY = GeneratorInfo("emergency-access", False, (SecretFile("password", True, False),), (), ())
LUKS = GeneratorInfo("luks", False, (SecretFile("passphrase", True, True),), (), ())


@pytest.fixture
def fleet(ctx, index, monkeypatch):
    nodes = {n: dict(index.nodes["node1"]) for n in ("node1", "node2", "node3")}
    ctx.__dict__["index"] = dataclasses.replace(index, nodes=nodes)
    # node3 is opted out: it has no boot generators.
    boot = [PER_MACHINE, INITRD_SSH, EMERGENCY, LUKS]
    gens = {"node1": [SHARED, *boot], "node2": [SHARED, *boot], "node3": [SHARED]}
    monkeypatch.setattr(secretstore, "generators", lambda root, machine: gens[machine])
    monkeypatch.setattr(secrets, "cloud_issued", lambda ctx: set())
    return ctx


@pytest.fixture
def generated(monkeypatch):
    """What the runner was asked for: (targets, regenerate) per call. Each is followed by a
    rekey, or a node would be deployed without the new value."""
    calls = []
    rekeyed = []

    def generate(root, targets=None, regenerate=False, reference=None):
        calls.append((targets, regenerate))
        return []

    monkeypatch.setattr(secretstore, "generate", generate)
    monkeypatch.setattr(secretstore, "rekey", lambda root: rekeyed.append(len(calls)))
    monkeypatch.setattr(secrets.ship, "ship", lambda *a, **k: True)
    yield calls
    assert rekeyed == list(range(1, len(calls) + 1))


def test_a_shared_generator_rotates_on_one_machine_alone(fleet, generated):
    with ui.scripted([True]):
        actions.find("secrets", "rotate").run(fleet, {"generator": "nomad-ca"})
    assert generated == [([("node1", "nomad-ca")], True)]


def test_a_per_machine_generator_rotates_on_every_machine_that_has_it(fleet, generated):
    with ui.scripted([True]):
        actions.find("secrets", "rotate").run(fleet, {"generator": "wg-ctrl"})
    assert generated == [([("node1", "wg-ctrl"), ("node2", "wg-ctrl")], True)]


def test_the_disk_bound_generators_are_never_rotated(fleet, generated):
    with pytest.raises(AvcError, match="refusing to regenerate luks"):
        actions.find("secrets", "rotate").run(fleet, {"generator": "luks"})
    assert generated == []


@pytest.mark.parametrize("generator", ["initrd-ssh", "emergency-access"])
def test_what_the_node_holds_is_not_rotated_from_here(fleet, generated, generator):
    # A new initrd host key would reach only the repository: every node's initrd keeps
    # serving the one placed at install, and `avc boot unlock` then refuses them all.
    with pytest.raises(AvcError, match=f"refusing to regenerate {generator}"):
        actions.find("secrets", "rotate").run(fleet, {"generator": generator})
    assert generated == []


@pytest.mark.parametrize("generator", ["juicefs-rsa", "restic"])
def test_what_opens_existing_data_is_never_rotated_even_without_a_policy(fleet, generated, monkeypatch, generator):
    # No secrets/policy.toml at all, as a site made from the template starts: the refusal is
    # in code, not in the site's policy.
    gens = {m: [*g, GeneratorInfo(generator, True, (SecretFile("x", True, True),), (), ())] for m, g in
            {m: secretstore.generators(fleet.root, m) for m in ("node1", "node2", "node3")}.items()}
    monkeypatch.setattr(secretstore, "generators", lambda root, machine: gens[machine])
    assert not (fleet.root / "secrets" / "policy.toml").exists()
    with pytest.raises(AvcError, match=f"refusing to regenerate {generator}"):
        actions.find("secrets", "rotate").run(fleet, {"generator": generator})
    assert generated == []


def test_the_inventory_does_not_call_the_initrd_key_safe(fleet, monkeypatch):
    rows = {}
    monkeypatch.setattr(secretstore, "status", lambda root, m: Summary([], [], []))
    monkeypatch.setattr(secrets, "_age_days", lambda root, s: 400)
    monkeypatch.setattr(ui, "table", lambda title, cols, data: rows.update({r[0]: r[5] for r in data}))
    actions.find("secrets", "inventory").run(fleet, {})
    assert "manual" in rows["initrd-ssh"] and "manual" in rows["emergency-access"]
    assert "never" in rows["luks"]
    assert "safe" not in rows["initrd-ssh"]


def test_per_machine_vars_are_named_by_machine(fleet):
    ids = secrets._var_ids(fleet)
    assert "nomad-ca/ca.crt" in ids
    assert {"node1:initrd-ssh/ssh_host_ed25519_key", "node2:initrd-ssh/ssh_host_ed25519_key"} <= set(ids)
    assert not any(i.startswith("node3:initrd-ssh") for i in ids)
    assert secrets.parse_var(fleet, "node2:luks/passphrase") == ("node2", "luks/passphrase")
    assert secrets.parse_var(fleet, "nomad-ca/ca.crt") == ("node1", "nomad-ca/ca.crt")
    with pytest.raises(AvcError, match="per machine"):
        secrets.parse_var(fleet, "luks/passphrase")


def test_provision_generates_on_each_machine_that_needs_it(fleet, generated, monkeypatch):
    statuses = {
        "node1": Summary([], [], []),
        "node2": Summary(["initrd-ssh/ssh_host_ed25519_key"], [], []),
        "node3": Summary([], [], []),
    }
    monkeypatch.setattr(secretstore, "status", lambda root, m: statuses[m])
    with ui.scripted([True]):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [([("node2", "initrd-ssh")], False)]


def test_provision_leaves_a_key_pair_the_provider_issues_to_cloud_apply(fleet, generated, monkeypatch):
    # With topology.cloud, nobody has ovh-s3 to type before the first `avc cloud apply`.
    statuses = {
        "node1": Summary(["ovh-s3/access-key", "ovh-s3/secret-key", "backup-target/access-key"], [], []),
        "node2": Summary([], [], []),
        "node3": Summary([], [], []),
    }
    monkeypatch.setattr(secretstore, "status", lambda root, m: statuses[m])
    monkeypatch.setattr(secrets, "cloud_issued", lambda ctx: {"ovh-s3", "backup-state-target"})
    with ui.scripted([True]):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [([("node1", "backup-target")], False)]


def test_provision_with_only_issued_pairs_missing_asks_for_nothing(fleet, generated, monkeypatch):
    statuses = {m: Summary(["ovh-s3/access-key"] if m == "node1" else [], [], []) for m in ("node1", "node2", "node3")}
    monkeypatch.setattr(secretstore, "status", lambda root, m: statuses[m])
    monkeypatch.setattr(secrets, "cloud_issued", lambda ctx: {"ovh-s3"})
    actions.find("secrets", "provision").run(fleet, {})
    assert generated == []


def test_provision_asks_for_the_pair_where_no_provider_is_named(fleet, generated, monkeypatch):
    statuses = {m: Summary(["ovh-s3/access-key"] if m == "node1" else [], [], []) for m in ("node1", "node2", "node3")}
    monkeypatch.setattr(secretstore, "status", lambda root, m: statuses[m])
    with ui.scripted([True]):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [([("node1", "ovh-s3")], False)]


@pytest.mark.parametrize(
    "summary",
    [
        Summary([], [], ["luks"]),
        Summary(["volume-identity/secret"], [], []),
        Summary(["initrd-ssh/ssh_host_ed25519_key"], [], []),
        Summary([], [], ["emergency-access"]),
    ],
)
def test_provision_does_not_make_a_node_held_secret_anew_on_an_installed_node(fleet, generated, monkeypatch, summary):
    # Generating it for node1 would make it anew, and node1 is installed: its disks, its
    # initrd and its ESP all still have the old value. node2 is not installed yet, so it is
    # generated there as usual, and the run still fails for node1.
    statuses = {"node1": summary, "node2": summary, "node3": Summary([], [], [])}
    monkeypatch.setattr(secretstore, "status", lambda root, m: statuses[m])
    assert fleet.installed == ["node1"]
    with ui.scripted([True]), pytest.raises(AvcError, match="not provisioned on node1"):
        actions.find("secrets", "provision").run(fleet, {})
    name = (summary.missing or summary.outdated)[0].split("/")[0]
    assert generated == [([("node2", name)], False)]


@pytest.mark.parametrize("generator", ["juicefs-rsa", "restic", "blog-jfs"])
def test_provision_does_not_make_what_opens_existing_data_through_another_machine(fleet, generated, monkeypatch, generator):
    # A shared generator is every node's. node1 is installed and holds the data the old
    # value opens; that node2 is not installed must not let the fleet's value be made anew
    # through node2. What node2 alone is short of is still made.
    gens = {m: [*secretstore.generators(fleet.root, m), GeneratorInfo(generator, True, (SecretFile("x", True, True),), (), ())]
            for m in ("node1", "node2", "node3")}
    monkeypatch.setattr(secretstore, "generators", lambda root, machine: gens[machine])
    shared = Summary([f"{generator}/x"], [], [])
    statuses = {"node1": shared, "node2": Summary([f"{generator}/x", "wg-ctrl/private"], [], []), "node3": shared}
    monkeypatch.setattr(secretstore, "status", lambda root, m: statuses[m])
    with ui.scripted([True]), pytest.raises(AvcError, match="not provisioned on node1"):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [([("node2", "wg-ctrl")], False)]


def test_provision_makes_what_reads_a_missing_generator_too(fleet, generated, monkeypatch):
    # nomad-tls is issued by nomad-ca: a new CA with the old certificates is a cluster that
    # refuses itself. And luks reading a missing generator on an installed node is held.
    tls = GeneratorInfo("nomad-tls", False, (SecretFile("agent.key", True, True),), (), ("nomad-ca",))
    gens = {m: [*secretstore.generators(fleet.root, m), tls] for m in ("node1", "node2", "node3")}
    monkeypatch.setattr(secretstore, "generators", lambda root, machine: gens[machine])
    monkeypatch.setattr(secretstore, "status", lambda root, m: Summary(["nomad-ca/ca.crt"], [], []))
    with ui.scripted([True]):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [([(m, g) for m in ("node1", "node2", "node3") for g in ("nomad-ca", "nomad-tls")], False)]


def test_a_per_machine_path_names_its_machine(tmp_path):
    # Where a file is kept comes from the flake (lib/secrets-layout.nix), per machine.
    f = SecretFile("ssh_host_ed25519_key", True, True, "partitioning", "secrets/per-machine/node2/initrd-ssh/ssh_host_ed25519_key.age")
    gen = GeneratorInfo("initrd-ssh", False, (f,))
    assert gen.path(tmp_path, f) == tmp_path / "secrets/per-machine/node2/initrd-ssh/ssh_host_ed25519_key.age"
    assert f.age_name == "per-machine/node2/initrd-ssh/ssh_host_ed25519_key" and not f.lowered


# ── replacing a data-bound key, after a node left the operators' control ─────


@pytest.fixture
def with_data_keys(fleet, monkeypatch):
    extra = [GeneratorInfo(n, True, (SecretFile("x", True, True),), (), ()) for n in ("juicefs-rsa", "restic", "blog-jfs")]
    gens = {m: [*secretstore.generators(fleet.root, m), *extra] for m in ("node1", "node2", "node3")}
    monkeypatch.setattr(secretstore, "generators", lambda root, machine: gens[machine])
    return fleet


@pytest.mark.parametrize("generator", ["juicefs-rsa", "restic", "blog-jfs"])
def test_replace_makes_a_data_bound_key_only_for_its_name_typed_back(with_data_keys, generated, generator):
    # What `rotate` and `provision` refuse for good has one way through, and it is typed.
    with ui.scripted([f"replace {generator}"]):
        actions.find("secrets", "replace").run(with_data_keys, {"generator": generator})
    assert generated == [([("node1", generator)], True)]


@pytest.mark.parametrize("answer", ["juicefs-rsa", "yes", "replace restic", ""])
def test_replace_makes_nothing_for_any_other_answer(with_data_keys, generated, answer):
    from avc.errors import Aborted

    with ui.scripted([answer]), pytest.raises(Aborted):
        actions.find("secrets", "replace").run(with_data_keys, {"generator": "juicefs-rsa"})
    assert generated == []


def test_replace_is_not_something_yes_answers(with_data_keys, generated, monkeypatch):
    # `avc -y` takes confirmations as given. This is not a confirmation.
    monkeypatch.setattr(ui, "assume_yes", True)
    with pytest.raises(AvcError, match="not something `-y` answers"):
        actions.find("secrets", "replace").run(with_data_keys, {"generator": "restic"})
    assert generated == []


@pytest.mark.parametrize("generator", ["luks", "initrd-ssh", "nomad-ca", "wg-ctrl"])
def test_replace_is_for_data_bound_keys_and_nothing_else(with_data_keys, generated, generator):
    # The disk-bound ones stay refused by every command: a new recovery key opens no disk.
    with pytest.raises(AvcError, match="is not bound to data"):
        actions.find("secrets", "replace").run(with_data_keys, {"generator": generator})
    assert generated == []


def test_replace_offers_only_the_data_bound_keys(with_data_keys):
    assert secrets.replaceable(with_data_keys) == ["blog-jfs", "juicefs-rsa", "restic"]
