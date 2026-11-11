"""Shared generators go through the leader; per-machine ones, machine by machine."""

from __future__ import annotations

import dataclasses

import pytest

from avc import actions, ui
from avc.core import vars as clanvars
from avc.core.vars import GeneratorInfo, VarFile, VarsSummary
from avc.errors import AvcError
from avc.flows import secrets

SHARED = GeneratorInfo("nomad-ca", True, (VarFile("ca.crt", False, True),), (), ())
PER_MACHINE = GeneratorInfo("wg-ctrl", False, (VarFile("private", True, True),), (), ())
INITRD_SSH = GeneratorInfo("initrd-ssh", False, (VarFile("ssh_host_ed25519_key", True, True),), (), ())
EMERGENCY = GeneratorInfo("emergency-access", False, (VarFile("password", True, False),), (), ())
LUKS = GeneratorInfo("luks", False, (VarFile("passphrase", True, True),), (), ())


@pytest.fixture
def fleet(ctx, index, monkeypatch):
    nodes = {n: dict(index.nodes["node1"]) for n in ("node1", "node2", "node3")}
    ctx.__dict__["index"] = dataclasses.replace(index, nodes=nodes)
    # node3 is opted out: it has no boot generators.
    boot = [PER_MACHINE, INITRD_SSH, EMERGENCY, LUKS]
    gens = {"node1": [SHARED, *boot], "node2": [SHARED, *boot], "node3": [SHARED]}
    monkeypatch.setattr(clanvars, "generators", lambda root, machine: gens[machine])
    return ctx


@pytest.fixture
def generated(monkeypatch):
    calls = []
    monkeypatch.setattr(clanvars, "generate", lambda root, m, g=None, regenerate=False: calls.append((m, g, regenerate)))
    monkeypatch.setattr(secrets.ship, "ship", lambda *a, **k: True)
    return calls


def test_a_shared_generator_rotates_on_the_leader_alone(fleet, generated):
    with ui.scripted([True]):
        actions.find("secrets", "rotate").run(fleet, {"generator": "nomad-ca"})
    assert generated == [("node1", "nomad-ca", True)]


def test_a_per_machine_generator_rotates_on_every_machine_that_has_it(fleet, generated):
    with ui.scripted([True]):
        actions.find("secrets", "rotate").run(fleet, {"generator": "wg-ctrl"})
    assert generated == [("node1", "wg-ctrl", True), ("node2", "wg-ctrl", True)]


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
    gens = {m: [*g, GeneratorInfo(generator, True, (VarFile("x", True, True),), (), ())] for m, g in
            {m: clanvars.generators(fleet.root, m) for m in ("node1", "node2", "node3")}.items()}
    monkeypatch.setattr(clanvars, "generators", lambda root, machine: gens[machine])
    assert not (fleet.root / "secrets" / "policy.toml").exists()
    with pytest.raises(AvcError, match=f"refusing to regenerate {generator}"):
        actions.find("secrets", "rotate").run(fleet, {"generator": generator})
    assert generated == []


def test_the_inventory_does_not_call_the_initrd_key_safe(fleet, monkeypatch):
    rows = {}
    monkeypatch.setattr(clanvars, "status", lambda root, m: VarsSummary([], [], []))
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
        "node1": VarsSummary([], [], []),
        "node2": VarsSummary(["initrd-ssh/ssh_host_ed25519_key"], [], []),
        "node3": VarsSummary([], [], []),
    }
    monkeypatch.setattr(clanvars, "status", lambda root, m: statuses[m])
    with ui.scripted([True]):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [("node2", None, False)]


@pytest.mark.parametrize(
    "summary",
    [
        VarsSummary([], [], ["luks"]),
        VarsSummary(["volume-identity/secret"], [], []),
        VarsSummary(["initrd-ssh/ssh_host_ed25519_key"], [], []),
        VarsSummary([], [], ["emergency-access"]),
    ],
)
def test_provision_does_not_make_a_node_held_secret_anew_on_an_installed_node(fleet, generated, monkeypatch, summary):
    # `clan vars generate node1` would make it anew, and node1 is installed: its disks, its
    # initrd and its ESP all still have the old value. node2 is not installed yet, so it is
    # generated there as usual, and the run still fails for node1.
    statuses = {"node1": summary, "node2": summary, "node3": VarsSummary([], [], [])}
    monkeypatch.setattr(clanvars, "status", lambda root, m: statuses[m])
    assert fleet.installed == ["node1"]
    with ui.scripted([True]), pytest.raises(AvcError, match="not provisioned on node1"):
        actions.find("secrets", "provision").run(fleet, {})
    assert generated == [("node2", None, False)]


def test_a_per_machine_path_names_its_machine(tmp_path):
    f = INITRD_SSH.files[0]
    assert INITRD_SSH.path(tmp_path, f, "node2") == (
        tmp_path / "secrets/clan-vars/per-machine/node2/initrd-ssh/ssh_host_ed25519_key/ssh_host_ed25519_key.age"
    )
    with pytest.raises(ValueError):
        INITRD_SSH.path(tmp_path, f)
