"""What the rollback commands send to a node, and what they do with the answer.
tests/deploy-safety.nix runs the same scripts on a real profile and tick."""

from __future__ import annotations

import dataclasses
import os
import subprocess

import pytest

from avc import actions
from avc.cli import build_parser
from avc.core import deploy_state
from avc.core.node import Node
from avc.errors import AvcError

BASENAME = "0" * 32 + "-nixos-system-node1-26.05"


@pytest.fixture
def ssh(monkeypatch):
    """Answers per host: (exit status, stdout, stderr). Records what each host was sent."""
    answers: dict[str, tuple[int, str, str]] = {}
    sent: list[tuple[str, str]] = []

    def run(self, command, check=True, timeout=60):
        rc, out, err = answers.get(self.name, (0, "", ""))
        sent.append((self.name, command))
        if check and rc != 0:
            raise AvcError(err)
        return subprocess.CompletedProcess([], rc, out, err)

    monkeypatch.setattr(Node, "run", run)
    return answers, sent


@pytest.fixture
def fleet(ctx, index):
    nodes = {n: dict(index.nodes["node1"]) for n in ("node1", "node2", "node3")}
    ctx.__dict__["index"] = dataclasses.replace(index, nodes=nodes)
    ctx.__dict__["installed"] = list(nodes)
    return ctx


def run(ctx, group, name, **given):
    actions.find(group, name).run(ctx, given)


def test_the_commands_parse():
    parser = build_parser()
    args = parser.parse_args(["boot", "rollback", "--all"])
    assert args.all and args.node is None and args._action.name == "rollback"
    args = parser.parse_args(["boot", "unrollback", "node1", BASENAME])
    assert (args.node, args.closure) == ("node1", BASENAME)
    assert parser.parse_args(["deploy", "retry", "node1"]).node == "node1"


def test_retry_sends_the_script(ctx, ssh):
    run(ctx, "deploy", "retry", node="node1")
    assert ssh[1] == [("node1", deploy_state.RETRY)]


def test_rollback_sends_the_script(ctx, ssh):
    answers, sent = ssh
    answers["node1"] = (0, BASENAME + "\n", "")
    run(ctx, "boot", "rollback", node="node1", all=False)
    assert sent == [("node1", deploy_state.REFUSE_LATER)]


def test_rollback_with_nothing_after_is_an_error_on_one_node(ctx, ssh):
    ssh[0]["node1"] = (deploy_state.NOTHING_AFTER, "", "it runs its newest generation")
    with pytest.raises(AvcError, match="newest generation"):
        run(ctx, "boot", "rollback", node="node1", all=False)


@pytest.mark.parametrize("answer", [(255, "", "Connection refused"), (0, "", "")])
def test_rollback_that_did_not_refuse_anything_is_an_error(ctx, ssh, answer):
    # The second is a clean exit that names no closure: no proof anything was listed.
    ssh[0]["node1"] = answer
    with pytest.raises(AvcError):
        run(ctx, "boot", "rollback", node="node1", all=False)


def test_rollback_all_tries_every_node_and_then_fails(fleet, ssh):
    answers, sent = ssh
    answers["node1"] = (255, "", "Connection refused")
    answers["node2"] = (deploy_state.NOTHING_AFTER, "", "it runs its newest generation")
    answers["node3"] = (0, BASENAME + "\n", "")
    with pytest.raises(AvcError, match="not rolled back: node1$"):
        run(fleet, "boot", "rollback", node=None, all=True)
    assert [host for host, _ in sent] == ["node1", "node2", "node3"]


def test_rollback_all_allows_a_node_with_nothing_after(fleet, ssh):
    answers, _ = ssh
    answers["node1"] = (deploy_state.NOTHING_AFTER, "", "it runs its newest generation")
    answers["node2"] = (deploy_state.NOTHING_AFTER, "", "it runs its newest generation")
    answers["node3"] = (0, BASENAME + "\n", "")
    run(fleet, "boot", "rollback", node=None, all=True)


def test_rollback_all_with_nothing_anywhere_is_an_error(fleet, ssh):
    answers, _ = ssh
    for n in ("node1", "node2", "node3"):
        answers[n] = (deploy_state.NOTHING_AFTER, "", "it runs its newest generation")
    with pytest.raises(AvcError, match="no node had anything"):
        run(fleet, "boot", "rollback", node=None, all=True)


def test_rollback_refuses_a_node_and_all(ctx, ssh):
    with pytest.raises(AvcError, match="not both"):
        run(ctx, "boot", "rollback", node="node1", all=True)
    assert ssh[1] == []


@pytest.mark.parametrize("closure", [BASENAME, f"/nix/store/{BASENAME}"])
def test_unrollback_takes_a_basename_or_a_store_path(ctx, ssh, closure):
    run(ctx, "boot", "unrollback", node="node1", closure=closure)
    assert ssh[1] == [("node1", deploy_state.unrefuse_script(BASENAME))]


@pytest.mark.parametrize(
    "closure",
    [
        "x",
        f"{BASENAME}; rm -rf /",
        f"$(reboot)-{BASENAME}",
        f"/nix/store/../{BASENAME}",
        "e" * 32 + "-nixos-system",  # e is not in Nix's alphabet
        BASENAME + "\nsecond",
    ],
)
def test_unrollback_sends_nothing_for_a_bad_name(ctx, ssh, closure):
    with pytest.raises(AvcError, match="not a closure"):
        run(ctx, "boot", "unrollback", node="node1", closure=closure)
    assert ssh[1] == []


# ── install, unlock, bind, reboot ───────────────────────────────────────────

from avc.core import repo  # noqa: E402
from avc.core import vars as clanvars  # noqa: E402
from avc.core.repo import Change  # noqa: E402
from avc.flows import boot as boot_flow  # noqa: E402

PASSPHRASE = "0f" * 32


def test_every_boot_command_is_registered():
    names = {a.name for a in actions.in_group("boot")}
    assert {"preflight", "install", "unlock", "status", "enroll", "bind", "reboot", "rollback", "unrollback"} <= names


@pytest.mark.parametrize(
    "change",
    [
        Change("??", "vars/per-machine/node1/volume-identity/hash/value"),
        Change(" M", "secrets/clan-vars/per-machine/node1/luks/passphrase/passphrase.age"),
    ],
)
def test_preflight_refuses_vars_that_are_not_committed(ctx, monkeypatch, change):
    evaluated = []
    monkeypatch.setattr(repo, "changes", lambda root: [Change(" M", "topology.nix"), change])
    monkeypatch.setattr(boot_flow.proc, "out", lambda *a, **k: evaluated.append(a) or "{}")
    with pytest.raises(AvcError, match="not committed"):
        run(ctx, "boot", "preflight", node="node1")
    assert evaluated == []


def test_preflight_forces_both_drvpaths(ctx, monkeypatch):
    seen = []
    monkeypatch.setattr(repo, "changes", lambda root: [Change(" M", "topology.nix")])

    def out(cmd, cwd=None, timeout=None):
        seen.append(cmd)
        return '{"toplevel": "/nix/store/x.drv", "disko": "/nix/store/y.drv", "identity": "ab", "thumbprints": ["t"], "url": "http://192.0.2.1:7654"}'

    monkeypatch.setattr(boot_flow.proc, "out", out)
    monkeypatch.setattr(boot_flow, "_fingerprint", lambda pub: "fp")
    run(ctx, "boot", "preflight", node="node1")
    (cmd,) = seen
    assert cmd[:4] == ["nix", "eval", "--json", ".#nixosConfigurations.node1.config"]
    assert "system.build.toplevel.drvPath" in cmd[-1] and "system.build.diskoScript.drvPath" in cmd[-1]


def test_preflight_refuses_an_opted_out_node(ctx, monkeypatch):
    monkeypatch.setitem(ctx.index.nodes["node1"], "boot", {"enabled": False, "sshPort": 2222, "hostKeyPub": None})
    with pytest.raises(AvcError, match="boot security off"):
        run(ctx, "boot", "preflight", node="node1")


def test_unlock_argv_is_exact():
    assert boot_flow.unlock_argv("192.0.2.1", 2222, "/tmp/kh") == [
        "ssh",
        "-tt",
        "-p",
        "2222",
        "-o",
        "UserKnownHostsFile=/tmp/kh",
        "-o",
        "StrictHostKeyChecking=yes",
        "root@192.0.2.1",
        "systemd-tty-ask-password-agent",
        "--query",
    ]
    assert (
        boot_flow.known_hosts_line("192.0.2.1", 2222, "ssh-ed25519 AAAAkey initrd-host")
        == "[192.0.2.1]:2222 ssh-ed25519 AAAAkey\n"
    )


def test_unlock_pins_the_repositorys_host_key(ctx, monkeypatch):
    calls = []

    def fake_run(argv):
        known = argv[argv.index("-o") + 1].removeprefix("UserKnownHostsFile=")
        calls.append((argv, open(known).read()))
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(boot_flow.subprocess, "run", fake_run)
    run(ctx, "boot", "unlock", node="node1")
    ((argv, known),) = calls
    pub = ctx.index.nodes["node1"]["boot"]["hostKeyPub"]
    assert known == f"[192.0.2.1]:2222 {' '.join(pub.split()[:2])}\n"
    assert argv[-3:] == ["root@192.0.2.1", "systemd-tty-ask-password-agent", "--query"]


def test_install_argv():
    assert boot_flow.install_argv("node1", "192.0.2.9") == [
        "clan", "machines", "install", "node1", "--target-host", "root@192.0.2.9", "--yes",
    ]
    assert boot_flow.install_argv("node1", "root@192.0.2.9")[5] == "root@192.0.2.9"


@pytest.fixture
def piped(monkeypatch):
    """What each pipe to a node sent: (command, stdin)."""
    sent: list[tuple[str, str]] = []

    def pipe(self, command, data, check=True, timeout=120):
        sent.append((command, data))
        return subprocess.CompletedProcess([], 0, "Bound.\n", "")

    monkeypatch.setattr(Node, "pipe", pipe)
    return sent


def test_bind_sends_the_passphrase_on_stdin_only(ctx, monkeypatch, tmp_path, piped, ssh, capsys):
    adv = tmp_path / "adv.jws"
    adv.write_text('{"payload": "x"}')
    monkeypatch.setattr(clanvars, "get_value", lambda root, machine, var: PASSPHRASE)
    run(ctx, "boot", "bind", node="node1", adv=str(adv), replace=False, device=None)
    assert piped == [
        ("install -m 0600 /dev/stdin /run/adv.jws.pending", '{"payload": "x"}'),
        (boot_flow.bind_script(False, None), PASSPHRASE),
    ]
    assert "cluster-boot-seal bind --adv /run/adv.jws.pending" in piped[1][0]
    # Never on a command line, and never printed.
    assert all(PASSPHRASE not in command for command, _ in piped)
    assert all(PASSPHRASE not in command for _, command in ssh[1])
    out = capsys.readouterr()
    assert PASSPHRASE not in out.out and PASSPHRASE not in out.err


def test_bind_replace_and_device(ctx, monkeypatch, tmp_path, piped):
    adv = tmp_path / "adv.jws"
    adv.write_text("{}")
    monkeypatch.setattr(clanvars, "get_value", lambda root, machine, var: PASSPHRASE)
    run(ctx, "boot", "bind", node="node1", adv=str(adv), replace=True, device="/dev/disk/by-partlabel/disk-nvme1-luks")
    assert (
        "cluster-boot-seal bind --adv /run/adv.jws.pending --replace --device /dev/disk/by-partlabel/disk-nvme1-luks"
        in piped[-1][0]
    )


def _run_bind_script(tmp_path, seal_rc):
    """bind_script as the node's shell runs it, with a stand-in cluster-boot-seal that reads
    the passphrase and exits with `seal_rc`."""
    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "cluster-boot-seal").write_text(f"#!/bin/sh\ncat >/dev/null\nexit {seal_rc}\n")
    (stub / "cluster-boot-seal").chmod(0o755)
    pending, marker = tmp_path / "adv.jws.pending", tmp_path / "adv.jws"
    pending.write_text("{}")
    script = boot_flow.bind_script(True, None, pending=str(pending), marker=str(marker))
    env = {**os.environ, "PATH": f"{stub}:{os.environ.get('PATH', '/bin')}"}
    p = subprocess.run(["sh", "-c", script], input=PASSPHRASE, text=True, env=env, capture_output=True)
    return p.returncode, pending.exists(), marker.exists()


def test_a_failed_bind_leaves_no_marker(tmp_path):
    # An advertisement nobody pinned, say: cluster-boot-seal refuses before touching a slot.
    rc, pending, marker = _run_bind_script(tmp_path, 1)
    assert (rc, pending, marker) == (1, False, False)
    # So `avc boot reboot` still refuses the short Clevis count of the boot before.
    report = "cluster_boot_unlock_clevis_devices 0\ncluster_boot_unlock_expected_devices 2\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(report=report) + ("bound_this_boot=yes\n" if marker else "bound_this_boot=no\n"))
    assert any("0 of 2" in r for r in refusals)


def test_a_bind_that_succeeded_leaves_the_marker(tmp_path):
    assert _run_bind_script(tmp_path, 0) == (0, False, True)


def test_a_failed_bind_after_a_good_one_keeps_the_good_ones_marker(tmp_path):
    # The first bind this boot succeeded; a second one is refused. The first one's binding is
    # still on disk, and the seal check is what judges it.
    assert _run_bind_script(tmp_path, 0)[2]
    assert _run_bind_script(tmp_path, 4) == (4, False, True)


def test_bind_reports_a_failed_bind(ctx, monkeypatch, tmp_path):
    adv = tmp_path / "adv.jws"
    adv.write_text("{}")
    monkeypatch.setattr(clanvars, "get_value", lambda root, machine, var: PASSPHRASE)
    monkeypatch.setattr(
        Node,
        "pipe",
        lambda self, command, data, check=True, timeout=120: subprocess.CompletedProcess(
            [], 1 if "cluster-boot-seal" in command else 0, "", "refusing: advertisement is not signed by a pinned key"
        ),
    )
    with pytest.raises(AvcError, match="not signed by a pinned key"):
        run(ctx, "boot", "bind", node="node1", adv=str(adv), replace=True, device=None)


@pytest.mark.parametrize("device", ["nvme1", "/dev/x; reboot", "/dev/$(id)", "/dev/a b"])
def test_bind_refuses_a_device_that_is_not_a_plain_path(ctx, tmp_path, piped, device):
    adv = tmp_path / "adv.jws"
    adv.write_text("{}")
    with pytest.raises(AvcError, match="not a device path"):
        run(ctx, "boot", "bind", node="node1", adv=str(adv), replace=False, device=device)
    assert piped == []


REPORT_OK = "cluster_boot_unlock_clevis_devices 2\ncluster_boot_unlock_expected_devices 2\n"


SEAL_OK = "seal_check=0\nseal: OK: /dev/a token 0\nseal: OK: /dev/b token 0\n"
IDENTITY_OK = "identity_check=0\nidentity: identity OK\n"


def check_output(
    contract="same",
    burned="no",
    report=REPORT_OK,
    esps=("/boot 9000000", "/boot-fallback 9000000"),
    seal=SEAL_OK,
    identity=IDENTITY_OK,
    default=f"default_entry={BASENAME}\ndefault_refused=no\ndefault_is_running=yes\n",
):
    head = "\n".join([f"contract={contract}", *(f"esp {e}" for e in esps), f"burned={burned}"]) + "\n"
    return head + default + seal + identity + report


def test_reboot_preflight_passes_a_clean_node():
    refusals, notes = boot_flow.reboot_verdict(check_output())
    assert refusals == []
    assert any("Only a real reboot" in n for n in notes)


def test_reboot_preflight_refuses_a_contract_change():
    refusals, _ = boot_flow.reboot_verdict(check_output(contract="differs"))
    assert any("boot contract" in r for r in refusals)


def test_reboot_preflight_refuses_a_default_entry_on_the_rollback_denylist():
    # Rolled back from a kernel bump: the same boot contract, and the bad closure still the
    # default entry. A reboot would go straight back into it.
    default = f"default_entry={BASENAME}\ndefault_refused=yes\ndefault_is_running=no\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(default=default))
    assert any("rollback denylist" in r and BASENAME in r for r in refusals)


@pytest.mark.parametrize(
    "default",
    ["default_entry=\ndefault_refused=unknown\ndefault_is_running=no\n", f"default_entry={BASENAME}\ndefault_refused=unknown\n", ""],
)
def test_reboot_preflight_refuses_when_the_denylist_cannot_be_read(default):
    refusals, _ = boot_flow.reboot_verdict(check_output(default=default))
    assert any("can't tell whether the default entry" in r for r in refusals)


def test_reboot_preflight_notes_a_default_entry_that_is_not_running():
    default = f"default_entry={BASENAME}\ndefault_refused=no\ndefault_is_running=no\n"
    refusals, notes = boot_flow.reboot_verdict(check_output(default=default))
    assert refusals == []
    assert any("not the running closure" in n for n in notes)


def test_reboot_check_reads_the_default_entry():
    assert deploy_state.DEFAULT_ENTRY in boot_flow.REBOOT_CHECK
    assert "/var/lib/cluster-upgrade/refused" in deploy_state.DEFAULT_ENTRY.replace("$S", deploy_state.STATE)


def test_reboot_preflight_refuses_a_slot_bound_to_an_unpinned_tang_key():
    seal = "seal_check=4\nseal: OK: /dev/a token 0\nseal: FAILED: /dev/b token 1: bound to a Tang key that is not pinned\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(seal=seal))
    assert any("no longer pinned" in r and "/dev/b token 1" in r for r in refusals)


def test_reboot_messages_point_at_the_readme_not_the_design():
    import inspect

    assert "design section" not in inspect.getsource(boot_flow)


def test_reboot_preflight_refuses_a_partial_clevis_unlock():
    report = "cluster_boot_unlock_clevis_devices 1\ncluster_boot_unlock_expected_devices 2\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(report=report))
    assert any("1 of 2" in r for r in refusals)


def test_reboot_preflight_refuses_a_passphrase_boot_that_nothing_rebound():
    report = "cluster_boot_unlock_clevis_devices 0\ncluster_boot_unlock_expected_devices 2\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(report=report))
    assert any("0 of 2" in r for r in refusals)


def test_reboot_preflight_after_a_bind_this_boot():
    # Install S7: the last boot (S5) was typed, the node was bound since, and only a reboot
    # can prove the binding. The seal check still has to pass.
    report = "cluster_boot_unlock_clevis_devices 0\ncluster_boot_unlock_expected_devices 2\n"
    refusals, notes = boot_flow.reboot_verdict(check_output(report=report) + "bound_this_boot=yes\n")
    assert refusals == []
    assert any("proves the new binding" in n for n in notes)
    seal = "seal_check=1\nseal: FAILED: /dev/b has no Clevis binding\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(report=report, seal=seal) + "bound_this_boot=yes\n")
    assert any("/dev/b has no Clevis binding" in r for r in refusals)


def test_reboot_check_reports_a_bind_this_boot():
    assert f"test -e {boot_flow.ADV_ON_NODE}" in boot_flow.REBOOT_CHECK
    assert boot_flow.ADV_ON_NODE.startswith("/run/")


def test_reboot_preflight_lets_a_burned_boot_through():
    # Emergency recovery burned PCR 7: the binding only looks broken, and a reboot clears it.
    report = "cluster_boot_unlock_clevis_devices 0\ncluster_boot_unlock_expected_devices 2\n"
    refusals, notes = boot_flow.reboot_verdict(check_output(burned="yes", report=report))
    assert refusals == []
    assert any("burned" in n for n in notes)


def test_reboot_preflight_refuses_with_no_esp_mounted():
    refusals, _ = boot_flow.reboot_verdict(check_output(esps=("/boot unmounted", "/boot-fallback unmounted")))
    assert any("no ESP" in r for r in refusals)


def test_reboot_preflight_refuses_while_an_automated_hold_is_set():
    refusals, _ = boot_flow.reboot_verdict(check_output() + "hold restore-app-x\n")
    assert any("restore-app-x" in r for r in refusals)


def test_reboot_preflight_refuses_a_leg_with_no_binding():
    # A disk replaced and never bound: the boot report from before the swap still says 2 of 2.
    seal = "seal_check=1\nseal: OK: /dev/a token 0\nseal: FAILED: /dev/b has no Clevis binding\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(seal=seal))
    assert any("/dev/b has no Clevis binding" in r for r in refusals)


def test_reboot_preflight_refuses_when_the_seal_check_cannot_run():
    refusals, _ = boot_flow.reboot_verdict(check_output(seal="seal_check=127\nseal: command not found\n"))
    assert any("could not run" in r for r in refusals)
    refusals, _ = boot_flow.reboot_verdict(check_output(seal=""))
    assert any("could not run" in r for r in refusals)


def test_reboot_preflight_lets_a_burned_seal_check_through():
    seal = "seal_check=3\nseal: BURNED: PCR 7 was burned this boot\n"
    report = "cluster_boot_unlock_clevis_devices 0\ncluster_boot_unlock_expected_devices 2\n"
    refusals, _ = boot_flow.reboot_verdict(check_output(burned="yes", seal=seal, report=report))
    assert refusals == []


@pytest.mark.parametrize("identity", ["identity_check=1\nidentity: refusing: no identity file\n", ""])
def test_reboot_preflight_refuses_a_missing_identity_secret(identity):
    # Every generation would halt at its identity check: KVM and rescue, not a reboot.
    refusals, _ = boot_flow.reboot_verdict(check_output(identity=identity))
    assert any("identity secret" in r for r in refusals)


def test_reboot_check_runs_the_seal_and_identity_checks():
    assert "cluster-boot-seal check" in boot_flow.REBOOT_CHECK
    assert "cluster-boot-seal identity" in boot_flow.REBOOT_CHECK


class FakeNode:
    """Answers BOOT_ID from a script of answers: a string, None for no answer, or an error."""

    name = "node1"

    def __init__(self, answers):
        self.answers = list(answers)

    def run(self, command, check=True, timeout=60):
        assert command == boot_flow.BOOT_ID
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        if a is None:
            return subprocess.CompletedProcess([], 255, "", "Connection refused")
        return subprocess.CompletedProcess([], 0, a + "\n", "")


def test_wait_back_needs_a_new_boot():
    n = FakeNode(["old", None, AvcError("timed out after 10s"), None, "new"])
    boot_flow._wait_back(n, "old", down_for=5, back_in=5, every=0)


def test_wait_back_fails_when_the_node_never_went_down():
    # Shutdown stuck with sshd still up, or the reboot command failed.
    with pytest.raises(AvcError, match="did not reboot"):
        boot_flow._wait_back(FakeNode(["old"]), "old", down_for=0.05, back_in=5, every=0.01)


def test_wait_back_fails_when_the_same_boot_answers_again():
    with pytest.raises(AvcError, match="did not come back"):
        boot_flow._wait_back(FakeNode([None, "old"]), "old", down_for=0.05, back_in=0.05, every=0.01)


def test_wait_back_survives_a_probe_that_times_out_while_going_down():
    n = FakeNode([AvcError("timed out after 10s"), "new"])
    boot_flow._wait_back(n, "old", down_for=5, back_in=5, every=0)
