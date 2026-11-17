"""An install's SSH host key: verified before anything is sent, then the only key any
connection of the run accepts (avc/core/hostpin.py, avc/flows/boot.py).

Nothing of avc is replaced here. The programs it starts are: `ssh-keyscan`, `ssh` and the
installer are files on PATH that record how they were run and answer as a rescue system
would, so what is asserted is the argv and environment of real processes, the shim that
nixos-anywhere's connections go through among them. A real sshd, a real kexec and a real
nixos-anywhere are tests/install-node.nix.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pytest

from avc import ui
from avc.core import hostpin, secretstore
from avc.errors import AvcError
from avc.flows import boot

HOST = "192.0.2.9"


def ed25519(name: str) -> tuple[str, str]:
    """A public key's shape, and nobody's key."""
    return ("ssh-ed25519", ("AAAAC3NzaC1lZDI1NTE5AAAAI" + name).ljust(68, "0"))


PRESENTED = ed25519("PresentedByTheRescueSystemsSshd")
PRESENTED_RSA = ("ssh-rsa", "AAAAB3NzaC1yc2EAAAADAQABAAAAQQC" + "x" * 57)
# In the rescue system's /etc/ssh, and so in the installer after the kexec. Not the key
# its sshd presents: a rescue system may keep that one elsewhere.
CARRIED = ed25519("CarriedIntoTheInstallerByTheKexec")
SOMEONE_ELSE = ed25519("SomeoneElseAnsweringOnTheAddress")

# What each fake appends to: one JSON object a line.
FAKE = """#!{python}
import json, os, sys
log, state = {log!r}, {state!r}
name = os.path.basename(sys.argv[0])
with open(log, "a") as f:
    f.write(json.dumps({{"name": name, "argv": sys.argv[1:], "known_hosts": None}}) + "\\n")
{body}
"""

KEYSCAN = """
print({host!r}, *{presented!r})
print({host!r}, *{rsa!r})
"""

# The far end holds the private half of what `state/host-key` names. ssh, as the real one
# does: the first value given for an option is the one that counts, and under strict
# checking a key that is not in the known_hosts file is refused before anything is sent.
SSH = """
def option(name, default=None):
    args = sys.argv[1:]
    for flag, value in zip(args, args[1:]):
        if flag == "-o" and value.startswith(name + "="):
            return value.split("=", 1)[1]
    return default

known = option("UserKnownHostsFile")
far = open(os.path.join(state, "host-key")).read().split()
if option("StrictHostKeyChecking") == "yes":
    lines = [line.split() for line in open(known).read().splitlines()]
    if [option("HostKeyAlias"), *far] not in lines:
        sys.stderr.write("No ED25519 host key is known for %s and you have requested strict checking.\\n" % option("HostKeyAlias"))
        sys.stderr.write("Host key verification failed.\\n")
        sys.exit(255)
with open(os.path.join(state, "reached"), "a") as f:
    f.write(" ".join(far) + "\\n")
if "ssh_host_ed25519_key" in sys.argv[-1]:
    print(*{carried!r}, "root@rescue")
"""

# The installer, as nixos-anywhere runs ssh: its own host key options first, and a wait
# for the installer that retries until it answers. Then the hook.
INSTALLER = """
import subprocess, time
anywhere = ["-o", "IdentitiesOnly=yes", "-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"]
target = sys.argv[1]
subprocess.run(["ssh", *anywhere, target, "kexec"], check=True)
if os.path.exists(os.path.join(state, "kexec-changes-the-key")):
    with open(os.path.join(state, "host-key"), "w") as f:
        f.write(" ".join({someone_else!r}))
with open(os.path.join(state, "installer-pid"), "w") as f:
    f.write(str(os.getpid()))
while subprocess.run(["ssh", *anywhere, "-o", "ConnectTimeout=10", target, "--", "exit", "0"]).returncode != 0:
    time.sleep(0.05)
subprocess.run(["ssh", "git@git.example.org", "git-upload-pack", "x"], check=True)
with open(os.path.join(state, "env.json"), "w") as f:
    json.dump(dict(os.environ), f)
hook = os.path.join(state, "hook")
if os.path.exists(hook):
    sys.exit(subprocess.run([sys.executable, hook]).returncode)
"""


@pytest.fixture
def world(tmp_path, monkeypatch):
    """A rescue system at HOST, and the programs an install runs, on PATH."""
    run = Path(tempfile.mkdtemp(prefix="avc-test-", dir=secretstore.runtime_dir()))
    monkeypatch.setattr(secretstore, "runtime_dir", lambda: run)
    bin_dir, state, log = tmp_path / "bin", tmp_path / "state", tmp_path / "log"
    bin_dir.mkdir()
    state.mkdir()
    log.write_text("")
    (state / "host-key").write_text(" ".join(PRESENTED))
    values = dict(host=HOST, presented=PRESENTED, rsa=PRESENTED_RSA, carried=CARRIED, someone_else=SOMEONE_ELSE)
    for name, body in (("ssh-keyscan", KEYSCAN), ("ssh", SSH), ("installer", INSTALLER)):
        path = bin_dir / name
        path.write_text(FAKE.format(python=sys.executable, log=str(log), state=str(state), body=body.format(**values)))
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setattr(ui, "assume_yes", False)

    class World:
        installer = [str(bin_dir / "installer"), f"root@{HOST}"]
        root = tmp_path

        def ran(self, name=None):
            runs = [json.loads(line) for line in log.read_text().splitlines()]
            return [r for r in runs if name is None or r["name"] == name]

        def reached(self):
            """The host key of whatever each connection that got through was talking to."""
            f = state / "reached"
            return [tuple(line.split()) for line in f.read_text().splitlines()] if f.exists() else []

        def set(self, name, text=""):
            (state / name).write_text(text)

        def read(self, name):
            return (state / name).read_text()

        def install(self, **k):
            boot.install_pinned(tmp_path, "node1", HOST, self.installer, **k)

    yield World()
    shutil.rmtree(run, ignore_errors=True)


class Tty:
    def isatty(self):
        return True


FP = hostpin.fingerprint(PRESENTED)


def test_a_fingerprint_is_what_ssh_keygen_prints():
    # `ssh-keygen -lf` of this public key (the VM tests' snake-oil key would do as well).
    key = ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAIMVy5k0Dn6BPDGMeDiq2JkyFvTuYHQnFjAoYAyuaKKjR")
    p = boot.proc.run(["ssh-keygen", "-lf", "-"], input=" ".join(key) + "\n")
    assert hostpin.fingerprint(key) == p.stdout.split()[1]


def test_a_wrong_fingerprint_refuses_before_anything_is_sent(world):
    wrong = hostpin.fingerprint(SOMEONE_ELSE)
    with pytest.raises(AvcError, match="does not present the host key") as refused:
        world.install(fingerprint=wrong)
    # It says what is there, and that nothing was done.
    assert FP in str(refused.value) and "Nothing was sent" in str(refused.value)
    # Only the read of the host key ran: no connection, no installer.
    assert [r["name"] for r in world.ran()] == ["ssh-keyscan"]
    assert world.reached() == []


def test_a_fingerprint_that_is_not_one_is_refused(world):
    with pytest.raises(AvcError, match="SHA256:"):
        world.install(fingerprint="aa:bb:cc")
    assert [r["name"] for r in world.ran()] == ["ssh-keyscan"]


@pytest.mark.parametrize("yes", [False, True])
def test_without_a_terminal_and_without_a_fingerprint_it_refuses(world, monkeypatch, yes):
    # --yes answers confirmations; this is not one of them.
    monkeypatch.setattr(ui, "assume_yes", yes)
    with pytest.raises(AvcError, match="--host-key-fingerprint"):
        world.install()
    assert [r["name"] for r in world.ran()] == ["ssh-keyscan"] and world.reached() == []


@pytest.mark.parametrize("yes", [False, True])
def test_at_a_terminal_the_operator_is_asked_whatever_yes_says(world, monkeypatch, yes):
    import questionary

    questions = []

    class No:
        def __init__(self, question, default=None):
            questions.append((question, default))

        def ask(self):
            return False

    monkeypatch.setattr(ui, "assume_yes", yes)
    monkeypatch.setattr(sys, "stdin", Tty())
    monkeypatch.setattr(questionary, "confirm", No)
    with pytest.raises(AvcError, match="not confirmed"):
        world.install()
    # Asked about the fingerprint of the key it would pin, with "no" as what Enter gives.
    ((question, default),) = questions
    assert FP in question and default is False
    assert [r["name"] for r in world.ran()] == ["ssh-keyscan"] and world.reached() == []


def test_the_operator_is_told_what_to_run_at_the_console(world, capsys):
    with ui.scripted([True]):
        world.install()
    said = " ".join(capsys.readouterr().err.split())
    assert FP in said and "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" in said and "IPMI/KVM" in said


def test_the_question_about_the_disks_comes_after_the_host_key_and_before_any_connection(world):
    order = []

    def ask():
        order.append([r["name"] for r in world.ran()])
        raise AvcError("no")

    with pytest.raises(AvcError, match="no"):
        world.install(fingerprint=FP, ask=ask)
    assert order == [["ssh-keyscan"]] and world.reached() == []


def pinned_options(argv):
    """An ssh command line's options, as ssh reads them: first value wins."""
    options = {}
    for flag, value in zip(argv, argv[1:], strict=False):
        if flag == "-o" and "=" in value:
            options.setdefault(*value.split("=", 1))
    return options


def test_every_connection_of_the_run_is_held_to_the_one_pinned_file(world, monkeypatch):
    # The hook, as `avc boot stage` reaches the installer: its options from `staging`, an
    # ssh and a `nix copy` (which takes them as NIX_SSHOPTS and runs ssh itself).
    world.set(
        "hook",
        f"""
import os, subprocess, sys
sys.path[:0] = {[p for p in sys.path if p]!r}
from pathlib import Path
from avc.flows import boot
with boot.staging(Path("/extra"), Path("/keys")) as opts:
    installer = boot.Installer(os.environ["IH_TARGET"], opts, Path({str(world.root / "control")!r}))
    installer.run("age-plugin-tpm --generate")
    assert "NIX_SSHOPTS" not in os.environ
    env = dict(os.environ, NIX_SSHOPTS=" ".join(installer.opts))
    subprocess.run(["ssh", *env["NIX_SSHOPTS"].split(), installer.target, "nix-daemon", "--stdio"], env=env, check=True)
""",
    )
    monkeypatch.setenv("IH_TARGET", f"root@{HOST}")
    world.install(fingerprint=FP, identity="/keys/rescue")

    env = json.loads(world.read("env.json"))
    pin_dir = Path(env[hostpin.PIN_ENV])
    known_hosts = str(pin_dir / "known_hosts")
    # The file is this run's own, in memory, and gone with the run.
    assert secretstore.filesystem(pin_dir.parent) in secretstore.RAM_FILESYSTEMS and not pin_dir.exists()
    assert env["PATH"].split(os.pathsep)[0] == str(pin_dir / "bin")
    assert shlex.split(env[boot.INSTALL_SSH_ENV]) == ["-i", "/keys/rescue"] and env["IH_ASSUME_YES"] == "1"

    connections = world.ran("ssh")
    to_target = [c for c in connections if f"root@{HOST}" in c["argv"]]
    # avc's first connection, nixos-anywhere's two, the hook's two.
    assert [c["argv"][c["argv"].index(f"root@{HOST}") + 1].split()[0] for c in to_target] == ["s=;", "kexec", "--", "age-plugin-tpm", "nix-daemon"]
    for c in to_target:
        options = pinned_options(c["argv"])
        assert options["UserKnownHostsFile"] == known_hosts, c
        assert options["StrictHostKeyChecking"] == "yes" and options["GlobalKnownHostsFile"] == "/dev/null", c
        assert options["HostKeyAlias"] == "avc-install-node1" and options["UpdateHostKeys"] == "no", c
    # nixos-anywhere's own "/dev/null, no checking" is still on its command line, and loses.
    assert "StrictHostKeyChecking=no" in to_target[1]["argv"] and "UserKnownHostsFile=/dev/null" in to_target[1]["argv"]
    # Another host's connection (a flake input over git) is not the installer's business.
    (other,) = [c for c in connections if c not in to_target]
    assert other["argv"] == ["git@git.example.org", "git-upload-pack", "x"]
    # Every one of them reached the machine whose key was verified.
    assert set(world.reached()) == {PRESENTED}


def test_the_keys_the_kexec_carries_are_read_over_the_verified_connection_and_pinned(world):
    # After the kexec the installer presents the key that was in the rescue system's
    # /etc/ssh, which is not the one its sshd presented. It was read over the first
    # connection, which the verified key had authenticated: no second comparison.
    world.set("hook", f"import shutil, os\nshutil.copy(os.path.join(os.environ[{hostpin.PIN_ENV!r}], 'known_hosts'), {str(world.root / 'pinned')!r})\n")
    world.install(fingerprint=FP)
    pinned = (world.root / "pinned").read_text().splitlines()
    assert pinned == [f"avc-install-node1 {' '.join(PRESENTED)}", f"avc-install-node1 {' '.join(CARRIED)}"]
    # Of what the scan returned, only the key that was compared is trusted.
    assert PRESENTED_RSA[1] not in "".join(pinned)


def test_a_key_that_changes_at_the_kexec_and_was_not_authenticated_stops_the_install(world):
    # Someone else answers on the address once the rescue system is gone. nixos-anywhere
    # would wait for "the installer" for ever, and then install on whatever answered.
    world.set("kexec-changes-the-key")
    world.set("hook", f"open({str(world.root / 'hook-ran')!r}, 'w')")
    began = time.monotonic()
    with pytest.raises(AvcError, match="not one verified for this install") as refused:
        world.install(fingerprint=FP)
    assert time.monotonic() - began < 30
    said = str(refused.value)
    assert "before `avc boot stage`" in said and "nothing on its disks was changed" in said and "no secret was sent" in said
    # The hook never ran, the installer is gone, and nothing reached the other machine.
    assert not (world.root / "hook-ran").exists()
    assert not Path(f"/proc/{world.read('installer-pid')}").exists()
    assert set(world.reached()) == {PRESENTED}


def test_what_a_refusal_says_follows_how_far_the_install_had_come(tmp_path):
    pin = hostpin.Pin(tmp_path, HOST, "avc-install-node1")
    pin.mark("refused", "root@192.0.2.9 -- exit 0")
    assert "before `avc boot stage`" in boot._refusal("node1", HOST, pin)
    pin.mark("staging")
    during = boot._refusal("node1", HOST, pin)
    assert "during `avc boot stage`" in during and "no disk secret was sent" in during and "nothing was shipped" in during
    pin.mark("staged", "/keys\n/extra\n")
    after = boot._refusal("node1", HOST, pin)
    assert "after `avc boot stage`" in after and "install again from the rescue system" in after
    assert "went to the verified machine" in after and "the refused connection was sent nothing" in after


def test_a_refusal_after_staging_removes_what_was_staged_in_memory(world):
    keys = world.root / "disk-keys"
    world.set(
        "hook",
        f"""
import os, sys
sys.path[:0] = {[p for p in sys.path if p]!r}
from pathlib import Path
from avc.flows import boot
keys = Path({str(keys)!r})
with boot.staging(Path({str(world.root / "extra")!r}), keys):
    keys.mkdir()
    (keys / "passphrase").write_text("recovery key")
# The partitioning: the far end is someone else from here on.
open({str(world.root / "state" / "host-key")!r}, "w").write({" ".join(SOMEONE_ELSE)!r})
import subprocess, time
while subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "root@{HOST}", "disko"]).returncode != 0:
    time.sleep(0.05)
""",
    )
    with pytest.raises(AvcError, match="after `avc boot stage`"):
        world.install(fingerprint=FP)
    assert not keys.exists() and set(world.reached()) == {PRESENTED}


def test_stage_refuses_an_installer_whose_connections_did_not_go_through_the_pin(tmp_path, monkeypatch):
    # nixos-anywhere found some other ssh first on its PATH: the kexec is behind us, over
    # connections that checked nothing.
    pin = hostpin.Pin(tmp_path, HOST, "avc-install-node1")
    pin.trust(PRESENTED)
    pin.shim()
    monkeypatch.setenv(hostpin.PIN_ENV, str(tmp_path))
    with pytest.raises(AvcError, match="without this install's pinned host key"), boot.staging(tmp_path / "e", tmp_path / "k"):
        raise AssertionError("staged")
    assert not pin.marked("staging")
    # And a host key refused to the hook's own connection is the install's to report.
    (tmp_path / "uses").write_text("root@192.0.2.9 kexec\n")
    with pytest.raises(AvcError), boot.staging(tmp_path / "e", tmp_path / "k") as opts:
        assert opts[:4] == ["-o", f"UserKnownHostsFile={tmp_path}/known_hosts", "-o", "GlobalKnownHostsFile=/dev/null"]
        raise AvcError("ssh root@192.0.2.9… failed (255):\nHost key verification failed.")
    assert pin.marked("staging") and pin.marked("refused") and not pin.marked("staged")


def test_the_shim_passes_on_stdin_stdout_and_the_exit_status(world, tmp_path):
    import subprocess

    pin = hostpin.Pin(tmp_path / "pin", HOST, "avc-install-node1")
    pin.dir.mkdir()
    pin.trust(PRESENTED)
    ssh = pin.shim() / "ssh"
    p = subprocess.run([str(ssh), f"root@{HOST}", "cat /etc/ssh/ssh_host_ed25519_key.pub"], capture_output=True, text=True, input="")
    assert p.returncode == 0 and p.stdout.split()[:2] == list(CARRIED)
    world.set("host-key", " ".join(SOMEONE_ELSE))
    p = subprocess.run([str(ssh), f"root@{HOST}", "true"], capture_output=True, text=True)
    assert p.returncode == 255 and "Host key verification failed" in p.stderr and pin.marked("refused")
    # From then on nothing is even tried.
    before = len(world.ran("ssh"))
    p = subprocess.run([str(ssh), f"root@{HOST}", "true"], capture_output=True, text=True)
    assert p.returncode == 255 and "refused earlier" in p.stderr and len(world.ran("ssh")) == before
