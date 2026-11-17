"""Boot: install, unlock and seal an encrypted node (modules/boot-security.nix), and keep
a node off a closure that did not survive a reboot.

The order of a fresh install is the README's "Installing a node": preflight, install (which
makes the node's age identity on its TPM, and leaves each leg a TPM slot bound to no PCR and
a slot for the recovery key), a first boot nobody types into, enroll, reboot, bind (the TPM
slot sealed to PCR 7), reboot. Each command runs one step and says what comes next.

Where a disk secret is, at an install: the recovery key (`luks/passphrase`) is ciphertext in
the repository, encrypted to the operators; `stage` decrypts it into a tmpfs here, the
installer (nixos-anywhere) sends it into the target's /run, the disko hook gives each leg a
slot for it, and the target's reboot and the installer's exit forget both copies. The key
a leg is formatted with never leaves the target's memory. Nothing else opens a disk. It is
sent over SSH to a host key the operator compared with the server's console before
anything else was sent, and to no other (avc/core/hostpin.py).

Rollback's order: hold every node, revert or pin the private repo, boot the old
generation at the console, then `avc boot rollback`.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any

from avc import ui
from avc.actions import Arg, action
from avc.core import deploy_state, hostpin, proc, repo, secretstore, ship
from avc.core.node import HOLD_DIR, Node, NothingAfter
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

# Written by emergency-pcr-burn in the initrd; /run outlives switch-root.
BURN_MARKER = "/run/cluster-boot/pcr7-burned"
TEXTFILES = "/var/lib/prometheus-node-exporter-text"
# `avc boot bind` writes this once `cluster-boot-seal bind` has returned 0, so its presence
# says that a bind succeeded this boot (/run clears at boot). `avc boot reboot` relies on that.
BOUND_MARKER = "/run/avc-boot-bound"
# New at every boot, so a node that answers with the old one has not rebooted.
BOOT_ID = "cat /proc/sys/kernel/random/boot_id"


def _nodes(ctx: Ctx) -> list[str]:
    return ctx.installed


def _all_nodes(ctx: Ctx) -> list[str]:
    # Install and preflight come before a node exists, so they choose from the topology.
    return list(ctx.index.nodes)


def _boot_info(ctx: Ctx, node: str) -> dict[str, Any]:
    info = ctx.index.nodes.get(node)
    if info is None:
        raise AvcError(f"unknown node {node!r} (known: {', '.join(ctx.index.nodes)})")
    boot = info.get("boot") or {}
    if not boot.get("enabled"):
        raise AvcError(f"{node} has boot security off (insecurePlaintextBoot): nothing to do here")
    return boot


# ── preflight ───────────────────────────────────────────────────────────────


def _changed_secrets(root: Path) -> list[str]:
    return sorted(c.path for c in repo.changes(root) if c.path.startswith("secrets/"))


PREFLIGHT_APPLY = (
    "c: { toplevel = c.system.build.toplevel.drvPath; disko = c.system.build.diskoScript.drvPath; "
    "identity = c.cluster.boot.identity.hash; }"
)


def preflight_facts(ctx: Ctx, node: str) -> dict[str, Any]:
    """What preflight checks, without printing. Refuses on secrets that are not committed,
    since an install uploads what is committed and a node built from anything else will not
    match it. Forcing both drvPaths is what makes every posture assertion fire here rather than on
    the server."""
    boot = _boot_info(ctx, node)
    changed = _changed_secrets(ctx.root)
    if changed:
        raise AvcError("secrets are not committed (git add secrets, then commit):\n  " + "\n  ".join(changed))
    with ui.spin(f"evaluating {node}: toplevel and disko script"):
        out = proc.out(
            ["nix", "eval", "--json", f".#nixosConfigurations.{node}.config", "--apply", PREFLIGHT_APPLY],
            cwd=ctx.root,
        )
    facts = json.loads(out)
    facts["hostKeyPub"] = boot.get("hostKeyPub")
    facts["sshPort"] = boot.get("sshPort")
    return facts


def _opted_out(ctx: Ctx, node: str) -> bool:
    info = ctx.index.nodes.get(node)
    if info is None:
        raise AvcError(f"unknown node {node!r} (known: {', '.join(ctx.index.nodes)})")
    return not (info.get("boot") or {}).get("enabled")


PLAIN_PREFLIGHT_APPLY = "c: { toplevel = c.system.build.toplevel.drvPath; disko = c.system.build.diskoScript.drvPath; }"


def plain_preflight(ctx: Ctx, node: str) -> None:
    """Before installing a node that opted out of boot security: the same two refusals, less
    what such a node does not have (an identity hash, an initrd host key)."""
    changed = _changed_secrets(ctx.root)
    if changed:
        raise AvcError("secrets are not committed (git add secrets, then commit):\n  " + "\n  ".join(changed))
    with ui.spin(f"evaluating {node}: toplevel and disko script"):
        proc.out(["nix", "eval", "--json", f".#nixosConfigurations.{node}.config", "--apply", PLAIN_PREFLIGHT_APPLY], cwd=ctx.root)
    ui.ok(f"{node} evaluates")


def _fingerprint(pub: str | None) -> str:
    if not pub:
        return "(none: run `avc secrets provision`)"
    p = proc.run(["ssh-keygen", "-lf", "-"], input=pub + "\n", check=False)
    return p.stdout.strip() if p.returncode == 0 else "(unreadable)"


@action("boot", "preflight", "Check a node before install or reboot (forces every assertion)", Arg("node", "Node", choices=_all_nodes))
def preflight(ctx: Ctx, node: str) -> None:
    facts = preflight_facts(ctx, node)
    ui.ok(f"{node} evaluates: every boot security assertion holds")
    ui.say(f"volume identity hash: {facts['identity']}")
    ui.say(f"initrd host key: {_fingerprint(facts['hostKeyPub'])}")
    ui.say("Record these with the node. Never regenerate volume-identity or luks after install.")


# ── install ─────────────────────────────────────────────────────────────────
#
# `install` verifies the rescue system's SSH host key, asks, then runs the site's installer
# for the node (`nix run .#install-<node>`, lib/mk-cluster.nix): nixos-anywhere from
# nixos-install-helper, in two runs with `stage` between them.
#
#   0. The rescue system's host key, read from it and compared by the operator with what
#      the server's console shows (or with --host-key-fingerprint), then pinned: every
#      connection of the run, avc's and nixos-anywhere's, is checked against it and against
#      nothing else (avc/core/hostpin.py). Over the first of them the host keys the kexec
#      will carry into the installer are read, and pinned too.
#   1. kexec: the rescue system becomes the NixOS installer, in memory, with the rescue
#      system's host keys (nixos-images' kexec `run` copies /etc/ssh/ssh_host_* into the
#      installer's initrd, and its restore-remote-access module puts them back).
#   2. `avc boot stage <node>`, started by the installer as its pre-install hook:
#        - the node's age identity, made on its TPM (age-plugin-tpm), or the one from the
#          last install if this TPM still holds its key;
#        - a new recipient shown and confirmed, then it and its identity file (encrypted to
#          the operators) written to the repository, and every secret the node reads
#          rekeyed to it;
#        - the identity file staged for the new root;
#        - the partitioning secrets decrypted for the installer's /run.
#   3. disko, nixos-install, reboot. The flake is evaluated only now, so the closure that
#      is installed holds the secrets the node can decrypt.
#
# The identity is made in the kexec'd installer and not in the provider's rescue system:
# that is the kernel and the TPM driver that will format the disks and enroll the TPM slot a
# moment later, it has Nix, so the plugin is the one this library pins and not a static
# build kept beside it, and a rescue system's kernel need not have a TPM driver at all.

# Set by `install` for the hook, which the installer starts: what its ssh takes besides
# the pinned host key (an identity file). The pin itself is hostpin.PIN_ENV.
INSTALL_SSH_ENV = "AVC_INSTALL_SSH"
# This program, for the hook to run (lib/mk-cluster.nix).
SELF_ENV = "AVC"
# Extra arguments for nixos-anywhere, for a site that needs them (--kexec <tarball>, …).
INSTALL_ARGS_ENV = "AVC_INSTALL_ARGS"
# The store paths copied to the installer (lib/avc.nix): age, and its TPM plugin.
AGE_ENV = "AVC_AGE"
AGE_TPM_ENV = "AVC_AGE_PLUGIN_TPM"

RECIPIENT = re.compile(r"^# (?:Recipient|public key): (\S+)$", re.M)

NOTHING_SENT = "Nothing was sent to it, and nothing on its disks, on its TPM or in the repository was changed."


def install_target(target: str) -> str:
    return target if "@" in target else f"root@{target}"


def install_argv(node: str, target: str, identity: str | None = None, extra: str = "") -> list[str]:
    """The site's installer for `node`, and what follows the target, which is nixos-anywhere's."""
    argv = ["nix", "run", f".#install-{node}", "--", install_target(target)]
    if identity:
        argv += ["-i", identity]
    return argv + shlex.split(extra)


def install_ssh(identity: str | None = None) -> list[str]:
    return ["-i", identity] if identity else []


def install_port(extra: list[str]) -> int | None:
    """The rescue system's SSH port, when nixos-anywhere is told one."""
    for flag, value in zip(extra, extra[1:], strict=False):
        if flag in ("-p", "--ssh-port") and value.isdigit():
            return int(value)
    return None


def _console_command(key: hostpin.HostKey) -> str:
    kind = key[0].removeprefix("ssh-").split("-")[0]  # ed25519, rsa, ecdsa
    return f"ssh-keygen -lf /etc/ssh/ssh_host_{kind}_key.pub"


def verify_host_key(host: str, keys: list[hostpin.HostKey], expected: str | None) -> hostpin.HostKey:
    """The one key of `keys` (what `host` presented, to a connection nothing authenticated)
    that is known to be the machine's: by the fingerprint given up front, or by the operator
    comparing it with the server's console. --yes does not answer this, and without a
    terminal only the fingerprint does."""
    shown = [(k, hostpin.fingerprint(k)) for k in keys]
    listing = "\n".join(f"  {fp} ({k[0]})" for k, fp in shown)
    if expected is not None:
        want = expected.strip().rstrip("=")
        if not want.startswith("SHA256:"):
            raise AvcError(f"--host-key-fingerprint takes a fingerprint as `ssh-keygen -lf` prints it (SHA256:…), not {expected!r}. {NOTHING_SENT}")
        for key, fp in shown:
            if fp == want:
                ui.ok(f"{host} presents the host key given: {fp} ({key[0]})")
                return key
        raise AvcError(
            f"{host} does not present the host key {want}. It presents:\n{listing}\n"
            f"That is another machine, or someone between you and it. {NOTHING_SENT}"
        )
    key, fp = shown[0]
    ui.info(f"{host} presents this SSH host key, and nothing has verified it yet:")
    ui.say(f"{fp} ({key[0]})")
    ui.say(f"At the server's console (IPMI/KVM, not SSH), in the rescue system, run: {_console_command(key)}")
    if not ui.can_ask():
        raise AvcError(
            f"{host}'s host key has to be compared with what its console shows, and there is no terminal to ask at: "
            f"read it there and give --host-key-fingerprint SHA256:…. {NOTHING_SENT}"
        )
    if not ui.attest(f"Does the console show exactly {fp}?"):
        raise AvcError(f"{host}'s host key was not confirmed. {NOTHING_SENT}")
    return key


# In the verified session: the host keys the kexec carries into the installer are the
# files /etc/ssh/ssh_host_*, which need not be the key the rescue system's sshd presents,
# and the installer's sshd reads the ed25519 and the rsa one. So an ed25519 key is made
# there if there is none (in the rescue system's memory: the installer will present it),
# and the public half of each, computed from the private file, is this command's output.
CARRIED_HOST_KEYS = (
    's=; [ "$(id -u)" = 0 ] || s="sudo -n"; k=/etc/ssh/ssh_host_ed25519_key; '
    'if ! $s test -s "$k"; then { $s mkdir -p /etc/ssh && $s ssh-keygen -q -t ed25519 -N "" -f "$k"; } </dev/null >/dev/null 2>&1 || true; fi; '
    'for t in ed25519 rsa; do k=/etc/ssh/ssh_host_${t}_key; if $s test -s "$k"; then $s ssh-keygen -y -f "$k" 2>/dev/null || true; fi; done'
)


def carry_host_key(pin: hostpin.Pin, target: str, identity: str | None = None, port: int | None = None) -> list[hostpin.HostKey]:
    """The first authenticated connection of an install: reads, over it, the host keys the
    installer will present after the kexec, and pins them. No key is trusted that did not
    come over a connection the pin had already checked."""
    cmd = ["ssh", *pin.options(), "-o", "ConnectTimeout=15", *(["-i", identity] if identity else []), *(["-p", str(port)] if port else [])]
    # ssh's own words go to the terminal: a password or a touch may be asked for there.
    p = subprocess.run([*cmd, target, CARRIED_HOST_KEYS], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
    if p.returncode == 255:
        raise AvcError(
            f"no verified SSH connection to {target} (ssh's message is above): if it names the host key, the machine that "
            f"answers now is not the one whose key was just verified. {NOTHING_SENT}"
        )
    keys = hostpin.parse_keys(p.stdout, hosted=False)
    for key in keys:
        pin.trust(key)
    if not keys:
        ui.warn(
            f"could not read the host keys {target} will carry into the installer (/etc/ssh/ssh_host_*): if the installer "
            "presents a key other than the one verified, the install stops there, before anything is partitioned or sent"
        )
    return keys


def _refusal(node: str, target: str, pin: hostpin.Pin) -> str:
    head = (
        f"{target} answered with an SSH host key that is not one verified for this install, and the connection was "
        f"refused ({pin.note('refused').strip() or 'ssh'}). Whatever answers there now is not known to be the machine. "
    )
    if not pin.marked("staging"):
        return head + (
            "That was before `avc boot stage`: nothing on its disks was changed, nothing was rekeyed or written to "
            "the repository, and no secret was sent."
        )
    kept = (
        f"If secrets/ changed (`git status secrets/`), it holds {node}'s recipient, read from the verified machine, "
        "and what was rekeyed to it; nothing was shipped."
    )
    if not pin.marked("staged"):
        return head + f"That was during `avc boot stage`: nothing on its disks was changed, and no disk secret was sent. {kept}"
    return head + (
        "That was after `avc boot stage`: the disks may be partitioned or partly installed, so install again from the "
        "rescue system. What had been sent by then (the recovery key, the volume identity secret and the initrd host "
        f"key, once the partitioning began) went to the verified machine, and the refused connection was sent nothing. {kept}"
    )


def install_pinned(
    root: Path,
    node: str,
    target: str,
    argv: list[str],
    identity: str | None = None,
    fingerprint: str | None = None,
    port: int | None = None,
    ask: Any = None,
) -> None:
    """Everything of an install that reaches the machine, under one pinned host key: the
    key verified, `ask` (the question about the disks), the keys the kexec carries, then the
    installer `argv` with the pin on its PATH and in its environment, watched for a refused
    key. tests/install-node.nix runs this with the installer app itself as `argv`."""
    target = install_target(target)
    host = target.split("@", 1)[1]
    with hostpin.pinned(node, host) as pin:
        with ui.spin(f"reading {host}'s SSH host key"):
            keys = hostpin.scan(host, port)
        pin.trust(verify_host_key(host, keys, fingerprint))
        if ask is not None:
            ask()
        carry_host_key(pin, target, identity, port)
        env = dict(os.environ)
        env["IH_ASSUME_YES"] = "1"  # asked above
        env[SELF_ENV] = os.path.abspath(sys.argv[0])
        env[INSTALL_SSH_ENV] = shlex.join(install_ssh(identity))
        env[hostpin.PIN_ENV] = str(pin.dir)
        # nixos-anywhere, ssh-copy-id and Nix find `ssh` on PATH: this one holds them to the pin.
        env["PATH"] = f"{pin.shim()}{os.pathsep}{env.get('PATH', '')}"
        rc = hostpin.run_watched(argv, root, env, pin)
        if pin.marked("refused"):
            # The installer was stopped, not left to end: what it staged in memory goes now.
            for left in pin.note("staged").splitlines():
                shutil.rmtree(left, ignore_errors=True)
            raise AvcError(_refusal(node, target, pin))
    if rc != 0:
        raise AvcError(
            f"the install of {node} ended with status {rc}. Before the partitioning nothing on the disks has changed; "
            "after it, run it again from the rescue system: it formats again. What it wrote under secrets/ is "
            f"{node}'s recipient and what was rekeyed to it, and the next run uses the same identity if the TPM still has it."
        )


@action(
    "boot",
    "install",
    "Install a node from a rescue system (destroys its disks)",
    Arg("node", "Node", choices=_all_nodes),
    Arg("target", "Rescue system, root@<address>"),
    Arg("identity", "SSH private key for the rescue system", option=True),
    Arg("host_key_fingerprint", "The SHA256:… fingerprint of the rescue system's SSH host key, read at its console: given, nothing is asked", option=True),
)
def install(ctx: Ctx, node: str, target: str, identity: str | None = None, host_key_fingerprint: str | None = None) -> None:
    opted_out = _opted_out(ctx, node)
    if opted_out:
        # Plain disks and no Secure Boot, by the topology's own word. Its secrets are still
        # its TPM's to decrypt, so the rest of an install is the same.
        plain_preflight(ctx, node)
        ui.warn(f"{node} has boot security off (insecurePlaintextBoot): its disks will be plaintext")
    else:
        preflight(ctx, node)

    def ask() -> None:
        ui.warn(f"this wipes every disk of {target} and installs {node} on it")
        ui.type_to_confirm(f"Type the node's name to install {node} on {target}", node)

    extra = os.environ.get(INSTALL_ARGS_ENV, "")
    install_pinned(
        ctx.root,
        node,
        target,
        install_argv(node, target, identity, extra),
        identity=identity,
        fingerprint=host_key_fingerprint,
        port=install_port(shlex.split(extra)),
        ask=ask,
    )
    ui.ok(f"{node} is installed and rebooting: its first boot unlocks from its TPM, and nobody types")
    ctx.forget()
    ship.ship(ctx, f"feat(secrets): {node}'s age identity, and what it reads rekeyed to it", paths=["secrets/"])
    if not opted_out:
        ui.say(
            f"Next: `avc boot status {node}` (Setup Mode, both legs ONLINE, TPM slots not sealed yet), "
            f"then `avc boot enroll {node}`, `avc boot reboot {node}`, `avc boot bind {node}`, `avc boot reboot {node}`."
        )


class Installer:
    """A machine whose TPM makes a node's identity, root over SSH: the target once it is the
    NixOS installer, under the install's pinned host key, or a running node, under the
    operator's known_hosts. One connection for all of it, so that a key that wants a touch
    wants one."""

    def __init__(self, target: str, ssh_opts: list[str], control: Path) -> None:
        self.target = install_target(target)
        self.opts = [*ssh_opts, "-o", "ControlMaster=auto", "-o", f"ControlPath={control}", "-o", "ControlPersist=120"]

    def run(self, command: str, input: str | None = None, check: bool = True, timeout: float | None = 300) -> subprocess.CompletedProcess[str]:
        return proc.run(["ssh", *self.opts, self.target, command], input=input, check=check, timeout=timeout)

    def copy(self, paths: list[str]) -> None:
        """Store paths, with what they need: the installer has Nix and nothing of ours."""
        env = dict(os.environ, NIX_SSHOPTS=shlex.join(self.opts))
        cmd = ["nix", "--extra-experimental-features", "nix-command", "copy", "--no-check-sigs", "--to", f"ssh-ng://{self.target}", *paths]
        p = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if p.returncode != 0:
            raise AvcError(f"could not copy age and its TPM plugin to {self.target}:\n{(p.stderr or p.stdout).strip()}")

    def close(self) -> None:
        subprocess.run(["ssh", *self.opts, "-O", "exit", self.target], capture_output=True)


def _tools() -> tuple[str, str]:
    age, plugin = os.environ.get(AGE_ENV), os.environ.get(AGE_TPM_ENV)
    if not age or not plugin:
        raise AvcError(f"{AGE_ENV} and {AGE_TPM_ENV} are not set: run avc from `nix run .#avc` or the devShell (lib/avc.nix)")
    return age, plugin


WAIT_FOR_TPM = (
    "modprobe -a tpm_crb tpm_tis 2>/dev/null; i=0; "
    "while [ ! -e /dev/tpmrm0 ] && [ $i -lt 15 ]; do sleep 1; i=$((i+1)); done; test -e /dev/tpmrm0"
)


def identity_works(installer: Installer, store: secretstore.Store, age: str, plugin: str, identity: str, recipient: str) -> bool:
    """Whether this machine's TPM holds the key `identity` names: a value encrypted here to
    the recipient, decrypted there. The identity goes in on stdin and is written nowhere."""
    nonce = os.urandom(16).hex()
    ciphertext = base64.b64encode(store.encrypt(nonce.encode(), ["-r", recipient])).decode()
    script = (
        "set -eu; d=$(mktemp -d -p /run); trap 'rm -rf \"$d\"' EXIT; cat > \"$d/identity\"; "
        f"printf %s {shlex.quote(ciphertext)} | base64 -d > \"$d/ciphertext\"; "
        f"PATH={shlex.quote(plugin)}/bin:$PATH {shlex.quote(age)}/bin/age -d -i \"$d/identity\" \"$d/ciphertext\""
    )
    p = installer.run(script, input=identity.rstrip() + "\n", check=False)
    return p.returncode == 0 and p.stdout.strip() == nonce


def node_identity(installer: Installer, store: secretstore.Store, node: str) -> tuple[str, str, bool]:
    """(identity file, recipient, new) for the machine `installer` reaches. The one in the
    repository when this TPM still answers for it (a reinstall: nothing to rekey), else a
    new one made on the TPM."""
    age, plugin = _tools()
    if installer.run(WAIT_FOR_TPM, check=False).returncode != 0:
        raise AvcError(f"{installer.target} has no TPM (/dev/tpmrm0): enable it in the firmware. Nothing on its disks was changed.")
    with ui.spin("copying age and its TPM plugin to the installer"):
        installer.copy([age, plugin])
    kept = store.node_identity(node)
    recipient = store.recipient(node)
    if kept is not None and recipient is not None:
        if identity_works(installer, store, age, plugin, kept, recipient):
            ui.ok(f"{node}'s TPM still holds its age key: the identity in the repository is kept, and nothing is rekeyed")
            return kept, recipient, False
        ui.warn(f"{node}'s identity in the repository does not work on this TPM (cleared, or another machine): a new one is made")
    made = installer.run(f"{shlex.quote(plugin)}/bin/age-plugin-tpm --generate").stdout
    found = RECIPIENT.search(made)
    if found is None or not any(line and not line.startswith("#") for line in made.splitlines()):
        raise AvcError(f"age-plugin-tpm on {installer.target} did not print an identity and its recipient")
    recipient = found.group(1)
    if not identity_works(installer, store, age, plugin, made, recipient):
        raise AvcError(f"the identity just made on {installer.target}'s TPM does not decrypt what is encrypted to it")
    return made, recipient, True


def confirm_recipient(node: str, recipient: str, where: str) -> None:
    """A new identity: everything `node` reads is about to be encrypted to a recipient that
    `where` printed. Shown, and confirmed by a person: --yes does not answer, and without a
    terminal it is refused. An identity the repository already holds asks nothing."""
    ui.warn(f"{where} made a new age identity for {node}, on its TPM. Its recipient:")
    ui.say(recipient)
    ui.say(f"Every secret {node} reads, the fleet's shared keys among them, is about to be encrypted to it and written to the repository.")
    refusal = f"Nothing was rekeyed or written to the repository, and nothing on {node}'s disks was changed."
    if not ui.can_ask():
        raise AvcError(f"a new recipient for {node} is confirmed at a terminal, and there is none. {refusal}")
    if not ui.attest(f"Encrypt everything {node} reads to this recipient?"):
        raise AvcError(f"{node}'s new recipient was not confirmed. {refusal}")


def _stage_file(base: Path, absolute: str, data: bytes) -> Path:
    path = base / absolute.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    return path


def stage_node(
    store: secretstore.Store,
    node: str,
    installer: Installer,
    extra_files: Path,
    disk_keys: Path,
    rekey: Any = None,
    confirm: Any = None,
) -> str:
    """What `stage` does, with everything it touches given (tests/install-node.nix runs it in a
    VM, against a real TPM and a real installer). Returns the node's recipient."""
    partitioning = [(g, f) for g in store.generators(node) for f in g.files if f.secret and f.needed_for == "partitioning"]
    missing = [f"{g.name}/{f.name}" for g, f in partitioning if not g.path(store.root, f).exists()]
    if missing:
        raise AvcError(f"{node}'s install secrets are not generated ({', '.join(missing)}): `avc secrets provision`. Nothing was partitioned.")
    # Plaintext waits in this directory for the installer to send it: memory, or refuse.
    if secretstore.filesystem(disk_keys) not in secretstore.RAM_FILESYSTEMS:
        raise AvcError(f"{disk_keys} is not on a tmpfs: a disk secret is never written to a disk. Nothing was partitioned.")

    identity, recipient, new = node_identity(installer, store, node)
    if new:
        # Before the repository or a single secret is touched.
        (confirm or confirm_recipient)(node, recipient, installer.target)
        store.set_node_identity(node, identity, recipient)
    # Rekeyed before the build, which is the installer's next step: the closure it installs
    # is the first one this node boots, and it must hold what the node can decrypt.
    (rekey or store.rekey)()

    cfg = store.export[node]
    _stage_file(extra_files, cfg["identityPath"], identity.encode())
    for g, f in partitioning:
        _stage_file(disk_keys, cfg["generators"][g.name]["files"][f.name]["path"], store.decrypt(g.path(store.root, f)))
    return recipient


@action(
    "boot",
    "stage",
    "The installer's step between the kexec and the partitioning (run by `avc boot install`, not by hand)",
    Arg("node", "Node", choices=_all_nodes),
)
def stage(ctx: Ctx, node: str) -> None:
    need = {v: os.environ.get(v) for v in ("IH_TARGET", "IH_EXTRA_FILES", "IH_DISK_KEYS", hostpin.PIN_ENV)}
    if not all(need.values()):
        raise AvcError(
            "`avc boot stage` is the installer's pre-install hook and reads "
            f"{', '.join(need)} from it: run `avc boot install {node} root@<rescue address>`"
        )
    _opted_out(ctx, node)  # an unknown node is refused; an opted-out one has no partitioning secrets, and is staged
    store = secretstore.store(ctx.root)
    extra_files, disk_keys = Path(need["IH_EXTRA_FILES"]), Path(need["IH_DISK_KEYS"])
    with staging(extra_files, disk_keys) as ssh_opts, tempfile.TemporaryDirectory(prefix="avc-ssh-", dir=secretstore.runtime_dir()) as control:
        installer = Installer(need["IH_TARGET"], ssh_opts, Path(control) / "c")
        try:
            recipient = stage_node(store, node, installer, extra_files, disk_keys)
        finally:
            installer.close()
    ui.ok(f"{node}'s recipient is {recipient}; its secrets are rekeyed to it, and the install secrets are staged")


@contextlib.contextmanager
def staging(extra_files: Path, disk_keys: Path) -> Iterator[list[str]]:
    """The hook's side of an install's pin (hostpin.PIN_ENV): the ssh options for the
    installer, the pinned ones first, and the marks `avc boot install` reads to say what had
    and had not happened if a host key is refused. Refuses to begin unless the installer's
    own connections went through the pin: the kexec is behind it, and if those were not
    checked, what answers now is not known to be the machine whose key was verified."""
    pin = hostpin.Pin.load(Path(os.environ.get(hostpin.PIN_ENV, "")))
    if not pin.keys():
        raise AvcError(f"this install has no verified host key for {pin.host}. Nothing was partitioned, rekeyed or sent.")
    if pin.uses() == 0:
        raise AvcError(
            f"the installer reached {pin.host} without this install's pinned host key: its ssh is not the one "
            f"`avc boot install` put on its PATH ({pin.dir}/bin). Nothing was partitioned, rekeyed or sent."
        )
    pin.mark("staging")
    try:
        yield [*pin.options(), *shlex.split(os.environ.get(INSTALL_SSH_ENV, ""))]
    except AvcError as e:
        if hostpin.refused(str(e)):
            pin.mark("refused", "avc boot stage")
        raise
    pin.mark("staged", f"{disk_keys}\n{extra_files}\n")


@action(
    "boot",
    "identity",
    "Make a node's age identity on its TPM again (the TPM was cleared or replaced, or the identity file is gone)",
    Arg("node", "Node", choices=_nodes),
)
def identity(ctx: Ctx, node: str) -> None:
    """A node that boots and decrypts none of its secrets: its TPM no longer holds the key
    its identity file names, or the file is gone from its disk. On the running node, the
    same step an install takes: the identity in the repository when this TPM still answers
    for it (the file is put back, nothing else changes), else a new one, its recipient
    committed and everything the node reads rekeyed to it."""
    n = ctx.node(node)
    store = secretstore.store(ctx.root)
    with tempfile.TemporaryDirectory(prefix="avc-ssh-", dir=secretstore.runtime_dir()) as control:
        running = Installer(f"root@{n.host}", ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"], Path(control) / "c")
        try:
            made, recipient, new = node_identity(running, store, node)
            if new:
                # Before the node, the repository or a secret is touched.
                confirm_recipient(node, recipient, running.target)
            path = store.export[node]["identityPath"]
            running.run(f"install -D -m 0400 /dev/stdin {shlex.quote(path)}", input=made.rstrip() + "\n")
        finally:
            running.close()
    if not new:
        ui.ok(f"{node}'s identity file is back at {path}: its secrets decrypt at the next activation (a deploy, or a reboot)")
        return
    store.set_node_identity(node, made, recipient)
    store.rekey()
    ui.ok(f"{node} has a new identity ({recipient}), and what it reads is rekeyed to it")
    ui.warn(
        f"{node} holds none of its secrets until a closure built from this tree is on it, and without them it cannot "
        f"pull one: `avc deploy break-glass {node}` applies the working tree over SSH"
    )
    ship.ship(ctx, f"feat(secrets): {node}'s new age identity, and what it reads rekeyed to it", paths=["secrets/"])


# ── unlock ──────────────────────────────────────────────────────────────────


def unlock_argv(host: str, port: int, known_hosts: str) -> list[str]:
    """Answers the initrd's password queries on a terminal, over the initrd's own sshd. Strict
    host key checking against the repository's public key: this protects against connecting
    to the wrong machine by accident, not against someone who has read the ESP, where the
    key is too."""
    return [
        "ssh",
        "-tt",
        "-p",
        str(port),
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "StrictHostKeyChecking=yes",
        f"root@{host}",
        "systemd-tty-ask-password-agent",
        "--query",
    ]


def known_hosts_line(host: str, port: int, pub: str) -> str:
    keytype, key = pub.split()[:2]
    return f"[{host}]:{port} {keytype} {key}\n"


@action("boot", "unlock", "Type the recovery key over the initrd's SSH (a node whose TPM refused)", Arg("node", "Node", choices=_all_nodes))
def unlock(ctx: Ctx, node: str) -> None:
    boot = _boot_info(ctx, node)
    pub = boot.get("hostKeyPub")
    if not pub:
        raise AvcError(f"{node} has no initrd host key in the repository: run `avc secrets provision`")
    host = ctx.index.nodes[node]["deployHost"]
    port = int(boot["sshPort"])
    ui.say(f"the recovery key is `avc secrets reveal {node}:luks/passphrase`. A typo puts the prompts out of step, so it may ask again.")
    with tempfile.NamedTemporaryFile("w", prefix="avc-initrd-", suffix=".known_hosts") as f:
        f.write(known_hosts_line(host, port, pub))
        f.flush()
        rc = subprocess.run(unlock_argv(host, port, f.name)).returncode
    if rc != 0:
        raise AvcError(f"ssh to {node}'s initrd ended with status {rc}")


# ── on the running node ─────────────────────────────────────────────────────


def _metrics(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and " " in line:
            name, value = line.rsplit(" ", 1)
            out[name] = value
    return out


@action("boot", "status", "Secure Boot, bindings, identity and the boot report", Arg("node", "Node", choices=_nodes))
def status(ctx: Ctx, node: str) -> None:
    n = ctx.node(node)
    ui.out(n.run("cluster-boot-seal status 2>&1", check=False).stdout)
    ui.out(n.run(f"cat {TEXTFILES}/boot_report.prom {TEXTFILES}/boot_audit.prom 2>/dev/null", check=False).stdout)


@action("boot", "enroll", "Enroll the node's own Secure Boot keys (firmware in Setup Mode)", Arg("node", "Node", choices=_nodes))
def enroll(ctx: Ctx, node: str) -> None:
    rc = ctx.node(node).stream("cluster-boot-seal enroll")
    if rc != 0:
        raise AvcError("enrollment refused or failed: see above")
    ui.ok(f"enrolled. Next: `avc boot reboot {node}` (still unlocked by the install's TPM slot), then `avc boot bind {node}`")


def bind_command(replace: bool, device: str | None) -> str:
    cmd = "cluster-boot-seal bind"
    if replace:
        cmd += " --replace"
    if device:
        if not device.startswith("/dev/") or any(c.isspace() or c in "'\"$`;&|\\" for c in device):
            raise AvcError(f"not a device path: {device!r}")
        cmd += f" --device {device}"
    return cmd


def bind_script(replace: bool, device: str | None, marker: str = BOUND_MARKER) -> str:
    """The bind, then the marker: `marker` is written only if the bind returned 0. A failed
    bind (Setup Mode, a burned PCR 7, a missing identity) must not leave the marker that
    turns `avc boot reboot`'s refusal of a short TPM count into a note. Its exit status is
    the bind's, or the marker's if writing it fails. The recovery key, when one is sent, is
    this script's stdin, and only the bind reads it."""
    bind = bind_command(replace, device)
    return f'rc=0; {bind} || rc=$?; if [ "$rc" = 0 ]; then touch {shlex.quote(marker)} || rc=$?; fi; exit "$rc"'


@action(
    "boot",
    "bind",
    "Bind each LUKS leg to the TPM, sealed to PCR 7 (enforcing Secure Boot only)",
    Arg("node", "Node", choices=_nodes),
    Arg("replace", "Replace the existing TPM binding", flag=True),
    Arg("device", "Only this leg, e.g. after a disk replacement", option=True),
    Arg("recovery_key", "Authorise with the node's recovery key, for a leg whose TPM slot is gone or does not open", flag=True),
)
def bind(ctx: Ctx, node: str, replace: bool = False, device: str | None = None, recovery_key: bool = False) -> None:
    command = bind_script(replace, device)
    # Without the key, each leg's own TPM slot authorises its new one, and the key stays
    # encrypted in the repository. With it: on stdin, from the repository (decrypted in
    # memory) to the node, and nowhere in between that prints.
    key = secretstore.get_value(ctx.root, node, "luks/passphrase") if recovery_key else ""
    p = ctx.node(node).pipe(command, key, check=False, timeout=600)
    ui.out(p.stdout)
    if p.returncode != 0:
        hint = "" if recovery_key else f" (a leg with no TPM slot that opens needs `avc boot bind {node} --recovery-key`)"
        raise AvcError(f"bind refused or failed ({p.returncode}): {(p.stderr or '').strip()}{hint}")
    ui.ok(f"bound. Next: `avc boot reboot {node}`, and nobody should have to type")


# ── reboot ──────────────────────────────────────────────────────────────────

# What the next boot depends on, read now, while it can still be fixed: the boot contract,
# the ESPs, holds, the bindings as they are on disk (`cluster-boot-seal check`: every leg
# that is there has a TPM slot that opens now), and the identity secret the
# initrd will look for. The last boot report says how the previous unlock went, which
# says nothing about a leg bound or replaced since, or a secret deleted since. And which
# closure the default entry is: after a rollback it is still the one rolled back from.
REBOOT_CHECK = rf"""
set -u
cmp -s /nix/var/nix/profiles/system/boot-contract /run/current-system/boot-contract && echo contract=same || echo contract=differs
{deploy_state.DEFAULT_ENTRY}
for e in /boot /boot-fallback; do
  if mountpoint -q "$e"; then echo "esp $e $(df --output=avail -B1 "$e" | tail -n 1 | tr -d ' ')"; else echo "esp $e unmounted"; fi
done
test -e {BURN_MARKER} && echo burned=yes || echo burned=no
test -e {BOUND_MARKER} && echo bound_this_boot=yes || echo bound_this_boot=no
for h in {HOLD_DIR}/*; do [ -e "$h" ] && echo "hold $(basename "$h")"; done
if out=$(cluster-boot-seal check 2>&1); then rc=0; else rc=$?; fi
echo "seal_check=$rc"
printf '%s\n' "$out" | sed 's/^/seal: /'
if out=$(cluster-boot-seal identity 2>&1); then rc=0; else rc=$?; fi
echo "identity_check=$rc"
printf '%s\n' "$out" | sed 's/^/identity: /'
cat {TEXTFILES}/boot_report.prom 2>/dev/null
"""


def _field(lines: list[str], key: str) -> str | None:
    for line in lines:
        if line.startswith(key):
            return line[len(key) :]
    return None


def reboot_verdict(text: str) -> tuple[list[str], list[str]]:
    """(refusals, notes) from what REBOOT_CHECK printed."""
    refusals: list[str] = []
    notes: list[str] = []
    lines = text.splitlines()
    if "contract=same" not in lines:
        refusals.append("the default entry's boot contract differs from the running one: the next boot may need the console")
    # Positive form: only a denylist read as not naming it lets this through.
    default = _field(lines, "default_entry=") or "(unreadable)"
    refused = _field(lines, "default_refused=")
    if refused == "yes":
        refusals.append(
            f"the default entry, {default}, is on the rollback denylist: this node would boot straight back into "
            "the closure it was rolled back from. Deploy a good closure first, which becomes the default, or pick the "
            "generation at the console"
        )
    elif refused != "no":
        refusals.append(
            f"can't tell whether the default entry, {default}, is on the rollback denylist "
            "(/var/lib/cluster-upgrade/refused unreadable, or the profile is)"
        )
    if "default_is_running=yes" not in lines and refused == "no":
        notes.append(f"the default entry, {default}, is not the running closure: the next boot runs {default}, not this one")
    esps = [line.split() for line in lines if line.startswith("esp ")]
    if not any(len(e) == 3 and e[2] != "unmounted" for e in esps):
        refusals.append("no ESP is mounted")
    for e in esps:
        if len(e) == 3 and e[2] == "unmounted":
            notes.append(f"{e[1]} is not mounted: that leg's ESP is not up to date")
    # Automated holds are what a running job (a backup, a failover restore) sets to keep the
    # node still. A reboot would pull the node out from under it.
    holds = [line.split(" ", 1)[1] for line in lines if line.startswith("hold ")]
    if holds:
        refusals.append(f"automated holds are set ({', '.join(holds)}): something is running that needs this node up")
    burned = "burned=yes" in lines
    if burned:
        notes.append("PCR 7 was burned this boot (emergency recovery): the binding only looks broken. Reboot to clear it.")
    seal = _field(lines, "seal_check=")
    failed = "; ".join(line.removeprefix("seal: ") for line in lines if line.startswith("seal: FAILED"))
    if seal == "1":
        refusals.append(
            f"a leg has no TPM binding, or its TPM slot does not open ({failed or 'cluster-boot-seal check'}): "
            "the next boot would wait at the prompt. Rebind first (`avc boot bind`, with --device for one leg)"
        )
    elif seal == "3" and not burned:
        refusals.append("cluster-boot-seal check says PCR 7 was burned, and the burn marker is gone: can't tell")
    elif seal not in ("0", "3"):
        refusals.append(f"cluster-boot-seal check could not run (rc={seal}): nothing says this node unlocks unattended")
    if any(line.startswith("seal: OK") and "NOT SEALED" in line for line in lines):
        notes.append(
            "a leg's TPM slot is the install's, not sealed to PCR 7: the next boot is unattended, and so is anyone "
            "else's boot of this machine. `avc boot bind` once Secure Boot is enforcing"
        )
    if _field(lines, "identity_check=") != "0":
        why = "; ".join(line.removeprefix("identity: ") for line in lines if line.startswith("identity: "))
        refusals.append(
            f"the volume identity secret is missing or wrong ({why or 'no answer'}): the node would halt at its next "
            "boot. Restore it first (README, Recovery: 'Identity secret damaged')"
        )
    m = _metrics(text)
    tpm, expected = m.get("cluster_boot_unlock_tpm_devices"), m.get("cluster_boot_unlock_expected_devices")
    # `avc boot bind` leaves its marker in /run only when the bind succeeded, so it is there
    # only if this boot was bound. Then the last unlock predates the binding: it was typed
    # (install S5, or the recovery that needed the bind), and only this reboot can prove the
    # new binding. The seal check above has already refused a leg that is unbound or whose
    # TPM slot does not open.
    bound_this_boot = "bound_this_boot=yes" in lines
    if tpm is None or expected is None:
        notes.append("no boot report on this node yet, so the last unlock's health is unknown")
    elif tpm != expected and not burned and bound_this_boot:
        notes.append(
            f"the last boot unlocked {tpm} of {expected} devices from the TPM, before this boot's "
            "`avc boot bind`: this reboot is what proves the new binding"
        )
    elif tpm != expected and not burned:
        refusals.append(f"the last boot unlocked {tpm} of {expected} devices from the TPM: fix the binding first")
    notes.append("These checks ran on the booted system. Only a real reboot proves the initrd unlocks from the TPM.")
    return refusals, notes


@action("boot", "reboot", "Reboot one node, after checking it should come back unattended", Arg("node", "Node", choices=_nodes))
def reboot(ctx: Ctx, node: str) -> None:
    _boot_info(ctx, node)
    n = ctx.node(node)
    refusals, notes = reboot_verdict(n.run(REBOOT_CHECK, check=False).stdout)
    for note in notes:
        ui.info(note)
    if refusals:
        for r in refusals:
            ui.err(r)
        raise AvcError(f"not rebooting {node}")
    if not ui.confirm(f"Reboot {node} now?"):
        return
    before = n.run(BOOT_ID, timeout=10).stdout.strip()
    try:
        n.run("systemctl reboot", check=False, timeout=30)
    except AvcError:
        pass  # the connection may go before the command returns
    _wait_back(n, before)


def _probe_boot_id(n: Node) -> str | None:
    """This boot's id, or None while the node does not answer."""
    try:
        p = n.run(BOOT_ID, check=False, timeout=10)
    except AvcError:
        return None
    return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None


def _wait_back(n: Node, before: str, down_for: float = 120, back_in: float = 900, every: float = 3) -> None:
    """Back means a new boot id. A node that still answers with the old one never rebooted:
    the command failed, or shutdown is stuck. Saying it was back would claim an unattended
    unlock nothing proved."""
    start = time.monotonic()
    gone = False
    with ui.spin(f"waiting for {n.name} to reboot and come back, unattended"):
        while True:
            now = _probe_boot_id(n)
            if now is None:
                gone = True
            elif now != before:
                ui.ok(f"{n.name} is back, on a new boot")
                return
            elapsed = time.monotonic() - start
            if not gone and elapsed > down_for:
                raise AvcError(f"{n.name} still runs the same boot after {down_for:.0f}s: it did not reboot")
            if elapsed > down_for + back_in:
                raise AvcError(
                    f"{n.name} did not come back within {down_for + back_in:.0f}s: it may be at the prompt "
                    f"(`avc boot unlock {n.name}`, with its recovery key)"
                )
            time.sleep(every)


# ── rollback ────────────────────────────────────────────────────────────────


def _report(node: str, refused: list[str]) -> None:
    for name in refused:
        ui.ok(f"{node}: refusing {name}")


def _rollback_all(ctx: Ctx) -> None:
    # Keep going past a node that fails: the others still need it, and the operator is
    # probably in the middle of an outage. The failure is reported at the end.
    any_refused = False
    failed = []
    for node in _nodes(ctx):
        try:
            _report(node, ctx.node(node).refuse_later())
            any_refused = True
        except NothingAfter as e:
            ui.warn(f"{node}: {e}")
        except AvcError as e:
            ui.err(f"{node}: {e}")
            failed.append(node)
    if failed:
        raise AvcError(f"not rolled back: {', '.join(failed)}")
    if not any_refused:
        raise AvcError("no node had anything to refuse")


@action(
    "boot",
    "rollback",
    "Refuse the generations after the running one, so the timer can't re-activate them",
    Arg("node", "Node", choices=_nodes, optional=True),
    Arg("all", "Every node", flag=True),
)
def rollback(ctx: Ctx, node: str | None, all: bool) -> None:
    if node and all:
        raise AvcError("give a node or --all, not both")
    if all:
        _rollback_all(ctx)
    else:
        node = node or ui.choose("Node", _nodes(ctx))
        _report(node, ctx.node(node).refuse_later())
    # The tick refuses these and goes no further, so nothing moves the profile.
    ui.warn("the boot default does not change: a reboot goes back to it until a good closure deploys")


@action(
    "boot",
    "unrollback",
    "Take a closure off a node's rollback denylist",
    Arg("node", "Node", choices=_nodes),
    Arg("closure", "Closure, as a basename or store path"),
)
def unrollback(ctx: Ctx, node: str, closure: str) -> None:
    basename = deploy_state.closure_basename(closure)
    if basename is None:
        raise AvcError(f"not a closure basename or store path: {closure!r}")
    ctx.node(node).unrefuse(basename)
    ui.ok(f"{node}: {basename} is no longer refused")
