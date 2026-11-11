"""Boot: install, unlock and seal an encrypted node (modules/boot-security.nix), and keep
a node off a closure that did not survive a reboot.

The order of a fresh install is the README's "Installing a node": preflight, install, unlock
(S3), enroll (S4), unlock again (S5), bind (S6), reboot (S7). Each command runs one step and
says what comes next.

Rollback's order: hold every node, revert or pin the private repo, boot the old
generation at the console, then `avc boot rollback`.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from avc import ui
from avc.actions import Arg, action
from avc.core import deploy_state, proc, repo
from avc.core import vars as clanvars
from avc.core.node import HOLD_DIR, Node, NothingAfter
from avc.errors import AvcError

if TYPE_CHECKING:
    from avc.context import Ctx

# Written by emergency-pcr-burn in the initrd; /run outlives switch-root.
BURN_MARKER = "/run/cluster-boot/pcr7-burned"
TEXTFILES = "/var/lib/prometheus-node-exporter-text"
# `avc boot bind`'s advertisement. It is uploaded under ADV_PENDING and becomes ADV_ON_NODE
# only once `cluster-boot-seal bind` has returned 0, so its presence says that a bind
# succeeded this boot (/run clears at boot). `avc boot reboot` relies on that.
ADV_ON_NODE = "/run/adv.jws"
ADV_PENDING = "/run/adv.jws.pending"
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


def _changed_vars(root: Path) -> list[str]:
    return sorted(c.path for c in repo.changes(root) if c.path.startswith(("vars/", "secrets/")))


PREFLIGHT_APPLY = (
    "c: { toplevel = c.system.build.toplevel.drvPath; disko = c.system.build.diskoScript.drvPath; "
    "identity = c.cluster.boot.identity.hash; thumbprints = c.cluster.boot.tang.thumbprints; "
    "url = c.cluster.boot.tang.url; }"
)


def preflight_facts(ctx: Ctx, node: str) -> dict[str, Any]:
    """What preflight checks, without printing. Refuses on vars that are not committed, since
    an install uploads what is committed and a node built from anything else will not match
    it. Forcing both drvPaths is what makes every posture assertion fire here rather than on
    the server."""
    boot = _boot_info(ctx, node)
    changed = _changed_vars(ctx.root)
    if changed:
        raise AvcError(
            "vars or secrets are not committed (git add vars secrets, then commit):\n  " + "\n  ".join(changed)
        )
    with ui.spin(f"evaluating {node}: toplevel and disko script"):
        out = proc.out(
            ["nix", "eval", "--json", f".#nixosConfigurations.{node}.config", "--apply", PREFLIGHT_APPLY],
            cwd=ctx.root,
        )
    facts = json.loads(out)
    facts["hostKeyPub"] = boot.get("hostKeyPub")
    facts["sshPort"] = boot.get("sshPort")
    return facts


def _fingerprint(pub: str | None) -> str:
    if not pub:
        return "(none: run clan vars generate)"
    p = proc.run(["ssh-keygen", "-lf", "-"], input=pub + "\n", check=False)
    return p.stdout.strip() if p.returncode == 0 else "(unreadable)"


@action("boot", "preflight", "Check a node before install or reboot (forces every assertion)", Arg("node", "Node", choices=_all_nodes))
def preflight(ctx: Ctx, node: str) -> None:
    facts = preflight_facts(ctx, node)
    ui.ok(f"{node} evaluates: every boot security assertion holds")
    ui.say(f"volume identity hash: {facts['identity']}")
    ui.say(f"initrd host key: {_fingerprint(facts['hostKeyPub'])}")
    ui.say(f"Tang: {facts['url']}, thumbprints {', '.join(facts['thumbprints'])}")
    ui.say("Record these with the node. Never regenerate volume-identity or luks after install.")


# ── install ─────────────────────────────────────────────────────────────────


def install_argv(node: str, target: str) -> list[str]:
    host = target if "@" in target else f"root@{target}"
    return ["clan", "machines", "install", node, "--target-host", host, "--yes"]


@action(
    "boot",
    "install",
    "Install a node from a rescue system (destroys its disks)",
    Arg("node", "Node", choices=_all_nodes),
    Arg("target", "Rescue system, root@<address>"),
)
def install(ctx: Ctx, node: str, target: str) -> None:
    preflight(ctx, node)
    ui.warn(f"this wipes every disk of {target} and installs {node} on it")
    ui.type_to_confirm(f"Type the node's name to install {node} on {target}", node)
    proc.run(install_argv(node, target), cwd=ctx.root, capture=False)
    ui.ok(f"installed. Next: `avc boot unlock {node}` (Setup Mode, passphrase typed), then `avc boot enroll {node}`")


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


@action("boot", "unlock", "Type the disk passphrase over the initrd's SSH", Arg("node", "Node", choices=_all_nodes))
def unlock(ctx: Ctx, node: str) -> None:
    boot = _boot_info(ctx, node)
    pub = boot.get("hostKeyPub")
    if not pub:
        raise AvcError(f"{node} has no initrd host key in the repository: run clan vars generate {node}")
    host = ctx.index.nodes[node]["deployHost"]
    port = int(boot["sshPort"])
    ui.say(f"the passphrase is `clan vars get {node} luks/passphrase`. A typo puts the prompts out of step, so it may ask again.")
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
    ui.ok(f"enrolled. Reboot, unlock by hand once (`avc boot unlock {node}`), and check `avc boot status {node}`")


def bind_command(replace: bool, device: str | None, adv: str = ADV_PENDING) -> str:
    cmd = f"cluster-boot-seal bind --adv {adv}"
    if replace:
        cmd += " --replace"
    if device:
        if not device.startswith("/dev/") or any(c.isspace() or c in "'\"$`;&|\\" for c in device):
            raise AvcError(f"not a device path: {device!r}")
        cmd += f" --device {device}"
    return cmd


def bind_script(replace: bool, device: str | None, pending: str = ADV_PENDING, marker: str = ADV_ON_NODE) -> str:
    """The bind, then the marker: the advertisement moves to `marker` only if the bind
    returned 0, and is removed otherwise. A failed bind (an advertisement nobody pinned, a
    burned PCR 7, a missing identity) must not leave the marker that turns `avc boot
    reboot`'s refusal of a short Clevis count into a note. Its exit status is the bind's,
    or the move's if that fails. The passphrase is this script's stdin, and only the bind
    reads it."""
    bind = bind_command(replace, device, adv=pending)
    return (
        f"rc=0; {bind} || rc=$?; "
        f'if [ "$rc" = 0 ]; then mv -f {pending} {marker} || rc=$?; fi; '
        f'if [ "$rc" != 0 ]; then rm -f {pending}; fi; exit "$rc"'
    )


@action(
    "boot",
    "bind",
    "Bind Clevis to Tang and PCR 7 (enforcing Secure Boot only)",
    Arg("node", "Node", choices=_nodes),
    Arg("adv", "Tang advertisement file (curl http://127.0.0.1:<port>/adv on the Tang host)"),
    Arg("replace", "Replace the existing binding", flag=True),
    Arg("device", "Only this leg, e.g. after a disk replacement", optional=True),
)
def bind(ctx: Ctx, node: str, adv: str, replace: bool = False, device: str | None = None) -> None:
    command = bind_script(replace, device)
    advertisement = Path(adv).expanduser().read_text()
    n = ctx.node(node)
    n.pipe(f"install -m 0600 /dev/stdin {ADV_PENDING}", advertisement)
    # On stdin, from clan's store to the node, and nowhere in between that prints.
    passphrase = clanvars.get_value(ctx.root, node, "luks/passphrase")
    p = n.pipe(command, passphrase, check=False, timeout=600)
    ui.out(p.stdout)
    if p.returncode != 0:
        raise AvcError(f"bind refused or failed ({p.returncode}): {(p.stderr or '').strip()}")
    ui.ok(f"bound. Next: `avc boot reboot {node}`, and nobody should have to type")


# ── reboot ──────────────────────────────────────────────────────────────────

# What the next boot depends on, read now, while it can still be fixed: the boot contract,
# the ESPs, holds, the bindings as they are on disk (`cluster-boot-seal check`: every leg
# that is there has a Clevis slot whose TPM share opens), and the identity secret the
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
test -e {ADV_ON_NODE} && echo bound_this_boot=yes || echo bound_this_boot=no
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
            f"a leg has no Clevis binding, or the TPM refuses its share ({failed or 'cluster-boot-seal check'}): "
            "the next boot would wait at the prompt. Rebind first (`avc boot bind`, with --device for one leg)"
        )
    elif seal == "3" and not burned:
        refusals.append("cluster-boot-seal check says PCR 7 was burned, and the burn marker is gone: can't tell")
    elif seal == "4":
        refusals.append(
            f"a Clevis slot is bound to a Tang key that is no longer pinned ({failed or 'cluster-boot-seal check'}): "
            "after a Tang rotation or reinstall it waits at the prompt once that key is gone. Rebind first "
            "(`avc boot bind <node> <adv> --replace`)"
        )
    elif seal not in ("0", "3"):
        refusals.append(f"cluster-boot-seal check could not run (rc={seal}): nothing says this node unlocks unattended")
    if _field(lines, "identity_check=") != "0":
        why = "; ".join(line.removeprefix("identity: ") for line in lines if line.startswith("identity: "))
        refusals.append(
            f"the volume identity secret is missing or wrong ({why or 'no answer'}): the node would halt at its next "
            "boot. Restore it first (README, Recovery: 'Identity secret damaged')"
        )
    m = _metrics(text)
    clevis, expected = m.get("cluster_boot_unlock_clevis_devices"), m.get("cluster_boot_unlock_expected_devices")
    # `avc boot bind` leaves its advertisement in /run only when the bind succeeded, so it is
    # there only if this boot was bound. Then the last unlock predates the binding: it was typed (install S5, or the
    # recovery that needed the bind), and only this reboot can prove the new binding. The
    # seal check above has already refused a leg that is unbound or whose TPM share fails.
    bound_this_boot = "bound_this_boot=yes" in lines
    if clevis is None or expected is None:
        notes.append("no boot report on this node yet, so the last unlock's health is unknown")
    elif clevis != expected and not burned and bound_this_boot:
        notes.append(
            f"the last boot unlocked {clevis} of {expected} devices through Clevis, before this boot's "
            "`avc boot bind`: this reboot is what proves the new binding"
        )
    elif clevis != expected and not burned:
        refusals.append(f"the last boot unlocked {clevis} of {expected} devices through Clevis: fix the binding first")
    notes.append(
        "Tang's own health comes from the off-host heartbeat, not from here. Only a real reboot proves this node's path to Tang."
    )
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
                    f"(`avc boot unlock {n.name}`)"
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
