"""One cluster node, over `ssh root@<deployHost>`.

Everything here is a thin, named wrapper around what README.md has the
operator type by hand: the pull-deploy hold files and unit
(modules/pull-deploy.nix), nomad with the node's scoped `avc` token, and the
cluster-backup / cluster-restore commands (modules/backup-core.nix).
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Any

from avc.core import deploy_state, proc
from avc.errors import AvcError

HOLD = "/run/cluster-upgrade.hold"
HOLD_DIR = "/run/cluster-upgrade.hold.d"


class NothingAfter(AvcError):
    """A rollback found no generation after the running one, so it refused nothing."""


@dataclass(frozen=True)
class Health:
    reachable: bool
    current_system: str = ""
    manual_hold: bool = False
    automated_holds: tuple[str, ...] = ()
    upgrade_result: str = ""  # cluster-upgrade's last Result= (success, exit-code, …)
    upgrade_finished: str = ""
    upgrade_active: bool = False
    failed_units: tuple[str, ...] = ()
    error: str = ""


class Node:
    def __init__(self, name: str, info: dict[str, Any]) -> None:
        self.name = name
        self.info = info
        # An explicit override, for a node reached through a bastion or an
        # ssh_config alias.
        self.host = os.environ.get("AVC_NODE_SSH") or info["deployHost"]

    def _argv(self, command: str, tty: bool = False) -> list[str]:
        opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        return ["ssh", *opts, "-t" if tty else "-n", f"root@{self.host}", command]

    def run(
        self, command: str, check: bool = True, timeout: float | None = 60
    ) -> subprocess.CompletedProcess[str]:
        return proc.run(self._argv(command), check=check, timeout=timeout)

    def pipe(
        self, command: str, data: str, check: bool = True, timeout: float | None = 120
    ) -> subprocess.CompletedProcess[str]:
        """Run with `data` on the remote command's stdin, never on its command line, so that a
        secret is not in any argv on either side or in a shell's history."""
        opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
        return proc.run(["ssh", *opts, f"root@{self.host}", command], check=check, input=data, timeout=timeout)

    def out(self, command: str, timeout: float | None = 60) -> str:
        return self.run(command, timeout=timeout).stdout.strip()

    def stream(self, command: str) -> int:
        """Run with the operator's terminal attached (logs, long jobs)."""
        return subprocess.run(self._argv(command, tty=True)).returncode

    # ── deploy ──────────────────────────────────────────────────────────────

    def health(self) -> Health:
        # One round trip: the overview polls every node in parallel.
        script = f"""
            readlink -f /run/current-system
            test -e {HOLD} && echo hold || echo nohold
            ls -1 {HOLD_DIR} 2>/dev/null | tr '\\n' ' '; echo
            systemctl show -p Result -p ExecMainExitTimestamp -p ActiveState cluster-upgrade.service \
              | tr '\\n' '|'; echo
            systemctl --failed --no-legend --plain | awk '{{print $1}}' | tr '\\n' ' '; echo
        """
        try:
            p = self.run(script, check=False, timeout=20)
        except AvcError as e:
            return Health(reachable=False, error=str(e))
        if p.returncode != 0:
            msg = (p.stderr or "").strip().splitlines()
            return Health(reachable=False, error=msg[-1] if msg else f"ssh exited {p.returncode}")
        lines = (p.stdout.splitlines() + [""] * 5)[:5]
        props = dict(kv.split("=", 1) for kv in lines[3].split("|") if "=" in kv)
        return Health(
            reachable=True,
            current_system=lines[0].strip(),
            manual_hold=lines[1].strip() == "hold",
            automated_holds=tuple(lines[2].split()),
            upgrade_result=props.get("Result", ""),
            upgrade_finished=props.get("ExecMainExitTimestamp", ""),
            upgrade_active=props.get("ActiveState") == "activating",
            failed_units=tuple(lines[4].split()),
        )

    def current_system(self) -> str:
        return self.out("readlink -f /run/current-system")

    def hold(self) -> None:
        self.run(f"touch {HOLD}")

    def release(self) -> None:
        self.run(f"rm -f {HOLD}")

    def deploy_retry(self) -> None:
        """Forget the failed attempts, so that the next tick tries the closure again."""
        self.run(deploy_state.RETRY)

    def refuse_later(self) -> list[str]:
        """Put every generation after the running one on the rollback denylist, and
        return their basenames. The denylist outlasts a reboot; a hold does not."""
        p = self.run(deploy_state.REFUSE_LATER, check=False)
        detail = (p.stderr or "").strip() or f"exit status {p.returncode}"
        if p.returncode == deploy_state.NOTHING_AFTER:
            raise NothingAfter(detail)
        refused = p.stdout.split()
        if p.returncode != 0 or not refused:
            raise AvcError(detail)
        return refused

    def unrefuse(self, basename: str) -> None:
        self.run(deploy_state.unrefuse_script(basename))

    def upgrade(self) -> subprocess.CompletedProcess[str]:
        """Run one pull-deploy now and wait for it: build from the pushed flake,
        switch if the closure changed. A held node skips (unit condition)."""
        return self.run("systemctl start cluster-upgrade.service", check=False, timeout=None)

    def journal(self, unit: str, lines: int = 40) -> str:
        return self.run(f"journalctl -u {shlex.quote(unit)} -n {lines} --no-pager -o cat", check=False).stdout

    # ── nomad ───────────────────────────────────────────────────────────────

    def nomad_cmd(self, args: str) -> str:
        """The CLI on the node, with its address, its client certificate (the API
        refuses a handshake without one), the apps namespace (every app's job is
        there, and `default` runs nothing) and the node's `avc` token: status, logs
        and restarts, never a submit, never management (modules/nomad-acl.nix)."""
        n = self.info["nomad"]
        return (
            f"NOMAD_ADDR={shlex.quote(n['addr'])} "
            f"NOMAD_CACERT={shlex.quote(n['caCert'])} "
            f"NOMAD_CLIENT_CERT={shlex.quote(n['clientCert'])} "
            f"NOMAD_CLIENT_KEY={shlex.quote(n['clientKey'])} "
            f"NOMAD_NAMESPACE={shlex.quote(n.get('namespace', 'apps'))} "
            f'NOMAD_TOKEN="$(cat {shlex.quote(n["tokenPath"])})" '
            f"nomad {args}"
        )

    def nomad(self, args: str, timeout: float | None = 120) -> subprocess.CompletedProcess[str]:
        return self.run(self.nomad_cmd(args), check=False, timeout=timeout)
