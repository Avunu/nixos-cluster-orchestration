"""One SSH host key, verified once, for every connection of an install.

A rescue system has a host key nobody has seen before, and what an install sends it is the
node's recovery key, and what it takes from it is the recipient every secret the node reads
is encrypted to. So the key is read first (`scan`), compared by the operator with what the
server's own console shows (avc/flows/boot.py), and written to a known_hosts file of this
run's own, in memory. From then on every connection is checked against that file and
nothing else: avc's by its options (`options`), and those of the programs that pick their
own options by an `ssh` put first on their PATH (`shim`, avc/core/pinned_ssh.py).

The file names the host by an alias (HostKeyAlias), not by its address: the installer
answers on the same address as the rescue system and may answer on another port, and it is
the same machine.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

from avc.core import secretstore
from avc.errors import AvcError

# Set by `avc boot install` for its hook, `avc boot stage`: this run's pin.
PIN_ENV = "AVC_INSTALL_PIN"

# Most wanted first: what is shown to the operator, and pinned, when a host has several.
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa")

HostKey = tuple[str, str]  # (key type, base64)


def fingerprint(key: HostKey) -> str:
    """As `ssh-keygen -lf` prints it."""
    digest = hashlib.sha256(base64.b64decode(key[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def parse_keys(text: str, hosted: bool) -> list[HostKey]:
    """Public keys, one a line: `<type> <base64> [comment]`, after a host name if `hosted`
    (ssh-keyscan). A line that is not one is not a key."""
    keys: list[HostKey] = []
    for line in text.splitlines():
        fields = line.split()
        if hosted:
            fields = fields[1:]
        if len(fields) < 2 or fields[0] not in KEY_TYPES or line.startswith("#"):
            continue
        try:
            base64.b64decode(fields[1], validate=True)
        except ValueError:
            continue
        if (fields[0], fields[1]) not in keys:
            keys.append((fields[0], fields[1]))
    return sorted(keys, key=lambda k: KEY_TYPES.index(k[0]))


def scan(host: str, port: int | None = None, timeout: int = 15) -> list[HostKey]:
    """The host keys `host` presents. Read over a connection nothing has authenticated:
    what comes back is a claim, to be compared with the console's."""
    cmd = ["ssh-keyscan", "-T", str(timeout), *(["-p", str(port)] if port else []), host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * 4)
    except FileNotFoundError as e:
        raise AvcError("ssh-keyscan: not found on PATH") from e
    except subprocess.TimeoutExpired as e:
        raise AvcError(f"{host} did not answer ssh-keyscan within {timeout * 4}s") from e
    keys = parse_keys(p.stdout, hosted=True)
    if not keys:
        said = (p.stderr or "").strip().splitlines()
        raise AvcError(f"{host} presented no SSH host key ({said[-1] if said else 'no answer'}). Nothing was sent to it.")
    return keys


def refused(text: str) -> bool:
    """Whether this is ssh saying it would not accept the far end's host key."""
    return "Host key verification failed" in text or "HOST IDENTIFICATION HAS CHANGED" in text


class Pin:
    """This run's known_hosts, and what holds every connection to it."""

    def __init__(self, directory: Path, host: str, alias: str) -> None:
        self.dir, self.host, self.alias = directory, host, alias
        self.known_hosts = directory / "known_hosts"

    @classmethod
    def load(cls, directory: Path) -> Pin:
        try:
            cfg = json.loads((directory / "pin.json").read_text())
        except (OSError, ValueError) as e:
            raise AvcError(f"{directory} is not an install's host key pin: {e}") from e
        return cls(directory, cfg["host"], cfg["alias"])

    def keys(self) -> list[HostKey]:
        if not self.known_hosts.exists():
            return []
        return parse_keys(self.known_hosts.read_text(), hosted=True)

    def trust(self, key: HostKey) -> None:
        """Only a key that was compared out of band, or read over a connection this pin
        had already authenticated."""
        if key not in self.keys():
            with self.known_hosts.open("a") as f:
                f.write(f"{self.alias} {key[0]} {key[1]}\n")

    def options(self) -> list[str]:
        """For ssh's command line, before anything else: the first value of an option wins."""
        return [
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"HostKeyAlias={self.alias}",
            "-o", "UpdateHostKeys=no",
            "-o", "VerifyHostKeyDNS=no",
        ]  # fmt: skip

    def shim(self) -> Path:
        """The directory to put first on the PATH of a program that runs ssh with options of
        its own. Its `ssh` is avc/core/pinned_ssh.py, over the ssh found on PATH now."""
        real = shutil.which("ssh")
        if real is None:
            raise AvcError("ssh: not found on PATH")
        cfg = {"host": self.host, "alias": self.alias, "ssh": os.path.realpath(real), "options": self.options()}
        (self.dir / "pin.json").write_text(json.dumps(cfg))
        script = self.dir / "pinned_ssh.py"
        shutil.copyfile(Path(__file__).with_name("pinned_ssh.py"), script)
        bin_dir = self.dir / "bin"
        bin_dir.mkdir(exist_ok=True)
        ssh = bin_dir / "ssh"
        # -I: nothing of the caller's environment or directory on its path.
        ssh.write_text(f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -I {shlex.quote(str(script))} "$@"\n')
        ssh.chmod(0o700)
        return bin_dir

    # What the run leaves here for `avc boot install` to read: files, since the programs
    # that write them are the installer's children and not this one's.
    def mark(self, name: str, text: str = "") -> None:
        (self.dir / name).write_text(text)

    def marked(self, name: str) -> bool:
        return (self.dir / name).exists()

    def note(self, name: str) -> str:
        try:
            return (self.dir / name).read_text()
        except OSError:
            return ""

    def uses(self) -> int:
        """How many connections went through the shim."""
        return len(self.note("uses").splitlines())


@contextlib.contextmanager
def pinned(node: str, host: str) -> Iterator[Pin]:
    """A pin for one run, in memory, gone with it."""
    with tempfile.TemporaryDirectory(prefix="avc-install-", dir=secretstore.runtime_dir()) as d:
        os.chmod(d, 0o700)
        yield Pin(Path(d), host, f"avc-install-{node}")


def descendants(pid: int) -> list[int]:
    """Every process under `pid`, from /proc."""
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            # pid (comm) state ppid …; comm may hold anything, so count from its last ")".
            ppid = int((entry / "stat").read_text().rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(int(entry.name))
    found, queue = [], [pid]
    while queue:
        for child in children.get(queue.pop(), []):
            found.append(child)
            queue.append(child)
    return found


def _alive(pid: int) -> bool:
    try:
        # A zombie is over: its parent has not asked yet.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def stop_tree(p: subprocess.Popen[bytes], grace: float = 5) -> None:
    """End `p` and everything it started. Not by process group: the installer shares this
    program's, so that it can read the terminal."""
    pids = [p.pid, *descendants(p.pid)]
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid in pids:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, sig)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and any(_alive(pid) for pid in pids):
            time.sleep(0.1)
        pids = [pid for pid in pids if _alive(pid)]
        if not pids:
            break
    p.wait()


def run_watched(argv: list[str], cwd: Path, env: dict[str, str], pin: Pin, every: float = 1) -> int:
    """Run the installer to its end, or to the moment a connection of it is refused the
    pinned host key: then it is stopped, where it would otherwise retry for ever."""
    p = subprocess.Popen(argv, cwd=cwd, env=env)
    try:
        while True:
            try:
                return p.wait(timeout=every)
            except subprocess.TimeoutExpired:
                if pin.marked("refused"):
                    stop_tree(p)
    except BaseException:
        stop_tree(p)
        raise
