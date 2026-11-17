"""`ssh`, for the programs an install runs that choose their own host key options.

nixos-anywhere starts every ssh with `-o UserKnownHostsFile=/dev/null -o
StrictHostKeyChecking=no`, and ssh keeps the first value it is given for an option, so
nothing appended to its command line (`--ssh-option`) can turn checking back on. This is
put first on the installer's PATH instead (avc/core/hostpin.py), under the name `ssh`, and
puts the pinned options in front of whatever the caller wrote: nixos-anywhere's own
connections, ssh-copy-id's, and the ones Nix opens for `nix copy`.

A connection to any other host (git fetching a flake input) is passed on as it is.

When ssh refuses the far end's host key, this leaves a marker beside the pin: every later
connection of the run is refused here without being tried, and `avc boot install`, which
watches for the marker, stops the installer. Without that, nixos-anywhere's "wait until it
answers" loops would retry a refused key for ever.

Run as a file, by a Python with nothing of avc's on its path: standard library only.
"""

import json
import os
import select
import signal
import subprocess
import sys

REFUSALS = (b"Host key verification failed", b"HOST IDENTIFICATION HAS CHANGED")


def destination(arg: str) -> str:
    """The host an ssh argument names, were it the destination: `user@host`, `host`."""
    host = arg.rsplit("@", 1)[-1]
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def main(argv: list[str]) -> int:
    pin = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(pin, "pin.json")) as f:
        cfg = json.load(f)
    args = argv[1:]
    if not any(destination(a) == cfg["host"] for a in args):
        os.execv(cfg["ssh"], ["ssh", *args])
    refused = os.path.join(pin, "refused")
    if os.path.exists(refused):
        sys.stderr.write(f"avc: {cfg['host']}'s host key was refused earlier in this install: not connecting\n")
        return 255
    with open(os.path.join(pin, "uses"), "a") as f:
        f.write(" ".join(args)[:200] + "\n")

    p = subprocess.Popen([cfg["ssh"], *cfg["options"], *args], stderr=subprocess.PIPE)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda s, _: p.send_signal(s))
    fd = p.stderr.fileno()
    seen = b""
    # Until ssh exits, not until its stderr closes: a connection master it leaves behind
    # (ControlPersist) holds the pipe open.
    while True:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            os.write(2, chunk)
            seen = (seen + chunk)[-8192:]
        elif p.poll() is not None:
            os.set_blocking(fd, False)
            try:
                while chunk := os.read(fd, 65536):
                    os.write(2, chunk)
                    seen = (seen + chunk)[-8192:]
            except BlockingIOError:
                pass
            break
    rc = p.wait()
    if rc == 255 and any(r in seen for r in REFUSALS):
        with open(refused, "w") as f:
            f.write(" ".join(args)[:200] + "\n")
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
