"""What `avc deploy retry` and `avc boot rollback` / `unrollback` run on a node,
to edit the state lib/cluster-upgrade.nix keeps there.

These are shell text sent over ssh rather than a command installed on the node,
because a rollback runs on the generation the operator escaped to, and that may be
older than any command this code could install.

tests/deploy-safety.nix runs this file's scripts in a VM against the real tick, so
this module stays standard library only. It is loaded there by file path.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path

STATE = "/var/lib/cluster-upgrade"

# rollback's exit status when the node runs its newest generation. Outside what sed
# and grep use, as those can end the script through `set -e`.
NOTHING_AFTER = 10

RETRY = f"""
set -eu
rm -f {STATE}/attempts {STATE}/target
"""

# The shell is in refuse_later.sh, which the node's rollback guard runs at boot as well
# (modules/pull-deploy-core.nix): one text, so both refuse the same closures.
REFUSE_LATER = f"S={STATE}\nNOTHING_AFTER={NOTHING_AFTER}\n" + Path(__file__).with_name("refuse_later.sh").read_text()

# What the next boot runs, for `avc boot reboot` (avc/flows/boot.py splices this into its
# check). The default entry is the profile's current generation. After `avc boot rollback`
# that is still the closure the node was rolled back from, and often with the same boot
# contract, since a kernel or nixpkgs bump changes none. Prints, never exits:
#   default_entry=<basename>          the profile's target, empty if it can't be read
#   default_refused=yes|no|unknown    on the rollback denylist; unknown if that can't be read
#   default_is_running=yes|no         the same closure as /run/current-system
DEFAULT_ENTRY = (
    f"S={STATE}\n"
    + r"""
d=$(readlink -f /nix/var/nix/profiles/system 2>/dev/null) || d=
b=${d##*/}
echo "default_entry=$b"
if [ -z "$b" ]; then
  echo default_refused=unknown
elif [ -e "$S/refused" ]; then
  rc=0
  grep -qxF -- "$b" "$S/refused" 2>/dev/null || rc=$?
  case $rc in
    0) echo default_refused=yes ;;
    1) echo default_refused=no ;;
    *) echo default_refused=unknown ;;
  esac
else
  echo default_refused=no
fi
if [ -n "$d" ] && [ "$d" = "$(readlink -f /run/current-system 2>/dev/null)" ]; then
  echo default_is_running=yes
else
  echo default_is_running=no
fi
"""
)

# A store path's basename: a 32-character hash in Nix's alphabet, a dash, a name.
_BASENAME = re.compile(r"[0-9a-df-np-sv-z]{32}-[0-9A-Za-z+._?=-]+")


def closure_basename(closure: str) -> str | None:
    """What the denylist holds, from a basename or a store path. None if it is neither."""
    name = closure.strip().removeprefix("/nix/store/")
    return name if _BASENAME.fullmatch(name) else None


def unrefuse_script(basename: str) -> str:
    """Fails if the closure isn't listed, as that is probably a mistyped name."""
    return (
        f"S={STATE}\nb={shlex.quote(basename)}\n"
        + r"""
set -eu
rc=0
grep -qxF -- "$b" "$S/refused" || rc=$?
if [ "$rc" = 1 ]; then
  echo "$b is not on the denylist" >&2
  exit 1
elif [ "$rc" != 0 ]; then
  exit "$rc"
fi
rc=0
grep -vxF -- "$b" "$S/refused" >"$S/refused.tmp" || rc=$?
[ "$rc" -le 1 ] || exit "$rc"
mv "$S/refused.tmp" "$S/refused"
"""
    )
