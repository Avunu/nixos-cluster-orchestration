# Refuses every generation of the system profile after the running one, oldest first, and
# prints each. The caller sets S (the tick's state directory) and NOTHING_AFTER (the exit
# status when the running closure is the newest generation). Run by `avc boot rollback`
# over ssh (avc/core/deploy_state.py) and, at boot, by modules/pull-deploy-core.nix's
# rollback guard, so the two refuse exactly the same closures.
#
# The running closure may be in the profile several times, and its last appearance is the
# one that counts. A hand-edited list may have no final newline, and appending to that
# would run two names together so that neither matched, hence the sed.
: "${S:?}" "${NOTHING_AFTER:?}"
set -eu
P=/nix/var/nix/profiles
cur=$(readlink -f /run/current-system)
on=
later=
for n in $(ls -1 "$P" | sed -n 's/^system-\([0-9][0-9]*\)-link$/\1/p' | sort -n); do
  t=$(readlink -f "$P/system-$n-link")
  if [ "$t" = "$cur" ]; then
    on=1
    later=
  elif [ -n "$on" ]; then
    later="$later $t"
  fi
done
if [ -z "$on" ]; then
  echo "$cur is not a generation of $P/system, so nothing says what came after it" >&2
  exit 1
fi
if [ -z "$later" ]; then
  echo "it runs its newest generation, so nothing comes after it to refuse" >&2
  exit "$NOTHING_AFTER"
fi
mkdir -p "$S"
if [ -e "$S/refused" ]; then
  sed -e '$a\' "$S/refused" >"$S/refused.tmp"
else
  : >"$S/refused.tmp"
fi
for t in $later; do
  b=${t##*/}
  rc=0
  grep -qxF -- "$b" "$S/refused.tmp" || rc=$?
  case $rc in
    0) ;;
    1) printf '%s\n' "$b" >>"$S/refused.tmp" ;;
    *) exit "$rc" ;;
  esac
  printf '%s\n' "$b"
done
mv "$S/refused.tmp" "$S/refused"
