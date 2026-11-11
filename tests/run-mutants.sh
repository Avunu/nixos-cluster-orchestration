#!/usr/bin/env bash
# Builds every mutant in legacyPackages.<system>.mutants, or the ones named.
#
#   tests/run-mutants.sh [-j N] [mutant...]
#
# A mutant is a normal green build (tests/lib/control.py): it succeeds only if
# removing its control made the named assertion go false. So a failed build here
# means a control the tests do not actually depend on, and this script exits
# non-zero. So does failing to find out what the mutants are: only a list that came
# back empty is "no mutants". tests/security-policy.nix holds it to all of this.
#
# One evaluation, then builds of the .drv files. `nix build .#mutants.x` per mutant
# keeps an evaluator's heap, tens of GB here, for as long as that mutant's VM test
# runs, which at -j 4 took more memory than the tests themselves. Evaluating them
# together costs one heap, it is gone before the first build starts, and a .drv
# costs almost nothing to build from. It also means a mutant that does not evaluate
# fails the whole run before anything is built, which is what you want before hours
# of VM tests.
#
# -j is nix's --max-jobs, so it also caps every other derivation these builds need.
# All of them is a pre-release step and takes hours run one at a time. Raise -j,
# bounded by memory rather than cores: the boot tests take about 5 GB each.
set -euo pipefail

jobs=1
while getopts 'j:' opt; do
  case "$opt" in
    j) jobs=$OPTARG ;;
    *) echo "usage: $0 [-j N] [mutant...]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

system=$(nix eval --raw --impure --expr builtins.currentSystem)
attr=".#legacyPackages.$system.mutants"

if [ "$#" -gt 0 ]; then
  # These go into a Nix expression, so a name has to be a name. That includes the
  # empty one, which must not read as nothing to do.
  select=""
  for mutant in "$@"; do
    case "$mutant" in
      "" | *[!A-Za-z0-9_-]*)
        echo "run-mutants.sh: not a mutant name: '$mutant'" >&2
        exit 2
        ;;
    esac
    select="$select \"$mutant\""
  done
  select="[$select ]"
else
  select="builtins.attrNames m"
fi

# A plain assignment, so that set -e sees a failure. Inside `mapfile < <(...)` the
# exit status is dropped, and a flake that does not evaluate reads as a clean run
# with nothing to prove.
drvs=$(nix eval --raw "$attr" --apply \
  "m: builtins.concatStringsSep \"\\n\" (map (n: (builtins.getAttr n m).drvPath) ($select))")
targets=()
if [ -n "$drvs" ]; then
  while IFS= read -r drv; do
    targets+=("$drv^*")
  done <<<"$drvs"
fi

if [ "${#targets[@]}" -eq 0 ]; then
  echo "no mutants defined"
  exit 0
fi

# --keep-going: a mutant that fails should not cost the proof of the others.
nix build -L --no-link --keep-going --max-jobs "$jobs" "${targets[@]}"
echo "${#targets[@]} mutant(s) proven"
