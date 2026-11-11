#!/usr/bin/env bash
# tools/ci/list.sh ATTRSET — the names in a flake attribute set, as a JSON list, for a
# workflow matrix. Reading the names does not evaluate what is behind them (every check
# and mutant is `detach`ed, tests/lib/detached-check.nix), so this costs little.
#
# An empty list is a failure: a matrix over nothing would let the merge gate pass with
# nothing built.
#
#   tools/ci/list.sh checks.x86_64-linux        -> ["alert-rules","alerting",...]
set -euo pipefail

flake=${CI_FLAKE:-.}
if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "list.sh: give exactly one attribute set" >&2
  exit 2
fi
names=$(nix --option eval-cores 1 eval --json "$flake#$1" --apply builtins.attrNames)
case $names in
  '[]' | '')
    echo "list.sh: $1 has no attributes" >&2
    exit 1
    ;;
esac
printf '%s\n' "$names"
