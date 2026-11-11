#!/usr/bin/env bash
# tools/ci/build.sh ATTR... — build flake attributes the way CI must on an ordinary
# runner: each one evaluated on its own, by a nix process that then exits, and only the
# resulting .drv handed to `nix build`.
#
# Why not `nix flake check`: it evaluates every check in ONE process and keeps much of
# it until the end. This flake's measured peak for that is 16 to 32 GB single-threaded,
# and 53 GB with Determinate Nix's parallel evaluation (README, "Testing"). And
# `nix build .#x` holds its evaluator's heap for as long as a VM test runs. One check at
# a time costs at most about 9 GB to evaluate (container-isolation) and almost nothing
# while it builds, which fits a 16 GB runner.
#
# Every failure is loud: an attribute that does not evaluate is a failed build, not a
# skipped one.
#
#   tools/ci/build.sh checks.x86_64-linux.boot-install
#   CI_EVAL_ONLY=1 tools/ci/build.sh devShells.x86_64-linux.default
set -euo pipefail

flake=${CI_FLAKE:-.}
if [ "$#" -eq 0 ]; then
  echo "build.sh: no attribute given" >&2
  exit 2
fi

for attr in "$@"; do
  if [ -z "$attr" ]; then
    echo "build.sh: an empty attribute name" >&2
    exit 2
  fi
  echo "::group::evaluate $attr"
  # eval-cores 1: Determinate Nix's parallel evaluator multiplies the heap. Other Nix
  # versions warn that they do not know the setting, and carry on.
  drv=$(nix --option eval-cores 1 eval --raw "$flake#$attr.drvPath")
  echo "$attr -> $drv"
  echo "::endgroup::"
  case $drv in
    /nix/store/*.drv) ;;
    *)
      echo "build.sh: $attr evaluated to '$drv', not a derivation" >&2
      exit 1
      ;;
  esac
  if [ -n "${CI_EVAL_ONLY:-}" ]; then
    continue
  fi
  # --max-jobs bounds the VMs this runner starts at once; a boot test wants 5 GB.
  nix build --no-link --print-build-logs --max-jobs "${CI_MAX_JOBS:-1}" "$drv^*"
done
