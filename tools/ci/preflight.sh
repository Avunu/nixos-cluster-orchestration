#!/usr/bin/env bash
# tools/ci/preflight.sh — refuse to start on a runner that cannot run the VM tests, rather
# than fail an hour in, or worse, let a check that needs KVM fall back to something slower.
#
# Needs: Nix with flakes, /dev/kvm usable by this user, and `kvm` and `nixos-test` among
# Nix's system-features (the VM tests require both), at least 16 GB of RAM, and at least
# 50 GB free on the filesystem that holds /nix/store. On a runner that is itself a VM,
# nested virtualisation must be on. Every job that builds runs this, as each may land on a
# different runner.
#
# The thresholds can be raised, never skipped: PREFLIGHT_MIN_MEM_KB (default 15625000,
# 16 GB) and PREFLIGHT_MIN_FREE_GB (default 50). PREFLIGHT_MEMINFO is for the test of this
# script (tests/ci-workflows.nix).
set -euo pipefail

min_mem_kb=${PREFLIGHT_MIN_MEM_KB:-15625000}
min_free_gb=${PREFLIGHT_MIN_FREE_GB:-50}
meminfo=${PREFLIGHT_MEMINFO:-/proc/meminfo}

fail=0
if ! command -v nix >/dev/null; then
  echo "preflight: nix is not on PATH" >&2
  exit 1
fi
nix --version
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "preflight: /dev/kvm is missing or not read-write for $(id -un)" >&2
  fail=1
fi
features=$(nix config show system-features 2>/dev/null || nix show-config 2>/dev/null | sed -n 's/^system-features = //p')
for f in kvm nixos-test; do
  case " $features " in
    *" $f "*) ;;
    *)
      echo "preflight: system-features lacks $f (have: $features)" >&2
      fail=1
      ;;
  esac
done
if ! nix eval --expr 1 >/dev/null 2>&1; then
  echo "preflight: nix cannot evaluate; are the nix-command and flakes features enabled?" >&2
  fail=1
fi
# Positive form: a value that can't be read is a refusal, not a pass.
mem_kb=$(awk '$1 == "MemTotal:" { print $2 }' "$meminfo" 2>/dev/null || true)
if ! [[ "$mem_kb" =~ ^[0-9]+$ ]] || [ "$mem_kb" -lt "$min_mem_kb" ]; then
  echo "preflight: MemTotal is ${mem_kb:-unreadable} kB, under the ${min_mem_kb} kB a VM check needs" >&2
  fail=1
fi
free_kb=$(df -Pk /nix/store 2>/dev/null | awk 'NR == 2 { print $4 }' || true)
if ! [[ "$free_kb" =~ ^[0-9]+$ ]] || [ "$free_kb" -lt $((min_free_gb * 1000000000 / 1024)) ]; then
  echo "preflight: ${free_kb:-unreadable} kB free under /nix/store, under the ${min_free_gb} GB the boot tests' disks need" >&2
  fail=1
fi
echo "preflight: MemTotal ${mem_kb:-?} kB, ${free_kb:-?} kB free under /nix/store"
exit "$fail"
