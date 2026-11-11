# lib/deploy-canary-publish.nix — the canary's half of the staged rollout (design D22,
# modules/pull-deploy-core.nix): once this node has BOOTED a closure, and the boot was
# good, say so where the other nodes' pull deploys look before they activate the same
# boot stack. lib/cluster-upgrade.nix is the other half.
#
# What it publishes is one file per boot stack, named by the sha256 of the closure's
# `boot-stack` file, which every node of a site renders identically (the nixpkgs,
# kernel and library sources its boot is built from, and nothing per node). A follower
# hashes its candidate's file the same way and looks for that name.
#
# Only a boot counts. The stack is read from /run/booted-system, never from
# /run/current-system: a pull deploy switches the canary to a new closure at once, and
# that proves nothing about the kernel, initrd and unlock path, which first run at the
# next reboot. A switch is exactly what must not open the gate.
#
# Only a good boot counts. On a node with boot security the boot report must say Clevis
# opened every leg: a stack that boots only because someone typed the passphrase would
# leave every other node needing a console at its next reboot, which is the failure this
# exists to stop. The report must be this boot's (its timestamp after the kernel's boot
# time), or it says nothing about this stack.
#
# Never on the root disk. The markers live on the shared filesystem, and an unmounted
# one is a plain directory on this node's own disk that no other node can see. Writing
# there would publish nothing and look like it had, so the store must be a mount point.
#
# `edit` is for the mutants in flake.nix, which take one control out of the text.
{
  lib,
  pkgs,
  # Where the markers go, and the mount it must be on.
  markerDir,
  markerMount,
  # This boot needs a fresh boot report (modules/boot-report.nix) ...
  requireReport,
  # ... and that report must show a Clevis unlock of every leg.
  requireCleanUnlock,
  node,
  edit ? lib.id,
}:
pkgs.writeShellApplication {
  name = "cluster-deploy-canary-publish";
  runtimeInputs = with pkgs; [
    coreutils
    gawk
    systemd
    util-linux
  ];
  # No errexit: every refusal below is reported, with its reason, before it exits.
  bashOptions = [
    "nounset"
    "pipefail"
  ];
  text = edit ''
    M=/var/lib/prometheus-node-exporter-text
    DIR=${lib.escapeShellArg markerDir}
    MOUNT=${lib.escapeShellArg markerMount}
    mkdir -p "$M"
    metric() {
      printf '%s\n' "$@" >"$M/deploy_canary.prom.tmp"
      mv "$M/deploy_canary.prom.tmp" "$M/deploy_canary.prom"
    }
    # The value of one series in the boot report, or nothing.
    report() { awk -v k="$1" '$1 == k { print $2 }' "$M/boot_report.prom" 2>/dev/null; }

    if ! systemctl is-active --quiet multi-user.target; then
      echo "canary-publish: this boot has not reached multi-user.target yet; the next run looks again"
      exit 0
    fi

    booted=$(readlink -f /run/booted-system)
    if [ ! -e "$booted/boot-stack" ]; then
      echo "canary-publish: $booted carries no boot-stack, so its boot vouches for nothing"
      metric "cluster_deploy_canary_unproven 1" "cluster_deploy_canary_published 0"
      exit 0
    fi
    key=$(sha256sum "$booted/boot-stack" | cut -d' ' -f1)

    ${lib.optionalString requireReport ''
      btime=$(awk '$1 == "btime" { print $2 }' /proc/stat)
      at=$(report cluster_boot_report_timestamp_seconds)
      # Positive form: anything unreadable or not a number is not this boot's report.
      fresh=""
      if [[ "$at" =~ ^[0-9]+$ ]] && [[ "$btime" =~ ^[0-9]+$ ]] && [ "$at" -ge "$btime" ]; then
        fresh=1
      fi
      if [ -z "$fresh" ]; then
        echo "canary-publish: no boot report from this boot (report at ''${at:-never}, boot at ''${btime:-unknown}); boot stack $key is not published"
        metric "cluster_deploy_canary_unproven 1" "cluster_deploy_canary_published 0"
        exit 0
      fi
    ''}
    ${lib.optionalString requireCleanUnlock ''
      passphrase=$(report cluster_boot_unlock_passphrase)
      opened=$(report cluster_boot_unlock_clevis_devices)
      legs=$(report cluster_boot_unlock_expected_devices)
      # Positive form again: a missing or garbled series must not read as a clean unlock.
      clean=""
      if [ "$passphrase" = 0 ] && [[ "$legs" =~ ^[1-9][0-9]*$ ]] && [ "$opened" = "$legs" ]; then
        clean=1
      fi
      if [ -z "$clean" ]; then
        echo "canary-publish: this boot was not a Clevis unlock of every leg (passphrase=''${passphrase:-?} clevis=''${opened:-?} of ''${legs:-?}); boot stack $key is not published"
        metric "cluster_deploy_canary_unproven 1" "cluster_deploy_canary_published 0"
        exit 0
      fi
    ''}

    # Bounded, as in the follower's gate: a hung mount reads as not mounted.
    if ! timeout -k 5 30 mountpoint -q "$MOUNT"; then
      echo "canary-publish: $MOUNT is not mounted; boot stack $key waits for it, and the next run tries again"
      metric "cluster_deploy_canary_unproven 0" "cluster_deploy_canary_published 0"
      exit 0
    fi
    if timeout -k 5 30 test -e "$DIR/$key"; then
      echo "canary-publish: boot stack $key is already published"
    elif ! {
      timeout -k 5 60 mkdir -p "$DIR" \
        && printf '{"node":"%s","toplevel":"%s","boot_id":"%s","at":%s}\n' \
          ${lib.escapeShellArg node} "$(basename "$booted")" "$(cat /proc/sys/kernel/random/boot_id)" "$(date +%s)" \
          >"$DIR/.$key.tmp" \
        && mv "$DIR/.$key.tmp" "$DIR/$key"
    }; then
      echo "canary-publish: cannot write $DIR/$key"
      metric "cluster_deploy_canary_unproven 0" "cluster_deploy_canary_published 0"
      exit 1
    else
      echo "canary-publish: booted $booted cleanly; published boot stack $key"
    fi
    metric "cluster_deploy_canary_unproven 0" "cluster_deploy_canary_published 1"
  '';
}
