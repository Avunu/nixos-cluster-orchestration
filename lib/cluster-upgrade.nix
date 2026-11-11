# lib/cluster-upgrade.nix — one tick of the pull deploy. See modules/pull-deploy.nix for
# why it exists, and modules/pull-deploy-core.nix for what runs it.
#
# `edit` is for tests/deploy-safety's mutants, which remove one control from the text.
{
  lib,
  pkgs,
  # A shell command that prints the store path of the closure this node should run.
  targetCommand,
  # The staged rollout (design D22, modules/pull-deploy-core.nix): on a node that is not
  # the canary, `{ markerDir; markerMount; }`, where the canary says which boot stacks it
  # has booted. null on the canary itself, and on a site without one.
  follower ? null,
  edit ? lib.id,
}:
pkgs.writeShellApplication {
  name = "cluster-upgrade";
  runtimeInputs = with pkgs; [
    nix
    coreutils
    diffutils
    git
    gnugrep
    jq
    systemd
    util-linux
  ];
  # No errexit: the `rc=$?` below needs the switch to return.
  bashOptions = [
    "nounset"
    "pipefail"
  ];
  text = edit ''
    S=/var/lib/cluster-upgrade
    M=/var/lib/prometheus-node-exporter-text
    mkdir -p "$S" "$M"
    MAX=3
    metric() {
      printf '%s\n' "$@" >"$M/deploy.prom.tmp"
      mv "$M/deploy.prom.tmp" "$M/deploy.prom"
    }
    pending() { if [ "$(readlink -f /run/booted-system)" = "$1" ]; then echo 0; else echo 1; fi; }

    new=$(${targetCommand}) || {
      echo "cluster-upgrade: build failed"
      metric "cluster_deploy_build_failed 1"
      exit 1
    }
    cur=$(readlink -f /run/current-system)
    good=$(cat "$S/good" 2>/dev/null || true)
    state_target=$(cat "$S/target" 2>/dev/null || true)
    attempts=$(cat "$S/attempts" 2>/dev/null || echo 0)
    [ "$state_target" = "$new" ] || attempts=0

    # A closure is done only when it activated cleanly, and `new == cur` does not say
    # that: a failed unit gives switch-to-configuration rc=4 with /run/current-system
    # already on the new closure, so comparing the two alone would never retry it.
    if [ "$new" = "$cur" ] && [ "$good" = "$new" ]; then
      echo "cluster-upgrade: already current and activated"
      metric "cluster_deploy_build_failed 0" "cluster_deploy_activation_failed 0" \
        "cluster_deploy_contract_blocked 0" "cluster_deploy_rollback_held 0" \
        "cluster_deploy_canary_wait 0" "cluster_reboot_pending $(pending "$new")"
      exit 0
    fi

    # Persistent rollback hold. An operator who booted an older generation to escape a
    # bad closure must not have the timer re-activate it. /run clears on reboot; this
    # does not.
    # grep says 0 listed, 1 not listed, 2 could not read. Only a missing file means
    # nothing is refused: a list that can't be read may well name this closure.
    denied=1
    if [ -e "$S/refused" ]; then
      grep -qxF "$(basename "$new")" "$S/refused"
      denied=$?
    fi
    if [ "$denied" = 0 ]; then
      echo "cluster-upgrade: $new is on the rollback denylist; refusing to activate"
      metric "cluster_deploy_rollback_held 1" "cluster_deploy_activation_failed 0"
      exit 0
    elif [ "$denied" != 1 ]; then
      echo "cluster-upgrade: cannot read $S/refused; refusing to activate $new"
      metric "cluster_deploy_rollback_held 1" "cluster_deploy_activation_failed 0"
      exit 1
    fi

    # Stale-alert recovery: the closure already activated (it is current) but an earlier
    # tick saw a unit failing during an outage and banked attempts=MAX. If nothing is
    # failing now, mark it good instead of alerting forever. These are the states
    # switch-to-configuration itself returns rc=4 for. --failed alone is not enough: a
    # unit still retrying is in auto-restart and is not listed as failed. A systemctl
    # that errors prints nothing, the same as a healthy node, so it has to be told apart:
    # with no answer the closure stays failed and the tick below reports that.
    if [ "$new" = "$cur" ] && [ "$attempts" -ge "$MAX" ]; then
      if ! unhealthy=$(systemctl list-units --state=failed,auto-restart,auto-restart-queued --plain --no-legend); then
        echo "cluster-upgrade: cannot list units; not calling $new healthy"
      elif [ -z "$unhealthy" ]; then
        echo "cluster-upgrade: $new is current and healthy now; clearing the failed state"
        echo "$new" >"$S/good"
        rm -f "$S/attempts"
        metric "cluster_deploy_activation_failed 0" "cluster_deploy_attempts 0" \
          "cluster_deploy_contract_blocked 0" "cluster_deploy_rollback_held 0" \
          "cluster_deploy_canary_wait 0" "cluster_reboot_pending $(pending "$new")"
        exit 0
      fi
    fi

    # The contract is everything an unlock depends on, rendered at build time into the
    # closure. The gate compares the candidate with what is RUNNING, not with the config
    # repo, so a change has to be explicitly approved per closure on the node. A refusal
    # exits 0: a metric raises this, not UnitFailed as well.
    want=$(cat "$new/boot-contract" 2>/dev/null || echo MISSING)
    have=$(cat "$cur/boot-contract" 2>/dev/null || echo MISSING)
    if [ "$want" != "$have" ] && ! grep -qxF "$(basename "$new")" /run/cluster-upgrade.approve 2>/dev/null; then
      echo "cluster-upgrade: REFUSING $new: boot contract differs from the running system"
      diff <(echo "$have") <(echo "$want") || true
      changed=$(jq -rn --argjson a "$have" --argjson b "$want" \
        '[($a | keys) + ($b | keys) | unique[] as $k | select($a[$k] != $b[$k]) | $k] | join(" ")' 2>/dev/null) \
        || changed=""
      echo "cluster-upgrade: contract fields that differ: ''${changed:-unknown}"
      # Approving this is not enough to retire a key: every older generation signed with the
      # same keys still has it, and still passes PCR 7 when someone who kept a copy puts it
      # back on the ESP. The operator has to hear that here, where the approval is asked for.
      case " $changed " in
        *" authorizedKeysSha256 "*)
          echo "cluster-upgrade: the initrd's authorized keys change. A key removed here still opens every older signed generation anyone kept a copy of, with PCR 7 intact. Retiring it for good needs new Secure Boot signing keys and a rebind (README)."
          ;;
      esac
      metric "cluster_deploy_contract_blocked 1" "cluster_deploy_activation_failed 0"
      exit 0
    fi

    ${lib.optionalString (follower != null) ''
      # The staged rollout (design D22). A new boot stack (the nixpkgs, kernel and library
      # sources a boot is built from, cluster.deploy.bootStack) is in every node's next
      # closure at once, and its kernel, initrd and unlock path first run at a reboot. So a
      # stack that cannot boot would pass every build gate here, activate everywhere, and
      # stop the whole fleet at its next reboots. The canary takes it first; this node
      # activates it only once the canary has BOOTED it cleanly and published that
      # (lib/deploy-canary-publish.nix), or a human lists this closure by hand. Nothing is
      # activated meanwhile and the profile is untouched, so the default boot entry stays
      # the old stack. Exits 0 like the contract's refusal: a metric raises it.
      #
      # Only the stack is compared, and only with what RUNS: an app release on the same
      # stack goes straight through, and a stack this node already runs needs nothing.
      stack_new=$(cat "$new/boot-stack" 2>/dev/null || echo MISSING)
      stack_cur=$(cat "$cur/boot-stack" 2>/dev/null || echo MISSING)
      if [ "$stack_new" != "$stack_cur" ]; then
        proof=""
        why=""
        if [ "$stack_new" = MISSING ]; then
          why="it carries no boot-stack, so no canary boot can vouch for it"
        # Bounded: a hung FUSE mount (a JuiceFS metadata outage) must not hang the tick.
        # Timing out reads as "not mounted", which waits.
        elif ! timeout -k 5 30 mountpoint -q ${lib.escapeShellArg follower.markerMount}; then
          # Unmounted, the marker directory is a plain directory on this node's own disk,
          # and nothing in it came from the canary.
          why="${follower.markerMount} is not mounted, so no marker on it can be read"
        else
          stack_key=$(sha256sum "$new/boot-stack" | cut -d' ' -f1)
          if timeout -k 5 30 test -f ${lib.escapeShellArg follower.markerDir}/"$stack_key"; then
            proof="the canary booted it ($stack_key)"
          else
            why="the canary has not booted boot stack $stack_key"
          fi
        fi
        if [ -z "$proof" ] && grep -qxF "$(basename "$new")" /run/cluster-upgrade.skip-canary 2>/dev/null; then
          proof="listed in /run/cluster-upgrade.skip-canary"
        fi
        if [ -z "$proof" ]; then
          echo "cluster-upgrade: WAITING FOR THE CANARY before activating $new: $why"
          diff <(echo "$stack_cur") <(echo "$stack_new") || true
          metric "cluster_deploy_canary_wait 1" "cluster_deploy_contract_blocked 0" \
            "cluster_deploy_activation_failed 0"
          exit 0
        fi
        echo "cluster-upgrade: $new is a new boot stack: $proof"
      fi
    ''}
    if [ "$attempts" -ge "$MAX" ]; then
      echo "cluster-upgrade: $new failed $attempts times; waiting for a new commit"
      metric "cluster_deploy_activation_failed 1" "cluster_deploy_attempts $attempts"
      exit 1
    fi

    echo "cluster-upgrade: $cur -> $new"
    echo "$new" >"$S/target"
    echo $((attempts + 1)) >"$S/attempts"
    nix-env -p /nix/var/nix/profiles/system --set "$new"
    "$new/bin/switch-to-configuration" switch
    rc=$?
    echo "cluster-upgrade: switch rc=$rc attempt=$((attempts + 1))"
    if [ "$rc" = 0 ]; then
      echo "$new" >"$S/good"
      rm -f "$S/attempts"
      metric "cluster_deploy_build_failed 0" "cluster_deploy_activation_failed 0" \
        "cluster_deploy_contract_blocked 0" "cluster_deploy_rollback_held 0" "cluster_deploy_attempts 0" \
        "cluster_deploy_canary_wait 0" "cluster_reboot_pending $(pending "$new")"
      exit 0
    fi
    metric "cluster_deploy_activation_failed 1" "cluster_deploy_attempts $((attempts + 1))"
    exit "$rc"
  '';
}
