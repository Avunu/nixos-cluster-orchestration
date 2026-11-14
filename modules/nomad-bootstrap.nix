# modules/nomad-bootstrap.nix — stateful fencing, on EVERY node (Phase 7).
#
# nomad-fence.{service,timer} (R1): SIGKILL / agent crash / reboot can orphan
# container@<app> (it lives in machine.slice, outside the raw_exec wrapper's
# process group — the TERM trap never ran). The reconciler stops any RUNNING
# managed container whose Nomad allocation is not running on THIS node,
# restoring "task alive == container running".
#
# The other half — registering rendered jobspecs, which is a singleton — lives
# in modules/nomad-bootstrap-leader.nix and is assigned by the `nomad-leader`
# tag through inventory.instances. This file carries no leader conditional.
#
# What it asks, and what it does with the answer, is where the danger is:
#
#   - It runs as the `fence` role (modules/nomad-acl.nix): read-job in `apps` and
#     agent read. Not the management token, which no longer leaves the leader.
#   - The allocation query names the `apps` namespace. Without it a scoped token gets
#     403, and a management token gets `200 []`, which reads as "nothing runs
#     anywhere" and would stop every container on the node. So the namespace, the
#     query and the token moved together, and `fence-no-namespace` (flake.nix) is
#     the mutant that drops it.
#   - A refusal (401/403) is LOUD: the unit fails, so UnitFailed fires. A fence that
#     cannot read is a fence that silently fences nothing. But first it logs in again,
#     once: a token the cluster no longer knows (ACL state rebuilt) otherwise stayed
#     refused until the 6-hourly login timer.
#   - Nomad unreachable, or a 5xx, stays fail-safe: exit 0, fence nothing. Never stop
#     workloads on an API blip; only on positive knowledge.
#   - Every run that got its answers writes
#     cluster_fence_last_success_timestamp_seconds, and NomadFenceStale
#     (lib/alert-rules.nix) fires when that stops, whatever the reason.
{
  config,
  lib,
  pkgs,
  node,
  clusterLib,
  ...
}:
let
  net = clusterLib.net;

  nomadAddr = net.nomadAddr node;
  pki = clusterLib.nomadPki;
  token = "${pki.tokenDir}/fence";
  # The HTTP API wants a client certificate before anything else (cluster-common.nix).
  # A handshake that fails is a curl failure like any other below: fail-safe, no fence.
  tls = pki.cliTlsFor config.clan.core.vars.generators;

  # Managed container names (the only units the fencer may touch).
  managedApps = builtins.attrNames config.cluster.nomadApps;

  textDir = "/var/lib/prometheus-node-exporter-text";
  metric = "${textDir}/nomad_fence.prom";

  # Allocations that may still own a container, in the apps namespace. `namespace=`
  # must stay: see the header. Not `running` alone: an allocation on a client that was
  # cut off is `unknown` (a job's `disconnect` block, which a failover design that keeps
  # the original allocation relies on, reconcile = "keep_original"), and for about a second after the
  # client is back the API answers 200 with that allocation still `unknown` [RAN, a
  # review's probe on Nomad 1.11.3]. A fence that read only `running` would stop the
  # very container keep_original keeps. `pending` too: a container already up for an
  # allocation Nomad has not yet marked running is not an orphan.
  allocsQuery =
    "/v1/allocations?namespace=${clusterLib.nomad.appsNamespace}&filter="
    + lib.escapeURL ''ClientStatus == "running" or ClientStatus == "unknown" or ClientStatus == "pending"'';

  fenceText = ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.jq
        pkgs.curl
        pkgs.systemd
      ]
    }:/run/current-system/sw/bin

    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    # A node whose fence has never succeeded reads as stale too, from 0, rather than
    # as no metric at all, which no alert can see.
    if [ ! -e ${metric} ]; then
      mkdir -p ${textDir}
      printf 'cluster_fence_last_success_timestamp_seconds 0\n' > ${metric}
    fi

    # No token is a fence that cannot read: loud, like a refusal.
    tok=$(cat ${token} 2>/dev/null || true)
    if [ -z "$tok" ]; then
      echo "nomad-fence: no token in ${token} (nomad-login@fence has not logged in): NOT fencing" >&2
      exit 1
    fi

    # get PATH FILE: the body in FILE on 2xx. Refused: log in again once (the token
    # may be one the cluster no longer knows: its ACL state rebuilt, the token expired
    # early), ask again, and fail the unit if it is still refused. Anything else:
    # fence nothing and succeed, as before. 15 s, not 5: with no leader, Nomad holds a
    # request up to its rpc_hold_timeout (5 s) before answering 500, and a 5 s client
    # timeout raced it [RAN, fence-failsafe-on-5xx's mutant saw 000 where the test saw
    # 500]. Either way it fences nothing; this way it says why.
    relogged=0
    get() {
      local code
      code=$(curl -sS --max-time 15 ${tls.curlArgs} -o "$2" -w '%{http_code}' \
        -H "X-Nomad-Token: $tok" "${nomadAddr}$1") || code=000
      case "$code" in
        2??) return 0 ;;
        401 | 403)
          echo "nomad-fence: $1 refused (HTTP $code: $(head -c 200 "$2" 2>/dev/null))" >&2
          if [ "$relogged" = 0 ]; then
            relogged=1
            echo "nomad-fence: logging in again (nomad-login@fence) and asking once more" >&2
            timeout 30 systemctl start nomad-login@fence.service || true
            tok=$(cat ${token} 2>/dev/null || true)
            get "$1" "$2"
            return 0
          fi
          echo "nomad-fence: still refused after a fresh login: NOT fencing" >&2
          exit 1
          ;;
        *)
          echo "nomad-fence: $1: HTTP $code, Nomad not answering; fencing nothing (fail-safe)"
          exit 0
          ;;
      esac
    }

    get "${allocsQuery}" "$work/allocs"
    get /v1/agent/self "$work/self"
    self=$(jq -r '.stats.client["node_id"] // empty' "$work/self")
    if [ -z "$self" ]; then
      echo "nomad-fence: the local agent reports no client node ID; fencing nothing (fail-safe)"
      exit 0
    fi

    for app in ${lib.escapeShellArgs managedApps}; do
      if systemctl is-active --quiet "container@$app"; then
        # Is there a running alloc of job app-<name> on THIS node?
        want=$(jq -r --arg job "app-$app" --arg node "$self" \
          '[ .[] | select(.JobID == $job and .NodeID == $node) ] | length' "$work/allocs")
        if [ "$want" = "0" ]; then
          echo "fencing orphan container@$app (no running allocation on this node)"
          nixos-container stop "$app" || systemctl stop "container@$app" || true
        fi
      fi
    done

    printf 'cluster_fence_last_success_timestamp_seconds %s\n' "$(date +%s)" > ${metric}.tmp
    mv ${metric}.tmp ${metric}
  '';

in
lib.mkMerge [
  # No fence, no metric: a file left from when there was one would be stale forever.
  (lib.mkIf (managedApps == [ ]) { systemd.tmpfiles.rules = [ "r ${metric}" ]; })

  (lib.mkIf (managedApps != [ ]) {
    # The fence mutant (flake.nix) edits this text.
    system.build.nomadFenceText = fenceText;

    systemd.services.nomad-fence = {
      description = "Stop orphaned Nomad-managed containers (R1 fencing)";
      after = [
        "nomad.service"
        "nomad-login@fence.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.writeShellScript "nomad-fence" fenceText}";
      };
    };
    systemd.timers.nomad-fence = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = "30s";
        RandomizedDelaySec = "5s";
      };
    };
  })
]
