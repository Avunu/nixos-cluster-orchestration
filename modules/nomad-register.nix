# modules/nomad-register.nix — declarative job registration, on every Nomad server.
#
# Waits for Nomad raft leadership, then `nomad job run` every rendered
# system.build.nomadJobs.*. Idempotent: Nomad diffs and no-ops unchanged jobs.
# The unit's ExecStart references the store-hashed jobs dir, so any deploy that
# changes a jobspec re-triggers it and only changed jobs re-register.
#
# Every server does it, so that no one node has to be up, or deployed, for a job to
# be registered: the first server to switch to a generation registers its jobs and
# the others find nothing to change. What that costs is a submit per job per server
# per deploy, each a no-op at the raft leader.
#
# A server registers a generation's jobs ONCE, when it switches to it. Servers are
# not always on the same generation (one not deployed yet, one held back by a failed
# deploy), and a server that registered at every boot would put its old jobspecs back
# over a newer server's each time it restarted. After the first time it registers only
# a job the cluster no longer has, or has dead: the repair a boot-time registration
# used to be.
#
# It registers as the `registrar` role: submit, read and list jobs in the `apps`
# namespace, nothing else. The ACL bootstrap and everything the scoped tokens rest
# on (namespaces, policies, the JWT auth method) is nomad-acl-init's, in
# modules/nomad-acl.nix, which is the only reader of the management token.
#
# The counterpart fencing reconciler runs on every node: modules/nomad-bootstrap.nix.
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
  nomad = "${config.services.nomad.package}/bin/nomad";
  pki = clusterLib.nomadPki;
  token = "${pki.tokenDir}/registrar";
  # The HTTP API wants a client certificate before anything else (cluster-common.nix).
  tls = clusterLib.nomadPki.cliTlsFor config.clan.core.vars.generators;

  # All rendered jobspecs -> one store dir; hash changes when any job changes.
  jobsDir = pkgs.linkFarm "nomad-jobs" (
    lib.mapAttrsToList (name: drv: {
      name = "${name}.json";
      path = drv;
    }) config.system.build.nomadJobs
  );

  managedApps = builtins.attrNames config.cluster.nomadApps;
  isServer = net.hasTag "nomad-server" node;
  stamp = "/var/lib/nomad-bootstrap/registered";

  registerScript = pkgs.writeShellScript "nomad-register-jobs" ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.curl
        # The leadership wait below pipes into grep; without it every check
        # failed and each deploy sat out the full five-minute wait.
        pkgs.gnugrep
        pkgs.jq
      ]
    }
    export NOMAD_ADDR=${nomadAddr}
    ${lib.concatStrings (lib.mapAttrsToList (k: v: "export ${k}=${v}\n") tls.env)}
    # Wait for raft leadership (up to ~5 min).
    for i in $(seq 1 60); do
      if curl -sf --max-time 5 ${tls.curlArgs} "${nomadAddr}/v1/status/leader" | grep -q ':'; then
        break
      fi
      sleep 5
    done

    # The registrar token, from nomad-login@registrar (ordered before this unit). At
    # boot that login may still be waiting on nomad-acl-init, so wait for the file
    # rather than fail on the first look.
    for i in $(seq 1 60); do
      [ -s ${token} ] && break
      sleep 5
    done
    NOMAD_TOKEN=$(cat ${token}); export NOMAD_TOKEN
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT

    # Has this server registered this generation's jobs before? Then it registers
    # only what the cluster has lost (the header says why).
    again=0
    [ "$(cat ${stamp} 2>/dev/null || true)" = "${jobsDir}" ] && again=1

    # Each jobspec names its namespace (`apps`, lib/mk-app-container.nix).
    for f in ${jobsDir}/*.json; do
      job=$(jq -r '.Job.ID' "$f")
      if [ "$again" = 1 ]; then
        code=$(curl -sS --max-time 15 ${tls.curlArgs} -o "$work/job" -w '%{http_code}' \
          -H "X-Nomad-Token: $NOMAD_TOKEN" \
          "${nomadAddr}/v1/job/$job?namespace=${clusterLib.nomad.appsNamespace}") || code=000
        case "$code" in
          200)
            if [ "$(jq -r '.Status // empty' "$work/job")" != dead ]; then
              continue
            fi
            echo "$job is dead: registering it again"
            ;;
          404) echo "$job is not registered: registering it" ;;
          *)
            echo "nomad-bootstrap: $job: HTTP $code" >&2
            exit 1
            ;;
        esac
      else
        echo "registering $f"
      fi
      ${nomad} job run -detach -json "$f"
    done
    printf '%s' "${jobsDir}" > ${stamp}.tmp
    mv ${stamp}.tmp ${stamp}
  '';
in
lib.mkIf (isServer && managedApps != [ ]) {
  systemd.services.nomad-bootstrap = {
    description = "Register rendered Nomad jobs (declarative convergence)";
    # Registration must not race the JuiceFS placement flag. A jobspec with
    # `meta.jfs_ready = true` in its constraints, submitted before the flag is
    # set, gets an evaluation with no placements and no blocked eval, and Nomad
    # never retries it: the jobs sit dead until someone re-registers them. Wait
    # for jfs-nomad-meta to finish first. `wants` (not `requires`) so a failed
    # flag never blocks registration of the jobs that do not need JuiceFS.
    after = [
      "nomad.service"
      "network-online.target"
      "jfs-nomad-meta.service"
      "nomad-acl-init.service"
      "nomad-login@registrar.service"
    ];
    wants = [
      "network-online.target"
      "jfs-nomad-meta.service"
      "nomad-acl-init.service"
      "nomad-login@registrar.service"
    ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${registerScript}";
      StateDirectory = "nomad-bootstrap";
      # A token that expired between refreshes, or a leader that came up late: try
      # again rather than leave the jobs unregistered until the next deploy.
      Restart = "on-failure";
      RestartSec = 30;
    };
  };
}
