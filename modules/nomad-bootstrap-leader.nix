# modules/nomad-bootstrap-leader.nix — declarative job registration (singleton).
#
# Waits for Nomad raft leadership, then `nomad job run` every rendered
# system.build.nomadJobs.*. Idempotent — Nomad diffs and no-ops unchanged jobs.
# The unit's ExecStart references the store-hashed jobs dir, so any deploy that
# changes a jobspec re-triggers it and only changed jobs re-register.
#
# Assigned to the ONE node tagged `nomad-leader` via inventory.instances in
# flake.nix. Registration is a singleton not because two nodes would corrupt
# anything (job submission is idempotent) but because N nodes racing to submit
# the same N jobs on every deploy is pointless churn against the raft leader.
#
# It registers as the `registrar` role: submit, read and list jobs in the `apps`
# namespace, nothing else. The ACL bootstrap and everything the scoped tokens rest
# on (namespaces, policies, the JWT auth method) is nomad-acl-init's, in
# modules/nomad-acl.nix, which is the only reader of the management token.
#
# The counterpart fencing reconciler runs on every node — see
# modules/nomad-bootstrap.nix.
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

  managedApps = builtins.attrNames config.clusterApps;

  registerScript = pkgs.writeShellScript "nomad-register-jobs" ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.curl
        # The leadership wait below pipes into grep; without it every check
        # failed and each deploy sat out the full five-minute wait.
        pkgs.gnugrep
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

    # Each jobspec names its namespace (`apps`, lib/mk-app-container.nix).
    for f in ${jobsDir}/*.json; do
      echo "registering $f"
      ${nomad} job run -detach -json "$f"
    done
  '';
in
lib.mkIf (managedApps != [ ]) {
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
      # A token that expired between refreshes, or a leader that came up late: try
      # again rather than leave the jobs unregistered until the next deploy.
      Restart = "on-failure";
      RestartSec = 30;
    };
  };
}
