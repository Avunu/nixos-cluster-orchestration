# modules/alerting.nix — alerting, wired to topology, clusterApps and clan vars.
#
# Imported by modules/monitoring-server.nix, so it runs on the ONE node tagged
# `metrics`, next to Prometheus. The logic is modules/alerting-core.nix; this
# file only decides what to watch and where the token comes from.
#
#   cluster-alert-test      fire a test alert through the whole path
#
# Recipients and sender: topology.alerting. The Cloudflare token:
#   clan vars set <metrics node> alerting/cf-email-token
{
  config,
  lib,
  pkgs,
  topology,
  ...
}:
let
  apps = config.clusterApps;
  backedUp = lib.filterAttrs (_: a: a.backup.enable) apps;
  hasDb =
    n: a:
    a.backup.engine != "none"
    && (
      a.backup.engine != null
      || config.containers.${n}.config.services.postgresql.enable
      || config.containers.${n}.config.services.mysql.enable
    );
  # What the weekly rehearsal restores: a database dump, local state, or both.
  isVerified = n: a: hasDb n a || a.backup.localSnapshot;
  target = topology.backup.target;
in
{
  imports = [ ./alerting-core.nix ];

  # Shared with the cluster-watchdog Worker (wrangler secret put WATCHDOG_TOKEN
  # < <(clan vars get node1 alerting-watchdog/token)).
  clan.core.vars.generators.alerting-watchdog = {
    share = true;
    files.token = { };
    runtimeInputs = [
      pkgs.coreutils
      pkgs.openssl
    ];
    script = ''
      openssl rand -hex 32 | tr -d '\n' > "$out/token"
    '';
  };

  clan.core.vars.generators.alerting = {
    share = true;
    prompts.cf-email-token = {
      description = "Cloudflare API token, Email Sending permission only (alert emails)";
      type = "hidden";
      persist = true;
    };
  };

  cluster.alerting = {
    clusterName = config.clan.core.settings.name;
    inherit (topology.alerting) cloudflareAccountId from to;
    tokenFile = config.clan.core.vars.generators.alerting.files.cf-email-token.path;
    backupApps = lib.attrNames backedUp;
    verifiedApps = lib.attrNames (lib.filterAttrs isVerified backedUp);
    freeipaApps = lib.attrNames (lib.filterAttrs (_: a: a.freeipa != null) apps);
    # Every public hostname of every app, probed the way a user reaches it --
    # except those behind Cloudflare Access, where the edge answers with its
    # login redirect and the probe would never reach the tunnel or the app.
    appProbes = lib.concatLists (
      lib.mapAttrsToList (
        n: a:
        map (host: {
          app = n;
          url = "https://${host}/";
        }) (lib.subtractLists a.tunnel.accessProtected (lib.attrNames (a.tunnel.ingress or { })))
      ) apps
    );
    heartbeat = lib.optionalAttrs (topology.alerting.heartbeatUrl or null != null) {
      url = topology.alerting.heartbeatUrl;
      tokenFile = config.clan.core.vars.generators.alerting-watchdog.files.token.path;
    };
    targetProbes =
      lib.optional (target.type == "s3") target.endpoint
      ++ lib.optional (target.type == "rest") target.url;
  };
}
