# modules/alerting.nix — alerting, wired to topology, clusterApps and the site's secrets.
#
# Imported by modules/monitoring-server.nix, so it runs on every node, next to that
# node's Prometheus. Each node evaluates the same rules over the same targets and
# tells its own Alertmanager; the Alertmanagers gossip on the mesh, so one alert is
# one email, whichever nodes are up. The logic is modules/alerting-core.nix; this
# file only decides what to watch and where the token comes from.
#
#   cluster-alert-test      fire a test alert through the whole path
#
# Recipients and sender: topology.alerting. The Cloudflare token:
#   agenix edit secrets/shared/alerting/cf-email-token.age
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  clusterSite,
  ...
}:
let
  net = clusterLib.net;
  peers = lib.filterAttrs (n: nd: n != nodeName && (nd.provisioned or true)) topology.nodes;
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
  # < <(agenix view secrets/shared/alerting-watchdog/token.age)).
  cluster.secrets.generators.alerting-watchdog = {
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

  cluster.secrets.generators.alerting = {
    share = true;
    prompts.cf-email-token = {
      description = "Cloudflare API token, Email Sending permission only (alert emails)";
      type = "hidden";
      persist = true;
    };
  };

  # It gossips on the mesh address, which exists only once the mesh is up.
  systemd.services.alertmanager = net.meshBoundUnit;

  cluster.alerting = {
    gossip = {
      listenAddress = net.meshIp topology node;
      peers = lib.mapAttrsToList (_: nd: net.meshIp topology nd) peers;
      port = net.alertmanagerClusterPort;
    };
    report.self = "${net.meshIp topology node}:${toString net.nodeExporterPort}";
    clusterName = clusterSite.name;
    inherit (topology.alerting) cloudflareAccountId from to;
    tokenFile = config.cluster.secrets.generators.alerting.files.cf-email-token.path;
    backupApps = lib.attrNames backedUp;
    verifiedApps = lib.attrNames (lib.filterAttrs isVerified backedUp);
    freeipaApps = lib.attrNames (lib.filterAttrs (_: a: a.freeipa != null) apps);
    stateBackupApps = config.cluster.stateBackup.apps or [ ];
    stateBackupStaleHours = topology.backup.state.staleHours or 4;
    # Every public hostname of every app, probed the way a user reaches it --
    # except those behind Cloudflare Access, where the edge answers with its
    # login redirect and the probe would never reach the tunnel or the app.
    appProbes = lib.concatLists (
      lib.mapAttrsToList (
        n: a:
        map (host: {
          app = n;
          url = "https://${host}${a.tunnel.probePath}";
        }) (lib.subtractLists a.tunnel.accessProtected (lib.attrNames (a.tunnel.ingress or { })))
      ) apps
    );
    heartbeat = lib.optionalAttrs (topology.alerting.heartbeatUrl or null != null) {
      url = topology.alerting.heartbeatUrl;
      tokenFile = config.cluster.secrets.generators.alerting-watchdog.files.token.path;
    };
    targetProbes =
      lib.optional (target.type == "s3") target.endpoint
      ++ lib.optional (target.type == "rest") target.url;
  };
}
