# modules/monitoring-server.nix — Prometheus, on every node.
#
# No node is the monitoring node. Each runs a Prometheus that scrapes every node's
# exporters and Nomad's own /v1/metrics (with the relabel container@(.*)\.service ->
# nspawn_container), evaluates the same rules, and holds its own history; and with
# it, imported below, an Alertmanager (modules/alerting.nix) and a Loki
# (modules/logging-server.nix) that every node's log shipper feeds. So monitoring
# survives any node, and does not depend on the scheduler it watches: nothing here is
# placed, elected or moved.
#
# What that costs: the stack N times over, in memory and in disk, and N histories that
# are the same except where a node was down and has a gap of its own. An alert is one
# email all the same (the Alertmanagers gossip), and Grafana, wherever Nomad puts it,
# asks the node it is on (modules/kinds/grafana.nix).
{
  config,
  lib,
  pkgs,
  topology,
  node,
  clusterLib,
  ...
}:
let
  net = clusterLib.net;

  # Placeholders (`provisioned = false`) are not scraped: an address that has
  # never existed would be a NodeDown alert forever.
  provisioned = lib.filterAttrs (_: nd: nd.provisioned or true) topology.nodes;
  # On the mesh, except Nomad's, which stays on the control VLAN under mTLS.
  targetsOn =
    port: lib.mapAttrsToList (_: nd: "${net.meshIp topology nd}:${toString port}") provisioned;
  nomadTargets = lib.mapAttrsToList (
    _: nd: "${nd.controlIp}:${toString net.nomadHttpPort}"
  ) provisioned;
  meshIp = net.meshIp topology node;

  # Nomad's API wants a client certificate (verify_https_client), and neither
  # Prometheus nor the autoscaler runs as root, which the vars files are readable by.
  # So each gets them as systemd credentials, at the path systemd puts them for that
  # unit, and names that path in its configuration.
  tls = clusterLib.nomadPki.cliTlsFor config.cluster.secrets.generators;
  nomadCreds = [
    "nomad-ca.crt:${tls.caCert}"
    "nomad-cli.crt:${tls.clientCert}"
    "nomad-cli.key:${tls.clientKey}"
  ];
  credPath = unit: id: "/run/credentials/${unit}.service/${id}";

in
{
  imports = [
    ./alerting.nix
    ./logging-server.nix
  ];

  services.prometheus = {
    enable = true;
    port = net.prometheusPort;
    # The mesh address, not loopback: Grafana runs in a container
    # (modules/kinds/grafana.nix) and reaches it there, through the one rule the
    # host firewall keeps for it ahead of the weak-host drop.
    listenAddress = meshIp;
    globalConfig.scrape_interval = "15s";
    # promtool's full check opens every file the configuration names, and the
    # Nomad scrape's certificate paths exist only inside the running unit
    # (credentials, below), so the build would fail on them. The syntax is still
    # checked.
    checkConfig = "syntax-only";

    scrapeConfigs = [
      {
        job_name = "nixos-hosts";
        static_configs = [
          {
            targets = targetsOn net.nodeExporterPort;
          }
        ];
        # container@<name>.service -> nspawn_container="<name>".
        metric_relabel_configs = [
          {
            source_labels = [ "name" ];
            regex = "container@(.*)\\.service";
            target_label = "nspawn_container";
            replacement = "\${1}";
          }
        ];
      }
      {
        # On the control IP over https, with the CLI certificate: /v1/metrics has
        # no ACL check, but the handshake wants a certificate first.
        job_name = "nomad";
        scheme = "https";
        tls_config = {
          ca_file = credPath "prometheus" "nomad-ca.crt";
          cert_file = credPath "prometheus" "nomad-cli.crt";
          key_file = credPath "prometheus" "nomad-cli.key";
        };
        metrics_path = "/v1/metrics";
        params.format = [ "prometheus" ];
        static_configs = [
          {
            targets = nomadTargets;
          }
        ];
      }
      {
        job_name = "smartctl";
        static_configs = [ { targets = targetsOn net.smartctlExporterPort; } ];
      }
    ];
  };

  systemd.services.prometheus = lib.mkMerge [
    net.meshBoundUnit
    { serviceConfig.LoadCredential = nomadCreds; }
  ];

  # Nomad's telemetry (what the `nomad` job above scrapes) is on every node:
  # modules/cluster-common.nix.
}
