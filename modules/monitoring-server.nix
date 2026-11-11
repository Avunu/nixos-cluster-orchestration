# modules/monitoring-server.nix — Prometheus + Nomad Autoscaler (singleton).
#
# Assigned to the ONE node tagged `metrics` via inventory.instances in flake.nix.
#   - Prometheus scrapes every node-exporter + Nomad's own /v1/metrics, with the
#     relabel container@(.*)\.service -> nspawn_container (README step 2).
#   - Nomad Autoscaler (no NixOS module upstream) as a systemd unit, plugins via
#     withPlugins; APM = Prometheus, target = Nomad (step 3).
#
# Alerting (Alertmanager, rules, probes, email) is modules/alerting.nix, and
# the log store (Loki) is modules/logging-server.nix, both imported below:
# they need Prometheus/Alertmanager beside them, so they follow this role.
#
# Autoscaler note: this is a singleton today because two agents would both act
# on the same scaling policies. Running it on a second node needs leader
# election, which is why the tag is deliberately not on node2/node3 yet.
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
  tls = clusterLib.nomadPki.cliTlsFor config.clan.core.vars.generators;
  nomadCreds = [
    "nomad-ca.crt:${tls.caCert}"
    "nomad-cli.crt:${tls.clientCert}"
    "nomad-cli.key:${tls.clientKey}"
  ];
  credPath = unit: id: "/run/credentials/${unit}.service/${id}";

  autoscalerEnv = pkgs.nomad-autoscaler.withPlugins (ps: [
    ps.prometheus
    ps.nomad_apm
    ps.nomad_target
    ps.target_value
    ps.threshold
  ]);

  autoscalerConfig = pkgs.writeText "nomad-autoscaler.hcl" ''
    plugin_dir = "${autoscalerEnv}/share"

    nomad {
      address     = "${net.nomadAddr node}"
      ca_cert     = "${credPath "nomad-autoscaler" "nomad-ca.crt"}"
      client_cert = "${credPath "nomad-autoscaler" "nomad-cli.crt"}"
      client_key  = "${credPath "nomad-autoscaler" "nomad-cli.key"}"
      # Its token is scoped to this namespace (modules/nomad-acl.nix).
      namespace   = "${clusterLib.nomad.appsNamespace}"
    }

    apm "prometheus" {
      driver = "prometheus"
      config = {
        address = "http://${meshIp}:${toString net.prometheusPort}"
      }
    }

    apm "nomad-apm" {
      driver = "nomad-apm"
    }

    target "nomad-target" {
      driver = "nomad-target"
    }

    strategy "target-value" {
      driver = "target-value"
    }

    strategy "threshold" {
      driver = "threshold"
    }
  '';
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

  systemd.services.nomad-autoscaler = {
    description = "Nomad Autoscaler (Prometheus APM -> Nomad target)";
    after = [
      "nomad.service"
      "prometheus.service"
      "nomad-login@autoscaler.service"
    ];
    wants = [ "nomad-login@autoscaler.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      # The token goes in via the environment, NOT into autoscalerConfig: that
      # HCL is a Nix store path, and the store is world-readable.
      #
      # Without it the agent starts happily and then 403s on every scaling
      # decision once ACLs are bootstrapped — it looks alive and does nothing.
      #
      # It is the `autoscaler` role's token (scale and list in `apps`, read on
      # node, operator and agent), read once at start: nomad-login@autoscaler
      # restarts this unit each time it refreshes the token (modules/nomad-acl.nix).
      # Until that login has succeeded the credential is missing and the start
      # fails; Restart= tries again.
      LoadCredential = [
        "nomad-token:${clusterLib.nomadPki.tokenDir}/autoscaler"
      ]
      ++ nomadCreds;
      ExecStart = pkgs.writeShellScript "nomad-autoscaler-start" ''
        set -euo pipefail
        NOMAD_TOKEN=$(cat "$CREDENTIALS_DIRECTORY/nomad-token"); export NOMAD_TOKEN
        exec ${autoscalerEnv}/bin/nomad-autoscaler agent -config ${autoscalerConfig}
      '';
      Restart = "on-failure";
      RestartSec = 10;
      DynamicUser = true;
    };
  };
}
