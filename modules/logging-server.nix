# modules/logging-server.nix — Loki: the cluster's log store (singleton).
#
# Imported by modules/monitoring-server.nix, so it follows the `metrics` role:
# Loki sits beside Prometheus and Alertmanager, and every node's Vector
# (modules/logging.nix) pushes to it over the WireGuard control mesh. It has no
# authentication of its own: before the mesh, anything on the control VLAN could
# read it and push forged lines into it (`loki-forged-push-refused`).
#
# Chunks, the TSDB index, the WAL and the compactor's state all live in /var/lib/loki,
# which is its own ZFS dataset (lib/mk-disk-layout.nix, quota 50G) on the node's LUKS
# pool. Nothing goes to object storage and Loki holds no credentials. Chunks and the
# WAL are plaintext log lines, client data included [RAN in the design's spike], so
# the disk encryption is what protects them at rest; a bucket would have put them
# in front of the storage provider instead.
#
# What that costs, accepted: moving the `metrics` tag gives the new node an EMPTY
# Loki, and the history goes with the node if the node is lost. Every node's Vector
# resumes from its own journal cursor, so nothing still in a journal is lost, and
# retention (topology.logging.retention) is what bounds the store anyway. A backup
# would keep client-bearing lines past that retention, so there is none. The node the
# tag moved AWAY from keeps its old store, which its own Loki no longer compacts:
# modules/logging.nix applies the same retention to it (loki-retired-store).
#
# The limits started from an earlier filesystem-backed deployment's, with the
# reasons for them kept beside each.
{
  lib,
  pkgs,
  topology,
  clusterLib,
  node,
  ...
}:
let
  net = clusterLib.net;
  retention = topology.logging.retention;
  # The dataset's mountpoint (lib/mk-disk-layout.nix). StateDirectory below names it
  # relative to /var/lib, so it has to stay under there.
  dataDir = "/var/lib/loki";
  meshIp = net.meshIp topology node;

  # Loki's ruler reads <directory>/<tenant>/*.yaml; with auth disabled the
  # tenant is "fake".
  rulesDir = pkgs.runCommand "loki-rules" { } ''
    mkdir -p $out/fake
    cp ${
      pkgs.writeText "app-logs.yaml" (
        builtins.toJSON (import ../lib/log-alert-rules.nix { inherit lib; })
      )
    } $out/fake/app-logs.yaml
  '';

  lokiConfig = {
    auth_enabled = false;
    analytics.reporting_enabled = false;

    server = {
      # The mesh address: where every node's Vector and the Grafana container
      # reach it, and the only address the host firewall lets them use for it.
      http_listen_address = meshIp;
      http_listen_port = net.lokiPort;
      grpc_listen_address = "127.0.0.1";
      grpc_listen_port = 9095;
    };

    common = {
      instance_addr = "127.0.0.1";
      path_prefix = dataDir;
      replication_factor = 1;
      ring.kvstore.store = "inmemory";
      # On the node's own (encrypted) disk. The ruler reads its rules from the store
      # path below, so rules_directory only satisfies the filesystem client.
      storage.filesystem = {
        chunks_directory = "${dataDir}/chunks";
        rules_directory = "${dataDir}/rules";
      };
    };

    schema_config.configs = [
      {
        # Before any entry a node can backfill: a journal's oldest entry may
        # predate the day this was deployed.
        from = "2026-01-01";
        store = "tsdb";
        object_store = "filesystem";
        schema = "v13";
        index = {
          prefix = "index_";
          period = "24h";
        };
      }
    ];

    compactor = {
      working_directory = "${dataDir}/compactor";
      # Lines older than topology.logging.retention are deleted, not just hidden: the
      # compactor marks their chunks and removes the files retention_delete_delay
      # (2h by default) later. `retention-removes-old` in tests/logging.nix.
      retention_enabled = true;
      delete_request_store = "filesystem";
    };

    limits_config = {
      retention_period = retention;
      # Defaults (4 MB/s, 3 MB/s per stream) throttle a node's backlog replay
      # -- after a Loki outage, or the first start, when every journal on the
      # node ships from its beginning -- so badly that retried batches arrive
      # out of order and are hard-rejected (observed).
      ingestion_rate_mb = 50;
      ingestion_burst_size_mb = 100;
      per_stream_rate_limit = "20MB";
      per_stream_rate_limit_burst = "40MB";
      # The ingest window follows retention (the default is one week), so a
      # node that was cut off can still backfill everything it kept.
      reject_old_samples = true;
      reject_old_samples_max_age = retention;
      # unit / syslog_identifier / pid / container_host (modules/logging.nix).
      allow_structured_metadata = true;
      # Grafana's log volume histograms.
      volume_enabled = true;
    };

    ruler = {
      storage = {
        type = "local";
        local.directory = "${rulesDir}";
      };
      rule_path = "${dataDir}/rules-tmp";
      # The Alertmanager beside it (modules/alerting-core.nix): log alerts
      # arrive by the same email as every other alert.
      alertmanager_url = "http://127.0.0.1:9093";
      ring.kvstore.store = "inmemory";
      enable_api = true;
    };
  };

in
{
  services.loki = {
    enable = true;
    inherit dataDir;
    # The nixpkgs module runs `loki -verify-config` on this at build time, so a
    # configuration Loki rejects fails the build rather than the deploy.
    configuration = lokiConfig;
  };

  # Binds the mesh address, which exists only once wg-ctrl is up.
  systemd.services.loki = lib.mkMerge [
    net.meshBoundUnit
    {
      # The dataset is mounted after activation created the `loki` user's home, so on
      # a fresh install its root is root:root 0755 and Loki could not write it.
      # systemd puts ownership right at every start, and 0700 keeps the plaintext
      # chunks from every other local user. WorkingDirectory (the nixpkgs unit) already
      # orders the unit after the mount.
      serviceConfig = {
        StateDirectory = lib.removePrefix "/var/lib/" dataDir;
        StateDirectoryMode = "0700";
      };
    }
  ];

  # Loki's own health (LokiDown in lib/alert-rules.nix), and the per-node
  # shippers', scraped by the Prometheus beside it.
  services.prometheus.scrapeConfigs = [
    {
      job_name = "loki";
      static_configs = [ { targets = [ "${meshIp}:${toString net.lokiPort}" ]; } ];
    }
    {
      job_name = "vector";
      static_configs = [
        {
          targets = lib.mapAttrsToList (
            _: nd: "${net.meshIp topology nd}:${toString net.vectorMetricsPort}"
          ) (lib.filterAttrs (_: nd: nd.provisioned or true) topology.nodes);
        }
      ];
    }
  ];
}
