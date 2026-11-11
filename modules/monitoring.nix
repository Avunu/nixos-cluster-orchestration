# modules/monitoring.nix — per-node metrics exporter (Phase 9).
#
# EVERY node: prometheus-node-exporter with the systemd + cgroups collectors —
# each nspawn container is a `container@<name>.service` unit, so per-container
# CPU/memory surfaces without any in-container agent (see README's
# "Operational loop", step 1).
#
# The scraping/scaling half (Prometheus + Nomad Autoscaler) is a singleton and
# lives in modules/monitoring-server.nix, assigned by the `metrics` tag through
# inventory.instances. This file carries no leader conditional.
#
# Both exporters listen on the node's mesh address (modules/mesh-control-core.nix)
# only: before the mesh, an attacker on the control VLAN read all of node_exporter.
{
  config,
  lib,
  topology,
  node,
  clusterLib,
  ...
}:
let
  textDir = "/var/lib/prometheus-node-exporter-text";
  known = lib.attrNames config.clusterApps;
  net = clusterLib.net;
  meshIp = net.meshIp topology node;
in
{
  services.prometheus.exporters.node = {
    enable = true;
    listenAddress = meshIp;
    port = clusterLib.net.nodeExporterPort;
    enabledCollectors = [
      "systemd"
      "cgroups"
      # Metrics written by jobs rather than scraped from daemons: backup
      # freshness, restore rehearsals (modules/backup-core.nix).
      "textfile"
    ];
    extraFlags = [
      "--collector.textfile.directory=/var/lib/prometheus-node-exporter-text"
      # node_systemd_service_restart_total, for UnitRestartLoop (lib/alert-rules.nix): a
      # unit that restarts for ever is never "failed".
      "--collector.systemd.enable-restarts-metrics"
    ];
  };
  systemd.tmpfiles.rules = [ "d ${textDir} 0755 root root -" ];

  # Per-app textfile metrics outlive the app: once an app leaves apps/, nothing
  # rewrites its cluster_backup_* or cluster_app_deploy_* file, so its
  # BackupStale and AppDeployDegraded alerts would fire forever (demo-erp
  # did, for a week after its removal). Drop the files of apps no longer
  # declared on every switch. Only metrics are removed; the app's state under
  # /var/lib/nixos-containers is left for a human.
  system.activationScripts.prune-app-metrics = ''
    known=" ${lib.concatStringsSep " " known} "
    for f in ${textDir}/cluster_app_deploy_*.prom ${textDir}/cluster_backup_*.prom; do
      [ -e "$f" ] || continue
      b=''${f##*/}
      case "$b" in
        cluster_app_deploy_*) app=''${b#cluster_app_deploy_}; app=''${app%.prom} ;;
        *) app=''${b#cluster_backup_}; app=''${app%_*.prom} ;;
      esac
      case "$known" in
        *" $app "*) ;;
        *) echo "prune-app-metrics: removing $b ($app is no longer declared)"; rm -f "$f" ;;
      esac
    done
  '';

  # SMART health and wear of every disk (the ZFS mirror's NVMes).
  services.prometheus.exporters.smartctl = {
    enable = true;
    listenAddress = meshIp;
    port = clusterLib.net.smartctlExporterPort;
  };

  systemd.services.prometheus-node-exporter = net.meshBoundUnit;
  systemd.services.prometheus-smartctl-exporter = net.meshBoundUnit;
}
