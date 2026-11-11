# promtool unit tests for lib/alert-rules.nix: every alert FIRES when it should
# and stays quiet when it should not. The reference setup had rules paused for
# months because they fired on missing data; this is the guard against that.
#
# Rules are rendered with annotate = false: promtool compares annotations
# verbatim, and what is under test is expressions, durations and labels.
#
# Run: nix build .#checks.<system>.alert-rules
{ pkgs, lib }:
let
  rules = import ../lib/alert-rules.nix {
    inherit lib;
    backupApps = [ "demo-odoo" ];
    freeipaApps = [ "idm" ];
    annotate = false;
  };
  rulesFile = pkgs.writeText "rules.yml" (builtins.toJSON rules);

  # One case: input series as [ selector values ] pairs, and at `at`, exactly
  # `expect` firing (each an attrset of labels besides alertname).
  case = alertname: series: at: expect: {
    interval = "1m";
    input_series = map (sv: {
      series = builtins.elemAt sv 0;
      values = builtins.elemAt sv 1;
    }) series;
    alert_rule_test = [
      {
        eval_time = at;
        inherit alertname;
        exp_alerts = map (l: { exp_labels = l; }) expect;
      }
    ];
  };
  none = [ ];
  # One input series, and the labels an alert on instance "n" carries.
  s = selector: values: [
    selector
    values
  ];
  crit = severity: {
    instance = "n";
    inherit severity;
  };

  tests = [
    # ── backups ─────────────────────────────────────────────────────────────
    # A timestamp stuck at 0 is a backup that stopped; one that tracks time()
    # (+60 per minute) is a backup that keeps succeeding.
    (case "BackupStale"
      [
        [
          ''cluster_backup_last_success_timestamp_seconds{app="demo-odoo"}''
          "0x2000"
        ]
      ]
      "31h"
      [
        {
          app = "demo-odoo";
          severity = "critical";
        }
      ]
    )
    (case "BackupStale" [
      [
        ''cluster_backup_last_success_timestamp_seconds{app="demo-odoo"}''
        "0+60x2000"
      ]
    ] "31h" none)
    (case "BackupStale" [
      [
        ''cluster_backup_last_success_timestamp_seconds{app="demo-odoo"}''
        "0x2000"
      ]
    ] "29h" none)
    (case "BackupPartial"
      [
        [
          ''cluster_backup_last_status{app="demo-odoo"}''
          "2x20"
        ]
      ]
      "10m"
      [
        {
          app = "demo-odoo";
          severity = "warning";
        }
      ]
    )
    (case "BackupPartial" [
      [
        ''cluster_backup_last_status{app="demo-odoo"}''
        "1x20"
      ]
    ] "10m" none)
    # absent(): an app that has NEVER written the metric.
    (case "BackupNeverRan"
      [
        [
          "some_other_metric"
          "1x2000"
        ]
      ]
      "31h"
      [
        {
          app = "demo-odoo";
          severity = "critical";
        }
      ]
    )
    (case "BackupNeverRan" [
      [
        ''cluster_backup_last_success_timestamp_seconds{app="demo-odoo"}''
        "0+60x2000"
      ]
    ] "31h" none)
    (case "BackupNeverRan" [
      [
        "some_other_metric"
        "1x2000"
      ]
    ] "29h" none)
    (case "BackupVerifyStale"
      [
        [
          ''cluster_backup_verify_last_success_timestamp_seconds{app="demo-odoo"}''
          "0x12000"
        ]
      ]
      "8d1h"
      [
        {
          app = "demo-odoo";
          severity = "warning";
        }
      ]
    )
    (case "BackupVerifyStale" [
      [
        ''cluster_backup_verify_last_success_timestamp_seconds{app="demo-odoo"}''
        "0+60x12000"
      ]
    ] "8d1h" none)

    # ── units ───────────────────────────────────────────────────────────────
    (case "UnitFailed"
      [
        [
          ''node_systemd_unit_state{name="cluster-backup-demo-odoo.service",state="failed",instance="n"}''
          "1x30"
        ]
      ]
      "20m"
      [
        {
          name = "cluster-backup-demo-odoo.service";
          state = "failed";
          instance = "n";
          severity = "warning";
        }
      ]
    )
    (case "UnitFailed" [
      [
        ''node_systemd_unit_state{name="cluster-backup-demo-odoo.service",state="failed",instance="n"}''
        "0x30"
      ]
    ] "20m" none)
    # App units are critical, and not double-reported as UnitFailed.
    (case "AppUnitFailed"
      [
        [
          ''node_systemd_unit_state{name="container@demo-odoo.service",state="failed",instance="n"}''
          "1x30"
        ]
      ]
      "10m"
      [
        {
          name = "container@demo-odoo.service";
          state = "failed";
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "UnitFailed" [
      [
        ''node_systemd_unit_state{name="container@demo-odoo.service",state="failed",instance="n"}''
        "1x30"
      ]
    ] "20m" none)
    (case "AppDeployDegraded"
      [
        [
          ''cluster_app_deploy_degraded{app="demo-odoo",instance="n"}''
          "1x30"
        ]
      ]
      "10m"
      [
        {
          app = "demo-odoo";
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "AppDeployDegraded" [
      [
        ''cluster_app_deploy_degraded{app="demo-odoo",instance="n"}''
        "1x3 0x30"
      ]
    ] "10m" none)

    # ── availability ────────────────────────────────────────────────────────
    (case "NodeDown"
      [
        [
          ''up{job="nixos-hosts",instance="n"}''
          "0x10"
        ]
      ]
      "5m"
      [
        {
          job = "nixos-hosts";
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "NodeDown" [
      [
        ''up{job="nixos-hosts",instance="n"}''
        "1x10"
      ]
    ] "5m" none)
    (case "AppDown"
      [
        [
          ''probe_success{job="apps",app="demo-odoo",instance="https://m/"}''
          "0x20"
        ]
      ]
      "10m"
      [
        {
          job = "apps";
          app = "demo-odoo";
          instance = "https://m/";
          severity = "critical";
        }
      ]
    )
    (case "AppDown" [
      [
        ''probe_success{job="apps",app="demo-odoo",instance="https://m/"}''
        "1x20"
      ]
    ] "10m" none)

    # ── storage ─────────────────────────────────────────────────────────────
    (case "ZfsPoolUnhealthy"
      [
        [
          ''node_zfs_zpool_state{zpool="rpool",state="degraded",instance="n"}''
          "1x5"
        ]
      ]
      "3m"
      [
        {
          zpool = "rpool";
          state = "degraded";
          instance = "n";
          severity = "critical";
        }
      ]
    )
    # node_exporter reports every state; only a non-online one set to 1 counts.
    (case "ZfsPoolUnhealthy" [
      [
        ''node_zfs_zpool_state{zpool="rpool",state="online",instance="n"}''
        "1x5"
      ]
      [
        ''node_zfs_zpool_state{zpool="rpool",state="degraded",instance="n"}''
        "0x5"
      ]
    ] "3m" none)
    (case "FilesystemFull"
      [
        [
          ''node_filesystem_avail_bytes{fstype="zfs",mountpoint="/state",instance="n"}''
          "1x10"
        ]
        [
          ''node_filesystem_size_bytes{fstype="zfs",mountpoint="/state",instance="n"}''
          "100x10"
        ]
      ]
      "8m"
      [
        {
          fstype = "zfs";
          mountpoint = "/state";
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "FilesystemFull" [
      [
        ''node_filesystem_avail_bytes{fstype="zfs",mountpoint="/state",instance="n"}''
        "50x10"
      ]
      [
        ''node_filesystem_size_bytes{fstype="zfs",mountpoint="/state",instance="n"}''
        "100x10"
      ]
    ] "8m" none)
    (case "JuiceFSUnwritable"
      [
        [
          ''cluster_jfs_probe_success{instance="n"}''
          "0x20"
        ]
      ]
      "15m"
      [
        {
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "JuiceFSUnwritable" [
      [
        ''cluster_jfs_probe_success{instance="n"}''
        "1x20"
      ]
    ] "15m" none)
    (case "JuiceFSMetaDumpStale"
      [
        [
          ''cluster_jfs_meta_dump_newest_timestamp_seconds{instance="n"}''
          "0x300"
        ]
      ]
      "4h"
      [
        {
          instance = "n";
          severity = "warning";
        }
      ]
    )
    (case "JuiceFSMetaDumpStale" [
      [
        ''cluster_jfs_meta_dump_newest_timestamp_seconds{instance="n"}''
        "0+60x300"
      ]
    ] "4h" none)

    # ── FreeIPA ─────────────────────────────────────────────────────────────
    (case "FreeIPADown"
      [
        [
          ''cluster_freeipa_up{app="idm"}''
          "0x40"
        ]
      ]
      "25m"
      [
        {
          app = "idm";
          severity = "critical";
        }
      ]
    )
    # A first install (down for ~5 minutes) must not page.
    (case "FreeIPADown" [
      [
        ''cluster_freeipa_up{app="idm"}''
        "0x10 1x30"
      ]
    ] "25m" none)
    (case "FreeIPAUnhealthy"
      [
        [
          ''cluster_freeipa_healthcheck_errors{app="idm"}''
          "2x40"
        ]
      ]
      "35m"
      [
        {
          app = "idm";
          severity = "warning";
        }
      ]
    )
    # Warnings alone, or a server that is down (-1: no healthcheck), are not errors.
    (case "FreeIPAUnhealthy" [
      [
        ''cluster_freeipa_healthcheck_errors{app="idm"}''
        "-1x40"
      ]
    ] "35m" none)
    (case "FreeIPARestartPending"
      [
        [
          ''cluster_freeipa_restart_pending{app="idm"}''
          "1x1600"
        ]
      ]
      "25h"
      [
        {
          app = "idm";
          severity = "warning";
        }
      ]
    )
    (case "FreeIPARestartPending" [
      [
        ''cluster_freeipa_restart_pending{app="idm"}''
        "1x600 0x1000"
      ]
    ] "25h" none)
    (case "FreeIPAHealthStale"
      [
        [
          ''cluster_freeipa_health_last_run_timestamp_seconds{app="idm"}''
          "0x120"
        ]
      ]
      "90m"
      [
        {
          app = "idm";
          severity = "warning";
        }
      ]
    )
    (case "FreeIPAHealthStale" [
      [
        ''cluster_freeipa_health_last_run_timestamp_seconds{app="idm"}''
        "0+60x120"
      ]
    ] "90m" none)
    (case "FreeIPAHealthNeverRan"
      [
        [
          "some_other_metric"
          "1x120"
        ]
      ]
      "90m"
      [
        {
          app = "idm";
          severity = "warning";
        }
      ]
    )
    (case "FreeIPAHealthNeverRan" [
      [
        ''cluster_freeipa_health_last_run_timestamp_seconds{app="idm"}''
        "0+60x120"
      ]
    ] "90m" none)

    # ── the log pipeline ────────────────────────────────────────────────────
    (case "LokiDown"
      [
        [
          ''up{job="loki",instance="m"}''
          "0x10"
        ]
      ]
      "8m"
      [
        {
          job = "loki";
          instance = "m";
          severity = "warning";
        }
      ]
    )
    (case "LokiDown" [
      [
        ''up{job="loki",instance="m"}''
        "1x10"
      ]
    ] "8m" none)
    (case "LogShipperDown"
      [
        [
          ''up{job="vector",instance="n"}''
          "0x20"
        ]
      ]
      "15m"
      [
        {
          job = "vector";
          instance = "n";
          severity = "warning";
        }
      ]
    )
    (case "LogShipperDown" [
      [
        ''up{job="vector",instance="n"}''
        "1x20"
      ]
    ] "15m" none)
    # Errors climbing for 30 minutes fire; a counter that stopped climbing
    # (a blip that recovered) does not.
    (case "LogShippingFailing"
      [
        [
          ''vector_component_errors_total{component_id="loki",instance="n"}''
          "0+5x40"
        ]
      ]
      "35m"
      [
        {
          instance = "n";
          severity = "warning";
        }
      ]
    )
    (case "LogShippingFailing" [
      [
        ''vector_component_errors_total{component_id="loki",instance="n"}''
        "0+5x5 25x40"
      ]
    ] "35m" none)

    # ── nomad ───────────────────────────────────────────────────────────────
    # A fence that stopped succeeding (a timestamp stuck at 0, never run), and one that
    # succeeds every minute.
    (case "NomadFenceStale"
      [
        [
          ''cluster_fence_last_success_timestamp_seconds{instance="n"}''
          "0x30"
        ]
      ]
      "20m"
      [
        {
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "NomadFenceStale" [
      [
        ''cluster_fence_last_success_timestamp_seconds{instance="n"}''
        "0+60x30"
      ]
    ] "20m" none)
    # Stale for 9 minutes only (it stopped at 11m, the rule's 600s is crossed at 21m):
    # still quiet at 20m, so the threshold is the expression's, not just the `for`.
    (case "NomadFenceStale" [
      [
        ''cluster_fence_last_success_timestamp_seconds{instance="n"}''
        "0+60x11 660x30"
      ]
    ] "20m" none)

    # ── network ─────────────────────────────────────────────────────────────
    # A path that has lost its jumbo frames, for longer than two probe runs.
    (case "VrackJumboBroken"
      [
        [
          ''cluster_vrack_mtu_ok{instance="n",vlan="control",peer="node2"}''
          "0x30"
        ]
      ]
      "15m"
      [
        {
          instance = "n";
          vlan = "control";
          peer = "node2";
          severity = "critical";
        }
      ]
    )
    # Healthy: quiet.
    (case "VrackJumboBroken" [
      [
        ''cluster_vrack_mtu_ok{instance="n",vlan="mesh",peer="node2"}''
        "1x30"
      ]
    ] "15m" none)
    # Recovered: broken for 20 minutes, then carrying jumbo again. It resolves.
    (case "VrackJumboBroken" [
      [
        ''cluster_vrack_mtu_ok{instance="n",vlan="control",peer="node2"}''
        "0x20 1x20"
      ]
    ] "30m" none)
    # One bad probe run (5 minutes) is not a page.
    (case "VrackJumboBroken" [
      [
        ''cluster_vrack_mtu_ok{instance="n",vlan="storage",peer="node3"}''
        "1x10 0x5 1x20"
      ]
    ] "15m" none)
    # A peer that answers nothing has no sample: NodeDown's alert, not this one.
    (case "VrackJumboBroken" [
      [
        ''cluster_vrack_peer_reachable{instance="n",vlan="control",peer="node2"}''
        "0x30"
      ]
    ] "15m" none)

    # ── cases the first version of this file left out ───────────────────────
    (case "AppUnitFailed" [
      [
        ''node_systemd_unit_state{name="container@demo-odoo.service",state="failed",instance="n"}''
        "1x2 0x30"
      ]
    ] "10m" none)
    (case "BackupCheckStale"
      [ (s ''cluster_backup_check_last_success_timestamp_seconds{app="demo-odoo"}'' "0x12000") ]
      "8d1h"
      [
        {
          app = "demo-odoo";
          severity = "warning";
        }
      ]
    )
    (case "BackupCheckStale" [
      (s ''cluster_backup_check_last_success_timestamp_seconds{app="demo-odoo"}'' "0+60x12000")
    ] "8d1h" none)
    (case "BackupNeverVerified" [ (s "some_other_metric" "1x12000") ] "8d1h" [
      {
        app = "demo-odoo";
        severity = "warning";
      }
    ])
    (case "BackupNeverVerified" [
      (s ''cluster_backup_verify_last_success_timestamp_seconds{app="demo-odoo"}'' "0+60x12000")
    ] "8d1h" none)
    (case "BackupTargetDown" [ (s ''probe_success{job="backup-target",instance="https://b/"}'' "0x40") ]
      "35m"
      [
        {
          job = "backup-target";
          instance = "https://b/";
          severity = "warning";
        }
      ]
    )
    (case "BackupTargetDown" [
      (s ''probe_success{job="backup-target",instance="https://b/"}'' "0x20 1x20")
    ] "35m" none)
    (case "FilesystemFilling"
      [
        (s ''node_filesystem_avail_bytes{fstype="zfs",mountpoint="/",instance="n"}'' "10x40")
        (s ''node_filesystem_size_bytes{fstype="zfs",mountpoint="/",instance="n"}'' "100x40")
      ]
      "35m"
      [
        {
          fstype = "zfs";
          mountpoint = "/";
          instance = "n";
          severity = "warning";
        }
      ]
    )
    (case "FilesystemFilling" [
      (s ''node_filesystem_avail_bytes{fstype="zfs",mountpoint="/",instance="n"}'' "50x40")
      (s ''node_filesystem_size_bytes{fstype="zfs",mountpoint="/",instance="n"}'' "100x40")
    ] "35m" none)
    (case "DiskUnhealthy" [ (s ''smartctl_device_smart_status{device="nvme0",instance="n"}'' "0x20") ]
      "10m"
      [
        {
          device = "nvme0";
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "DiskUnhealthy" [
      (s ''smartctl_device_smart_status{device="nvme0",instance="n"}'' "1x20")
    ] "10m" none)
    (case "JuiceFSProbeStale" [ (s ''cluster_jfs_probe_timestamp_seconds{instance="n"}'' "0x60") ] "45m"
      [
        {
          instance = "n";
          severity = "warning";
        }
      ]
    )
    (case "JuiceFSProbeStale" [
      (s ''cluster_jfs_probe_timestamp_seconds{instance="n"}'' "0+60x60")
    ] "45m" none)

    # ── nomad TLS (WS13) ────────────────────────────────────────────────────
    # Nomad's gauges count down from the certificate's NotAfter.
    (case "NomadTlsCertExpiring"
      [ (s ''nomad_agent_tls_cert_expiration_seconds{instance="n"}'' "86400x10") ]
      "5m"
      [
        {
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "NomadTlsCertExpiring" [
      (s ''nomad_agent_tls_cert_expiration_seconds{instance="n"}'' "2678400x10")
    ] "5m" none)
    (case "NomadTlsCaExpiring"
      [ (s ''nomad_agent_tls_ca_expiration_seconds{instance="n"}'' "7689600x10") ]
      "5m"
      [
        {
          instance = "n";
          severity = "critical";
        }
      ]
    )
    (case "NomadTlsCaExpiring" [
      (s ''nomad_agent_tls_ca_expiration_seconds{instance="n"}'' "7862400x10")
    ] "5m" none)

    # ── boot (WS13) ─────────────────────────────────────────────────────────
    # node_boot_time_seconds is when the node booted, as epoch seconds; promtool's
    # clock starts at 0, so "600" is a boot ten minutes in.
    (case "NodeRebooted" [ (s ''node_boot_time_seconds{instance="n"}'' "600x60") ] "20m" [
      (crit "warning")
    ])
    (case "NodeRebooted" [ (s ''node_boot_time_seconds{instance="n"}'' "600x60") ] "50m" none)
    (case "BootUnlockedByPassphrase" [
      (s ''cluster_boot_unlock_passphrase{instance="n"}'' "1x30")
      (s ''cluster_boot_report_timestamp_seconds{instance="n"}'' "600x30")
    ] "20m" [ (crit "critical") ])
    (case "BootUnlockedByPassphrase" [
      (s ''cluster_boot_unlock_passphrase{instance="n"}'' "0x30")
      (s ''cluster_boot_report_timestamp_seconds{instance="n"}'' "600x30")
    ] "20m" none)
    # A day on, the alert lets go of a boot that is already known.
    (case "BootUnlockedByPassphrase" [
      (s ''cluster_boot_unlock_passphrase{instance="n"}'' "1x1600")
      (s ''cluster_boot_report_timestamp_seconds{instance="n"}'' "600x1600")
    ] "25h" none)
    # Booted at 0 and never reported: fires once 15 minutes and the `for` have passed.
    (case "BootReportMissing" [ (s ''node_boot_time_seconds{instance="n",job="nixos-hosts"}'' "0x40") ]
      "25m"
      [
        {
          instance = "n";
          job = "nixos-hosts";
          severity = "critical";
        }
      ]
    )
    (case "BootReportMissing" [
      (s ''node_boot_time_seconds{instance="n",job="nixos-hosts"}'' "0x40")
    ] "12m" none)
    # Booted at 1h, and the only report is the previous boot's.
    (case "BootReportMissing"
      [
        (s ''node_boot_time_seconds{instance="n",job="nixos-hosts"}'' "3600x80")
        (s ''cluster_boot_report_timestamp_seconds{instance="n",job="nixos-hosts"}'' "0x80")
      ]
      "70m"
      [
        {
          instance = "n";
          job = "nixos-hosts";
          severity = "critical";
        }
      ]
    )
    # This boot's report arrives at 25 minutes: resolved.
    (case "BootReportMissing" [
      (s ''node_boot_time_seconds{instance="n",job="nixos-hosts"}'' "0x60")
      (s ''cluster_boot_report_timestamp_seconds{instance="n",job="nixos-hosts"}'' "_x25 1500x35")
    ] "35m" none)
    (case "SecureBootOff" [
      (s ''cluster_boot_secure_boot_enabled{instance="n"}'' "0x10")
      (s ''cluster_boot_setup_mode{instance="n"}'' "0x10")
    ] "5m" [ (crit "critical") ])
    (case "SecureBootOff" [
      (s ''cluster_boot_secure_boot_enabled{instance="n"}'' "1x10")
      (s ''cluster_boot_setup_mode{instance="n"}'' "1x10")
    ] "5m" [ (crit "critical") ])
    # -1: the variable could not be read. That is not a pass.
    (case "SecureBootOff" [
      (s ''cluster_boot_secure_boot_enabled{instance="n"}'' "-1x10")
      (s ''cluster_boot_setup_mode{instance="n"}'' "-1x10")
    ] "5m" [ (crit "critical") ])
    (case "SecureBootOff" [
      (s ''cluster_boot_secure_boot_enabled{instance="n"}'' "1x10")
      (s ''cluster_boot_setup_mode{instance="n"}'' "0x10")
    ] "5m" none)
    (case "Pcr7Changed" [
      (s ''cluster_boot_pcr7_info{instance="n",value="aa"}'' "1x60")
      (s ''cluster_boot_pcr7_info{instance="n",value="bb"}'' "_x60 1x1600")
    ] "2h" [ (crit "critical") ])
    (case "Pcr7Changed" [ (s ''cluster_boot_pcr7_info{instance="n",value="aa"}'' "1x200") ] "2h" none)
    # A day after the change, only the new value is in the window.
    (case "Pcr7Changed" [
      (s ''cluster_boot_pcr7_info{instance="n",value="aa"}'' "1x60")
      (s ''cluster_boot_pcr7_info{instance="n",value="bb"}'' "_x60 1x1600")
    ] "26h" none)
    (case "UnlockTpmShareFailing" [ (s ''cluster_unlock_tpm_share_ok{instance="n"}'' "0x30") ] "20m" [
      (crit "critical")
    ])
    (case "UnlockTpmShareFailing" [
      (s ''cluster_unlock_tpm_share_ok{instance="n"}'' "0x10 1x20")
    ] "25m" none)
    (case "RebootPendingTooLong" [ (s ''cluster_reboot_pending{instance="n"}'' "1x21000") ] "14d1h" [
      (crit "warning")
    ])
    (case "RebootPendingTooLong" [ (s ''cluster_reboot_pending{instance="n"}'' "1x21000") ] "13d" none)
    (case "RebootPendingTooLong" [
      (s ''cluster_reboot_pending{instance="n"}'' "1x20200 0x1000")
    ] "14d1h" none)
    (case "PoolVdevNotEncrypted" [ (s ''cluster_zpool_plain_vdevs{instance="n"}'' "1x10") ] "5m" [
      (crit "critical")
    ])
    (case "PoolVdevNotEncrypted" [
      (s ''cluster_zpool_plain_vdevs{instance="n"}'' "1x3 0x10")
    ] "10m" none)
    (case "VolumeIdentityMissing" [ (s ''cluster_volume_identity_ok{instance="n"}'' "0x10") ] "5m" [
      (crit "critical")
    ])
    (case "VolumeIdentityMissing" [
      (s ''cluster_volume_identity_ok{instance="n"}'' "0x3 1x10")
    ] "10m" none)
    (case "ClevisBindingMissing"
      [
        (s ''cluster_boot_clevis_tokens{instance="n",device="/dev/disk/by-partlabel/disk-nvme1-luks"}'' "0x30")
      ]
      "20m"
      [
        {
          instance = "n";
          device = "/dev/disk/by-partlabel/disk-nvme1-luks";
          severity = "critical";
        }
      ]
    )
    # A rebind: unbound for five minutes, then bound again.
    (case "ClevisBindingMissing" [
      (s ''cluster_boot_clevis_tokens{instance="n",device="/dev/disk/by-partlabel/disk-nvme1-luks"}'' "1x5 0x5 1x20")
    ] "20m" none)
    (case "ClevisBoundToUnpinnedTang"
      [
        (s ''cluster_boot_clevis_unpinned_tokens{instance="n",device="/dev/disk/by-partlabel/disk-nvme1-luks"}'' "1x30")
      ]
      "20m"
      [
        {
          instance = "n";
          device = "/dev/disk/by-partlabel/disk-nvme1-luks";
          severity = "critical";
        }
      ]
    )
    # A --replace rebind: the old slot lingers for minutes, then goes.
    (case "ClevisBoundToUnpinnedTang" [
      (s ''cluster_boot_clevis_unpinned_tokens{instance="n",device="/dev/disk/by-partlabel/disk-nvme1-luks"}'' "1x5 0x25")
    ] "20m" none)
    (case "CoreDumpsNotOff" [ (s ''cluster_core_pattern_ok{instance="n"}'' "0x30") ] "20m" [
      (crit "warning")
    ])
    (case "CoreDumpsNotOff" [ (s ''cluster_core_pattern_ok{instance="n"}'' "1x30") ] "20m" none)
    # The fixture's nodes all opt out: this fires there, by design.
    (case "BootSecurityOptedOut" [ (s ''cluster_boot_insecure_optout{instance="n"}'' "1x10") ] "5m" [
      (crit "critical")
    ])
    (case "BootSecurityOptedOut" [
      (s ''cluster_boot_insecure_optout{instance="n"}'' "0x10")
    ] "5m" none)
    # Scoped to nodes that have not opted out, and still firing when the boot report
    # never ran at all (no cluster_boot_insecure_optout).
    (case "TangVlanPresent" [ (s ''cluster_tang_vlan_present{instance="n"}'' "1x10") ] "5m" [
      (crit "critical")
    ])
    (case "TangVlanPresent" [
      (s ''cluster_tang_vlan_present{instance="n"}'' "1x10")
      (s ''cluster_boot_insecure_optout{instance="n"}'' "0x10")
    ] "5m" [ (crit "critical") ])
    (case "TangVlanPresent" [
      (s ''cluster_tang_vlan_present{instance="n"}'' "1x10")
      (s ''cluster_boot_insecure_optout{instance="n"}'' "1x10")
    ] "5m" none)
    (case "TangVlanPresent" [ (s ''cluster_tang_vlan_present{instance="n"}'' "0x10") ] "5m" none)
    (case "EspNotMounted" [ (s ''cluster_esp_mounted{instance="n",esp="/boot-fallback"}'' "0x30") ]
      "20m"
      [
        {
          instance = "n";
          esp = "/boot-fallback";
          severity = "warning";
        }
      ]
    )
    (case "EspNotMounted" [
      (s ''cluster_esp_mounted{instance="n",esp="/boot-fallback"}'' "0x30")
      (s ''cluster_boot_insecure_optout{instance="n"}'' "1x30")
    ] "20m" none)
    (case "EspNotMounted" [
      (s ''cluster_esp_mounted{instance="n",esp="/boot-fallback"}'' "0x5 1x30")
    ] "20m" none)
    (case "WatchdogDeviceMissing" [ (s ''cluster_watchdog_device{instance="n"}'' "0x90") ] "70m" [
      (crit "warning")
    ])
    (case "WatchdogDeviceMissing" [ (s ''cluster_watchdog_device{instance="n"}'' "0x90") ] "50m" none)
    (case "WatchdogDeviceMissing" [
      (s ''cluster_watchdog_device{instance="n"}'' "0x90")
      (s ''cluster_boot_insecure_optout{instance="n"}'' "1x90")
    ] "70m" none)
    (case "WatchdogDeviceMissing" [ (s ''cluster_watchdog_device{instance="n"}'' "1x90") ] "70m" none)
    (case "IommuDisabled" [ (s ''cluster_iommu_groups{instance="n"}'' "0x90") ] "70m" [
      (crit "warning")
    ])
    (case "IommuDisabled" [
      (s ''cluster_iommu_groups{instance="n"}'' "0x90")
      (s ''cluster_boot_insecure_optout{instance="n"}'' "1x90")
    ] "70m" none)
    (case "IommuDisabled" [ (s ''cluster_iommu_groups{instance="n"}'' "12x90") ] "70m" none)

    # ── deploy (WS13) ───────────────────────────────────────────────────────
    (case "DeployActivationFailing" [ (s ''cluster_deploy_activation_failed{instance="n"}'' "1x30") ]
      "20m"
      [
        (crit "critical")
      ]
    )
    (case "DeployActivationFailing" [
      (s ''cluster_deploy_activation_failed{instance="n"}'' "1x30")
    ] "10m" none)
    (case "DeployActivationFailing" [
      (s ''cluster_deploy_activation_failed{instance="n"}'' "1x10 0x20")
    ] "25m" none)
    (case "DeployBlockedByBootContract" [ (s ''cluster_deploy_contract_blocked{instance="n"}'' "1x10") ]
      "5m"
      [
        (crit "critical")
      ]
    )
    (case "DeployBlockedByBootContract" [
      (s ''cluster_deploy_contract_blocked{instance="n"}'' "1x3 0x10")
    ] "10m" none)
    (case "DeployRollbackHeld" [ (s ''cluster_deploy_rollback_held{instance="n"}'' "1x10") ] "5m" [
      (crit "warning")
    ])
    (case "DeployRollbackHeld" [
      (s ''cluster_deploy_rollback_held{instance="n"}'' "1x3 0x10")
    ] "10m" none)

    (case "DeployWaitingForCanary" [ (s ''cluster_deploy_canary_wait{instance="n"}'' "1x1600") ] "25h" [
      (crit "warning")
    ])
    (case "DeployWaitingForCanary" [
      (s ''cluster_deploy_canary_wait{instance="n"}'' "1x1600")
    ] "20h" none)
    (case "DeployWaitingForCanary" [
      (s ''cluster_deploy_canary_wait{instance="n"}'' "1x1000 0x600")
    ] "26h" none)
    (case "CanaryBootUnproven" [ (s ''cluster_deploy_canary_unproven{instance="n"}'' "1x30") ] "20m" [
      (crit "warning")
    ])
    (case "CanaryBootUnproven" [
      (s ''cluster_deploy_canary_unproven{instance="n"}'' "1x30")
    ] "10m" none)
    (case "CanaryBootUnproven" [
      (s ''cluster_deploy_canary_unproven{instance="n"}'' "1x10 0x20")
    ] "25m" none)

    # ── leak (WS13 rules, WS14's scan) ──────────────────────────────────────
    (case "CanaryFound" [ (s ''cluster_canary_hits{instance="n",path_class="tmp"}'' "3x10") ] "5m" [
      {
        instance = "n";
        path_class = "tmp";
        severity = "critical";
      }
    ])
    (case "CanaryFound" [ (s ''cluster_canary_hits{instance="n",path_class="tmp"}'' "0x10") ] "5m" none)
    (case "CanaryScanStale"
      [ (s ''cluster_canary_last_run_timestamp_seconds{instance="n"}'' "0x12000") ]
      "8d2h"
      [
        (crit "warning")
      ]
    )
    (case "CanaryScanStale" [
      (s ''cluster_canary_last_run_timestamp_seconds{instance="n"}'' "0+60x12000")
    ] "8d2h" none)
    (case "JuiceFSVolumeNotEncrypted" [ (s ''cluster_jfs_encrypted{instance="n"}'' "0x10") ] "5m" [
      (crit "critical")
    ])
    (case "JuiceFSVolumeNotEncrypted" [
      (s ''cluster_jfs_encrypted{instance="n"}'' "0x3 1x10")
    ] "10m" none)

    # ── audit delivery (WS13) ───────────────────────────────────────────────
    (case "AuditDeliveryStale"
      [ (s ''cluster_audit_spool_oldest_timestamp_seconds{instance="n"}'' "0x200") ]
      "90m"
      [
        (crit "warning")
      ]
    )
    (case "AuditDeliveryStale" [
      (s ''cluster_audit_spool_oldest_timestamp_seconds{instance="n"}'' "0+60x200")
    ] "90m" none)
    # Delivered: the spool is empty and the metric is gone.
    (case "AuditDeliveryStale" [
      (s ''cluster_audit_spool_oldest_timestamp_seconds{instance="n"}'' "0x70")
    ] "90m" none)
    (case "AuditEventRejected" [ (s ''cluster_audit_rejected_files{instance="n"}'' "2x10") ] "5m" [
      (crit "warning")
    ])
    (case "AuditEventRejected" [ (s ''cluster_audit_rejected_files{instance="n"}'' "0x10") ] "5m" none)
    # A producer that stopped saying it works; one that keeps saying so.
    (case "AuditProducerStale"
      [
        (s ''cluster_audit_producer_heartbeat_timestamp_seconds{instance="n",producer="journal"}'' "0x60")
      ]
      "30m"
      [
        {
          instance = "n";
          producer = "journal";
          severity = "warning";
        }
      ]
    )
    (case "AuditProducerStale" [
      (s ''cluster_audit_producer_heartbeat_timestamp_seconds{instance="n",producer="journal"}'' "0+60x60")
    ] "30m" none)
    (case "AuditNomadStreamRefused" [ (s ''cluster_audit_nomad_stream_status{instance="n"}'' "403x30") ]
      "20m"
      [
        (crit "warning")
      ]
    )
    (case "AuditNomadStreamRefused" [
      (s ''cluster_audit_nomad_stream_status{instance="n"}'' "200x30")
    ] "20m" none)
    # One restart a minute for an hour: a loop. Steady counters, and a unit outside the
    # list (nomad-login@ retries by design), stay quiet.
    (case "UnitRestartLoop"
      [ (s ''node_systemd_service_restart_total{instance="n",name="juicefs-mount.service"}'' "0+1x60") ]
      "40m"
      [
        {
          instance = "n";
          name = "juicefs-mount.service";
          severity = "warning";
        }
      ]
    )
    (case "UnitRestartLoop" [
      (s ''node_systemd_service_restart_total{instance="n",name="juicefs-mount.service"}'' "5x60")
      (s ''node_systemd_service_restart_total{instance="n",name="nomad.service"}'' "0+1x60")
    ] "40m" none)

    # ── the heartbeat never stops ───────────────────────────────────────────
    (case "Watchdog" [
      [
        "x"
        "1x5"
      ]
    ] "1m" [ { severity = "none"; } ])
  ];

  testFile = pkgs.writeText "alert-rules-test.yml" (
    builtins.toJSON {
      rule_files = [ "${rulesFile}" ];
      evaluation_interval = "1m";
      inherit tests;
    }
  );

  # Every alert has a case that fires and a case that stays quiet. Reported at build
  # time, not thrown, so one missing case doesn't stop the rest of the flake evaluating.
  alertNames = lib.unique (lib.concatMap (g: map (r: r.alert) g.rules) rules.groups);
  casesFor =
    name: firing:
    lib.filter (
      t: lib.any (a: a.alertname == name && (a.exp_alerts != [ ]) == firing) t.alert_rule_test
    ) tests;
  # Watchdog is vector(1): it fires always, by design, and has nothing to be quiet on.
  uncovered = lib.filter (
    n: casesFor n true == [ ] || (n != "Watchdog" && casesFor n false == [ ])
  ) alertNames;

  # The annotations as deployed, so a broken template fails here rather than in the
  # Prometheus of a node.
  annotatedRulesFile = pkgs.writeText "rules-annotated.yml" (
    builtins.toJSON (
      import ../lib/alert-rules.nix {
        inherit lib;
        backupApps = [ "demo-odoo" ];
        freeipaApps = [ "idm" ];
      }
    )
  );
in
pkgs.runCommand "alert-rules-tests" { nativeBuildInputs = [ pkgs.prometheus.cli ]; } ''
  ${lib.optionalString (uncovered != [ ]) ''
    echo "alerts without both a firing and a quiet case: ${lib.concatStringsSep " " uncovered}" >&2
    exit 1
  ''}
  echo "${toString (builtins.length alertNames)} alerts, each with a firing and a quiet case"
  promtool check rules ${rulesFile}
  promtool check rules ${annotatedRulesFile}
  promtool test rules ${testFile}
  touch $out
''
