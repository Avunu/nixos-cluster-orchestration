# lib/alert-rules.nix — the cluster's Prometheus alert rules, as data.
#
#   import ./lib/alert-rules.nix { inherit lib; backupApps = [ "demo-odoo" … ]; }
#
# A function of the backed-up apps because one class of rule has to name each
# app: absent() cannot see an app that has never written a metric, and "never
# backed up" is exactly the failure that went unnoticed before. Everything else
# is written once, over labels.
#
# Every rule has a firing AND a resolving case in tests/alert-rules-test.nix --
# an earlier setup had rules paused for months
# because they fired on missing data and nobody could tell.
#
# Severities: critical = act now (paged-style: repeats hourly); warning = act
# this week (repeats every 12h). Watchdog is the heartbeat, never a page.
{
  lib,
  backupApps ? [ ],
  verifiedApps ? backupApps,
  # FreeIPA servers (modules/kinds/freeipa.nix), whose health the node reports.
  freeipaApps ? [ ],
  # Tests set this false: promtool compares annotations verbatim, and the
  # expressions and labels are what the tests are about.
  annotate ? true,
}:
let
  hours = h: toString (h * 3600);
  days = d: toString (d * 86400);

  # A node that opted out of boot security (topology.nodes.<n>.insecurePlaintextBoot)
  # has no ESP pair or hardware checks to speak of, and BootSecurityOptedOut
  # already says so once. Its own boot report writes cluster_boot_insecure_optout 1.
  # `unless`, not `and ... == 0`: a node whose boot report never ran must still alert.
  notOptedOut = expr: "(${expr}) unless on (instance) cluster_boot_insecure_optout == 1";

  rule =
    {
      alert,
      expr,
      for ? "0m",
      severity,
      summary,
      description ? null,
      labels ? { },
    }:
    {
      inherit alert expr for;
      labels = labels // {
        inherit severity;
      };
    }
    // lib.optionalAttrs annotate {
      annotations = {
        inherit summary;
      }
      // lib.optionalAttrs (description != null) { inherit description; };
    };
in
{
  groups = [
    {
      name = "backups";
      rules = [
        (rule {
          alert = "BackupStale";
          expr = "time() - cluster_backup_last_success_timestamp_seconds > ${hours 30}";
          for = "10m";
          severity = "critical";
          summary = "{{ $labels.app }}: no successful backup for {{ $value | humanizeDuration }}";
          description = "Check `journalctl -u cluster-backup-{{ $labels.app }}` on the app's homeNode; run `cluster-backup {{ $labels.app }}` once fixed.";
        })
        (rule {
          alert = "BackupPartial";
          expr = "cluster_backup_last_status == 2";
          for = "5m";
          severity = "warning";
          summary = "{{ $labels.app }}: last backup could not read some files";
        })
        (rule {
          alert = "BackupVerifyStale";
          expr = "time() - cluster_backup_verify_last_success_timestamp_seconds > ${days 8}";
          for = "10m";
          severity = "warning";
          summary = "{{ $labels.app }}: backups not proven restorable for {{ $value | humanizeDuration }}";
          description = "The weekly restore rehearsal (cluster-backup-verify-{{ $labels.app }}) has not passed.";
        })
        (rule {
          alert = "BackupCheckStale";
          expr = "time() - cluster_backup_check_last_success_timestamp_seconds > ${days 8}";
          for = "10m";
          severity = "warning";
          summary = "{{ $labels.app }}: repository not pruned/checked for {{ $value | humanizeDuration }}";
        })
      ]
      # absent() needs a literal selector, hence one rule per app.
      ++ map (
        app:
        rule {
          alert = "BackupNeverRan";
          # The app label makes each per-app rule distinct (promtool lints
          # same-name, same-label rules as duplicates) and names it in the email.
          labels.app = app;
          expr = ''absent(cluster_backup_last_success_timestamp_seconds{app="${app}"})'';
          for = "30h";
          severity = "critical";
          summary = "${app}: has never been backed up successfully";
        }
      ) backupApps
      ++ map (
        app:
        rule {
          alert = "BackupNeverVerified";
          # The app label makes each per-app rule distinct (promtool lints
          # same-name, same-label rules as duplicates) and names it in the email.
          labels.app = app;
          expr = ''absent(cluster_backup_verify_last_success_timestamp_seconds{app="${app}"})'';
          for = "8d";
          severity = "warning";
          summary = "${app}: backups have never passed a restore rehearsal";
        }
      ) verifiedApps;
    }
    {
      name = "units";
      rules = [
        # One rule covers every oneshot and daemon on every node: backups and
        # rehearsals, cluster-upgrade (pull-deploy), JuiceFS, nomad-fence...
        (rule {
          alert = "UnitFailed";
          expr = ''node_systemd_unit_state{state="failed", name!~"container@.*"} == 1'';
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.name }} failed on {{ $labels.instance }}";
          description = "`systemctl status {{ $labels.name }}` / `journalctl -u {{ $labels.name }}` on the node. For a nomad-* unit refused with 403: `systemctl start 'nomad-login@*'` (nomad-token-check does it every 5 min).";
        })
        # A daemon that restarts for ever never reaches "failed", so UnitFailed can't see
        # it: the audit producers (Restart=always, no start limit), a JuiceFS mount
        # retrying an unreachable metadata engine, juicefs-format retrying an outage.
        (rule {
          alert = "UnitRestartLoop";
          expr = ''increase(node_systemd_service_restart_total{name=~"cluster-audit-.+\\.service|juicefs-(mount|format)\\.service"}[15m]) >= 3'';
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.name }} keeps restarting on {{ $labels.instance }}";
          description = "`journalctl -u {{ $labels.name }}` on the node: it is not failing for good, so UnitFailed stays quiet.";
        })
        # The two that mean an app is not running what was deployed.
        (rule {
          alert = "AppUnitFailed";
          expr = ''node_systemd_unit_state{state="failed", name=~"container@.*"} == 1'';
          for = "5m";
          severity = "critical";
          summary = "{{ $labels.name }} failed on {{ $labels.instance }}";
        })
        # A metric rather than a failing unit: a unit failing during a switch
        # fails the host's deploy (lib/mk-app-container.nix, reloadScript).
        (rule {
          alert = "AppDeployDegraded";
          expr = "cluster_app_deploy_degraded == 1";
          for = "5m";
          severity = "critical";
          summary = "{{ $labels.app }}: the last deploy did not apply inside the container";
          description = "`nixos-container run {{ $labels.app }} -- systemctl --failed`; the reload's own report is in `journalctl -u container@{{ $labels.app }}`. A new secret or bind mount needs `nomad job restart app-{{ $labels.app }}`.";
        })
      ];
    }
    {
      name = "nomad";
      rules = [
        # The fence (modules/nomad-bootstrap.nix) writes this on every run that got its
        # answers, and only then. It stops when the fence cannot read (a refused token:
        # its unit fails too) and when Nomad is not answering (fail-safe: it exits 0 and
        # fences nothing), and the second is the one nothing else sees. A node whose
        # fence never succeeded reads 0. `for`: at boot the fence first runs at 2 min,
        # and the file still holds the time from before the reboot.
        (rule {
          alert = "NomadFenceStale";
          expr = "time() - cluster_fence_last_success_timestamp_seconds > 600";
          for = "5m";
          severity = "critical";
          summary = "the Nomad fence on {{ $labels.instance }} has not completed a run for {{ $value | humanizeDuration }}";
          description = "An orphaned container there would keep running. `journalctl -u nomad-fence -u nomad-login@fence` on the node. A refused token (403 even after the fence's own fresh login): Nomad's ACL state may have been rebuilt, so `systemctl start 'nomad-login@*'` on every node once nomad-acl-init has run on the nomad-leader node.";
        })
        # Nomad's own gauges (command/agent/tls_metrics.go in 1.11), scraped from
        # /v1/metrics. An expired agent certificate is a full outage, not a warning: every
        # node goes `down` within about 90 s (tests/control-plane-failure.nix). The fix is
        # security.nomadTlsRotation (agent certificates) or a new nomad-ca (all of them).
        (rule {
          alert = "NomadTlsCertExpiring";
          expr = "nomad_agent_tls_cert_expiration_seconds < ${days 30}";
          severity = "critical";
          summary = "the Nomad agent certificate on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}";
          description = "Bump topology.security.nomadTlsRotation and deploy: every agent certificate is reissued. When it expires, every node drops out of the cluster.";
        })
        (rule {
          alert = "NomadTlsCaExpiring";
          expr = "nomad_agent_tls_ca_expiration_seconds < ${days 90}";
          severity = "critical";
          summary = "the Nomad CA expires in {{ $value | humanizeDuration }}";
          description = "Regenerating nomad-ca reissues every machine's certificate at once (a hard cut): plan it.";
        })
      ];
    }
    {
      # What a node says about its own boot (modules/boot-report.nix, boot_report.prom)
      # and the boot security audit every 5 minutes (modules/boot-security-core.nix,
      # boot_audit.prom). Nothing alerts on cluster_boot_tpm_refusals alone: a leg the TPM
      # refused is a leg the TPM did not open, which BootUnlockedByPassphrase and
      # UnlockTpmFailing already say.
      name = "boot";
      rules = [
        (rule {
          alert = "NodeRebooted";
          expr = "time() - node_boot_time_seconds < 1800";
          severity = "warning";
          summary = "{{ $labels.instance }} rebooted {{ $value | humanizeDuration }} ago";
          description = "Expected after `avc boot reboot`; otherwise find out why. The boot report says how it unlocked.";
        })
        # The prompt is reached on every boot, so the unlocked-device count is the signal
        # (design D18). One day: the alert says what the last boot was, then lets go.
        (rule {
          alert = "BootUnlockedByPassphrase";
          expr = "cluster_boot_unlock_passphrase == 1 and time() - cluster_boot_report_timestamp_seconds < ${days 1}";
          severity = "critical";
          summary = "{{ $labels.instance }}: the last boot was unlocked by a typed passphrase, not by the TPM";
          description = "If none of you typed it, someone else did. If one of you did, it was needed because the TPM refused (PCR 7 changed: firmware or Secure Boot keys) or a leg has no TPM binding: `cluster-boot-seal check` on the node, and the boot's journal (`journalctl -b -u 'systemd-cryptsetup@*'`).";
        })
        # A report from before this boot, or none 15 minutes in. Opted-out nodes write the
        # timestamp too, so this covers them.
        (rule {
          alert = "BootReportMissing";
          expr = "node_boot_time_seconds - cluster_boot_report_timestamp_seconds > 900 or (time() - node_boot_time_seconds > 900 unless cluster_boot_report_timestamp_seconds)";
          for = "5m";
          severity = "critical";
          summary = "{{ $labels.instance }} has not reported on its boot";
          description = "`systemctl status cluster-boot-report` on the node. Until it reports, nothing here says how the node unlocked.";
        })
        # Fails closed: a value of -1 (the EFI variable could not be read) fires too.
        (rule {
          alert = "SecureBootOff";
          expr = "cluster_boot_secure_boot_enabled != 1 or cluster_boot_setup_mode != 0";
          severity = "critical";
          summary = "{{ $labels.instance }} booted without Secure Boot enforcing";
          description = "Firmware reset or tampered with. The TPM cannot have unlocked this boot. Check the BIOS, then the README's 'Who can do what, once sealed' (Recovery), its firmware rows.";
        })
        # Two values of PCR 7 within a day: the firmware's Secure Boot state changed.
        (rule {
          alert = "Pcr7Changed";
          expr = "count by (instance) (count_over_time(cluster_boot_pcr7_info[1d])) > 1";
          severity = "critical";
          summary = "PCR 7 on {{ $labels.instance }} changed within the last day";
          description = "Keys enrolled, cleared or added in firmware. The TPM will not unlock the disks until the change is explained and the node rebound (`avc boot bind <node> --replace`).";
        })
        # From the boot report: the TPM opened every expected leg. The unlock that really ran
        # is the producer, not a trial of the TPM slot in stage 2 (design D24).
        (rule {
          alert = "UnlockTpmFailing";
          expr = "cluster_unlock_tpm_ok == 0";
          for = "15m";
          severity = "critical";
          summary = "{{ $labels.instance }}: the TPM did not unlock every leg on the last boot";
          description = "The next reboot needs a human too. `cluster-boot-seal check` on the node; rebind with `avc boot bind <node> [--replace]` once the cause is known.";
        })
        (rule {
          alert = "RebootPendingTooLong";
          expr = "cluster_reboot_pending == 1";
          for = "14d";
          severity = "warning";
          summary = "{{ $labels.instance }} has run a closure it has not booted for two weeks";
          description = "A boot path change is unproven until the node reboots into it. `avc boot reboot <node>`, one node at a time.";
        })
        (rule {
          alert = "PoolVdevNotEncrypted";
          expr = "cluster_zpool_plain_vdevs > 0";
          severity = "critical";
          summary = "{{ $labels.instance }}: {{ $value }} vdev(s) of rpool are not on dm-crypt";
          description = "`zpool status -P rpool` and `dmsetup table`. Data written now is on a disk in plaintext.";
        })
        (rule {
          alert = "VolumeIdentityMissing";
          expr = "cluster_volume_identity_ok == 0";
          severity = "critical";
          summary = "{{ $labels.instance }}: the volume identity secret is missing or wrong";
          description = "The next boot halts at volume-identity-check, on every generation. `cluster-boot-seal identity`; the repair is the README's 'Identity secret damaged' (Recovery).";
        })
        # A leg with no TPM binding holds the next boot at the prompt. A rebind in progress
        # is minutes, hence the `for`.
        (rule {
          alert = "TpmBindingMissing";
          expr = "cluster_boot_tpm_tokens == 0";
          for = "15m";
          severity = "critical";
          summary = "{{ $labels.device }} on {{ $labels.instance }} has no TPM binding";
          description = "The next reboot waits for a passphrase. `avc boot bind <node> --device {{ $labels.device }}`.";
        })
        (rule {
          alert = "CoreDumpsNotOff";
          expr = "cluster_core_pattern_ok == 0";
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.instance }}: kernel.core_pattern is not the pipe to false";
          description = "A crashing process can leave its memory on disk. `sysctl kernel.core_pattern`; modules/coredumps-off.nix sets it.";
        })
        (rule {
          alert = "BootSecurityOptedOut";
          expr = "cluster_boot_insecure_optout == 1";
          severity = "critical";
          summary = "{{ $labels.instance }} runs without boot security (insecurePlaintextBoot)";
          description = "Its disks are plaintext and it has no Secure Boot, and it holds the fleet's shared keys (JuiceFS volume key, S3, restic, backup target) beside the age key that decrypts them: one pulled drive reads every client's files and backups, whatever runs on it. Install it encrypted.";
        })
        (rule {
          alert = "EspNotMounted";
          expr = notOptedOut "cluster_esp_mounted == 0";
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.esp }} is not mounted on {{ $labels.instance }}";
          description = "Generations installed now miss that ESP, so the disk behind it would boot an old one. A dead disk: replace it. Otherwise `mount {{ $labels.esp }}` and reinstall the bootloader.";
        })
        (rule {
          alert = "WatchdogDeviceMissing";
          expr = notOptedOut "cluster_watchdog_device == 0";
          for = "1h";
          severity = "warning";
          summary = "{{ $labels.instance }} has no hardware watchdog";
          description = "A hung kernel will not reset itself. Check the board's watchdog driver (systemd's RuntimeWatchdogSec needs /dev/watchdog0).";
        })
        (rule {
          alert = "IommuDisabled";
          expr = notOptedOut "cluster_iommu_groups == 0";
          for = "1h";
          severity = "warning";
          summary = "{{ $labels.instance }} has no IOMMU groups";
          description = "DMA from a device is not confined. Enable VT-d / AMD-Vi in firmware.";
        })
      ];
    }
    {
      # The pull loop (lib/cluster-upgrade.nix, deploy.prom). Each tick rewrites the file,
      # so a metric missing from the last write is absent, not 0, and these resolve.
      name = "deploy";
      rules = [
        (rule {
          alert = "DeployActivationFailing";
          expr = "cluster_deploy_activation_failed == 1";
          for = "15m";
          severity = "critical";
          summary = "{{ $labels.instance }} cannot activate the deployed closure";
          description = "`journalctl -u cluster-upgrade` on the node. Three attempts per closure, then it waits for a new commit; `avc deploy retry <node>` once fixed.";
        })
        (rule {
          alert = "DeployBlockedByBootContract";
          expr = "cluster_deploy_contract_blocked == 1";
          severity = "critical";
          summary = "{{ $labels.instance }} refuses a closure that changes what an unlock depends on";
          description = "`journalctl -u cluster-upgrade` names the fields. If intended, approve the closure on the node in /run/cluster-upgrade.approve.";
        })
        (rule {
          alert = "DeployRollbackHeld";
          expr = "cluster_deploy_rollback_held == 1";
          severity = "warning";
          summary = "{{ $labels.instance }} holds back a closure on its rollback denylist";
          description = "After `avc boot rollback`, or a boot into an older generation. `avc boot unrollback <node> <closure>` once a fixed closure is deployed.";
        })
        # The staged rollout (design D22). Waiting is the design working: every node but
        # the canary holds a new boot stack until the canary has rebooted into it. A day of
        # it means nobody has, and meanwhile these nodes take no deploy at all.
        (rule {
          alert = "DeployWaitingForCanary";
          expr = "cluster_deploy_canary_wait == 1";
          for = "1d";
          severity = "warning";
          summary = "{{ $labels.instance }} has waited a day for the canary to boot a new boot stack";
          description = "A nixpkgs, kernel, Lanzaboote, clan or library bump is held back until the canary node reboots into it and unlocks from the TPM. `avc boot reboot <canary>`, and watch it. If the canary cannot be rebooted, list the closure in /run/cluster-upgrade.skip-canary on each node instead.";
        })
        (rule {
          alert = "CanaryBootUnproven";
          expr = "cluster_deploy_canary_unproven == 1";
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.instance }}, the canary, booted without a clean TPM unlock, so it vouches for nothing";
          description = "Its boot stack is not published and the other nodes keep waiting. `journalctl -u cluster-deploy-canary-publish` names the reason; fix the unlock (UnlockTpmFailing) and reboot the canary again.";
        })
      ];
    }
    {
      # Client data where it must not be (WS14's canary scan) and a JuiceFS volume
      # without its key (modules/storage-juicefs.nix).
      name = "leak";
      rules = [
        (rule {
          alert = "CanaryFound";
          expr = "cluster_canary_hits > 0";
          severity = "critical";
          summary = "the canary turned up in {{ $labels.path_class }} on {{ $labels.instance }}";
          description = "Client data reaches that place in plaintext. Find the writer before anything else is written there.";
        })
        (rule {
          alert = "CanaryScanStale";
          expr = "time() - cluster_canary_last_run_timestamp_seconds > ${days 8}";
          for = "1h";
          severity = "warning";
          summary = "the canary scan on {{ $labels.instance }} has not run for {{ $value | humanizeDuration }}";
          description = "A scan that does not run finds nothing. `systemctl status cluster-canary-scan`.";
        })
        (rule {
          alert = "JuiceFSVolumeNotEncrypted";
          expr = "cluster_jfs_encrypted == 0";
          severity = "critical";
          summary = "{{ $labels.instance }} refused a JuiceFS volume that is not encrypted";
          description = "juicefs-mount found no key in the volume's settings and did not mount it. Nothing is written in plaintext, but nothing is written at all.";
        })
      ];
    }
    {
      # The off-host audit trail's sender (modules/audit-ship-core.nix, audit.prom). A
      # trail that stopped arriving looks exactly like a quiet cluster from the Worker.
      name = "audit";
      rules = [
        (rule {
          alert = "AuditDeliveryStale";
          expr = "time() - cluster_audit_spool_oldest_timestamp_seconds > ${hours 1}";
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.instance }} has held audit events for {{ $value | humanizeDuration }}";
          description = "The Worker's /event is unreachable or refusing this node's token. `journalctl -u cluster-audit-send`; events wait in /var/lib/cluster-audit/spool and are not lost.";
        })
        # The producers (journal, nomad_acl, send) each rewrite a heartbeat while they
        # work. They restart for ever and never reach "failed", and the two rules above see
        # only what reached the spool: a follower that cannot read sends nothing at all.
        (rule {
          alert = "AuditProducerStale";
          expr = "time() - cluster_audit_producer_heartbeat_timestamp_seconds > 900";
          for = "5m";
          severity = "warning";
          summary = "the audit producer {{ $labels.producer }} on {{ $labels.instance }} has not worked for {{ $value | humanizeDuration }}";
          description = "SSH logins, deploys or Nomad ACL changes are not reaching the off-host trail. `journalctl -u 'cluster-audit-*'` on the node.";
        })
        (rule {
          alert = "AuditNomadStreamRefused";
          expr = "cluster_audit_nomad_stream_status != 200";
          for = "15m";
          severity = "warning";
          summary = "Nomad's ACL event stream answers {{ $value }} to the audit follower on {{ $labels.instance }}";
          description = "0 is no answer (TLS or network), 403 a management token that changed. ACL changes are not in the off-host trail until it reads 200.";
        })
        (rule {
          alert = "AuditEventRejected";
          expr = "cluster_audit_rejected_files > 0";
          severity = "warning";
          summary = "the Worker refused {{ $value }} audit event(s) from {{ $labels.instance }}";
          description = "A shape the Worker's allowlist does not take (HTTP 400, 413 or 422): node and Worker disagree. The events are in /var/lib/cluster-audit/rejected; delete them once read.";
        })
      ];
    }
    {
      name = "availability";
      rules = [
        (rule {
          alert = "NodeDown";
          expr = ''up{job="nixos-hosts"} == 0'';
          for = "3m";
          severity = "critical";
          summary = "{{ $labels.instance }} is not reporting metrics";
        })
        (rule {
          alert = "AppDown";
          expr = ''probe_success{job="apps"} == 0'';
          for = "5m";
          severity = "critical";
          summary = "{{ $labels.app }} is unreachable at {{ $labels.instance }}";
          description = "Probed from the metrics node through Cloudflare: tunnel, nginx and app all have to work.";
        })
        (rule {
          alert = "BackupTargetDown";
          expr = ''probe_success{job="backup-target"} == 0'';
          for = "30m";
          severity = "warning";
          summary = "backup target {{ $labels.instance }} is unreachable";
        })
      ];
    }
    {
      # The vRack and the control mesh (modules/mesh-control-core.nix).
      name = "network";
      rules = [
        # vrack-mtu-probe pings every installed peer, on each VLAN and on the mesh, at
        # the configured MTU with don't-fragment, every 5 minutes. 0 means a small ping
        # answered and the full-size one didn't: frames above some size vanish on that
        # path (D25). Everything still looks up, and transfers hang; TCP only gets
        # through by probing down (tcp_mtu_probing). A peer that answers nothing gets
        # no sample at all, which is NodeDown's alert, not this one. `for`: two probe
        # runs, so one lost ping train does not page.
        (rule {
          alert = "VrackJumboBroken";
          expr = "cluster_vrack_mtu_ok == 0";
          for = "10m";
          severity = "critical";
          summary = "{{ $labels.instance }} to {{ $labels.peer }} on {{ $labels.vlan }}: full-size frames are lost, small ones pass";
          description = "The path is not carrying the MTU the topology sets for it. Check `ping -M do -s <mtu - 28> <peer>` both ways; if the provider does not carry jumbo frames there, set vlans.*.mtu = 1500 (the mesh follows to 1420).";
        })
      ];
    }
    {
      name = "storage";
      rules = [
        (rule {
          alert = "ZfsPoolUnhealthy";
          expr = ''node_zfs_zpool_state{state!="online"} > 0'';
          for = "1m";
          severity = "critical";
          summary = "ZFS pool {{ $labels.zpool }} is {{ $labels.state }} on {{ $labels.instance }}";
        })
        (rule {
          alert = "FilesystemFull";
          expr = ''node_filesystem_avail_bytes{fstype=~"zfs|ext4|xfs|vfat"} / node_filesystem_size_bytes < 0.05'';
          for = "5m";
          severity = "critical";
          summary = "{{ $labels.mountpoint }} on {{ $labels.instance }} is {{ $value | humanizePercentage }} free";
        })
        (rule {
          alert = "FilesystemFilling";
          expr = ''node_filesystem_avail_bytes{fstype=~"zfs|ext4|xfs|vfat"} / node_filesystem_size_bytes < 0.15'';
          for = "30m";
          severity = "warning";
          summary = "{{ $labels.mountpoint }} on {{ $labels.instance }} is {{ $value | humanizePercentage }} free";
        })
        (rule {
          alert = "DiskUnhealthy";
          expr = "smartctl_device_smart_status == 0";
          for = "5m";
          severity = "critical";
          summary = "{{ $labels.device }} on {{ $labels.instance }} fails its SMART health check";
        })
        (rule {
          alert = "JuiceFSUnwritable";
          expr = "cluster_jfs_probe_success == 0";
          for = "10m";
          severity = "critical";
          summary = "/mnt/jfs is not writable on {{ $labels.instance }}";
        })
        (rule {
          alert = "JuiceFSProbeStale";
          expr = "time() - cluster_jfs_probe_timestamp_seconds > 1800";
          for = "10m";
          severity = "warning";
          summary = "the JuiceFS probe on {{ $labels.instance }} has not run for {{ $value | humanizeDuration }}";
          description = "Usually means the mount is hung: the probe itself times out.";
        })
        (rule {
          alert = "JuiceFSMetaDumpStale";
          expr = "time() - cluster_jfs_meta_dump_newest_timestamp_seconds > ${hours 3}";
          for = "10m";
          severity = "warning";
          summary = "newest JuiceFS metadata dump is {{ $value | humanizeDuration }} old";
          description = "A reinstalled juicefs-meta node restores from the newest dump; older means more orphaned chunks.";
        })
      ];
    }
    {
      # From cluster-freeipa-health (modules/kinds/freeipa.nix), every 15 minutes.
      name = "freeipa";
      rules = [
        (rule {
          alert = "FreeIPADown";
          expr = "cluster_freeipa_up == 0";
          # A first install takes about five minutes, an upgrade longer.
          for = "20m";
          severity = "critical";
          summary = "{{ $labels.app }}: FreeIPA is not running (ipactl status)";
          description = "`nixos-container run {{ $labels.app }} -- journalctl -u podman-freeipa`; Kerberos and LDAP are down for every client.";
        })
        (rule {
          alert = "FreeIPAUnhealthy";
          expr = "cluster_freeipa_healthcheck_errors > 0";
          for = "30m";
          severity = "warning";
          summary = "{{ $labels.app }}: ipa-healthcheck reports {{ $value }} error(s)";
          description = "`machinectl shell {{ $labels.app }}`, then `podman exec freeipa ipa-healthcheck --failures-only` -- expiring certificates show up here first.";
        })
        (rule {
          alert = "FreeIPARestartPending";
          expr = "cluster_freeipa_restart_pending == 1";
          for = "24h";
          severity = "warning";
          summary = "{{ $labels.app }}: a deployed FreeIPA change has not been applied for a day";
          description = "Deploys never restart the server (a restart is an upgrade); the nightly cluster-freeipa-autoupgrade-{{ $labels.app }} applies it, so this means that is failing or off. `journalctl -u cluster-freeipa-autoupgrade-{{ $labels.app }}`, or run `cluster-freeipa-upgrade {{ $labels.app }}` on its node.";
        })
        (rule {
          alert = "FreeIPAHealthStale";
          expr = "time() - cluster_freeipa_health_last_run_timestamp_seconds > ${hours 1}";
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.app }}: the FreeIPA health check has not run for {{ $value | humanizeDuration }}";
        })
      ]
      # absent() needs a literal selector, hence one rule per app.
      ++ map (
        app:
        rule {
          alert = "FreeIPAHealthNeverRan";
          labels.app = app;
          expr = ''absent(cluster_freeipa_health_last_run_timestamp_seconds{app="${app}"})'';
          for = "1h";
          severity = "warning";
          summary = "${app}: the FreeIPA health check has never reported";
        }
      ) freeipaApps;
    }
    {
      # The log pipeline (modules/logging.nix -> modules/logging-server.nix).
      # The Loki ruler's own alerts (lib/log-alert-rules.nix) go quiet when
      # this breaks, so these are what notice.
      name = "logs";
      rules = [
        (rule {
          alert = "LokiDown";
          expr = ''up{job="loki"} == 0'';
          for = "5m";
          severity = "warning";
          summary = "Loki on {{ $labels.instance }} is down: logs are queueing on every node";
          description = "Nodes keep their journals and resume from their cursors, so nothing is lost until a guest journal rotates past SystemMaxUse. `journalctl -u loki` on the metrics node.";
        })
        (rule {
          alert = "LogShipperDown";
          expr = ''up{job="vector"} == 0'';
          for = "10m";
          severity = "warning";
          summary = "the log shipper on {{ $labels.instance }} is down";
          description = "`journalctl -u vector` on the node.";
        })
        (rule {
          alert = "LogShippingFailing";
          expr = ''sum by (instance) (rate(vector_component_errors_total{component_id="loki"}[10m])) > 0'';
          for = "15m";
          severity = "warning";
          summary = "{{ $labels.instance }} has been failing to push logs to Loki for 15m";
          description = "`journalctl -u vector` on the node; usually Loki rejecting (limits, clock skew) or unreachable.";
        })
      ];
    }
    {
      name = "meta";
      rules = [
        # Always firing, by design: proof that Prometheus -> Alertmanager ->
        # bridge is alive. An off-cluster dead-man watches for it to STOP.
        (rule {
          alert = "Watchdog";
          expr = "vector(1)";
          severity = "none";
          summary = "alerting pipeline heartbeat";
        })
      ];
    }
  ];
}
