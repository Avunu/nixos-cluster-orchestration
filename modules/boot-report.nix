# modules/boot-report.nix — what a node says about its own boot (design 1.19).
#
# A stage-2 oneshot, once per boot, after the journal holds the initrd's lines
# (modules/boot-report.py says what it reads and why). It writes boot_report.prom for the
# alerts in lib/alert-rules.nix's `boot` group, and, when the audit trail is on, a boot
# event into its spool (modules/audit-ship-core.nix) for the Worker, which mails a
# FIRING for a boot that was not a clean Clevis unlock under Secure Boot.
#
# A node that opted out (insecurePlaintextBoot, so cluster.boot.enable is false) has no
# unlock to report: it writes cluster_boot_insecure_optout 1 and the report's
# timestamp, and sends nothing. BootSecurityOptedOut fires on it.
#
# Clan-independent: nothing here reads topology or vars. The boot VM tests import it
# directly, and a mutant takes a control out of the script through cluster.bootReport.script.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.cluster.bootReport;
  text = builtins.readFile ./boot-report.py;
in
{
  imports = [ ./audit-ship-core.nix ];

  options.cluster.bootReport = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "Report on each boot (metrics, and an audit event when cluster.audit is on).";
    };

    optedOut = mkOption {
      type = types.bool;
      default = !config.cluster.boot.enable;
      defaultText = lib.literalExpression "!config.cluster.boot.enable";
      description = "Report only that boot security is off.";
    };

    expectedDevices = mkOption {
      type = types.int;
      default = builtins.length (lib.attrNames config.boot.initrd.luks.devices);
      defaultText = lib.literalExpression "the number of boot.initrd.luks.devices";
      description = "LUKS legs Clevis must answer for the boot to count as a Clevis unlock.";
    };

    script = mkOption {
      type = types.str;
      default = text;
      description = "The report's Python. Only a mutant changes it (flake.nix, boot-report-counts-attempts).";
    };
  };

  config = lib.mkIf cfg.enable {
    # The text, so a mutant can edit it and fail loudly when the listing moves.
    system.build.bootReportText = text;

    systemd.services.cluster-boot-report = {
      description = "Report how this boot unlocked (metrics, audit event)";
      wantedBy = [ "multi-user.target" ];
      # The initrd's journal, with Clevis's lines and any initrd SSH login in it.
      after = [ "systemd-journal-flush.service" ];
      # Once per boot. A switch must not send a second boot event, or fail on this.
      restartIfChanged = false;
      environment = {
        EXPECTED_DEVICES = toString cfg.expectedDevices;
        OPTED_OUT = if cfg.optedOut then "1" else "";
        NODE = config.cluster.audit.node;
        METRICS_DIR = "/var/lib/prometheus-node-exporter-text";
        SPOOL_DIR = lib.optionalString (
          config.cluster.audit.enable && !cfg.optedOut
        ) config.cluster.audit.spoolDir;
      };
      path = [ config.systemd.package ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = pkgs.writeScript "cluster-boot-report" ("#!${pkgs.python3}/bin/python3\n" + cfg.script);
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectHome = true;
      };
    };
  };
}
