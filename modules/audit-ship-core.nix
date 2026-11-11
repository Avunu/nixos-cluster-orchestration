# modules/audit-ship-core.nix — the node's half of the off-host audit trail.
#
# Clan-independent, as modules/backup-core.nix is: modules/audit-ship.nix supplies the
# URL and the token from the topology and clan vars, and the boot VM tests import this
# with plain files (tests/lib/boot-harness.nix's targets, through modules/boot-report.nix).
#
# Events go to the cluster-watchdog Worker's POST /event (workers/cluster-watchdog),
# which only ever writes them to R2: nothing on a node, and nothing that steals a node's
# token, can read or delete the trail through it. Each node has its own token, and the
# Worker refuses an event a token is not entitled to: another node's name, a kind it may
# not send, any field its allowlist does not name.
#
#   cluster-audit-send          the spool -> the Worker, for ever; deletes on 2xx only
#   cluster-audit-journal       sshd's "Accepted ..." lines and cluster-upgrade's
#                               outcomes -> ssh_login and deploy events
#   cluster-audit-nomad-acl     the nomad-leader node: Nomad's ACL event stream ->
#                               nomad_acl events. It needs the management token: the
#                               stream gives anonymous and scoped tokens an empty body.
#   modules/boot-report.nix     one boot event per boot
#
# The spool (/var/lib/cluster-audit/spool) is what makes "the receiver is down" a delay
# and not a loss: producers write an event in whole and then move their cursor on; the
# sender removes it only once the Worker has taken it. A body the Worker can never take
# (400, 413, 422) moves to /var/lib/cluster-audit/rejected, so it cannot hold up the rest
# (AuditEventRejected). Metrics in audit.prom; AuditDeliveryStale fires on an event
# older than an hour.
#
# A failing delivery is a metric, not a failing unit: these run for ever and retry, and a
# switch must not fail because the Worker is unreachable (section 0 of the design).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.cluster.audit;

  stateDir = "/var/lib/cluster-audit";
  metricsDir = "/var/lib/prometheus-node-exporter-text";

  script = pkgs.writeScript "cluster-audit" (
    "#!${pkgs.python3}/bin/python3\n" + builtins.readFile ./audit-ship.py
  );

  common = {
    SPOOL_DIR = cfg.spoolDir;
    REJECTED_DIR = "${stateDir}/rejected";
    STATE_DIR = stateDir;
    METRICS_DIR = metricsDir;
    NODE = cfg.node;
  };

  # Runs for ever. Restart for a crash; a delivery failure never exits.
  daemon = {
    wantedBy = [ "multi-user.target" ];
    environment = common;
    path = [ config.systemd.package ];
    serviceConfig = {
      Restart = "always";
      RestartSec = 10;
      StateDirectory = "cluster-audit";
      StateDirectoryMode = "0700";
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectHome = true;
    };
    # Holds no state of its own beyond the spool and its cursor, so a switch can restart it.
    startLimitIntervalSec = 0;
  };
in
{
  options.cluster.audit = {
    enable = lib.mkEnableOption "the off-host audit trail (events to the watchdog Worker's /event)";

    url = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The Worker's /event URL (topology.alerting.auditUrl).";
    };

    tokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "This node's bearer token for /event, as a path (the `audit/token` var). Read as a systemd credential.";
    };

    caFile = mkOption {
      type = types.str;
      default = "/etc/ssl/certs/ca-certificates.crt";
      description = "CA bundle for an https URL.";
    };

    node = mkOption {
      type = types.str;
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
      description = "The name events carry, which the Worker requires to be the token's sender.";
    };

    spoolDir = mkOption {
      type = types.str;
      default = "${stateDir}/spool";
      readOnly = true;
      description = "Where producers put events for the sender. modules/boot-report.nix writes here.";
    };

    journal.enable = mkOption {
      type = types.bool;
      default = true;
      description = "Ship SSH logins and pull-deploy outcomes from the journal.";
    };

    nomadAcl = {
      enable = lib.mkEnableOption "Nomad ACL change events from the event stream (the nomad-leader node)";
      address = mkOption {
        type = types.str;
        description = "Nomad's HTTPS address.";
      };
      tokenFile = mkOption {
        type = types.str;
        description = "The management token. Scoped tokens see an empty stream.";
      };
      caCert = mkOption { type = types.str; };
      clientCert = mkOption { type = types.str; };
      clientKey = mkOption { type = types.str; };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.url != null && cfg.tokenFile != null;
        message = "cluster.audit: url and tokenFile must both be set.";
      }
    ];

    systemd.services."cluster-audit-send" = lib.recursiveUpdate daemon {
      description = "Deliver spooled audit events to the off-host trail";
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];
      environment = {
        AUDIT_URL = cfg.url;
        CA_FILE = cfg.caFile;
      };
      serviceConfig = {
        ExecStart = "${script} send";
        LoadCredential = [ "token:${cfg.tokenFile}" ];
      };
    };

    systemd.services."cluster-audit-journal" = lib.mkIf cfg.journal.enable (
      lib.recursiveUpdate daemon {
        description = "Audit events from the journal: SSH logins, deploy outcomes";
        after = [ "systemd-journal-flush.service" ];
        serviceConfig.ExecStart = "${script} follow-journal";
      }
    );

    systemd.services."cluster-audit-nomad-acl" = lib.mkIf cfg.nomadAcl.enable (
      lib.recursiveUpdate daemon {
        description = "Audit events from Nomad's ACL event stream";
        after = [ "nomad.service" ];
        environment = {
          NOMAD_ADDR = cfg.nomadAcl.address;
          NOMAD_CACERT = cfg.nomadAcl.caCert;
          NOMAD_CLIENT_CERT = cfg.nomadAcl.clientCert;
          NOMAD_CLIENT_KEY = cfg.nomadAcl.clientKey;
        };
        serviceConfig = {
          ExecStart = "${script} follow-nomad-acl";
          LoadCredential = [ "nomad-token:${cfg.nomadAcl.tokenFile}" ];
        };
      }
    );
  };
}
