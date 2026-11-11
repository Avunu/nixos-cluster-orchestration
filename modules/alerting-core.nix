# modules/alerting-core.nix — Alertmanager + rules + probes + email bridge.
#
# The clan-independent half of alerting; modules/alerting.nix feeds it from
# topology, clusterApps and clan vars, and tests/alerting.nix drives it in a VM
# against a stub of the Cloudflare API.
#
#   Prometheus (rules: lib/alert-rules.nix)
#     -> Alertmanager (127.0.0.1:9093; grouping, repeats, inhibition)
#       -> alert-email-bridge (127.0.0.1:9099; Alertmanager webhook JSON -> text)
#         -> send-notification-email (lib/notify-email.nix)
#           -> Cloudflare Email Sending API
#
# Probes: blackbox_exporter checks every app's public hostname through
# Cloudflare (tunnel + nginx + app, the path a user takes) and the backup
# target's endpoint.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.cluster.alerting;

  rules = import ../lib/alert-rules.nix {
    inherit lib;
    inherit (cfg) backupApps verifiedApps freeipaApps;
  };
  rulesFile = pkgs.writeText "cluster-alert-rules.yml" (builtins.toJSON rules);

  notifyEmail = import ../lib/notify-email.nix {
    inherit pkgs;
    inherit (cfg) apiBase;
    accountId = cfg.cloudflareAccountId;
    from = cfg.from;
    recipients = cfg.to;
  };

  bridgePort = 9099;
  alertmanagerPort = 9093;

  # Where to reach the local Prometheus: its bind address, unless that is a
  # wildcard. On the metrics node it binds the control IP so Grafana's
  # container can query it (modules/monitoring-server.nix), and a loopback
  # query would be refused.
  promHost =
    let
      a = config.services.prometheus.listenAddress;
    in
    if a == "0.0.0.0" || a == "" then "127.0.0.1" else a;
  blackboxPort = 9115;

  # Alertmanager webhook JSON -> one email per notification.
  bridge = pkgs.writers.writePython3Bin "alert-email-bridge" { flakeIgnore = [ "E501" ]; } ''
    import http.server
    import json
    import os
    import subprocess
    import sys
    import urllib.request

    SENDER = "${notifyEmail}/bin/send-notification-email"
    SHOWN = ("app", "name", "instance", "zpool", "mountpoint", "device", "severity")


    def build_message(payload):
        status = payload.get("status", "unknown")
        alerts = payload.get("alerts", [])
        common = payload.get("commonLabels", {})
        firing = [a for a in alerts if a.get("status") == "firing"]
        name = common.get("alertname", "alerts")
        where = common.get("app") or common.get("name") or common.get("instance") or ""
        tag = "FIRING x%d" % len(firing) if status == "firing" else "RESOLVED"
        subject = "[%s] %s%s" % (tag, name, (" . " + where) if where else "")

        lines = []
        for a in alerts:
            labels = a.get("labels", {})
            ann = a.get("annotations", {})
            lines.append("%s  %s" % (a.get("status", "?").upper(), labels.get("alertname", "?")))
            if ann.get("summary"):
                lines.append("  " + ann["summary"])
            if ann.get("description"):
                lines.append("  " + ann["description"])
            for key in SHOWN:
                if key in labels:
                    lines.append("  %s=%s" % (key, labels[key]))
            lines.append("  since " + a.get("startsAt", "?"))
            lines.append("")
        lines.append("-- ${cfg.clusterName} alerting (Alertmanager on the metrics node)")
        return subject, "\n".join(lines)


    def relay_heartbeat():
        """The Watchdog, relayed to the off-cluster dead-man (cluster-watchdog
        Worker). Going through the bridge rather than straight from
        Alertmanager makes every heartbeat prove the bridge is alive too."""
        url = os.environ.get("WATCHDOG_URL")
        if not url:
            return
        with open(os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "watchdog-token")) as f:
            token = f.read().strip()
        req = urllib.request.Request(url, data=b"{}", method="POST", headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        })
        urllib.request.urlopen(req, timeout=20).close()


    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            try:
                if self.path.startswith("/heartbeat"):
                    relay_heartbeat()
                else:
                    subject, body = build_message(json.loads(raw))
                    subprocess.run([SENDER, subject, body], check=True)
                code = 204
            except Exception as exc:
                sys.stderr.write("alert-email-bridge: %s\n" % exc)
                code = 500
            self.send_response(code)
            self.end_headers()

        def log_message(self, *args):
            return


    http.server.HTTPServer(("127.0.0.1", ${toString bridgePort}), Handler).serve_forever()
  '';

  blackboxConfig = pkgs.writeText "blackbox.yml" (
    builtins.toJSON {
      modules = {
        # An app answers: 2xx, a redirect to its login page, or Access asking
        # who we are. What it must not do is time out or 5xx.
        http_app = {
          prober = "http";
          timeout = "15s";
          http = {
            method = "GET";
            follow_redirects = false;
            preferred_ip_protocol = "ip4";
            valid_status_codes = [
              200
              301
              302
              303
              307
              308
              401
              403
            ];
          };
        };
        # A backup target answers at all (S3 roots are 403 to anonymous callers).
        http_alive = {
          prober = "http";
          timeout = "15s";
          http = {
            method = "GET";
            follow_redirects = false;
            preferred_ip_protocol = "ip4";
            valid_status_codes = [
              200
              204
              301
              302
              400
              401
              403
              404
              405
            ];
          };
        };
      };
    }
  );

  probeJob = name: module: targets: {
    job_name = name;
    metrics_path = "/probe";
    params.module = [ module ];
    static_configs = map (t: {
      targets = [ t.url ];
      labels = lib.optionalAttrs (t ? app) { inherit (t) app; };
    }) targets;
    relabel_configs = [
      {
        source_labels = [ "__address__" ];
        target_label = "__param_target";
      }
      {
        source_labels = [ "__param_target" ];
        target_label = "instance";
      }
      {
        target_label = "__address__";
        replacement = "127.0.0.1:${toString blackboxPort}";
      }
    ];
  };

  weeklyReport = pkgs.writeShellScript "cluster-weekly-report" ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.curl
        pkgs.jq
        pkgs.coreutils
      ]
    }
    prom=http://${promHost}:${toString config.services.prometheus.port}/api/v1/query
    # app -> value, for one metric
    q() { curl -fsS --get "$prom" --data-urlencode "query=$1" | jq -r '.data.result[] | "\(.metric.app // .metric.alertname)\t\(.value[1])"'; }
    now=$(date +%s)
    ago() { # seconds -> "3h", "2d"
      local s=$(( now - ''${1%.*} ))
      if [ "$s" -lt 7200 ]; then echo "$(( s / 60 ))m ago"; elif [ "$s" -lt 172800 ]; then echo "$(( s / 3600 ))h ago"; else echo "$(( s / 86400 ))d ago"; fi
    }
    declare -A last verify check added
    while IFS=$'\t' read -r a v; do last[$a]=$v; done < <(q cluster_backup_last_success_timestamp_seconds)
    while IFS=$'\t' read -r a v; do verify[$a]=$v; done < <(q cluster_backup_verify_last_success_timestamp_seconds)
    while IFS=$'\t' read -r a v; do check[$a]=$v; done < <(q cluster_backup_check_last_success_timestamp_seconds)
    while IFS=$'\t' read -r a v; do added[$a]=$v; done < <(q cluster_backup_bytes_added)
    firing=$(curl -fsS --get "$prom" --data-urlencode 'query=ALERTS{alertstate="firing", alertname!="Watchdog"}' \
      | jq -r '.data.result[] | .metric.alertname + (if .metric.app then " (" + .metric.app + ")" else "" end)' | sort -u)

    ok=0 bad=0 body=""
    # Plain ifs: under `set -e`, `x+="$( [ … ] && … )"` exits the script when
    # the test is false (an assignment has its substitution's status).
    when() { if [ -n "$1" ]; then ago "$1"; else echo never; fi; }
    for a in ${lib.concatStringsSep " " cfg.backupApps}; do
      l=''${last[$a]:-}
      if [ -n "$l" ] && [ $(( now - ''${l%.*} )) -lt 108000 ]; then
        ok=$((ok + 1)); mark="ok  "
      else
        bad=$((bad + 1)); mark="LATE"
      fi
      size=""
      if [ -n "''${added[$a]:-}" ]; then size=" ($(numfmt --to=iec "''${added[$a]%.*}")B new)"; fi
      body+="$mark $a"$'\n'
      body+="      last backup: $(when "$l")$size"$'\n'
      body+="      restore rehearsal: $(when "''${verify[$a]:-}")"$'\n'
      body+="      repository check: $(when "''${check[$a]:-}")"$'\n'
    done
    nfiring=0
    if [ -n "$firing" ]; then nfiring=$(printf '%s\n' "$firing" | wc -l); fi
    subject="[REPORT] weekly: $ok/$((ok + bad)) apps backed up, $nfiring alert(s) firing"
    body+=$'\n'"Firing now: ''${firing:-nothing}"$'\n\n'"-- ${cfg.clusterName} weekly report (cluster-weekly-report on the metrics node)"
    exec ${notifyEmail}/bin/send-notification-email "$subject" "$body"
  '';

  cluster-alert-test = pkgs.writeShellScriptBin "cluster-alert-test" ''
    # Fire a real alert through Alertmanager -> bridge -> Cloudflare, to prove
    # the path (and the token) works. It resolves by itself after 5 minutes.
    exec ${config.services.prometheus.alertmanager.package}/bin/amtool \
      --alertmanager.url=http://127.0.0.1:${toString alertmanagerPort} \
      alert add ClusterAlertTest severity=warning \
      --annotation=summary="test alert from $(hostname) -- the alerting path works" \
      --end="$(date -u -d '+5 minutes' +%Y-%m-%dT%H:%M:%SZ)"
  '';
in
{
  options.cluster.alerting = {
    clusterName = lib.mkOption {
      type = lib.types.str;
      default = "cluster";
      description = "How the signature of alert and report emails names this cluster.";
    };
    cloudflareAccountId = lib.mkOption { type = lib.types.str; };
    from = lib.mkOption { type = lib.types.str; };
    to = lib.mkOption { type = lib.types.listOf lib.types.str; };
    tokenFile = lib.mkOption {
      type = lib.types.str;
      description = "File with the Cloudflare API token (Email Sending only).";
    };
    apiBase = lib.mkOption {
      type = lib.types.str;
      default = "https://api.cloudflare.com/client/v4";
    };
    backupApps = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Apps that must have a recent backup (absent() rules are per app).";
    };
    verifiedApps = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Apps with a database, whose backups must pass the weekly restore rehearsal.";
    };
    freeipaApps = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "FreeIPA servers whose health check must keep reporting.";
    };
    appProbes = lib.mkOption {
      type = lib.types.listOf (lib.types.attrsOf lib.types.str);
      default = [ ];
      description = "[{ app; url; }] probed through their public hostnames.";
    };
    targetProbes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Backup target endpoints that must answer.";
    };
    heartbeat = {
      url = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "https://cluster-watchdog.example.workers.dev/heartbeat";
        description = "The dead-man Worker's heartbeat endpoint. null = the Watchdog is discarded.";
      };
      tokenFile = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "File with the bearer token the Worker expects.";
      };
    };
    report = {
      schedule = lib.mkOption {
        type = lib.types.str;
        default = "Mon *-*-* 12:00:00";
        description = "When the weekly backup report is emailed (OnCalendar, UTC).";
      };
    };
  };

  config = {
    services.prometheus = {
      ruleFiles = [ rulesFile ];
      alertmanagers = [
        { static_configs = [ { targets = [ "127.0.0.1:${toString alertmanagerPort}" ]; } ]; }
      ];
      scrapeConfigs =
        lib.optional (cfg.appProbes != [ ]) (probeJob "apps" "http_app" cfg.appProbes)
        ++ lib.optional (cfg.targetProbes != [ ]) (
          probeJob "backup-target" "http_alive" (map (url: { inherit url; }) cfg.targetProbes)
        );

      alertmanager = {
        enable = true;
        listenAddress = "127.0.0.1";
        port = alertmanagerPort;
        # Single instance: no gossip port listening on every interface.
        extraFlags = [ "--cluster.listen-address=" ];
        configuration = {
          route = {
            receiver = "email";
            group_by = [
              "alertname"
              "app"
              "name"
              "instance"
            ];
            group_wait = "30s";
            group_interval = "5m";
            repeat_interval = "12h";
            routes = [
              {
                matchers = [ ''alertname="Watchdog"'' ];
                receiver = "heartbeat";
                group_wait = "0s";
                group_interval = "1m";
                repeat_interval = "5m";
              }
              {
                matchers = [ ''severity="critical"'' ];
                receiver = "email";
                group_wait = "10s";
                repeat_interval = "1h";
              }
            ];
          };
          # A dead node takes its units, probes and filesystems with it: say
          # it once, not once per symptom.
          inhibit_rules = [
            {
              source_matchers = [ ''alertname="NodeDown"'' ];
              target_matchers = [ ''alertname!="NodeDown"'' ];
              equal = [ "instance" ];
            }
          ];
          receivers = [
            {
              name = "email";
              webhook_configs = [
                {
                  url = "http://127.0.0.1:${toString bridgePort}/";
                  send_resolved = true;
                }
              ];
            }
            (
              {
                name = "heartbeat";
              }
              // lib.optionalAttrs (cfg.heartbeat.url != null) {
                webhook_configs = [
                  {
                    url = "http://127.0.0.1:${toString bridgePort}/heartbeat";
                    send_resolved = false;
                  }
                ];
              }
            )
          ];
        };
      };

      exporters.blackbox = {
        enable = true;
        listenAddress = "127.0.0.1";
        port = blackboxPort;
        configFile = blackboxConfig;
        # At info it logs every redirect of every probe, every interval;
        # failures are logged at error and are what the alerts are built on.
        extraFlags = [ "--log.level=warn" ];
      };
    };

    # Alerts evaluated before Alertmanager is listening are retried anyway;
    # ordering just keeps the first minutes of the journal clean.
    systemd.services.prometheus = {
      after = [ "alertmanager.service" ];
      wants = [ "alertmanager.service" ];
    };

    systemd.services.alert-email-bridge = {
      description = "Alertmanager webhook -> Cloudflare Email";
      wantedBy = [ "multi-user.target" ];
      before = [ "alertmanager.service" ];
      serviceConfig = {
        ExecStart = "${bridge}/bin/alert-email-bridge";
        DynamicUser = true;
        LoadCredential = [
          "cf-email-token:${cfg.tokenFile}"
        ]
        ++ lib.optional (cfg.heartbeat.tokenFile != null) "watchdog-token:${cfg.heartbeat.tokenFile}";
        Environment = lib.optional (cfg.heartbeat.url != null) "WATCHDOG_URL=${cfg.heartbeat.url}";
        Restart = "always";
        RestartSec = 5;
      };
    };

    # A good-news email once a week: what every app's backups look like and
    # what is firing. Silence is not evidence -- a report that stops arriving,
    # or arrives with an app missing, is.
    systemd.services.cluster-weekly-report = {
      description = "Email the weekly backup report";
      after = [ "prometheus.service" ];
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        LoadCredential = [ "cf-email-token:${cfg.tokenFile}" ];
        ExecStart = weeklyReport;
      };
    };
    systemd.timers.cluster-weekly-report = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.report.schedule;
        Persistent = true;
      };
    };

    environment.systemPackages = [ cluster-alert-test ];
  };
}
