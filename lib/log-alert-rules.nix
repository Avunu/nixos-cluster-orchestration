# lib/log-alert-rules.nix — alerts on LOG CONTENT, evaluated by Loki's ruler.
#
#   import ./lib/log-alert-rules.nix { inherit lib; }
#
# Same shape as lib/alert-rules.nix, but LogQL, and evaluated by Loki
# (modules/logging-server.nix), which hands firing alerts to the same
# Alertmanager -- so they arrive by the same email, grouped and repeated by
# the same routes. Written over the label contract of modules/logging.nix:
# node, app, site, service, level.
#
# Kept few and coarse on purpose. The reference setup paused most of its log
# rules within weeks as noise; an app's own error chatter is for a developer
# looking at Grafana, not for an email. These are the ones that mean something
# is broken regardless of the app.
{
  lib,
  annotate ? true,
}:
let
  rule =
    {
      alert,
      expr,
      for ? "0m",
      severity,
      summary,
      description ? null,
    }:
    {
      inherit alert expr for;
      labels = {
        inherit severity;
      };
    }
    // lib.optionalAttrs annotate {
      annotations = {
        inherit summary;
      }
      // lib.optionalAttrs (description != null) { inherit description; };
    };

  # Grafana's app-logs dashboard, pre-filtered to the offending stream.
  explore = "Grafana → App Logs, app={{ $labels.app }}, site={{ $labels.site }}.";
in
{
  groups = [
    {
      name = "app-logs";
      interval = "1m";
      rules = [
        # A process saying it is in real trouble: journald priority crit or
        # worse (Python's CRITICAL, a daemon's crit). Rare by construction.
        (rule {
          alert = "AppLogCritical";
          expr = ''sum by (app, site, service) (count_over_time({level=~"crit|alert|emerg"}[5m])) > 0'';
          severity = "critical";
          summary = "{{ $labels.app }}/{{ $labels.service }}: critical log entries";
          description = explore;
        })
        # Errors are normal in small numbers; a sustained flood is a regression
        # or an outage behind the app (database, Redis, a broken deploy).
        (rule {
          alert = "AppErrorBurst";
          expr = ''sum by (app, site) (count_over_time({app!="platform", level="err"}[10m])) > 100'';
          for = "10m";
          severity = "warning";
          summary = "{{ $labels.app }} ({{ $labels.site }}): {{ $value }} errors in 10 minutes";
          description = explore;
        })
        # frappe-migrate / odoo-migrate roll back and keep the old code serving
        # on failure, so nothing else fails loudly: the deploy just did not take.
        (rule {
          alert = "AppMigrationFailed";
          expr = ''sum by (app, site) (count_over_time({service="migrate"} |~ "(?i)migration failed|rolled back|rolling back" [15m])) > 0'';
          severity = "critical";
          summary = "{{ $labels.app }} ({{ $labels.site }}): a database migration failed";
          description = "The migrate unit rolled back; the app still runs the previous schema. " + explore;
        })
      ];
    }
  ];
}
