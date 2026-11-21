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
    # WordPress (modules/kinds/wordpress.nix). Its migrate unit (wp core update-db,
    # rolled back on failure) is AppMigrationFailed's, under service="migrate", like
    # frappe's and odoo's. These are what is particular to it, matched on text that
    # only PHP, systemd or wp-cloud-files write, so no label but the app's is assumed.
    {
      name = "wordpress";
      interval = "1m";
      rules = [
        # A fatal is a page, a cron run or a CLI command that died: on a read-only
        # tree, mostly a plugin bump that does not run on this PHP or core.
        (rule {
          alert = "WordPressPhpFatal";
          expr = ''sum by (app, site) (count_over_time({app=~".+", app!="platform"} |= "PHP Fatal error" [5m])) > 0'';
          severity = "warning";
          summary = "{{ $labels.app }} ({{ $labels.site }}): PHP fatal errors";
          description = explore;
        })
        # The timer fires every minute; three failures in four minutes is three in a
        # row. Scheduled posts, mail queues and Action Scheduler stop with it.
        (rule {
          alert = "WordPressCronFailing";
          expr = ''sum by (app) (count_over_time({app=~".+", app!="platform"} |= "wordpress-cron.service: Failed with result" [4m])) >= 3'';
          severity = "warning";
          summary = "{{ $labels.app }}: WordPress cron has failed three times in a row";
          description = explore;
        })
        # An attachment wp-cloud-files could not put in the bucket stays on the
        # container's uploads only, and is not where the site's URLs say.
        (rule {
          alert = "WordPressOffloadFailed";
          expr = ''sum by (app, site) (count_over_time({app=~".+", app!="platform"} |~ "(?i)offload failed" [15m])) > 0'';
          severity = "warning";
          summary = "{{ $labels.app }} ({{ $labels.site }}): media offload to the bucket failed";
          description = explore;
        })
      ];
    }
  ];
}
