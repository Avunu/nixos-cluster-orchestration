# Eval-level checks for the backup wiring, against the fixture node1 configuration
# plus pure checks of lib/backup-target.nix. The runtime is covered by
# tests/backup-roundtrip.nix (VM); what can regress here is what the cluster's
# own apps generate -- the old backup.nix ran mariadb-dump against a PostgreSQL
# app for exactly as long as nothing looked.
#
# Run: nix build .#checks.<system>.backup
{
  pkgs,
  lib,
  clusterLib,
  clanSystem,
}:
let
  c = clanSystem.config;
  svc = c.systemd.services;
  bt = clusterLib.backupTarget;

  profileOf = app: lib.last (lib.splitString " " svc."cluster-backup-${app}".serviceConfig.ExecStart);

  # The fixture's salt, read from the node's own topology argument, so a salt changed
  # in the fixture moves the expectation with it.
  salt = clanSystem._module.specialArgs.topology.backup.repoSalt;
  repoOf = app: bt.appRepoPath salt app;

  checks = [
    # ── generated units ─────────────────────────────────────────────────────
    {
      name = "every clusterApp pinned to node1 has backup + rehearsal units";
      ok = lib.all (a: svc ? "cluster-backup-${a}" && svc ? "cluster-backup-verify-${a}") (
        lib.attrNames (lib.filterAttrs (_: a: a.homeNode == "node1") c.clusterApps)
      );
    }
    {
      name = "nightly, weekly maintenance and weekly rehearsal timers exist";
      ok =
        c.systemd.timers ? cluster-backup
        && c.systemd.timers ? cluster-backup-maintenance
        && c.systemd.timers ? cluster-backup-verify;
    }
    {
      name = "the old clan provider is gone (its restore could not stop an app)";
      ok = !(c.clan.core.backups.providers ? s3);
    }
    {
      name = "credentials come from vars, not the store";
      ok = lib.all (
        cr: !(lib.hasInfix "/nix/store" cr)
      ) svc.cluster-backup-demo-odoo.serviceConfig.LoadCredential;
    }
    {
      name = "pull-deploys yield to backup/restore holds";
      ok = svc.cluster-upgrade.unitConfig.ConditionDirectoryNotEmpty == "!/run/cluster-upgrade.hold.d";
    }
    {
      # Not backups as such, but what a backup-safe restart of an app rests on:
      # a stop that runs to completion. Nomad's own default cap (30s) used to
      # cut every app's 90s stop short.
      name = "a container stop is not cut short by systemd or Nomad";
      ok =
        svc."container@demo-odoo".serviceConfig.TimeoutStopSec == c.clusterApps.demo-odoo.stopTimeoutSeconds
        &&
          c.services.nomad.settings.client.max_kill_timeout
          == "${toString clusterLib.nomad.maxKillTimeoutSeconds}s"
        && lib.all (a: a.nomad.killTimeoutSeconds >= a.stopTimeoutSeconds) (lib.attrValues c.clusterApps);
    }
    {
      name = "node_exporter reads the backup metrics";
      ok = lib.elem "textfile" c.services.prometheus.exporters.node.enabledCollectors;
    }

    # ── hashed repository paths (design 1.21, D17) ─────────────────────────
    {
      name = "a repository path is apps/<sha256>, and holds no part of the app's name";
      ok = lib.all (
        a:
        let
          p = repoOf a;
        in
        builtins.match "apps/[0-9a-f]{64}" p != null && !(lib.hasInfix a p)
      ) (lib.attrNames c.clusterApps);
    }
    {
      name = "the path depends on the salt, and differs per app";
      ok =
        bt.appRepoPath "salt-one-0123456789" "x" != bt.appRepoPath "salt-two-0123456789" "x"
        && repoOf "demo-odoo" != repoOf "demo-erp"
        && repoOf "demo-odoo" == bt.appRepoPath salt "demo-odoo";
    }
    {
      name = "the node's module uses it for every app (not backup-core's apps/<app> default)";
      ok = lib.all (a: c.cluster.backup.repoPathFor a == repoOf a) (lib.attrNames c.clusterApps);
    }

    # ── swappable target (pure) ─────────────────────────────────────────────
    {
      name = "s3 target: path-style repository per app";
      ok =
        bt.repository {
          type = "s3";
          endpoint = "https://s3.example.com/";
          bucket = "b";
        } "apps/x" == "s3:https://s3.example.com/b/apps/x"
        &&
          bt.options {
            type = "s3";
            endpoint = "e";
            bucket = "b";
          } == [ "s3.bucket-lookup=path" ];
    }
    {
      name = "rest, b2 and local targets render";
      ok =
        bt.repository {
          type = "rest";
          url = "https://rs.example.com";
        } "apps/x" == "rest:https://rs.example.com/apps/x"
        &&
          bt.repository {
            type = "b2";
            bucket = "b";
          } "apps/x" == "b2:b:apps/x"
        &&
          bt.repository {
            type = "local";
            path = "/srv/r";
          } "apps/x" == "/srv/r/apps/x";
    }
    {
      name = "an unknown backend type is an error, not a silent default";
      ok =
        !(builtins.tryEval (
          bt.repository {
            type = "ftp";
          } "x"
        )).success;
    }
  ];

  failed = lib.filter (x: !x.ok) checks;
in
pkgs.runCommand "backup-checks" { } ''
  # Engine detection, read from the generated per-app profiles.
  m=${profileOf "demo-odoo"}
  l=${profileOf "demo-erp"}
  expect() { grep -qxF "$2" "$1" || { echo "FAILED: $1 lacks: $2" >&2; cat "$1" >&2; exit 1; }; }
  expect "$m" 'ENGINE=postgresql'
  expect "$m" 'DB_UNIT=postgresql.service'
  expect "$m" 'APP_UNITS=(odoo.service odoo-migrate.service)'
  expect "$m" 'export RESTIC_REPOSITORY=s3:https://backup.example.net/fixture-backups/${repoOf "demo-odoo"}'
  expect "$l" 'export RESTIC_REPOSITORY=s3:https://backup.example.net/fixture-backups/${repoOf "demo-erp"}'
  # No profile names an app in its repository.
  for f in ${
    lib.concatStringsSep " " (
      map profileOf (lib.attrNames (lib.filterAttrs (n: _: svc ? "cluster-backup-${n}") c.clusterApps))
    )
  }; do
    app=$(sed -n 's/^APP=//p' "$f" | tr -d "'")
    if grep '^export RESTIC_REPOSITORY=' "$f" | grep -qF "$app"; then
      echo "FAILED: $f names its app in RESTIC_REPOSITORY" >&2; exit 1
    fi
  done
  expect "$l" 'ENGINE=mariadb'
  expect "$l" 'DB_UNIT=mysql.service'
  grep -q '^APP_UNITS=(.* frappe-erp.example.com.service' "$l" \
    || { echo "FAILED: demo-erp's frappe units are not stopped during a restore" >&2; exit 1; }
  # The PostgreSQL app's dump script must use pg_dump, never mariadb-dump.
  db=$(grep '^DB_SCRIPT=' "$m" | cut -d= -f2)
  grep -q 'pg_dump -Fc' "$db" && ! grep -q mariadb-dump "$db" \
    || { echo "FAILED: demo-odoo's dump script is not PostgreSQL's" >&2; exit 1; }

  ${
    if failed == [ ] then
      ''
        echo "${toString (builtins.length checks)} backup checks + engine detection passed"
        touch $out
      ''
    else
      ''
        echo "FAILED:" >&2
        ${lib.concatMapStringsSep "\n" (x: ''echo "  - ${x.name}" >&2'') failed}
        exit 1
      ''
  }
''
