# Eval-level check for modules/db-archive.nix: what `clusterApps.<app>.archive`
# gives an app's container, and what it refuses to evaluate.
#
# Not a VM test. tests/db-archive.nix runs the archiver; what can regress here is
# the wiring around it: which bucket and path, which secrets, which mounts.
#
# Run: nix build .#checks.<system>.db-archive-wiring
{
  pkgs,
  lib,
  topology,
  clusterLib,
  clanCoreModule,
  appContainerModule,
  overlayNetworkModule,
  dbArchiveModule,
}:
let
  node = topology.nodes.node1;

  mariaApp =
    { pkgs, ... }:
    {
      services.mysql = {
        enable = true;
        package = pkgs.mariadb;
      };
    };

  pgApp = {
    services.postgresql.enable = true;
  };

  systemWith =
    topology': extra:
    lib.nixosSystem {
      system = pkgs.stdenv.hostPlatform.system;
      specialArgs = {
        inherit clusterLib node;
        topology = topology';
        nodeName = "node1";
      };
      modules = [
        clanCoreModule
        appContainerModule
        overlayNetworkModule
        dbArchiveModule
        {
          boot.loader.grub.devices = [ "/dev/null" ];
          fileSystems."/" = {
            device = "/dev/null";
            fsType = "ext4";
          };
          system.stateVersion = topology.stateVersion;
          clan.core.enableRecommendedDefaults = false;
          clan.core.settings.machine.name = "node1";
          # A string: see tests/fixtures/default.nix.
          clan.core.settings.directory = toString ../.;

          clusterApps.shop = {
            tier = "monolith";
            module = mariaApp;
            archive.enable = true;
            archive.flushSeconds = 30;
          };
          clusterApps.ledger = {
            tier = "monolith";
            module = pgApp;
            archive.enable = true;
          };
          clusterApps.plain = {
            tier = "monolith";
            module = mariaApp;
          };
        }
        extra
      ];
    };

  sys = systemWith topology { };
  c = sys.config;
  inner = c.containers.shop.config;
  ledger = c.containers.ledger.config;
  plain = c.containers.plain.config;
  mounts = c.containers.shop.bindMounts;
  gens = c.clan.core.vars.generators;
  archive = inner.cluster.dbArchive;
  os = topology.objectStorage;

  # Whether an assertion fails in a system, by a phrase of its message. Only a
  # failing assertion's message is read: a passing one's may not evaluate.
  refusesIn = phrase: assertions: lib.any (a: !a.assertion && lib.hasInfix phrase a.message) assertions;
  refuses = phrase: system: refusesIn phrase system.config.assertions;

  without = path: lib.recursiveUpdate topology (lib.setAttrByPath path null);

  checks = [
    # ── where ───────────────────────────────────────────────────────────────
    {
      name = "the fixture topology passes this module's assertions";
      ok = !(refuses "dbArchiveBucket" sys) && !(refuses "archive needs" sys);
    }
    {
      name = "the container archives to the archive bucket at the site's endpoint";
      ok =
        archive.enable
        && archive.s3.bucket == os.dbArchiveBucket
        && archive.s3.endpoint == os.endpoint
        && archive.s3.region == os.region;
    }
    {
      name = "the path is db/<sha256>, and holds no part of the app's name";
      ok =
        builtins.match "db/[0-9a-f]{64}" archive.s3.prefix != null && !(lib.hasInfix "shop" archive.s3.prefix);
    }
    {
      name = "the path is not the app's restic repository path";
      ok =
        lib.removePrefix "db/" archive.s3.prefix
        != lib.removePrefix "apps/" (clusterLib.backupTarget.appRepoPath topology.backup.repoSalt "shop");
    }
    {
      name = "two apps get two paths, and another salt another path";
      ok =
        clusterLib.backupTarget.dbArchivePrefix "s" "a" != clusterLib.backupTarget.dbArchivePrefix "s" "b"
        && clusterLib.backupTarget.dbArchivePrefix "s" "a" != clusterLib.backupTarget.dbArchivePrefix "t" "a";
    }
    {
      name = "the app's own settings reach the archiver";
      ok = archive.flushSeconds == 30 && inner.systemd.timers.db-archive-push.timerConfig.OnUnitInactiveSec == "30s";
    }
    {
      name = "an app that sets nothing keeps eight daily base backups, a week of reach";
      ok =
        ledger.cluster.dbArchive.retainBaseBackups == 8
        && ledger.cluster.dbArchive.baseIntervalHours == 24
        && archive.retainBaseBackups == 8;
    }

    # ── secrets ─────────────────────────────────────────────────────────────
    {
      name = "the archive key is generated per app and shared by the fleet";
      ok = gens ? shop-db-archive && gens.shop-db-archive.share && gens.shop-db-archive.files.key.secret;
    }
    {
      name = "the S3 key is the app's own, prompted, and shared by the fleet";
      ok =
        gens ? shop-db-archive-s3
        && gens.shop-db-archive-s3.share
        && gens.shop-db-archive-s3.prompts ? "access-key"
        && gens.shop-db-archive-s3.prompts ? "secret-key"
        && gens.shop-db-archive-s3.prompts."secret-key".type == "hidden";
    }
    {
      name = "the three credentials are mounted read-only, where the archiver reads them";
      ok =
        lib.all (f: (mounts ? ${f}) && mounts.${f}.isReadOnly) [
          archive.credentialFiles.encryptionKey
          archive.credentialFiles.accessKey
          archive.credentialFiles.secretKey
        ]
        && archive.credentialFiles.encryptionKey != null;
    }
    {
      name = "no credential of the archive is in the container's closure";
      ok = lib.all (f: !(lib.hasPrefix "/nix/store" f)) (lib.attrValues archive.credentialFiles);
    }

    # ── the engine ──────────────────────────────────────────────────────────
    {
      name = "the container's MariaDB writes binary logs and ships them when it stops";
      ok =
        inner.services.mysql.settings.mysqld.log_bin == "mysql-bin"
        && inner.services.mysql.settings.mysqld.sync_binlog == 1
        && lib.any (lib.hasInfix "db-archive push --final") inner.systemd.services.mysql.serviceConfig.ExecStop;
    }
    {
      name = "the marker is in the data directory";
      ok = lib.hasPrefix "${inner.services.mysql.dataDir}/" archive.markerFile;
    }
    {
      name = "the container passes the archiver's own assertions";
      ok = !(refusesIn "cluster.dbArchive" inner.assertions);
    }
    {
      name = "the container's PostgreSQL hands its WAL to the archiver, and the last of it when it stops";
      ok =
        ledger.services.postgresql.settings.archive_mode == "on"
        && lib.hasInfix "pgbackrest-archive-push" ledger.services.postgresql.settings.archive_command
        && ledger.services.postgresql.settings.archive_timeout == ledger.cluster.dbArchive.flushSeconds
        && lib.any (lib.hasInfix "db-archive push --final") ledger.systemd.services.postgresql.serviceConfig.ExecStop;
    }
    {
      name = "its marker is in its data directory, and it passes the archiver's assertions";
      ok =
        lib.hasPrefix "${ledger.services.postgresql.dataDir}/" ledger.cluster.dbArchive.markerFile
        && !(refusesIn "cluster.dbArchive" ledger.assertions);
    }
    {
      name = "each engine archives its own database only";
      ok =
        ledger.cluster.dbArchive.engines == [ "postgresql" ]
        && archive.engines == [ "mariadb" ]
        && ledger.cluster.dbArchive.s3.prefix != archive.s3.prefix;
    }

    # ── metrics ─────────────────────────────────────────────────────────────
    {
      name = "the metrics directory is the container's only writable mount from this module";
      ok =
        mounts ? "/run/db-archive"
        && mounts."/run/db-archive".hostPath == "/run/cluster-db-archive/shop"
        && !mounts."/run/db-archive".isReadOnly
        && lib.hasPrefix "/run/db-archive/" archive.metricsFile;
    }
    {
      name = "the host creates that directory and relays from it on a timer";
      ok =
        lib.elem "d /run/cluster-db-archive/shop 0755 root root -" c.systemd.tmpfiles.rules
        && c.systemd.timers ? cluster-db-archive-metrics
        && c.systemd.services ? cluster-db-archive-metrics;
    }

    # ── an app that does not archive ────────────────────────────────────────
    {
      name = "an app without archive.enable gets none of it";
      ok =
        !(gens ? plain-db-archive)
        && !(gens ? plain-db-archive-s3)
        && !(c.containers.plain.bindMounts ? "/run/db-archive")
        && !(c.containers.plain.bindMounts ? "/run/secrets/db-archive-key")
        && !(plain.systemd.timers ? db-archive-push)
        && !(plain.services.mysql.settings.mysqld ? log_bin);
    }

    # ── what does not evaluate ──────────────────────────────────────────────
    {
      name = "no archive bucket is refused";
      ok = refuses "dbArchiveBucket is not set" (
        systemWith (without [
          "objectStorage"
          "dbArchiveBucket"
        ]) { }
      );
    }
    {
      name = "the JuiceFS bucket as the archive bucket is refused";
      ok = refuses "must be a bucket of its own" (
        systemWith (lib.recursiveUpdate topology {
          objectStorage.dbArchiveBucket = os.juicefsBucket;
        }) { }
      );
    }
    {
      name = "the backup target's bucket as the archive bucket is refused";
      ok = refuses "must be a bucket of its own" (
        systemWith (lib.recursiveUpdate topology {
          objectStorage.dbArchiveBucket = "backups-here";
          backup.target = {
            type = "s3";
            bucket = "backups-here";
          };
        }) { }
      );
    }
    {
      name = "no salt is refused";
      ok = refuses "archive needs topology.backup.repoSalt" (
        systemWith (without [
          "backup"
          "repoSalt"
        ]) { }
      );
    }
    {
      name = "an endpoint without TLS is refused for PostgreSQL";
      ok =
        let
          plainHttp = systemWith (lib.recursiveUpdate topology {
            objectStorage.endpoint = "http://s3.example.net";
          }) { };
        in
        refusesIn "over TLS only" plainHttp.config.containers.ledger.config.assertions
        && !(refusesIn "over TLS only" ledger.assertions);
    }
    {
      name = "a container with no database is refused";
      ok =
        let
          bad = systemWith topology {
            clusterApps.empty = {
              tier = "monolith";
              module = {
                systemd.services.stub.script = "sleep infinity";
              };
              archive.enable = true;
            };
          };
        in
        refusesIn "needs exactly one database" bad.config.containers.empty.config.assertions;
    }
  ];

  failed = lib.filter (c': !c'.ok) checks;
in
pkgs.runCommand "db-archive-wiring-checks" { } (
  if failed == [ ] then
    ''
      echo "${toString (builtins.length checks)} wiring checks passed"
      touch $out
    ''
  else
    ''
      echo "FAILED:" >&2
      ${lib.concatMapStringsSep "\n" (c': ''echo "  - ${c'.name}" >&2'') failed}
      exit 1
    ''
)
