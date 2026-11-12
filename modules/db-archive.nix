# modules/db-archive.nix — the host's half of the database archive.
#
# `clusterApps.<app>.archive.enable` archives the app's database continuously to
# object storage: a base backup and every change since, encrypted inside the
# container before it leaves (modules/db-mariadb.nix, modules/db-postgres.nix).
# This file gives the container what it needs and nothing of the host's:
#
#   - where: `topology.objectStorage.dbArchiveBucket`, under a path that is a
#     hash of `topology.backup.repoSalt` and the app's name, so the storage
#     provider does not read app names off the listing;
#   - two generators per app, shared across the fleet so the app can be archived
#     from whichever node runs it. `<app>-db-archive` is the archive key,
#     generated. `<app>-db-archive-s3` is prompted: an S3 key of the app's own,
#     which should reach this bucket and no other. The container holds both, so
#     a compromised app can damage its own archive, and with a key scoped no
#     further than the bucket, the other apps' archives too. It cannot read
#     theirs: each has its own archive key;
#   - a directory the container writes its metrics to, which a timer here copies
#     to the node exporter with an `app` label, taking only the lines it knows.
#
# Archiving is not restoring. Nothing here brings a database back; the restic
# backups (modules/backup.nix) remain the copy that is rehearsed.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  ...
}:
let
  inherit (lib) mkOption types;

  os = topology.objectStorage or { };
  bucket = os.dbArchiveBucket or null;
  salt = topology.backup.repoSalt or null;
  target = topology.backup.target or { };

  archived = lib.filterAttrs (_: a: a.archive.enable) config.clusterApps;
  names = lib.attrNames archived;

  textDir = "/var/lib/prometheus-node-exporter-text";
  runDir = name: "/run/cluster-db-archive/${name}";

  relay = pkgs.writeShellScript "cluster-db-archive-metrics" ''
    set -u
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.gawk
        pkgs.systemd
      ]
    }
    # The source is a file the container's root wrote. Read it as data from a
    # stranger: no following a link, no waiting on a pipe, 64 KiB at most, and
    # only the four lines this library writes, with numbers for values.
    relay() {
      local app=$1 src dst tmp
      src=${runDir "$app"}/metrics.prom
      dst=${textDir}/cluster_db_archive_$app.prom
      if ! systemctl is-active --quiet "container@$app.service" || [ ! -f "$src" ] || [ -L "$src" ]; then
        rm -f "$dst"
        return 0
      fi
      tmp=$(mktemp ${textDir}/.cluster_db_archive.XXXXXX) || return 0
      timeout 5 dd if="$src" iflag=nofollow,nonblock bs=64k count=1 status=none 2>/dev/null \
        | awk -v app="$app" '
            /^cluster_db_archive_(last_ok_timestamp_seconds|last_base_timestamp_seconds|generation|refused) [0-9]+(\.[0-9]+)?$/ {
              printf "%s{app=\"%s\"} %s\n", $1, app, $2
            }' > "$tmp"
      if [ -s "$tmp" ]; then
        chmod 0644 "$tmp"
        mv "$tmp" "$dst"
      else
        rm -f "$tmp" "$dst"
      fi
    }
    ${lib.concatMapStrings (n: "relay ${lib.escapeShellArg n}\n") names}
  '';
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        {
          options.archive = mkOption {
            type = import ../lib/app-archive-type.nix { inherit lib; };
            default = { };
            description = "Continuous archiving of this app's database to object storage (modules/db-archive.nix).";
          };

          config = lib.mkIf config.archive.enable {
            module = {
              imports = [
                ./db-mariadb.nix
                ./db-postgres.nix
              ];
              cluster.dbArchive = {
                enable = true;
                s3 = {
                  endpoint = os.endpoint or "";
                  region = os.region or "";
                  # Empty when unset: the assertions below say what is missing.
                  bucket = if bucket == null then "" else bucket;
                  prefix = if salt == null then "unset" else clusterLib.backupTarget.dbArchivePrefix salt name;
                };
                credentialFiles = {
                  accessKey = "/run/secrets/db-archive-access-key";
                  secretKey = "/run/secrets/db-archive-secret-key";
                  encryptionKey = "/run/secrets/db-archive-key";
                };
                inherit (config.archive) flushSeconds baseIntervalHours retainBaseBackups;
              };
            };

            secrets = {
              db-archive-key = {
                generator = "${name}-db-archive";
                file = "key";
              };
              db-archive-access-key = {
                generator = "${name}-db-archive-s3";
                file = "access-key";
              };
              db-archive-secret-key = {
                generator = "${name}-db-archive-s3";
                file = "secret-key";
              };
            };

            extraBindMounts."/run/db-archive" = {
              hostPath = runDir name;
              isReadOnly = false;
            };
          };
        }
      )
    );
  };

  config = lib.mkIf (archived != { }) {
    assertions = [
      {
        assertion = bucket != null && bucket != "";
        message = "topology.objectStorage.dbArchiveBucket is not set, and archive.enable is on for: ${lib.concatStringsSep ", " names}.";
      }
      {
        assertion = (os.endpoint or "") != "" && (os.region or "") != "";
        message = "clusterApps.<app>.archive needs topology.objectStorage.endpoint and .region.";
      }
      {
        assertion = salt != null;
        message = "clusterApps.<app>.archive needs topology.backup.repoSalt: each app's path in the archive bucket is a hash of it and the app's name.";
      }
      {
        # An app's container holds an S3 key for the archive bucket. In a bucket
        # of its own, that key can be one that opens nothing else.
        assertion =
          bucket == null
          || (bucket != (os.juicefsBucket or null) && !(target.type or "" == "s3" && target.bucket or null == bucket));
        message = "topology.objectStorage.dbArchiveBucket (${toString bucket}) must be a bucket of its own, not the JuiceFS volume's or the backup target's: every archived app's container holds a key to it.";
      }
    ];

    # share = true: one value for the fleet. An app is archived from whichever
    # node runs it, and a second key would be a second, unreadable archive.
    clan.core.vars.generators =
      lib.mapAttrs' (
        name: _:
        lib.nameValuePair "${name}-db-archive" {
          share = true;
          files.key = { };
          runtimeInputs = [
            pkgs.coreutils
            pkgs.openssl
          ];
          # 32 bytes as 64 hexadecimal characters.
          script = ''
            openssl rand -hex 32 | tr -d '\n' > "$out/key"
          '';
        }
      ) archived
      // lib.mapAttrs' (
        name: _:
        lib.nameValuePair "${name}-db-archive-s3" {
          share = true;
          prompts."access-key" = {
            description = "${name}: S3 access key for the database archive bucket (this app's own key)";
            persist = true;
          };
          prompts."secret-key" = {
            description = "${name}: S3 secret key for the database archive bucket";
            type = "hidden";
            persist = true;
          };
        }
      ) archived;

    # A bind mount's source must exist before the container starts.
    systemd.tmpfiles.rules = [
      "d /run/cluster-db-archive 0755 root root -"
    ]
    ++ map (n: "d ${runDir n} 0755 root root -") names;

    systemd.services.cluster-db-archive-metrics = {
      description = "Copy the database archivers' metrics out of the app containers";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = relay;
      };
    };
    systemd.timers.cluster-db-archive-metrics = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "1min";
        OnUnitInactiveSec = "30s";
        AccuracySec = "1s";
      };
    };
  };
}
