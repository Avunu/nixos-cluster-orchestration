# modules/db-postgres.nix — continuous archiving of a PostgreSQL to object storage.
#
# Acts where `cluster.dbArchive.enable` and `services.postgresql` are both on,
# which is inside an app's container (modules/db-archive.nix turns it on there)
# and nowhere on a host. pgBackRest does the transfers, and PostgreSQL does the
# shipping itself: while there are changes it closes a WAL segment at least every
# `flushSeconds` and hands each closed segment to `archive_command`, again and
# again until that succeeds. What is here is around that:
#
#   - `archive_command` reads its settings from a file in /run that
#     `db-archive push` writes on a timer, once the generation is known and the
#     three credentials are read. No file, no upload: PostgreSQL keeps the
#     segment and asks again.
#   - PostgreSQL keeps every segment that was not archived, and stops when its
#     disk is full. So with more than `postgres.queueMaxMiB` waiting, the oldest
#     is dropped and a file in the data directory says so. The archive then has
#     a gap, the freshness metric stands still, and a base backup is taken as
#     soon as the archive takes segments again: a restore starts from that one.
#   - A base backup when the generation has none, the newest is older than
#     `baseIntervalHours`, or there is a gap. pgBackRest removes the older ones.
#   - A last WAL switch as PostgreSQL stops, which by itself it does not do.
#
# The archive key is pgBackRest's repository passphrase. A segment from another
# cluster, or pushed with another key, pgBackRest refuses by itself.
#
# `db-archive` (in the system path) is all of it: push, base, status,
# next-generation, and `pgbackrest` for pgBackRest itself with the same
# settings. See modules/db-archive-common.nix for generations. The marker is in
# the data directory and left out of base backups, so a restored data directory
# has none and is not archived until it is given a generation.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.cluster.dbArchive;
  pg = config.services.postgresql;
  active = cfg.enable && pg.enable;

  stanza = "db";
  runDir = "/run/db-archive-pg";
  conf = "${runDir}/pgbackrest.conf";
  gapFile = "${pg.dataDir}/db-archive.gap";
  port = toString pg.settings.port;

  # Files of the archiver's own in the data directory. A base backup that
  # carried them would hand a restored database the old generation.
  ownFiles =
    lib.optionals (lib.hasPrefix "${pg.dataDir}/" cfg.markerFile) [
      (lib.removePrefix "${pg.dataDir}/" cfg.markerFile)
      ".db-archive-generation.tmp"
    ]
    ++ [
      "db-archive.gap"
      "db-archive.gap.closing"
    ];

  # Everything but the path and the three credentials, which `render` adds.
  globalConf = pkgs.writeText "db-archive-pgbackrest-global.conf" (
    cfg.mutate ''
      [global]
      repo1-type=s3
      repo1-s3-endpoint=${cfg.s3.host}
      repo1-storage-host=${cfg.s3.host}
      repo1-storage-port=${toString cfg.s3.port}
      repo1-storage-verify-tls=${if cfg.s3.verifyTls then "y" else "n"}
      repo1-s3-bucket=${cfg.s3.bucket}
      repo1-s3-region=${cfg.s3.region}
      repo1-s3-uri-style=path
      repo1-cipher-type=aes-256-cbc
      repo1-retention-full=${toString cfg.retainBaseBackups}
      repo1-bundle=y
      compress-type=zst
      start-fast=y
      archive-timeout=60
      log-level-console=warn
      log-level-file=off
    ''
  );
  stanzaConf = pkgs.writeText "db-archive-pgbackrest-stanza.conf" ''

    [global:backup]
    ${lib.concatMapStringsSep "\n" (f: "exclude=${f}") ownFiles}

    [${stanza}]
    pg1-path=${pg.dataDir}
    pg1-socket-path=/run/postgresql
    pg1-port=${port}
  '';

  # PostgreSQL runs this for each closed segment, as its own user, inside its
  # unit's sandbox, with the data directory as the working directory. pgBackRest
  # has a queue limit of its own, which drops the same way and leaves no record.
  #
  # The name matters: pgBackRest's `check` and `backup` refuse an
  # archive_command that does not contain "pgbackrest".
  archivePush = pkgs.writeShellScriptBin "pgbackrest-archive-push" (
    cfg.mutate ''
      set -u
      export PATH=${
        lib.makeBinPath [
          pkgs.pgbackrest
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnused
        ]
      }
      wal=$1
      ${lib.optionalString (cfg.postgres.queueMaxMiB != null) ''
        size=$(stat -c %s -- "$wal") || exit 1
        waiting=$(find pg_wal/archive_status -maxdepth 1 -name '*.ready' | wc -l) || exit 1
        if [ "$((waiting * size))" -gt ${toString (cfg.postgres.queueMaxMiB * 1048576)} ]; then
          # The record comes first, and is on disk before the segment is let go.
          printf '%s\n' "$wal" >> ${lib.escapeShellArg gapFile} && sync ${lib.escapeShellArg gapFile} || {
            echo "db-archive: $waiting WAL segments are waiting, over the limit, and the gap could not be recorded. Keeping $wal." >&2
            exit 1
          }
          echo "db-archive: DROPPED $wal: $waiting WAL segments are waiting, over the limit of ${toString cfg.postgres.queueMaxMiB} MiB. The archive has a gap until the next base backup." >&2
          exit 0
        fi
      ''}
      if [ ! -r ${conf} ]; then
        echo "db-archive: no archive settings at ${conf}: the archiver has not run yet, or has refused. Keeping $wal." >&2
        exit 1
      fi
      # A failure costs nothing, PostgreSQL asks again, so it is a quick one. A
      # stopping PostgreSQL asks six more times and waits for every answer, so
      # then it is quicker still: storage that is away must not hold a stop past
      # what the container is given to stop in. The postmaster writes its state
      # on the eighth line of its PID file.
      patience=10
      case "$(sed -n 8p postmaster.pid 2>/dev/null)" in
        stopping*) patience=3 ;;
      esac
      exec pgbackrest --config=${conf} --stanza=${stanza} --io-timeout="$patience" archive-push "$wal"
    ''
  );
  archiveCommand = "${archivePush}/bin/pgbackrest-archive-push %p";

  dbArchive = pkgs.writeShellScriptBin "db-archive" (
    cfg.mutate ''
      set -euo pipefail
      shopt -s inherit_errexit
      export PATH=${
        lib.makeBinPath [
          pg.finalPackage
          pkgs.pgbackrest
          pkgs.coreutils
          pkgs.findutils
          pkgs.gnugrep
          pkgs.jq
          pkgs.systemd
          pkgs.util-linux
        ]
      }
      . ${cfg.shellLib}
      # The commands below run as postgres, which cannot stand in root's home.
      cd /

      RUN=${runDir}
      CONF=${conf}
      TOP=${runDir}/top.conf
      GAP=${lib.escapeShellArg gapFile}
      PREFIX=${lib.escapeShellArg cfg.s3.prefix}

      sql() {
        runuser -u postgres -- timeout "''${SQL_DEADLINE:-30}" \
          psql -X -At -v ON_ERROR_STOP=1 -h /run/postgresql -p ${port} -d postgres -c "$1"
      }

      # pgbr <deadline> <settings file> <arguments...>
      pgbr() {
        local deadline=$1 file=$2
        shift 2
        runuser -u postgres -- timeout "$deadline" pgbackrest --config="$file" "$@"
      }
      # The same, on this generation's stanza.
      stanza() {
        local deadline=$1
        shift
        pgbr "$deadline" "$CONF" --stanza=${stanza} "$@"
      }

      # render <path in the bucket> <file>: pgBackRest's settings, for postgres
      # alone to read. All three credentials or no file.
      render() {
        local key ak sk
        key=$(dba_secret ${lib.escapeShellArg cfg.credentialFiles.encryptionKey}) || return 1
        case "$key" in
          *[!0-9a-f]*) dba_log "the archive key is not lowercase hexadecimal"; return 1 ;;
        esac
        [ "''${#key}" -eq 64 ] || { dba_log "the archive key is not 64 characters"; return 1; }
        ak=$(dba_secret ${lib.escapeShellArg cfg.credentialFiles.accessKey}) || return 1
        sk=$(dba_secret ${lib.escapeShellArg cfg.credentialFiles.secretKey}) || return 1
        install -d -m 0700 -o postgres -g postgres "$RUN" || return 1
        install -m 0600 -o postgres -g postgres /dev/null "$2.tmp" || return 1
        {
          cat ${globalConf}
          printf 'repo1-path=/%s\n' "$1"
          printf 'repo1-s3-key=%s\n' "$ak"
          printf 'repo1-s3-key-secret=%s\n' "$sk"
          printf 'repo1-cipher-pass=%s\n' "$key"
          cat ${stanzaConf}
        } > "$2.tmp" || return 1
        mv "$2.tmp" "$2"
      }

      # `repo-ls` prints one JSON object with a "." entry for the path itself,
      # and exits 0 on an empty prefix. Anything else on stdout, nothing on
      # stdout, or any other status, is "did not answer".
      dba_archive_entries() {
        local out
        render "$PREFIX" "$TOP" || return 1
        out=$(pgbr 60 "$TOP" --io-timeout=20 --log-level-console=off repo-ls --output=json 2>/dev/null) || return 1
        [ -n "$out" ] || return 1
        printf '%s' "$out" | jq -r '
          if type == "object" and has(".") then keys[] | select(. != ".")
          else error("not a listing") end' 2>/dev/null
      }

      # One run at a time decides the generation and writes the settings.
      lock() {
        mkdir -p "$DBA_STATE"
        exec 9> "$DBA_STATE/setup.lock"
        flock -w 120 9 || { dba_log "another db-archive run holds the lock"; exit 1; }
      }
      unlock() { exec 9>&-; }

      # The generation, on stdout, with the settings file written for it.
      # Without a generation there is no settings file, so nothing is archived
      # while the archiver refuses.
      setup() {
        local gen
        gen=$(dba_generation) || { rm -f "$CONF" "$RUN/generation"; return 1; }
        render "$PREFIX/gen-$gen" "$CONF" || { rm -f "$CONF"; return 1; }
        printf '%s\n' "$gen"
      }

      # archive_mode needs a restart of PostgreSQL to change.
      archiving_is_on() {
        local mode command
        mode=$(sql 'SHOW archive_mode') || { dba_log "PostgreSQL did not answer"; return 1; }
        command=$(sql 'SHOW archive_command') || { dba_log "PostgreSQL did not answer"; return 1; }
        if [ "$mode" != on ] || [ "$command" != ${lib.escapeShellArg archiveCommand} ]; then
          dba_log "PostgreSQL is not running with this archive_command: it has not been restarted since archiving was turned on, or the setting was changed"
          return 1
        fi
      }

      # Once per generation per boot: the stanza exists, and a segment closed
      # now reaches it.
      ensure() {
        local out
        [ "$(cat "$RUN/generation" 2>/dev/null || true)" != "$1" ] || return 0
        out=$(stanza 120 stanza-create 2>&1) || {
          printf '%s\n' "$out" >&2
          dba_log "stanza-create failed for generation $1. If this is not the database generation $1 was archived from, run: db-archive next-generation --yes"
          return 1
        }
        out=$(stanza 180 check 2>&1) || {
          printf '%s\n' "$out" >&2
          dba_log "a WAL segment closed now did not reach generation $1"
          return 1
        }
        printf '%s\n' "$1" > "$RUN/generation"
      }

      waiting() {
        find ${lib.escapeShellArg pg.dataDir}/pg_wal/archive_status -maxdepth 1 -name '*.ready' | wc -l
      }

      has_gap() { [ -e "$GAP" ] || [ -e "$GAP.closing" ]; }

      # When the newest complete base backup of this generation began, in epoch
      # seconds; 0 when it has none. "None" is pgBackRest saying so, never just
      # a quiet failure.
      newest_base() {
        local out
        out=$(stanza 90 --log-level-console=off info --output=json 2>/dev/null) \
          || { dba_log "pgbackrest info failed"; return 1; }
        printf '%s' "$out" | jq -er '
          if type != "array" or length != 1 then error("not one stanza")
          elif .[0].status.code == 0 then [ .[0].backup[].timestamp.start ] | max
          elif .[0].status.code == 2 then 0
          else error("status \(.[0].status.code): \(.[0].status.message)") end' \
          || { dba_log "pgbackrest info did not show this stanza in order: $(printf '%s' "$out" | head -c 300)"; return 1; }
      }

      cmd_push() {
        local gen n
        lock
        gen=$(setup) || exit 1
        dba_metric refused 0
        archiving_is_on || exit 1
        ensure "$gen" || exit 1
        n=$(waiting) || exit 1
        if has_gap; then
          dba_log "WAL segments were dropped: the archive has a gap, which the next base backup closes"
          # Once the archive takes segments again. Until then a backup cannot finish.
          [ "$n" -ne 0 ] || dba_start_base
          return 0
        fi
        if [ "$n" -ne 0 ]; then
          dba_log "$n WAL segments are waiting to be archived"
          return 0
        fi
        # Every closed segment is in the archive.
        dba_metric last_ok_timestamp_seconds "$(date +%s)"
      }

      # As PostgreSQL stops. It archives the segments it has closed and does
      # not close the one it is writing, so this does, and gives it a moment.
      cmd_final() {
        local n=0
        [ -r "$CONF" ] || return 0
        SQL_DEADLINE=10 sql 'SELECT pg_switch_wal()' > /dev/null \
          || { dba_log "PostgreSQL did not answer, so no WAL segment was closed"; return 0; }
        for _ in $(seq 15); do
          n=$(waiting) || return 0
          [ "$n" -ne 0 ] || return 0
          sleep 1
        done
        dba_log "$n WAL segments are still waiting as PostgreSQL stops; it tries them once more itself"
      }

      cmd_base() {
        local force=$1 gen before after now
        lock
        gen=$(setup) || exit 1
        archiving_is_on || exit 1
        ensure "$gen" || exit 1
        unlock
        before=$(newest_base) || { dba_log "could not list the base backups of generation $gen"; exit 1; }
        dba_metric last_base_timestamp_seconds "$before"
        now=$(date +%s)
        if [ "$force" != 1 ] && ! has_gap && [ "$((now - before))" -lt ${toString (cfg.baseIntervalHours * 3600)} ]; then
          return 0
        fi
        # A segment dropped from here on is a gap this backup does not close.
        if [ -e "$GAP" ]; then
          mv -f "$GAP" "$GAP.closing" || { dba_log "could not move $GAP"; exit 1; }
        fi
        dba_log "base backup of generation $gen"
        stanza 6h backup --type=full || { dba_log "the base backup failed"; exit 1; }
        after=$(newest_base) || { dba_log "the backup exited 0, but the base backups could not be listed"; exit 1; }
        [ "$after" -gt "$before" ] || { dba_log "the backup exited 0, but storage lists no new base backup"; exit 1; }
        rm -f "$GAP.closing"
        dba_metric last_base_timestamp_seconds "$after"
      }

      cmd_status() {
        local gen
        lock
        gen=$(setup) || exit 1
        unlock
        echo "generation: $gen (marker $DBA_MARKER)"
        echo "prefix: ${cfg.s3.bucket}/$PREFIX/gen-$gen"
        echo "WAL segments waiting: $(waiting)"
        if has_gap; then echo "gap: yes, until the next base backup"; else echo "gap: no"; fi
        cat "$DBA_METRICS" 2>/dev/null || true
        stanza 90 info
      }

      cmd_next_generation() {
        local new
        lock
        new=$(dba_next_generation) || exit 1
        if [ "''${1:-}" != --yes ]; then
          echo "would archive this data directory as generation $new; repeat with --yes" >&2
          exit 2
        fi
        dba_write_marker "$new" || exit 1
        # Nothing more goes to the old generation. The next run writes the new one's settings.
        rm -f "$CONF" "$RUN/generation"
        dba_metric generation "$new"
        dba_metric refused 0
        dba_log "generation $new"
        unlock
        dba_start_base
      }

      case "''${1:-}" in
        push)
          if [ "''${2:-}" = --final ]; then cmd_final; else cmd_push; fi
          ;;
        base)
          if [ "''${2:-}" = --force ]; then cmd_base 1; else cmd_base 0; fi
          ;;
        status) cmd_status ;;
        next-generation) cmd_next_generation "''${2:-}" ;;
        pgbackrest)
          # pgBackRest itself, with this generation's settings: a restore, a listing.
          shift
          lock
          setup > /dev/null || exit 1
          unlock
          stanza 6h "$@"
          ;;
        *)
          echo "usage: db-archive push [--final] | base [--force] | status | next-generation [--yes] | pgbackrest <arguments>" >&2
          exit 2
          ;;
      esac
    ''
  );

  # A timer's run while PostgreSQL is down is skipped, not failed.
  whenUp = "${pkgs.systemd}/bin/systemctl is-active --quiet postgresql.service";
in
{
  imports = [ ./db-archive-common.nix ];

  options.cluster.dbArchive.postgres.queueMaxMiB = mkOption {
    type = types.nullOr (types.ints.between 32 1048576);
    default = 4096;
    description = ''
      How much closed WAL may wait for the archive before the oldest segment is
      dropped. Dropping leaves the archive with a gap until the next base
      backup, which is taken as soon as the archive takes segments again. Not
      dropping fills the disk, and PostgreSQL stops. null never drops.
    '';
  };

  config = lib.mkIf active {
    cluster.dbArchive.engines = [ "postgresql" ];
    # In the data directory: a new cluster or a restored one has no marker.
    cluster.dbArchive.markerFile = lib.mkDefault "${pg.dataDir}/db-archive.generation";

    assertions = [
      {
        assertion = cfg.s3.scheme == "https";
        message = "cluster.dbArchive archives PostgreSQL with pgBackRest, which speaks to S3 over TLS only: s3.endpoint is \"${cfg.s3.endpoint}\".";
      }
    ];

    services.postgresql.settings = {
      archive_mode = "on";
      archive_command = archiveCommand;
      # With changes to ship, a segment is closed at least this often.
      archive_timeout = cfg.flushSeconds;
      wal_level = lib.mkDefault "replica";
    };

    environment.systemPackages = [ dbArchive ];

    systemd.tmpfiles.rules = [ "d ${runDir} 0700 postgres postgres -" ];

    systemd.services.postgresql.serviceConfig.ExecStop = [
      # `+`: outside the unit's sandbox and user, as the timers' runs are.
      # `-`: a failed last push must not turn a stop into a failure.
      "-+${dbArchive}/bin/db-archive push --final"
    ];

    systemd.services.db-archive-push = {
      description = "Keep PostgreSQL's WAL archive set up, and say how it is doing";
      after = [ "postgresql.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecCondition = whenUp;
        ExecStart = "${dbArchive}/bin/db-archive push";
      };
    };
    systemd.timers.db-archive-push = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "${toString cfg.flushSeconds}s";
        # Counted from the end of a run, failed or not. OnUnitActiveSec would
        # count from a oneshot becoming active, which a failed run never does.
        OnUnitInactiveSec = "${toString cfg.flushSeconds}s";
        AccuracySec = "1s";
      };
    };

    systemd.services.db-archive-base = {
      description = "Base backup of PostgreSQL to the archive, when one is due";
      after = [ "postgresql.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecCondition = whenUp;
        ExecStart = "${dbArchive}/bin/db-archive base";
      };
    };
    systemd.timers.db-archive-base = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "3min";
        # The run is one listing unless a base backup is due, so a failed one
        # is not left for an hour.
        OnUnitInactiveSec = "15min";
        RandomizedDelaySec = "5min";
      };
    };
  };
}
