# modules/db-mariadb.nix — continuous archiving of a MariaDB to object storage.
#
# Acts where `cluster.dbArchive.enable` and `services.mysql` are both on, which is
# inside an app's container (modules/db-archive.nix turns it on there) and
# nowhere on a host. WAL-G does the transfers; the rest is here because WAL-G
# leaves it out:
#
#   - `binlog-push` uploads closed binary logs and never closes one, so a timer
#     does: every `flushSeconds`, if the GTID position moved, FLUSH BINARY LOGS,
#     push, then look for the closed file in storage. The push's exit status is
#     not that check: WAL-G uploads what comes after the log its cache names,
#     and with a cache that names the log just closed it exits 0 having
#     uploaded nothing. The cache is therefore written from this script's own
#     record each time.
#   - Binary logs numbered again from the start are refused: their names are
#     already in storage, under another history.
#   - A base backup when the generation has none or the newest is older than
#     `baseIntervalHours`, then `delete retain`, which removes the base backups
#     beyond `retainBaseBackups` and the binary logs older than the oldest kept.
#   - A last flush and push as MariaDB stops, so a clean stop loses nothing.
#
# `db-archive` (in the system path) is all of it: push, base, status,
# next-generation, generations, drop-generation, and `wal-g` for WAL-G itself
# with the same settings. See modules/db-archive-common.nix for generations.
#
# WAL-G calls its MariaDB interface unstable. checks.db-archive is what says this
# works with the pinned versions.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.cluster.dbArchive;
  my = config.services.mysql;
  active = cfg.enable && my.enable;

  isMariaDB = lib.getName my.package == lib.getName pkgs.mariadb;
  socket = my.settings.mysqld.socket or "/run/mysqld/mysqld.sock";
  logBase = "mysql-bin";
  # WAL-G keeps "the last log I uploaded" here, in the home of the user it runs
  # as, whatever HOME says. One file for every generation, so `db-archive push`
  # writes it from its own record each time and never reads it.
  rootHome = config.users.users.root.home;
  walgCache = "${rootHome}/.walg_mysql_binlogs_cache";

  dbArchive = pkgs.writeShellScriptBin "db-archive" (cfg.mutate ''
    set -euo pipefail
    shopt -s inherit_errexit
    export PATH=${
      lib.makeBinPath [
        my.package
        pkgs.wal-g-mysql
        pkgs.coreutils
        pkgs.gawk
        pkgs.gnugrep
        pkgs.jq
        pkgs.systemd
        pkgs.util-linux
      ]
    }
    . ${cfg.shellLib}

    sql() { mariadb --protocol=socket -S ${lib.escapeShellArg socket} -u root -N -B -e "$1"; }

    # walg <deadline> <path below the prefix, "" for its top> <S3 retries> <args...>
    # A subshell, so no credential outlives the call.
    walg() (
      deadline=$1 sub=$2 retries=$3
      shift 3
      key=$(dba_secret ${lib.escapeShellArg cfg.credentialFiles.encryptionKey}) || exit 1
      case "$key" in
        *[!0-9a-f]*) dba_log "the archive key is not lowercase hexadecimal"; exit 1 ;;
      esac
      [ "''${#key}" -eq 64 ] || { dba_log "the archive key is not 64 characters"; exit 1; }
      AWS_ACCESS_KEY_ID=$(dba_secret ${lib.escapeShellArg cfg.credentialFiles.accessKey}) || exit 1
      AWS_SECRET_ACCESS_KEY=$(dba_secret ${lib.escapeShellArg cfg.credentialFiles.secretKey}) || exit 1
      export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
      export WALG_LIBSODIUM_KEY=$key WALG_LIBSODIUM_KEY_TRANSFORM=hex
      export WALE_S3_PREFIX=${lib.escapeShellArg "s3://${cfg.s3.bucket}/${cfg.s3.prefix}"}''${sub:+/$sub}
      export AWS_ENDPOINT=${lib.escapeShellArg cfg.s3.endpoint}
      export AWS_REGION=${lib.escapeShellArg cfg.s3.region}
      export AWS_S3_FORCE_PATH_STYLE=true
      export WALG_S3_MAX_RETRIES=$retries
      export WALG_MYSQL_DATASOURCE_NAME=${lib.escapeShellArg "root@unix(${socket})/mysql"}
      export WALG_STREAM_CREATE_COMMAND=${lib.escapeShellArg "mariabackup --backup --stream=xbstream --datadir=${my.dataDir} --user=root --socket=${socket}"}
      export HOME=${lib.escapeShellArg rootHome}
      cd / || exit 1
      exec timeout "$deadline" wal-g-mysql "$@"
    )

    # `st ls` prints a header and one row per entry, and exits 0 on an empty
    # prefix. Anything else on stdout, or any other status, is "did not answer".
    dba_archive_entries() {
      local out
      out=$(walg 30 "" 1 st ls 2>/dev/null) || return 1
      printf '%s\n' "$out" | awk '
        NR == 1 { if ($0 !~ /^type +size +last modified +name *$/) exit 3; seen = 1; next }
        $1 == "dir" || $1 == "obj" { n = $NF; sub(/\/$/, "", n); print n; next }
        NF { exit 3 }
        END { if (!seen) exit 3 }
      '
    }

    # `st ls -r` prints the same header and a row per object: type, size, date,
    # time, zone, the zone's name, the object's name. A generation that is not
    # there is the header alone.
    dba_generation_newest() {
      local out stamps
      out=$(walg 300 "gen-$1" 1 st ls -r 2>/dev/null) || return 1
      stamps=$(printf '%s\n' "$out" | awk '
        NR == 1 { if ($0 !~ /^type +size +last modified +name *$/) exit 3; seen = 1; next }
        $1 == "dir" { next }
        $1 == "obj" && NF >= 6 && $3 ~ /^[0-9]+-[0-9]+-[0-9]+$/ && $4 ~ /^[0-9:.]+$/ && $5 ~ /^[+-][0-9]+$/ {
          print $3, $4, $5; next
        }
        NF { exit 3 }
        END { if (!seen) exit 3 }
      ') || return 1
      # An empty line would be read by `date` as today.
      [ -n "$stamps" ] || return 0
      printf '%s\n' "$stamps" | date -f - +%s | sort -n | tail -n 1
    }

    # From the top of the prefix and with the slash, so that generation 1 is
    # not also generation 10. Object versions, where the bucket keeps them, are
    # left to the bucket's own rule.
    dba_generation_remove() {
      walg 30m "" 3 st rm "gen-$1/"
    }

    # After a base backup: count the earlier generations past their time.
    survey() {
      dba_list_generations > /dev/null || dba_log "the earlier generations could not be looked over"
    }

    # When the newest complete base backup of a generation began, in epoch
    # seconds; 0 when it has none. "None" is an empty list and WAL-G saying so,
    # never just a quiet failure.
    newest_base() {
      local out err rc=0
      err=$(mktemp)
      out=$(walg 60 "gen-$1" 1 backup-list --detail --json 2>"$err") || rc=$?
      if [ "$rc" -ne 0 ]; then
        dba_log "backup-list exited $rc: $(tail -n 3 "$err" | tr '\n' ' ')"
        rm -f "$err"; return 1
      fi
      if [ -z "$out" ]; then
        if grep -q 'No backups found' "$err"; then rm -f "$err"; echo 0; return 0; fi
        dba_log "backup-list printed nothing and did not say there are none: $(tail -n 3 "$err" | tr '\n' ' ')"
        rm -f "$err"; return 1
      fi
      rm -f "$err"
      printf '%s' "$out" | jq -er '
        if type != "array" then error("not a list")
        elif length == 0 then 0
        else [ .[].backup_name
               | capture("^stream_(?<t>[0-9]{8}T[0-9]{6}Z)$").t
               | strptime("%Y%m%dT%H%M%SZ") | mktime ] | max
        end' \
        || { dba_log "backup-list printed what is not a list of backups: $(printf '%s' "$out" | head -c 300)"; return 1; }
    }

    # Is this closed log in the generation's storage? Listed, not assumed.
    in_storage() {
      local listing
      listing=$(walg 30 "gen-$1" 1 st ls binlog_005/ 2>/dev/null) || return 1
      printf '%s\n' "$listing" \
        | awk -v n="$2." '$1 == "obj" && index($NF, n) == 1 { found = 1 } END { exit !found }'
    }

    # The highest-numbered binary log in the generation's storage, or nothing
    # when it holds none. For a push that has no record of its own to go by.
    newest_in_storage() {
      local listing
      listing=$(walg 30 "gen-$1" 1 st ls binlog_005/ 2>/dev/null) || return 1
      printf '%s\n' "$listing" | awk -v base=${lib.escapeShellArg "${logBase}."} '
        NR == 1 { if ($0 !~ /^type +size +last modified +name *$/) exit 3; seen = 1; next }
        $1 == "obj" && index($NF, base) == 1 {
          n = substr($NF, length(base) + 1); sub(/\..*$/, "", n)
          if (n ~ /^[0-9]+$/ && n + 0 >= max + 0) { max = n; name = base n }
        }
        END { if (!seen) exit 3; if (name != "") print name }
      '
    }

    # The number in a binary log's name, or nothing if it is not one.
    log_number() {
      case "$1" in
        ${logBase}.*) ;;
        *) return 1 ;;
      esac
      local n=''${1#${logBase}.}
      case "$n" in "" | *[!0-9]*) return 1 ;; esac
      printf '%s\n' "$((10#$n))"
    }

    # WAL-G uploads the logs numbered after the one its cache names. The cache
    # is one file for every generation, and WAL-G drops it only when it names a
    # log beyond the newest. So each push writes it from the generation's own
    # record: that log, or no cache and so every log.
    write_walg_cache() {
      if [ -n "$1" ]; then
        printf '{"LastArchivedBinlog":"%s"}\n' "$1" > ${lib.escapeShellArg walgCache}.tmp \
          && mv ${lib.escapeShellArg walgCache}.tmp ${lib.escapeShellArg walgCache}
      else
        rm -f ${lib.escapeShellArg walgCache}
      fi
    }

    cmd_push() {
      local final=$1 gen dir pos last have have_n current closed out deadline=900 retries=3
      if [ "$final" = 1 ]; then deadline=25 retries=1; fi
      # One push at a time: the timer's and the one at stop share WAL-G's cache.
      mkdir -p "$DBA_STATE"
      exec 9> "$DBA_STATE/push.lock"
      flock -w 20 9 || { dba_log "another push is still running"; exit 1; }
      gen=$(dba_generation) || exit 1
      dir="$DBA_STATE/gen-$gen"
      mkdir -p "$dir"
      pos=$(sql 'SELECT @@gtid_binlog_pos') || { dba_log "MariaDB did not answer"; exit 1; }
      current=$(sql 'SHOW BINARY LOGS' | awk 'END { print $1 }') || exit 1
      current=$(log_number "$current") || { dba_log "SHOW BINARY LOGS named no binary log"; exit 1; }

      # $dir/pushed-binlog is the last log this generation has in storage, by
      # this script's own check; without the record, storage is asked. The log
      # being written must be a later one. If it is not, the logs were numbered
      # again from the start (RESET MASTER, a data directory put back by hand),
      # names in storage would be reused, and a restore would replay two
      # histories as one.
      have=$(cat "$dir/pushed-binlog" 2>/dev/null || true)
      if [ -z "$have" ]; then
        have=$(newest_in_storage "$gen") \
          || { dba_log "generation $gen's binary logs could not be listed"; exit 1; }
      fi
      if [ -n "$have" ]; then
        have_n=$(log_number "$have") || { dba_log "$dir/pushed-binlog does not name a binary log"; exit 1; }
        if [ "$current" -le "$have_n" ]; then
          dba_refuse "MariaDB is writing ${logBase}.$current, and generation $gen already holds $have: the binary logs were renumbered. Run: db-archive next-generation --yes"
        fi
      fi
      dba_metric refused 0

      last=$(cat "$dir/pushed-gtid" 2>/dev/null || echo none)
      if [ "$pos" = "$last" ]; then
        # Nothing was written since a push that was confirmed in storage.
        dba_metric last_ok_timestamp_seconds "$(date +%s)"
        return 0
      fi
      sql 'FLUSH BINARY LOGS' || { dba_log "FLUSH BINARY LOGS failed"; exit 1; }
      # The newest closed log is the one before the last. It holds everything up to $pos.
      closed=$(sql 'SHOW BINARY LOGS' | awk '{ prev = cur; cur = $1 } END { print prev }') || exit 1
      log_number "$closed" > /dev/null || { dba_log "no closed binary log after a flush"; exit 1; }

      write_walg_cache "$have" || { dba_log "could not write WAL-G's cache"; exit 1; }
      out=$(walg "$deadline" "gen-$gen" "$retries" binlog-push 2>&1) \
        || { printf '%s\n' "$out" >&2; dba_log "binlog-push failed"; exit 1; }
      if ! in_storage "$gen" "$closed"; then
        printf '%s\n' "$out" >&2
        dba_log "binlog-push exited 0, but $closed is not in storage, or storage could not be listed"
        exit 1
      fi
      printf '%s\n' "$closed" > "$dir/.pushed-binlog.tmp" && mv "$dir/.pushed-binlog.tmp" "$dir/pushed-binlog" \
        || { dba_log "could not record the push"; exit 1; }
      printf '%s\n' "$pos" > "$dir/.pushed-gtid.tmp" && mv "$dir/.pushed-gtid.tmp" "$dir/pushed-gtid" \
        || { dba_log "could not record the push"; exit 1; }
      dba_metric last_ok_timestamp_seconds "$(date +%s)"
    }

    cmd_base() {
      local force=$1 gen before after now
      gen=$(dba_generation) || exit 1
      before=$(newest_base "$gen") || { dba_log "could not list the base backups of generation $gen"; exit 1; }
      dba_metric last_base_timestamp_seconds "$before"
      now=$(date +%s)
      if [ "$force" != 1 ] && [ "$((now - before))" -lt ${toString (cfg.baseIntervalHours * 3600)} ]; then
        return 0
      fi
      dba_log "base backup of generation $gen"
      walg 6h "gen-$gen" 3 backup-push || { dba_log "backup-push failed"; exit 1; }
      after=$(newest_base "$gen") || { dba_log "backup-push exited 0, but the base backups could not be listed"; exit 1; }
      [ "$after" -gt "$before" ] || { dba_log "backup-push exited 0, but storage lists no new base backup"; exit 1; }
      dba_metric last_base_timestamp_seconds "$after"
      walg 30m "gen-$gen" 3 delete retain FULL ${toString cfg.retainBaseBackups} --confirm \
        || { dba_log "the base backup is in storage, but deleting older ones failed"; exit 1; }
      survey
    }

    cmd_status() {
      local gen
      gen=$(dba_generation) || exit 1
      echo "generation: $gen (marker $DBA_MARKER)"
      echo "prefix: ${cfg.s3.bucket}/${cfg.s3.prefix}/gen-$gen"
      echo "gtid_binlog_pos: $(sql 'SELECT @@gtid_binlog_pos')"
      echo "pushed and confirmed: $(cat "$DBA_STATE/gen-$gen/pushed-gtid" 2>/dev/null || echo nothing)"
      cat "$DBA_METRICS" 2>/dev/null || true
      walg 60 "gen-$gen" 1 backup-list
    }

    cmd_next_generation() {
      local new
      new=$(dba_next_generation) || exit 1
      if [ "''${1:-}" != --yes ]; then
        echo "would archive this data directory as generation $new; repeat with --yes" >&2
        exit 2
      fi
      dba_write_marker "$new" || exit 1
      dba_metric generation "$new"
      dba_metric refused 0
      dba_log "generation $new"
      dba_start_base
    }

    case "''${1:-}" in
      push)
        if [ "''${2:-}" = --final ]; then cmd_push 1; else cmd_push 0; fi
        ;;
      base)
        if [ "''${2:-}" = --force ]; then cmd_base 1; else cmd_base 0; fi
        ;;
      status) cmd_status ;;
      next-generation) cmd_next_generation "''${2:-}" ;;
      generations) dba_list_generations || exit 1 ;;
      drop-generation)
        dba_drop_generation "''${2:-}" "''${3:-}" || exit $?
        survey
        ;;
      wal-g)
        # WAL-G itself, with this generation's settings: a fetch, a listing.
        shift
        gen=$(dba_generation) || exit 1
        walg 6h "gen-$gen" 3 "$@"
        ;;
      *)
        echo "usage: db-archive push [--final] | base [--force] | status | next-generation [--yes] | generations | drop-generation <N> [--yes] | wal-g <arguments>" >&2
        exit 2
        ;;
    esac
  '');

  # A timer's run while MariaDB is down is skipped, not failed.
  whenUp = "${pkgs.systemd}/bin/systemctl is-active --quiet mysql.service";
in
{
  imports = [ ./db-archive-common.nix ];

  config = lib.mkIf active {
    cluster.dbArchive.engines = [ "mariadb" ];
    # The data directory is the mount: the marker goes down with the data.
    cluster.dbArchive.markerFile = lib.mkDefault "${my.dataDir}/db-archive.generation";

    assertions = [
      {
        assertion = isMariaDB;
        message = "cluster.dbArchive archives MariaDB, not MySQL: services.mysql.package is ${lib.getName my.package}.";
      }
    ];

    services.mysql.settings.mysqld = {
      log_bin = logBase;
      binlog_format = "ROW";
      # A commit is in the binary log, on disk, before the client hears of it.
      sync_binlog = 1;
      gtid_strict_mode = "ON";
      server_id = lib.mkDefault 1;
      # The archive is where logs are kept; this bounds what stays on the disk.
      binlog_expire_logs_seconds = lib.mkDefault 259200;
    };

    environment.systemPackages = [ dbArchive ];

    systemd.services.mysql.serviceConfig.ExecStop = [
      # `+`: outside the unit's sandbox and user, as the timers' runs are.
      # `-`: a failed last push must not turn a stop into a failure.
      "-+${dbArchive}/bin/db-archive push --final"
    ];

    systemd.services.db-archive-push = {
      description = "Ship MariaDB's binary logs to the archive";
      after = [ "mysql.service" ];
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
      description = "Base backup of MariaDB to the archive, when one is due";
      after = [ "mysql.service" ];
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
