# modules/db-archive-common.nix — what the two database archivers share.
#
# Runs where the database runs: inside an app's container, or in any NixOS
# system that imports modules/db-mariadb.nix or modules/db-postgres.nix (the VM
# test does). It uses no clan vars and nothing of the host: credentials are
# files, and modules/db-archive.nix is what points them at an app's secrets.
#
# The archive of one database is `<bucket>/<prefix>/gen-<N>/`: a base backup and
# every change since, encrypted before it leaves. N is the generation of the data
# directory, kept in a marker file beside the data, so the two are lost together.
# A data directory with no marker may only start generation 1 on an archive that
# was listed and found empty. An archive that holds data, or one that could not
# be listed, stops the archiver with `cluster_db_archive_refused 1`: appending
# another history to a generation would leave a restore that replays both.
#
# Within its generation a database keeps `retainBaseBackups` base backups, and so
# reaches back `(retainBaseBackups - 1) * baseIntervalHours`: seven days as set.
# An earlier generation is kept for as long after its last write, and then
# `db-archive drop-generation <N> --yes` deletes it. Nothing deletes one unasked.
#
# Five metrics, written to `metricsFile` without labels:
#   cluster_db_archive_last_ok_timestamp_seconds    everything written so far was
#                                                   found in storage at this time
#   cluster_db_archive_last_base_timestamp_seconds  the newest base backup
#   cluster_db_archive_generation                   N
#   cluster_db_archive_refused                      1 while the archiver refuses
#   cluster_db_archive_droppable_generations        earlier generations past their
#                                                   time, as of the last base backup
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.cluster.dbArchive;

  nullOrPath = mkOption {
    type = types.nullOr types.str;
    default = null;
  };

  # `scheme://host[:port]`, nothing after it.
  endpointParts = builtins.match "(https?)://([^/:]+)(:([0-9]+))?/?" cfg.s3.endpoint;

  shellLib = pkgs.writeText "db-archive-lib.sh" (cfg.mutate ''
    # Sourced by the engine's `db-archive` under `set -euo pipefail`. The engine
    # defines three functions, each with a non-zero status when storage did not
    # answer:
    #   dba_archive_entries        the names at the top of this database's
    #                              prefix, one per line
    #   dba_generation_newest <N>  when generation N's newest object was written,
    #                              in epoch seconds; nothing when it holds none
    #   dba_generation_remove <N>  delete every object of generation N
    #
    # Every step that decides something tests its own status. `set -e` is off
    # inside anything called on the left of `||`, which is how these are called.
    DBA_STATE=${lib.escapeShellArg cfg.stateDir}
    DBA_METRICS=${lib.escapeShellArg cfg.metricsFile}
    DBA_MARKER=${lib.escapeShellArg cfg.markerFile}
    # How far back a restore reaches inside one generation, in seconds: from the
    # oldest base backup kept.
    DBA_WINDOW=${toString ((cfg.retainBaseBackups - 1) * cfg.baseIntervalHours * 3600)}

    dba_log() { echo "db-archive: $*" >&2; }

    # A metric is one file, so each job updates its own and the published file
    # always carries all of them. Written then renamed: a reader never sees half.
    dba_metric() {
      mkdir -p "$DBA_STATE/metrics"
      printf '%s\n' "$2" > "$DBA_STATE/metrics/.$1.tmp"
      mv "$DBA_STATE/metrics/.$1.tmp" "$DBA_STATE/metrics/$1"
      dba_publish
    }

    dba_publish() {
      local dir tmp f
      dir=$(dirname "$DBA_METRICS")
      mkdir -p "$dir"
      tmp=$(mktemp "$dir/.metrics.XXXXXX")
      for f in "$DBA_STATE"/metrics/*; do
        [ -f "$f" ] || continue
        printf 'cluster_db_archive_%s %s\n' "''${f##*/}" "$(cat "$f")"
      done > "$tmp"
      chmod 0644 "$tmp"
      mv "$tmp" "$DBA_METRICS"
    }

    dba_refuse() {
      dba_log "REFUSED: $*"
      dba_metric refused 1
      exit 1
    }

    # A credential, which must exist and hold something: an empty encryption key
    # would have the tools upload plaintext without a word.
    dba_secret() {
      local v
      [ -r "$1" ] || { dba_log "cannot read $1"; exit 1; }
      v=$(tr -d '\n' < "$1")
      [ -n "$v" ] || { dba_log "$1 is empty"; exit 1; }
      printf '%s' "$v"
    }

    # One chain: callers test its status, and `set -e` does not reach into a
    # function whose status is being tested.
    dba_write_marker() {
      local dir
      dir=$(dirname "$DBA_MARKER") \
        && printf '%s\n' "$1" > "$dir/.db-archive-generation.tmp" \
        && sync "$dir/.db-archive-generation.tmp" \
        && mv "$dir/.db-archive-generation.tmp" "$DBA_MARKER" \
        && sync "$dir"
    }

    # The generation this data directory archives under, on stdout. A refusal
    # sets `refused 1`; the caller sets it back to 0 once it is past its own.
    dba_generation() {
      local g entries
      if [ -e "$DBA_MARKER" ]; then
        g=$(cat "$DBA_MARKER") || dba_refuse "$DBA_MARKER could not be read"
        case "$g" in
          "" | 0* | *[!0-9]*) dba_refuse "$DBA_MARKER does not hold a generation number" ;;
        esac
      else
        entries=$(dba_archive_entries) \
          || dba_refuse "$DBA_MARKER is missing and the archive could not be listed, so it is not known to be empty"
        if [ -n "$entries" ]; then
          dba_refuse "$DBA_MARKER is missing and the archive already holds data. If this data directory is the one to keep archiving, run: db-archive next-generation --yes"
        fi
        g=1
        dba_write_marker "$g" || dba_refuse "$DBA_MARKER could not be written"
        dba_log "the archive is empty: this data directory starts generation 1"
        dba_start_base
      fi
      dba_metric generation "$g"
      printf '%s\n' "$g"
    }

    # A generation is restorable from its first base backup on, so a new one
    # does not wait for the timer. Both engines name the unit the same.
    dba_start_base() {
      systemctl start --no-block db-archive-base.service \
        || dba_log "could not start db-archive-base.service; its timer will"
    }

    # One past every generation the archive or the marker has seen.
    dba_next_generation() {
      local entries e n max=0
      entries=$(dba_archive_entries) || { dba_log "the archive could not be listed"; return 1; }
      for e in $entries; do
        case "$e" in
          gen-*)
            n=''${e#gen-}
            case "$n" in "" | *[!0-9]*) continue ;; esac
            [ "$n" -le "$max" ] || max=$n
            ;;
        esac
      done
      if [ -e "$DBA_MARKER" ]; then
        n=$(cat "$DBA_MARKER") || { dba_log "$DBA_MARKER could not be read"; return 1; }
        case "$n" in "" | *[!0-9]*) n=0 ;; esac
        [ "$n" -le "$max" ] || max=$n
      fi
      printf '%s\n' "$((max + 1))"
    }

    # ── earlier generations ─────────────────────────────────────────────────

    dba_when() { date -u -d "@$1" '+%Y-%m-%d %H:%M UTC'; }

    # Was this moment longer ago than a restore reaches back? A moment in the
    # future was not.
    dba_past_window() { [ "$(($(date +%s) - $1))" -ge "$DBA_WINDOW" ]; }

    # dba_generation_newest's answer, taken only as a number or as nothing.
    dba_newest() {
      local t
      t=$(dba_generation_newest "$1") || return 1
      case "$t" in *[!0-9]*) return 1 ;; esac
      printf '%s\n' "$t"
    }

    # The marker's generation, without starting one.
    dba_marker_generation() {
      local g
      [ -e "$DBA_MARKER" ] || { dba_log "$DBA_MARKER is missing: this data directory has no generation yet"; return 1; }
      g=$(cat "$DBA_MARKER") || { dba_log "$DBA_MARKER could not be read"; return 1; }
      case "$g" in
        "" | 0* | *[!0-9]*) dba_log "$DBA_MARKER does not hold a generation number"; return 1 ;;
      esac
      printf '%s\n' "$g"
    }

    # Every generation in the archive, one per line, and what may be done with
    # it. Also counts the ones past their time for the metric.
    dba_list_generations() {
      local cur entries e n newest count=0
      cur=$(dba_marker_generation) || return 1
      entries=$(dba_archive_entries) || { dba_log "the archive could not be listed"; return 1; }
      for e in $entries; do
        case "$e" in
          gen-*) n=''${e#gen-} ;;
          *) continue ;;
        esac
        case "$n" in "" | 0* | *[!0-9]*) continue ;; esac
        newest=$(dba_newest "$n") || { dba_log "generation $n could not be listed"; return 1; }
        if [ -z "$newest" ]; then
          echo "gen-$n: holds nothing"
        elif [ "$n" -eq "$cur" ]; then
          echo "gen-$n: this data directory's, last written $(dba_when "$newest")"
        elif [ "$n" -gt "$cur" ]; then
          echo "gen-$n: later than this data directory's, last written $(dba_when "$newest"). Not dropped from here"
        elif dba_past_window "$newest"; then
          count=$((count + 1))
          echo "gen-$n: last written $(dba_when "$newest"). Can be dropped: db-archive drop-generation $n --yes"
        else
          echo "gen-$n: last written $(dba_when "$newest"), kept until $(dba_when "$((newest + DBA_WINDOW))")"
        fi
      done
      dba_metric droppable_generations "$count"
    }

    # dba_drop_generation <N> [--yes]: delete an earlier generation that nothing
    # inside the window can need. Never this data directory's own, and never a
    # later one: that is another node's, written since this one was current.
    # "Could not be listed" is not "old".
    dba_drop_generation() {
      local n=$1 yes=''${2:-} cur newest
      case "$n" in
        "" | 0* | *[!0-9]*) dba_log "drop-generation takes a generation's number"; return 2 ;;
      esac
      cur=$(dba_marker_generation) || return 1
      if [ "$n" -ge "$cur" ]; then
        dba_log "generation $n is not an earlier one than this data directory's, which is $cur. It is not dropped from here"
        return 1
      fi
      newest=$(dba_newest "$n") \
        || { dba_log "generation $n could not be listed, so when it was last written is not known"; return 1; }
      [ -n "$newest" ] || { dba_log "generation $n holds nothing"; return 0; }
      if ! dba_past_window "$newest"; then
        dba_log "generation $n was last written $(dba_when "$newest"), inside the $((DBA_WINDOW / 3600)) hours a restore reaches back. It can be dropped from $(dba_when "$((newest + DBA_WINDOW))")"
        return 1
      fi
      if [ "$yes" != --yes ]; then
        echo "would delete every object of generation $n, last written $(dba_when "$newest"); repeat with --yes" >&2
        return 2
      fi
      dba_log "deleting generation $n"
      dba_generation_remove "$n" \
        || { dba_log "deleting generation $n failed. What is left of it may not restore"; return 1; }
      newest=$(dba_newest "$n") \
        || { dba_log "generation $n was deleted, and could not be listed afterwards"; return 1; }
      [ -z "$newest" ] || { dba_log "generation $n still holds objects after the delete"; return 1; }
      dba_log "generation $n dropped"
    }
  '');
in
{
  options.cluster.dbArchive = {
    enable = lib.mkEnableOption "continuous, client-side encrypted archiving of this system's database to object storage";

    s3 = {
      endpoint = mkOption {
        type = types.str;
        example = "https://s3.example.net";
        description = "The S3 endpoint: scheme, host and optional port, with no path.";
      };
      region = mkOption {
        type = types.str;
        description = "The region the endpoint signs requests for.";
      };
      bucket = mkOption {
        type = types.str;
        description = "The bucket, which must exist: the archiver creates none.";
      };
      prefix = mkOption {
        type = types.strMatching "[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*";
        description = "This database's own path in the bucket. Generations are `gen-<N>` below it.";
      };
      verifyTls = mkOption {
        type = types.bool;
        default = true;
        description = "Off only for a test's self-signed endpoint.";
      };
      scheme = mkOption {
        type = types.str;
        readOnly = true;
        default = if endpointParts == null then "" else builtins.elemAt endpointParts 0;
      };
      host = mkOption {
        type = types.str;
        readOnly = true;
        default = if endpointParts == null then "" else builtins.elemAt endpointParts 1;
      };
      port = mkOption {
        type = types.port;
        readOnly = true;
        default =
          if endpointParts == null then
            443
          else if builtins.elemAt endpointParts 3 != null then
            lib.toInt (builtins.elemAt endpointParts 3)
          else if builtins.elemAt endpointParts 0 == "https" then
            443
          else
            80;
      };
    };

    credentialFiles = {
      accessKey = nullOrPath // {
        description = "File holding the S3 access key.";
      };
      secretKey = nullOrPath // {
        description = "File holding the S3 secret key.";
      };
      encryptionKey = nullOrPath // {
        description = ''
          File holding this database's archive key: 64 hexadecimal characters.
          Nothing is uploaded without it, and nothing uploaded can be read
          without it, so it is kept wherever the backups' own passwords are.
        '';
      };
    };

    flushSeconds = mkOption {
      type = types.ints.between 10 3600;
      default = 60;
    };
    baseIntervalHours = mkOption {
      type = types.ints.between 1 168;
      default = 24;
    };
    retainBaseBackups = mkOption {
      type = types.ints.between 2 30;
      default = 8;
    };

    stateDir = mkOption {
      type = types.str;
      default = "/var/lib/db-archive";
      description = "The archiver's own bookkeeping. Losing it costs a re-upload, never data.";
    };
    metricsFile = mkOption {
      type = types.str;
      default = "/run/db-archive/metrics.prom";
      description = "Prometheus text, `cluster_db_archive_*` without labels. Whoever collects it adds them.";
    };
    markerFile = mkOption {
      type = types.str;
      description = "The generation marker. On the same filesystem as the data directory, so they are lost together.";
    };

    engines = mkOption {
      type = types.listOf types.str;
      default = [ ];
      internal = true;
      description = "Set by the engine modules: which databases are archived here.";
    };
    shellLib = mkOption {
      type = types.path;
      internal = true;
      readOnly = true;
      default = shellLib;
    };
    mutate = mkOption {
      type = types.functionTo types.str;
      internal = true;
      default = lib.id;
      description = "Edits the archiver's shell text. Set only by flake.nix's db-archive-* mutants.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.length cfg.engines == 1;
        message = "cluster.dbArchive.enable needs exactly one database in this system (services.mysql with MariaDB, or services.postgresql); found: ${
          if cfg.engines == [ ] then "none" else lib.concatStringsSep ", " cfg.engines
        }.";
      }
      {
        assertion = cfg.credentialFiles.encryptionKey != null;
        message = "cluster.dbArchive.credentialFiles.encryptionKey is not set. The archive is encrypted before it leaves the machine, always: there is no unencrypted mode.";
      }
      {
        assertion = cfg.credentialFiles.accessKey != null && cfg.credentialFiles.secretKey != null;
        message = "cluster.dbArchive.credentialFiles.accessKey and .secretKey must both be set.";
      }
      {
        assertion = endpointParts != null;
        message = "cluster.dbArchive.s3.endpoint must be scheme://host[:port] with no path, not \"${cfg.s3.endpoint}\".";
      }
    ];

    systemd.tmpfiles.rules = [
      "d ${cfg.stateDir} 0700 root root -"
      "d ${dirOf cfg.metricsFile} 0755 root root -"
    ];
  };
}
