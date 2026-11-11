# modules/backup-core.nix — per-app backups, restore and restore rehearsal.
#
# The clan-independent half of the backup system. modules/backup.nix imports
# it and supplies the credentials from clan vars; tests/backup-roundtrip.nix
# imports it directly with plain files and an S3 server inside the VM.
#
# ── what an app's backup is ─────────────────────────────────────────────────
# One restic snapshot per run, in the app's OWN repository
# (<topology.backup.target>/<cluster.backup.repoPathFor app>, --host <app>), holding:
#
#   - a LOGICAL dump of its database, taken inside the running container with
#     the container's own tools (pg_dumpall --globals-only + pg_dump -Fc -Z0 per
#     database; mariadb-dump --system=users + --databases per database), and
#   - its JuiceFS paths, read live.
#
# In the same snapshot, so a restore brings back a database and the files it
# references together.
#
# NOT the raw database directory. The off-site copy must survive a database
# major-version bump and a new node, which only a dump does, and raw database
# files dedup badly. The raw copy the old backup.nix shipped was also taken
# live, file by file -- restorable only by luck. Fast local rollback is what
# the 15-minute ZFS auto-snapshots of rpool/state are for.
#
# The exception is state no dump covers -- a directory server with its CA
# and Kerberos master keys. With backup.localSnapshot, the app's localState
# directories go into the same snapshot, read from a ZFS snapshot taken for
# the run (atomic, so crash-consistent with the app still up), after an
# optional backup.preCommand has had the app export itself into them.
#
# A repository per app, not per host: an app's backups are found by its name
# from any node, and dropping a client is dropping one prefix. The prefix is
# `apps/<app>` here; modules/backup.nix makes it a salted hash of the name
# (lib/backup-target.nix appRepoPath), so the storage provider does not see app names.
# `cluster-backup-list` prints each app's repository, which is how an operator maps a
# hash back to an app. `--host <app>` stays: it is inside the encrypted snapshot.
#
# What is plaintext, and where: the staging, verify and restore directories
# (/var/lib/cluster-backup, its cache) hold dumps and files in the clear while a run
# uses them, and until the next run replaces them. They are on the node's root pool,
# which is LUKS on a node that has not opted out of boot security, and plaintext on
# one that has. Nothing of them leaves the node except through restic, encrypted.
#
# ── where it runs ───────────────────────────────────────────────────────────
# An app is backed up on its homeNode -- the only node its database can be
# dumped on (monolith/split tiers are pinned there; so is every WordPress site,
# lib/mk-wordpress-site.nix). An unpinned app falls back to the node tagged
# `backup`. While a backup or restore runs, pull-deploys are held
# (/run/cluster-upgrade.hold.d, modules/pull-deploy-core.nix): a deploy reloads the
# container, which restarts the very units a dump is reading from.
#
# ── not the clan backups provider ───────────────────────────────────────────
# clan's contract is "restore these folders from this snapshot": no app
# argument, and no way to say "stop the app's units, drop and re-import the
# database, start them again". Delegating to it would be lossy, so the verbs
# are ours: cluster-backup, cluster-backup-list, cluster-restore.
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  ...
}:
let
  cfg = config.cluster.backup;
  bcfg = topology.backup;
  target = bcfg.target;
  bt = clusterLib.backupTarget;
  jfsMount = clusterLib.juicefs.mountPoint;

  isBackupNode = builtins.elem "backup" (node.tags or [ ]);

  # Apps whose backup runs on THIS node.
  apps = lib.filterAttrs (
    _n: app:
    app.backup.enable && (if app.homeNode != null then app.homeNode == nodeName else isBackupNode)
  ) config.clusterApps;
  appNames = lib.attrNames apps;

  guest = n: config.containers.${n}.config;

  engineOf =
    n: app:
    if app.backup.engine != null then
      app.backup.engine
    else if (guest n).services.postgresql.enable then
      "postgresql"
    else if (guest n).services.mysql.enable then
      "mariadb"
    else
      "none";

  dbUnits = {
    postgresql = [
      "postgresql.service"
      "postgresql.target"
      "postgresql-setup.service"
    ];
    mariadb = [ "mysql.service" ];
    none = [ ];
  };

  # Units to stop while the database is restored: everything ordered after (or
  # depending on) the database, transitively. Detected from the container's
  # own config, so an app gains no bookkeeping when it grows a unit.
  appUnitsOf =
    n: app: engine:
    if app.backup.appUnits != null then
      app.backup.appUnits
    else if engine == "none" then
      [ ]
    else
      let
        svcs = (guest n).systemd.services;
        db = dbUnits.${engine};
        names = lib.filter (x: !(lib.elem "${x}.service" db)) (lib.attrNames svcs);
        deps =
          x:
          let
            s = svcs.${x};
          in
          (s.after or [ ]) ++ (s.requires or [ ]) ++ (s.wants or [ ]) ++ (s.bindsTo or [ ]);
        grow =
          acc:
          let
            next = lib.unique (
              acc ++ map (x: "${x}.service") (lib.filter (x: lib.any (d: lib.elem d (db ++ acc)) (deps x)) names)
            );
          in
          if lib.length next == lib.length acc then acc else grow next;
      in
      grow [ ];

  dbPackage =
    n: engine:
    if engine == "postgresql" then
      (guest n).services.postgresql.finalPackage or (guest n).services.postgresql.package
    else
      (guest n).services.mysql.package;

  defaultExcludes = [
    # Odoo: login sessions, and the pre-migrate snapshots odoo-nix keeps -- the
    # database is already in this very snapshot as a dump.
    "*/sessions"
    "*/backups/*/premigrate"
    # frappe-nix's pre-migrate snapshots, for the same reason.
    "*/snapshots/premigrate-*"
  ];

  stagingRoot = "/var/lib/cluster-backup/staging";
  metricsDir = "/var/lib/prometheus-node-exporter-text";
  holdDir = "/run/cluster-upgrade.hold.d";

  # ── the database side, run INSIDE the container ────────────────────────────
  # `nixos-container run <n> -- <script> <args>` single-quotes each argument and
  # execs it as root through `su -l -c`, with stdin/stdout passed through; the
  # host's /nix/store is the container's, so the script can be a host-built
  # store path calling the container's own database binaries.
  dbScript =
    n: engine:
    let
      pkg = dbPackage n engine;
      runuser = "${pkgs.util-linux}/bin/runuser";
    in
    pkgs.writeShellScript "cluster-backup-db-${n}" (
      if engine == "postgresql" then
        ''
          set -euo pipefail
          export PATH=${pkg}/bin:${pkgs.coreutils}/bin
          as_pg() { ${runuser} -u postgres -- "$@"; }
          case "$1" in
            list)       as_pg psql -XAtc "select datname from pg_database where not datistemplate and datname <> 'postgres' order by 1" ;;
            globals)    as_pg pg_dumpall --globals-only ;;
            dump)       as_pg pg_dump -Fc -Z0 --dbname="$2" ;;
            tables)     as_pg psql -XAtd "$2" -c "select count(*) from information_schema.tables where table_schema not in ('pg_catalog','information_schema')" ;;
            terminate)  as_pg psql -XAtqc "select pg_terminate_backend(pid) from pg_stat_activity where datname = '$2' and pid <> pg_backend_pid()" >/dev/null ;;
            restore-globals) as_pg psql -X -q -v ON_ERROR_STOP=0 -d postgres >/dev/null ;;
            restore)    as_pg dropdb --if-exists --force "$2"
                        as_pg pg_restore --create --exit-on-error -d postgres ;;
            *) echo "cluster-backup-db: unknown action $1" >&2; exit 2 ;;
          esac
        ''
      else
        ''
          set -euo pipefail
          export PATH=${pkg}/bin:${pkgs.coreutils}/bin:${pkgs.gnugrep}/bin:${pkgs.gnused}/bin
          case "$1" in
            list)       mariadb -N -B -e 'show databases' | grep -vxE 'information_schema|performance_schema|mysql|sys' || true ;;
            # Users are NixOS-managed and not restored automatically; this is
            # for a human. MariaDB 11.4's own --system=users trips over a
            # collation mix in its query ("Illegal mix of collations" on
            # is_role='N'), so fall back to SHOW CREATE USER / SHOW GRANTS,
            # filtering roles in the shell rather than in SQL.
            globals)    mariadb-dump --system=users 2>/dev/null || {
                          echo "-- users via SHOW CREATE USER / SHOW GRANTS"
                          mariadb -N -B -e "select user, host, is_role from mysql.user" \
                            | while IFS=$'\t' read -r u h role; do
                                [ "$role" = Y ] && continue
                                mariadb -N -B -e "show create user '$u'@'$h'" 2>/dev/null | sed 's/$/;/' || true
                                mariadb -N -B -e "show grants for '$u'@'$h'" 2>/dev/null | sed 's/$/;/' || true
                              done
                        } ;;
            dump)       mariadb-dump --single-transaction --routines --triggers --events --databases "$2" ;;
            tables)     mariadb -N -B -e "select count(*) from information_schema.tables where table_schema = '$2'" ;;
            terminate)  mariadb -N -B -e "select id from information_schema.processlist where db = '$2' and id <> connection_id()" \
                          | while read -r id; do mariadb -e "kill $id" || true; done ;;
            restore-globals) cat >/dev/null ;; # users are NixOS-managed; users.sql stays in the snapshot for manual use
            restore)    mariadb -e "drop database if exists \`$2\`"
                        mariadb ;;
            *) echo "cluster-backup-db: unknown action $1" >&2; exit 2 ;;
          esac
        ''
    );

  dumpExt = engine: if engine == "postgresql" then "dump" else "sql";

  # ── per-app profile: everything the host-side scripts need to know ─────────
  profile =
    n: app:
    let
      engine = engineOf n app;
      jfsPaths = map (sub: "${jfsMount}/${sub}") (lib.attrValues app.juicefsPaths);
      localPaths = lib.attrValues app.localState;
      guestDataDir =
        if engine == "postgresql" then
          (guest n).services.postgresql.dataDir
        else if engine == "mariadb" then
          (guest n).services.mysql.dataDir
        else
          "";
    in
    pkgs.writeText "cluster-backup-profile-${n}" ''
      APP=${lib.escapeShellArg n}
      ENGINE=${engine}
      EXT=${dumpExt engine}
      DB_SCRIPT=${if engine == "none" then "" else dbScript n engine}
      DB_UNIT=${lib.escapeShellArg (lib.head (dbUnits.${engine} ++ [ "" ]))}
      GUEST_DATADIR=${lib.escapeShellArg guestDataDir}
      APP_UNITS=(${lib.escapeShellArgs (appUnitsOf n app engine)})
      JFS_PATHS=(${lib.escapeShellArgs jfsPaths})
      LOCAL_PATHS=(${lib.escapeShellArgs localPaths})
      EXCLUDES=(${
        lib.escapeShellArgs (map (e: "--exclude=${e}") (defaultExcludes ++ app.backup.exclude))
      })
      VERIFY_QUERY=${
        lib.escapeShellArg (if app.backup.verifyQuery != null then app.backup.verifyQuery else "")
      }
      LOCAL_SNAPSHOT=${if app.backup.localSnapshot then "1" else "0"}
      PRE_SCRIPT=${
        lib.optionalString (app.backup.preCommand != null) (
          pkgs.writeShellScript "cluster-backup-pre-${n}" ''
            set -euo pipefail
            ${app.backup.preCommand}
          ''
        )
      }
      VERIFY_LOCAL=${
        lib.optionalString (app.backup.verifyCommand != null) (
          pkgs.writeShellScript "cluster-backup-verify-local-${n}" ''
            set -euo pipefail
            ${app.backup.verifyCommand}
          ''
        )
      }
      declare -A LOCAL_GUEST=(${
        lib.concatStringsSep " " (
          lib.mapAttrsToList (g: h: "[${lib.escapeShellArg h}]=${lib.escapeShellArg g}") app.localState
        )
      })
      export RESTIC_REPOSITORY=${lib.escapeShellArg (bt.repository target (cfg.repoPathFor n))}
      STAGING=${stagingRoot}/${n}
    '';

  profiles = lib.mapAttrs profile apps;

  # ── shared shell library ───────────────────────────────────────────────────
  common = pkgs.writeText "cluster-backup-common.sh" ''
    export PATH=${
      lib.makeBinPath [
        pkgs.restic
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gnused
        pkgs.jq
        pkgs.rsync
        pkgs.util-linux
        pkgs.systemd
        pkgs.findutils
        pkgs.gawk
        config.boot.zfs.package
      ]
    }:/run/current-system/sw/bin

    # Credentials arrive through systemd LoadCredential -- never in the store,
    # never in any environment but this process tree.
    export RESTIC_PASSWORD_FILE="$CREDENTIALS_DIRECTORY/restic-password"
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (
        var: which: ''${var}=$(cat "$CREDENTIALS_DIRECTORY/backup-${which}"); export ${var}''
      ) (bt.credentialEnv target)
    )}
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (var: val: "export ${var}=${lib.escapeShellArg val}") (bt.env target)
    )}
    export RESTIC_CACHE_DIR=/var/cache/cluster-backup
    mkdir -p "$RESTIC_CACHE_DIR"

    RESTIC_OPTS=(${
      lib.escapeShellArgs (
        lib.concatMap (o: [
          "-o"
          o
        ]) (bt.options target)
      )
    })
    r() { restic "''${RESTIC_OPTS[@]}" "$@"; }

    # The repository of a new app does not exist yet. restic exits 10 for
    # exactly that; anything else (wrong password 12, unreachable 1) is an
    # error and must not be papered over by an init.
    ensure_repo() {
      local rc=0
      r cat config >/dev/null 2>&1 || rc=$?
      case "$rc" in
        0) ;;
        10) echo "$APP: initialising repository $RESTIC_REPOSITORY"; r init ;;
        *) echo "$APP: repository $RESTIC_REPOSITORY unusable (restic exit $rc)" >&2; return 1 ;;
      esac
    }

    # node_exporter textfile collector: write-then-rename so a scrape never
    # reads half a file.
    metric() { # file, then lines
      local f="${metricsDir}/$1.prom"; shift
      mkdir -p ${metricsDir}
      printf '%s\n' "$@" > "$f.tmp"
      mv "$f.tmp" "$f"
    }

    hold() { mkdir -p ${holdDir}; touch "${holdDir}/$1"; }
    unhold() { rm -f "${holdDir}/$1"; }

    # A deploy already underway would reload the container mid-dump.
    wait_for_deploy() {
      local i
      for i in $(seq 1 180); do
        systemctl is-active --quiet cluster-upgrade.service || return 0
        [ "$i" = 1 ] && echo "waiting for the running deploy to finish"
        sleep 10
      done
      echo "a deploy has been running for 30 minutes; giving up" >&2
      return 1
    }

    in_guest() { nixos-container run "$APP" -- "$DB_SCRIPT" "$@"; }

    # A command as a transient unit of the GUEST's systemd. `nixos-container
    # run` leaves its command in the host's session cgroup, outside the
    # container's cgroup tree, and from there `podman exec` cannot enter a
    # podman container (crun: .../cgroup.procs: No such file or directory).
    # A unit gets no PATH of its own, hence the explicit one; and its command
    # is found on systemd's fixed search path, not that PATH, so it must be
    # absolute (a preCommand is: a store path).
    in_guest_unit() {
      systemd-run -M "$APP" --pipe --wait --quiet --collect \
        -E PATH=/run/wrappers/bin:/run/current-system/sw/bin -- "$@"
    }

    # ── local state, read from a ZFS snapshot (backup.localSnapshot) ────────
    # One snapshot per dataset under the app's localState, with a FIXED name:
    # restic picks a backup's parent by its paths, so a path that stays the
    # same from run to run is what keeps every run after the first
    # incremental. Mountpoints are asked of findmnt rather than of zfs: the
    # datasets are legacy-mounted (lib/disk-layout.nix). Each directory's
    # live and snapshot paths go into $STAGING/local-paths, which restore and
    # rehearsal read back -- so neither has to re-derive where it came from.
    SNAP_DATASETS=()
    snapshot_local() {
      local p ds mnt fstype rel snap="cluster-backup-$APP"
      local -A taken=()
      SNAP_PATHS=()
      : > "$STAGING/local-paths"
      for p in "''${LOCAL_PATHS[@]}"; do
        [ -d "$p" ] || { echo "$APP: warning: $p does not exist; skipped" >&2; continue; }
        read -r ds mnt fstype < <(findmnt -n -o SOURCE,TARGET,FSTYPE -T "$p")
        [ "$fstype" = zfs ] || { echo "$APP: $p is on $fstype, not ZFS; cannot snapshot it" >&2; return 1; }
        if [ -z "''${taken[$ds]:-}" ]; then
          # A run that died before its cleanup left the snapshot behind.
          umount "''${mnt%/}/.zfs/snapshot/$snap" 2>/dev/null || true
          zfs destroy "$ds@$snap" 2>/dev/null || true
          zfs snapshot "$ds@$snap" || return 1
          taken[$ds]=1
          SNAP_DATASETS+=("$ds:$mnt")
        fi
        rel=''${p#"''${mnt%/}"}
        printf '%s\t%s\n' "$p" "''${mnt%/}/.zfs/snapshot/$snap$rel" >> "$STAGING/local-paths"
        SNAP_PATHS+=("''${mnt%/}/.zfs/snapshot/$snap$rel")
      done
      [ "''${#SNAP_PATHS[@]}" -gt 0 ] || { echo "$APP: no local state to snapshot" >&2; return 1; }
    }
    release_local() {
      local e snap="cluster-backup-$APP"
      for e in "''${SNAP_DATASETS[@]}"; do
        umount "''${e#*:}/.zfs/snapshot/$snap" 2>/dev/null || true
        zfs destroy "''${e%%:*}@$snap" || echo "$APP: warning: could not destroy ''${e%%:*}@$snap" >&2
      done
      SNAP_DATASETS=()
    }

    # restic and rsync read the same exclude pattern differently -- restic's
    # `*/sessions` matches a `sessions` right under the backed-up path, but
    # rsync's needs a directory above it -- so translate for a restore into
    # $1: an unanchored pattern loses its leading `*/` (rsync matches
    # unanchored patterns against the END of the path, at any depth), an
    # absolute one under $1 is anchored to the transfer root, and one
    # elsewhere does not apply. Result in REX.
    rsync_excludes() {
      local e
      REX=()
      for e in "''${EXCLUDES[@]#--exclude=}"; do
        if [[ "$e" == /* ]]; then
          [[ "$e" == "$1"/* ]] && REX+=("--exclude=/''${e#"$1"/}")
        else
          while [[ "$e" == '*/'* ]]; do e=''${e#'*/'}; done
          REX+=("--exclude=$e")
        fi
      done
    }
  '';

  # ── backup ─────────────────────────────────────────────────────────────────
  backupScript = pkgs.writeShellScript "cluster-backup-app" ''
    set -uo pipefail
    source ${common}
    source "$1"
    start=$(date +%s)
    status() { # 1 ok, 2 partial, 0 failed
      metric "cluster_backup_''${APP}_run" \
        "cluster_backup_last_run_timestamp_seconds{app=\"$APP\"} $(date +%s)" \
        "cluster_backup_last_status{app=\"$APP\"} $1"
    }
    fail() { echo "$APP: backup FAILED: $*" >&2; status 0; exit 1; }
    trap 'release_local; unhold "backup-$APP"' EXIT

    wait_for_deploy || fail "deploy in progress"
    hold "backup-$APP"
    ensure_repo || fail "repository"
    r unlock >/dev/null 2>&1 || true

    paths=()
    if [ "$ENGINE" != none ] || [ "$LOCAL_SNAPSHOT" = 1 ]; then
      rm -rf "$STAGING"; mkdir -p "$STAGING"; chmod 0700 "$STAGING"
      paths+=("$STAGING")
    fi
    if [ "$ENGINE" != none ]; then
      systemctl is-active --quiet "container@$APP" \
        || fail "container not running on $(hostname), so its database cannot be dumped"
      dbs=$(in_guest list) || fail "listing databases"
      [ -n "$dbs" ] || fail "no databases found"
      printf '%s\n' "$dbs" > "$STAGING/databases"
      in_guest globals > "$STAGING/globals.sql" || fail "dumping globals"
      while read -r db; do
        [ -n "$db" ] || continue
        in_guest dump "$db" > "$STAGING/$db.$EXT" || fail "dumping database $db"
        # What the rehearsal compares a restore against. Counted after the
        # dump: a table created in between is in neither, not in one only.
        n=$(in_guest tables "$db") || fail "counting tables in $db"
        printf '%s\t%s\n' "$db" "$n" >> "$STAGING/tables"
        echo "$APP: dumped $db ($n tables, $(du -h "$STAGING/$db.$EXT" | cut -f1))"
      done <<< "$dbs"
    fi
    if [ "$LOCAL_SNAPSHOT" = 1 ]; then
      if [ -n "$PRE_SCRIPT" ]; then
        systemctl is-active --quiet "container@$APP" \
          || fail "container not running on $(hostname), so its preCommand cannot run"
        in_guest_unit "$PRE_SCRIPT" || fail "preCommand"
      fi
      snapshot_local || fail "snapshotting local state"
      paths+=("''${SNAP_PATHS[@]}")
      echo "$APP: local state snapshotted (''${#SNAP_PATHS[@]} directories)"
    fi
    for p in "''${JFS_PATHS[@]}"; do
      if [ -e "$p" ]; then paths+=("$p"); else echo "$APP: warning: $p does not exist; skipped" >&2; fi
    done
    [ "''${#paths[@]}" -gt 0 ] || fail "nothing to back up"

    limit=()
    ${lib.optionalString (
      bcfg.uploadLimitKiB > 0
    ) "limit=(--limit-upload ${toString bcfg.uploadLimitKiB})"}
    summary=$(mktemp)
    rc=0
    r backup --host "$APP" --tag "app:$APP" --tag "engine:$ENGINE" --json --exclude-caches \
      "''${EXCLUDES[@]}" "''${limit[@]}" "''${paths[@]}" > "$summary" || rc=$?
    grep '"message_type":"error"' "$summary" | jq -r '"\(.item // "") \(.error.message // .error)"' >&2 || true
    case "$rc" in
      0) st=1 ;;
      3) st=2; echo "$APP: some files could not be read; the snapshot was still written" >&2 ;;
      *) rm -f "$summary"; fail "restic backup exited $rc" ;;
    esac
    added=$(jq -r 'select(.message_type == "summary") | .data_added' "$summary" | tail -1)
    snap=$(jq -r 'select(.message_type == "summary") | .snapshot_id' "$summary" | tail -1)
    rm -f "$summary"

    r forget --host "$APP" \
      --keep-daily ${toString bcfg.retention.daily} \
      --keep-weekly ${toString bcfg.retention.weekly} \
      --keep-monthly ${toString bcfg.retention.monthly} >/dev/null \
      || echo "$APP: warning: restic forget failed; retention not applied this run" >&2

    rm -rf "$STAGING"
    now=$(date +%s)
    metric "cluster_backup_''${APP}_success" \
      "cluster_backup_last_success_timestamp_seconds{app=\"$APP\"} $now" \
      "cluster_backup_bytes_added{app=\"$APP\"} ''${added:-0}" \
      "cluster_backup_duration_seconds{app=\"$APP\"} $((now - start))"
    status "$st"
    echo "$APP: snapshot ''${snap:-?} written ($((now - start))s, ''${added:-0} bytes new)"
  '';

  # ── maintenance: prune + check ─────────────────────────────────────────────
  maintenanceScript = pkgs.writeShellScript "cluster-backup-maintenance" ''
    set -uo pipefail
    source ${common}
    rc=0
    for prof in "$@"; do
      source "$prof"
      echo "== $APP"
      if ! r cat config >/dev/null 2>&1; then echo "$APP: no repository yet; skipped"; continue; fi
      r unlock >/dev/null 2>&1 || true
      if r prune --max-unused 10% && r check --read-data-subset=5%; then
        metric "cluster_backup_''${APP}_check" \
          "cluster_backup_check_last_success_timestamp_seconds{app=\"$APP\"} $(date +%s)"
      else
        echo "$APP: prune/check FAILED" >&2; rc=1
      fi
    done
    exit "$rc"
  '';

  # ── restore rehearsal ──────────────────────────────────────────────────────
  # Restores the latest dump into a throwaway database server -- started from
  # the container's OWN package, on a temporary datadir, as an unprivileged
  # user -- and checks every database has content. This is what makes "the
  # backup ran" into "the backup can be restored".
  verifyScript = pkgs.writeShellScript "cluster-backup-verify" ''
    set -uo pipefail
    source ${common}
    source "$1"
    fail() { echo "$APP: restore rehearsal FAILED: $*" >&2; exit 1; }
    [ "$ENGINE" != none ] || [ "$LOCAL_SNAPSHOT" = 1 ] \
      || { echo "$APP: no database and no local state; nothing to rehearse"; exit 0; }
    PKG=$2
    work=$(mktemp -d /var/lib/cluster-backup/verify/"$APP".XXXXXX)
    cleanup() {
      if [ "$ENGINE" = postgresql ]; then
        runuser -u cluster-backup-verify -- "$PKG/bin/pg_ctl" -D "$work/data" -m immediate stop >/dev/null 2>&1 || true
      elif [ "$ENGINE" = mariadb ]; then
        "$PKG/bin/mariadb-admin" --no-defaults -S "$work/sock" -u root shutdown >/dev/null 2>&1 || true
      fi
      rm -rf "$work"
    }
    trap cleanup EXIT

    # Pinned to one snapshot: two restores of `latest` could straddle a backup.
    snap=$(r snapshots --host "$APP" --latest 1 --json | jq -r '.[-1].id // empty') || fail "listing snapshots"
    [ -n "$snap" ] || fail "no snapshot"
    r restore "$snap" --target "$work/restore" --include "$STAGING" >/dev/null \
      || fail "restic restore"
    dumps="$work/restore$STAGING"

    # ── local state: every directory back, then the app's own check ────────
    if [ "$LOCAL_SNAPSHOT" = 1 ]; then
      [ -s "$dumps/local-paths" ] || fail "snapshot has no local state"
      inc=()
      while IFS=$'\t' read -r _ s; do inc+=(--include "$s"); done < "$dumps/local-paths"
      r restore "$snap" --target "$work/restore" "''${inc[@]}" >/dev/null || fail "restic restore of local state"
      # $ROOT/<guest path>, as the app sees it -- what verifyCommand is written against.
      while IFS=$'\t' read -r live s; do
        [ -n "$(ls -A "$work/restore$s" 2>/dev/null)" ] || fail "$live came back empty"
        g=''${LOCAL_GUEST[$live]:-$live}
        mkdir -p "$work/tree$(dirname "$g")"
        ln -s "$work/restore$s" "$work/tree$g"
      done < "$dumps/local-paths"
      if [ -n "$VERIFY_LOCAL" ]; then
        ROOT="$work/tree" "$VERIFY_LOCAL" || fail "verifyCommand"
      fi
      echo "$APP: local state restored and verified ($(wc -l < "$dumps/local-paths") directories)"
    fi

    # ── the database: into a throwaway server, table counts compared ───────
    if [ "$ENGINE" != none ]; then
      [ -s "$dumps/databases" ] || fail "snapshot has no database list"
      chown -R cluster-backup-verify: "$work"

      q() { # db, sql -> single value
        if [ "$ENGINE" = postgresql ]; then
          runuser -u cluster-backup-verify -- "$PKG/bin/psql" -h "$work" -p 5499 -U postgres -XAtc "$2" -d "$1"
        else
          "$PKG/bin/mariadb" --no-defaults -S "$work/sock" -u root -N -B "$1" -e "$2"
        fi
      }

      if [ "$ENGINE" = postgresql ]; then
        runuser -u cluster-backup-verify -- "$PKG/bin/initdb" -D "$work/data" -U postgres -A trust --no-sync >/dev/null \
          || fail "initdb"
        runuser -u cluster-backup-verify -- "$PKG/bin/pg_ctl" -D "$work/data" -w -l "$work/server.log" \
          -o "-h ''' -k $work -p 5499 -F" start >/dev/null || fail "starting postgres"
        runuser -u cluster-backup-verify -- "$PKG/bin/psql" -h "$work" -p 5499 -U postgres -X -q \
          -v ON_ERROR_STOP=0 -d postgres -f "$dumps/globals.sql" >/dev/null 2>&1
      else
        "$PKG/bin/mariadb-install-db" --no-defaults --basedir="$PKG" --datadir="$work/data" --user=cluster-backup-verify \
          --auth-root-authentication-method=normal --skip-test-db >/dev/null || fail "mariadb-install-db"
        runuser -u cluster-backup-verify -- "$PKG/bin/mariadbd" --no-defaults --datadir="$work/data" \
          --socket="$work/sock" --skip-networking --pid-file="$work/pid" --log-error="$work/server.log" &
        for _ in $(seq 1 60); do [ -S "$work/sock" ] && break; sleep 1; done
        [ -S "$work/sock" ] || fail "starting mariadb"
      fi

      while read -r db; do
        [ -n "$db" ] || continue
        f="$dumps/$db.$EXT"
        if [ "$ENGINE" = postgresql ]; then
          runuser -u cluster-backup-verify -- "$PKG/bin/pg_restore" -h "$work" -p 5499 -U postgres \
            --create --exit-on-error -d postgres "$f" || fail "pg_restore of $db"
          count="select count(*) from information_schema.tables where table_schema not in ('pg_catalog','information_schema')"
        else
          "$PKG/bin/mariadb" --no-defaults -S "$work/sock" -u root < "$f" || fail "import of $db"
          count="select count(*) from information_schema.tables where table_schema = database()"
        fi
        # The restore must bring back exactly the tables the backup saw -- an
        # empty database (a fresh install, MariaDB's `test`) is fine, a missing
        # table is not.
        got=$(q "$db" "$count" | tail -1) || fail "counting tables in restored $db"
        want=$(awk -F'\t' -v d="$db" '$1 == d { print $2 }' "$dumps/tables" 2>/dev/null)
        if [ -n "$want" ] && [ "$got" != "$want" ]; then
          fail "$db: $got tables restored, $want backed up"
        fi
        if [ -n "$VERIFY_QUERY" ]; then
          n=$(q "$db" "$VERIFY_QUERY" | tail -1) || fail "verify query on $db"
          [ "''${n:-0}" -gt 0 ] 2>/dev/null || fail "$db: verify query returned '$n'"
        fi
        echo "$APP: $db restored and verified ($got tables)"
      done < "$dumps/databases"
    fi

    metric "cluster_backup_''${APP}_verify" \
      "cluster_backup_verify_last_success_timestamp_seconds{app=\"$APP\"} $(date +%s)"
  '';

  # ── restore ────────────────────────────────────────────────────────────────
  restoreScript = pkgs.writeShellScript "cluster-restore-impl" ''
    set -uo pipefail
    source ${common}
    usage() {
      cat <<'EOF'
    cluster-restore <app> [--snapshot ID] [--db-only | --files-only] [--reinit-db] [--yes]
    cluster-restore <app> [--snapshot ID] --to-scratch DIR

      --snapshot ID    restic snapshot to restore (default: latest). See cluster-backup-list.
      --db-only        restore the database only, leave files alone
      --files-only     restore files only (JuiceFS, and local state for a
                       localSnapshot app), leave the database alone
      --reinit-db      wipe the database server's data directory first (corrupt datadir)
      --to-scratch DIR only extract the snapshot into DIR; nothing is touched
      --yes            actually do it (without it, the plan is printed and nothing runs)

    Runs on the app's homeNode. Pull-deploys are held for the duration. A ZFS
    snapshot of the app's local state is taken first; the JuiceFS files it
    replaces stay in /mnt/jfs/.trash for the trash period. A localSnapshot
    app's local state can be restored with its container stopped (a node
    rebuilt from nothing); while it runs, backup.appUnits are stopped first.
    EOF
    }
    [ $# -ge 1 ] || { usage; exit 2; }
    app=$1; shift
    declare -A PROFILES=(${
      lib.concatStringsSep " " (lib.mapAttrsToList (n: p: "[${n}]=${p}") profiles)
    })
    prof=''${PROFILES[$app]:-}
    if [ -z "$prof" ]; then
      echo "cluster-restore: '$app' is not backed up on this node ($(hostname))." >&2
      echo "  apps here: ${lib.concatStringsSep " " appNames}" >&2
      ${lib.concatStringsSep "\n      " (
        lib.mapAttrsToList (
          n: a:
          lib.optionalString (
            a.homeNode != null
          ) ''[ "$app" = ${n} ] && echo "  ${n} runs on its homeNode: ${a.homeNode}" >&2''
        ) config.clusterApps
      )}
      exit 2
    fi
    source "$prof"

    snapshot=latest db=1 files=1 reinit=0 yes=0 scratch=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --snapshot) snapshot=$2; shift ;;
        --db-only) files=0 ;;
        --files-only) db=0 ;;
        --reinit-db) reinit=1 ;;
        --to-scratch) scratch=$2; shift ;;
        --yes) yes=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "cluster-restore: unknown option $1" >&2; usage; exit 2 ;;
      esac
      shift
    done
    [ "$ENGINE" != none ] || db=0

    if [ -n "$scratch" ]; then
      mkdir -p "$scratch"
      r restore "$snapshot" --host "$APP" --target "$scratch" || exit 1
      echo "extracted $APP snapshot $snapshot into $scratch"
      exit 0
    fi

    echo "restore plan for $APP (snapshot: $snapshot):"
    [ "$db" = 1 ] && echo "  - database ($ENGINE): stop ''${APP_UNITS[*]:-nothing}, drop and re-import every database$([ "$reinit" = 1 ] && echo ", after wiping $GUEST_DATADIR")"
    [ "$files" = 1 ] && for p in "''${JFS_PATHS[@]}"; do echo "  - files: replace $p"; done
    localstate=0
    [ "$files" = 1 ] && [ "$LOCAL_SNAPSHOT" = 1 ] && localstate=1
    [ "$localstate" = 1 ] && for p in "''${LOCAL_PATHS[@]}"; do echo "  - local state: replace $p"; done
    running=0
    systemctl is-active --quiet "container@$APP" && running=1
    stop=0
    { [ "$db" = 1 ] || [ "$localstate" = 1 ]; } && [ "$running" = 1 ] && [ "''${#APP_UNITS[@]}" -gt 0 ] && stop=1
    [ "$stop" = 1 ] && echo "  - stop ''${APP_UNITS[*]} first, start them again after (deploy-time migrations re-run)"
    if [ "$yes" != 1 ]; then echo "(dry run -- add --yes to restore)"; exit 0; fi

    if [ "$db" = 1 ] && [ "$running" = 0 ]; then
      echo "cluster-restore: container $APP is not running here; start it first (nomad job status app-$APP)" >&2
      exit 1
    fi
    # Replacing a live app's files underneath it is how a directory server
    # gets corrupted; without units to stop, the container has to be down.
    if [ "$localstate" = 1 ] && [ "$running" = 1 ] && [ "''${#APP_UNITS[@]}" = 0 ]; then
      echo "cluster-restore: $APP is running and has no backup.appUnits to stop; stop it first (nomad job stop app-$APP)" >&2
      exit 1
    fi

    wait_for_deploy || exit 1
    hold "restore-$APP"
    work=$(mktemp -d /var/lib/cluster-backup/restore/"$APP".XXXXXX)
    trap 'unhold "restore-$APP"; rm -rf "$work"' EXIT

    ensure_repo || exit 1
    echo "== fetching snapshot"
    r restore "$snapshot" --host "$APP" --target "$work" || { echo "restic restore failed" >&2; exit 1; }

    # Safety point for the local state (the database's datadir). Copied out of,
    # never rolled back to: rpool/state holds every app on this node.
    stamp=$(date +%Y%m%d-%H%M%S)
    for p in "''${LOCAL_PATHS[@]}"; do
      ds=$(zfs list -H -o name "$p" 2>/dev/null) || { echo "note: $p is not on ZFS; no safety snapshot" >&2; continue; }
      zfs snapshot "$ds@pre-restore-$APP-$stamp" 2>/dev/null && echo "safety snapshot: $ds@pre-restore-$APP-$stamp"
      break
    done

    rc=0
    dumps="$work$STAGING"
    guest() { nixos-container run "$APP" -- "$@"; }
    [ "$db" = 0 ] || [ -s "$dumps/databases" ] || { echo "snapshot has no database dump" >&2; exit 1; }
    [ "$localstate" = 0 ] || [ -s "$dumps/local-paths" ] || { echo "snapshot has no local state" >&2; exit 1; }
    if [ "$stop" = 1 ]; then
      echo "== stopping ''${APP_UNITS[*]}"
      guest systemctl stop "''${APP_UNITS[@]}"
    fi
    if [ "$db" = 1 ]; then
      if [ "$reinit" = 1 ]; then
        echo "== re-initialising $GUEST_DATADIR"
        guest systemctl stop "$DB_UNIT"
        guest find "$GUEST_DATADIR" -mindepth 1 -delete
        # Both NixOS units initialise an empty data directory on start; the
        # roles and databases then come back from the dump itself.
        guest systemctl start "$DB_UNIT"
      fi
      in_guest restore-globals < "$dumps/globals.sql" || true
      while read -r d; do
        [ -n "$d" ] || continue
        echo "== restoring database $d"
        in_guest terminate "$d" || true
        in_guest restore "$d" < "$dumps/$d.$EXT" || { echo "restore of $d FAILED" >&2; rc=1; }
      done < "$dumps/databases"
    fi

    if [ "$localstate" = 1 ]; then
      while IFS=$'\t' read -r p s; do
        src="$work$s"
        [ -d "$src" ] || { echo "snapshot has no $p; skipped" >&2; continue; }
        echo "== restoring local state $p"
        mkdir -p "$p"
        # Numeric ids, hard links, ACLs and xattrs: local state belongs to
        # users that exist only inside the container (or inside an image in
        # it), and a directory server's files carry ACLs.
        rsync_excludes "$p"
        rsync -aHAX --numeric-ids --delete "''${REX[@]}" "$src/" "$p/" || rc=1
      done < "$dumps/local-paths"
    fi

    if [ "$files" = 1 ]; then
      for p in "''${JFS_PATHS[@]}"; do
        src="$work$p"
        [ -d "$src" ] || { echo "snapshot has no $p; skipped" >&2; continue; }
        echo "== restoring files $p"
        mkdir -p "$p"
        # Excluded paths were never backed up, so --delete must not touch them.
        rsync_excludes "$p"
        rsync -a --delete "''${REX[@]}" "$src/" "$p/" || rc=1
      done
    fi

    if [ "$stop" = 1 ]; then
      echo "== starting ''${APP_UNITS[*]}"
      guest systemctl start "''${APP_UNITS[@]}" || rc=1
    fi
    [ "$rc" = 0 ] && echo "restore of $APP complete" || echo "restore of $APP finished WITH ERRORS" >&2
    exit "$rc"
  '';

  listScript = pkgs.writeShellScript "cluster-backup-list-impl" ''
    set -uo pipefail
    source ${common}
    declare -A PROFILES=(${
      lib.concatStringsSep " " (lib.mapAttrsToList (n: p: "[${n}]=${p}") profiles)
    })
    [ $# -gt 0 ] || set -- ${lib.concatStringsSep " " appNames}
    for app in "$@"; do
      prof=''${PROFILES[$app]:-}
      [ -n "$prof" ] || { echo "$app: not backed up on this node" >&2; continue; }
      source "$prof"
      echo "== $APP ($RESTIC_REPOSITORY)"
      r snapshots --host "$APP" || true
    done
  '';

  credentials = [
    "restic-password:${cfg.credentialFiles.password}"
    "backup-id:${cfg.credentialFiles.id}"
    "backup-secret:${cfg.credentialFiles.secret}"
  ];

  # Operator commands run the implementation in a transient unit so systemd
  # hands over the credentials, exactly as the timer-driven units get them.
  withCreds =
    name: script:
    pkgs.writeShellScriptBin name ''
      exec ${pkgs.systemd}/bin/systemd-run --pipe --wait --collect --quiet \
        --unit="${name}-$$" --property=Type=oneshot \
        ${lib.concatMapStringsSep " " (c: "--property=LoadCredential=${c}") credentials} \
        --property=CacheDirectory=cluster-backup --property=StateDirectory=cluster-backup \
        ${script} "$@"
    '';

  cluster-backup = pkgs.writeShellScriptBin "cluster-backup" ''
    set -euo pipefail
    if [ $# -eq 0 ]; then
      echo "backing up every app on $(hostname): ${lib.concatStringsSep " " appNames}"
      exec systemctl start cluster-backup.service
    fi
    for app in "$@"; do
      systemctl start "cluster-backup-$app.service" || { journalctl -u "cluster-backup-$app" -n 30 --no-pager; exit 1; }
      journalctl -u "cluster-backup-$app" -n 3 --no-pager -o cat
    done
  '';

  unitDefaults = {
    Type = "oneshot";
    LoadCredential = credentials;
    CacheDirectory = "cluster-backup";
    StateDirectory = "cluster-backup";
    Nice = 19;
    IOSchedulingClass = "idle";
    TimeoutStartSec = "12h";
  };
in
{
  options.cluster.backup.repoPathFor = lib.mkOption {
    type = lib.types.functionTo lib.types.str;
    default = n: "apps/${n}";
    defaultText = lib.literalExpression ''n: "apps/''${n}"'';
    description = ''
      An app's repository path under the backup target. modules/backup.nix sets a
      salted hash of the name (lib/backup-target.nix appRepoPath); the default is for
      tests that import this module alone.
    '';
  };

  options.cluster.backup.credentialFiles = {
    password = lib.mkOption {
      type = lib.types.str;
      description = "File with the restic repository password.";
    };
    id = lib.mkOption {
      type = lib.types.str;
      description = "File with the backup target's access key id (S3 access key, B2 account id, rest-server user).";
    };
    secret = lib.mkOption {
      type = lib.types.str;
      description = "File with the backup target's secret.";
    };
  };

  config = lib.mkIf (apps != { }) {
    assertions = lib.mapAttrsToList (n: app: {
      assertion = app.localState == { } || app.homeNode != null;
      message = "clusterApps.${n}: an app with localState must set homeNode -- its database can only be backed up and restored where that state lives.";
    }) config.clusterApps;

    users.users.cluster-backup-verify = {
      isSystemUser = true;
      group = "cluster-backup-verify";
    };
    users.groups.cluster-backup-verify = { };

    systemd.tmpfiles.rules = [
      "d /var/lib/cluster-backup/verify 0755 root root -"
      "d /var/lib/cluster-backup/restore 0700 root root -"
      "d ${stagingRoot} 0700 root root -"
      "d ${metricsDir} 0755 root root -"
    ];

    systemd.services =
      lib.mapAttrs' (
        n: _app:
        lib.nameValuePair "cluster-backup-${n}" {
          description = "Back up ${n} to ${target.type} (restic)";
          wants = [ "network-online.target" ];
          after = [ "network-online.target" ];
          serviceConfig = unitDefaults // {
            ExecStart = "${backupScript} ${profiles.${n}}";
          };
        }
      ) apps
      // lib.mapAttrs' (
        n: app:
        let
          engine = engineOf n app;
        in
        lib.nameValuePair "cluster-backup-verify-${n}" {
          description = "Restore rehearsal for ${n}'s latest backup";
          wants = [ "network-online.target" ];
          after = [ "network-online.target" ];
          serviceConfig = unitDefaults // {
            ExecStart = "${verifyScript} ${profiles.${n}} ${
              if engine == "none" then "none" else dbPackage n engine
            }";
          };
        }
      ) apps
      // {
        # One timer, one app at a time: sequential keeps the node's IO and the
        # uplink to the target sane, and every app keeps its own unit, journal
        # and failed state.
        cluster-backup = {
          description = "Back up every app on this node";
          serviceConfig.Type = "oneshot";
          script = ''
            rc=0
            ${lib.concatMapStringsSep "\n" (n: "systemctl start cluster-backup-${n}.service || rc=1") appNames}
            exit $rc
          '';
        };
        cluster-backup-verify = {
          description = "Restore rehearsal for every app on this node";
          serviceConfig.Type = "oneshot";
          script = ''
            rc=0
            ${lib.concatMapStringsSep "\n" (
              n: "systemctl start cluster-backup-verify-${n}.service || rc=1"
            ) appNames}
            exit $rc
          '';
        };
        cluster-backup-maintenance = {
          description = "Prune and check every app's backup repository";
          wants = [ "network-online.target" ];
          after = [ "network-online.target" ];
          serviceConfig = unitDefaults // {
            ExecStart = "${maintenanceScript} ${lib.concatStringsSep " " (lib.attrValues profiles)}";
          };
        };
      };

    systemd.timers = {
      cluster-backup = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = bcfg.schedule;
          Persistent = true;
          RandomizedDelaySec = "20m";
        };
      };
      cluster-backup-maintenance = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = bcfg.maintenance;
          Persistent = true;
        };
      };
      cluster-backup-verify = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = bcfg.verify;
          Persistent = true;
        };
      };
    };

    environment.systemPackages = [
      cluster-backup
      (withCreds "cluster-backup-list" listScript)
      (withCreds "cluster-restore" restoreScript)
    ];
  };
}
