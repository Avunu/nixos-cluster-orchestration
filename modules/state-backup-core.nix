# modules/state-backup-core.nix — the frequent backup: each app's local state, off the
# nodes, from a replica.
#
# The nightly backup (modules/backup-core.nix) is the long history: a logical dump and
# the app's files, to `topology.backup.target`. Between two of them, the copies of an
# app's database are the nodes' own (modules/app-state.nix), and all of those are in one
# place. This is the copy that is not: `topology.backup.state` names a second target and
# a schedule of its own, hourly by default, so the two can go to different storage: this
# one near the nodes, where an hourly upload is cheap, and the nightly one far away.
#
#   what    the app's dataset as its newest replication snapshot has it: the database's
#           directory, crash-consistent, as a start after a power cut would find it. A
#           physical copy, so it restores to the same database version only; the
#           nightly dump is the one that survives a version bump. Not the app's JuiceFS
#           files, which are in object storage already.
#   where   one node per app, asked of `cluster-state backup-source`: a replica, so
#           reading a whole database every hour costs the running app nothing. The
#           snapshot is cloned, read-only, to a path that is the same every run, which
#           is what lets restic skip the files that did not change.
#   repo    the app's own, `state/<cluster.stateBackup.repoPathFor app>` on the target,
#           under the same restic password as the nightly one.
#
# cluster-state-backup [app…]          back up now, where this node is the one to
# cluster-state-backup-list [app…]     each app's snapshots
# cluster-state-restore <app> [--snapshot ID] [--yes]
#                                      the app stopped everywhere: its dataset replaced
#                                      by the snapshot's, here, and handed to the others
#
# modules/backup.nix supplies the credentials.
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
  cfg = config.cluster.stateBackup;
  scfg = topology.backup.state or null;
  bt = clusterLib.backupTarget;

  stateful = lib.filterAttrs (
    _: a: a.localState != { } && (a.preview.of or null) == null && (a.backup.enable or true)
  ) config.clusterApps;
  names = lib.attrNames stateful;
  # Not where cluster.state is off (a test VM without ZFS): there is no dataset to read.
  enabled = scfg != null && stateful != { } && (config.cluster.state.enable or false);

  target = scfg.target;
  retention = {
    hourly = 48;
    daily = 14;
  }
  // (scfg.retention or { });
  uploadLimitKiB = topology.backup.uploadLimitKiB or 0;

  stateTool = "${config.cluster.state.package}/bin/cluster-state";
  metricsDir = "/var/lib/prometheus-node-exporter-text";
  runDir = "/run/cluster-state-backup";

  common = pkgs.writeText "cluster-state-backup-common.sh" ''
    export PATH=${
      lib.makeBinPath [
        pkgs.restic
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.jq
        pkgs.util-linux
        pkgs.systemd
        config.boot.zfs.package
      ]
    }
    export RESTIC_PASSWORD_FILE="$CREDENTIALS_DIRECTORY/restic-password"
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (
        var: which: ''${var}=$(cat "$CREDENTIALS_DIRECTORY/backup-${which}"); export ${var}''
      ) (bt.credentialEnv target)
    )}
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (var: val: "export ${var}=${lib.escapeShellArg val}") (bt.env target)
    )}
    export RESTIC_CACHE_DIR=/var/cache/cluster-state-backup
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

    declare -A REPO=(${
      lib.concatStringsSep " " (
        map (n: "[${n}]=${lib.escapeShellArg (bt.repository target (cfg.repoPathFor n))}") names
      )
    })
    use() { # an app's repository, or no such app
      APP=$1
      [ -n "''${REPO[$APP]:-}" ] || { echo "'$APP' has no local state to back up (apps: ${lib.concatStringsSep " " names})" >&2; return 2; }
      export RESTIC_REPOSITORY=''${REPO[$APP]}
      MNT=${runDir}/$APP
    }
    # restic exits 10 for a repository that does not exist; anything else is an error
    # an init must not paper over.
    ensure_repo() {
      local rc=0
      r cat config >/dev/null 2>&1 || rc=$?
      case "$rc" in
        0) ;;
        10) echo "$APP: initialising repository $RESTIC_REPOSITORY"; r init ;;
        *) echo "$APP: repository $RESTIC_REPOSITORY unusable (restic exit $rc)" >&2; return 1 ;;
      esac
    }
    metric() {
      local f="${metricsDir}/cluster_backup_''${APP}_state.prom"
      mkdir -p ${metricsDir}
      printf '%s\n' "$@" > "$f.tmp" && mv "$f.tmp" "$f"
    }
  '';

  backupScript = pkgs.writeShellScript "cluster-state-backup-impl" ''
    set -uo pipefail
    source ${common}
    [ $# -gt 0 ] || set -- ${lib.concatStringsSep " " names}
    failed=0
    one() {
      use "$1" || return 1
      local src clone pool start created rc=0 summary
      start=$(date +%s)
      src=$(${stateTool} backup-source "$APP") || { echo "$APP: could not ask which node backs it up" >&2; return 1; }
      if [ -z "$src" ]; then
        # Another node's: what this one last said about it says nothing any more.
        rm -f "${metricsDir}/cluster_backup_''${APP}_state.prom"
        return 0
      fi
      pool=''${src%%/*}
      clone=$pool/state-backup/$APP
      zfs list -H -o name "$pool/state-backup" >/dev/null 2>&1 \
        || zfs create -o mountpoint=none -o canmount=off -o com.sun:auto-snapshot=false "$pool/state-backup" || return 1
      # A run that died left its clone behind.
      zfs destroy "$clone" 2>/dev/null || true
      zfs clone -o mountpoint="$MNT" -o readonly=on -o com.sun:auto-snapshot=false "$src" "$clone" \
        || { echo "$APP: could not clone $src" >&2; return 1; }
      created=$(zfs get -H -p -o value creation "$src")
      ensure_repo && { r unlock >/dev/null 2>&1 || true; } || rc=1
      if [ "$rc" = 0 ]; then
        summary=$(mktemp)
        # Dated as the data is, not as the upload: a restore is chosen by what it holds.
        r backup --host "$APP" --tag state --tag "snapshot:''${src#*@}" --time "$(date -d "@$created" '+%F %T')" \
          --json ${
            lib.optionalString (uploadLimitKiB > 0) "--limit-upload ${toString uploadLimitKiB}"
          } \
          "$MNT" > "$summary" || rc=$?
        grep '"message_type":"error"' "$summary" | jq -r '"\(.item // "") \(.error.message // .error)"' >&2 || true
        rm -f "$summary"
      fi
      zfs destroy "$clone" || echo "$APP: warning: could not destroy $clone" >&2
      [ "$rc" = 0 ] || { echo "$APP: state backup FAILED (restic exit $rc)" >&2; return 1; }
      r forget --host "$APP" --keep-hourly ${toString retention.hourly} --keep-daily ${toString retention.daily} >/dev/null \
        || echo "$APP: warning: restic forget failed; retention not applied this run" >&2
      metric \
        "cluster_state_backup_last_success_timestamp_seconds{app=\"$APP\"} $(date +%s)" \
        "cluster_state_backup_snapshot_timestamp_seconds{app=\"$APP\"} $created"
      echo "$APP: ''${src#*@} backed up from this node ($(( $(date +%s) - start ))s)"
    }
    for app in "$@"; do one "$app" || failed=1; done
    exit "$failed"
  '';

  maintenanceScript = pkgs.writeShellScript "cluster-state-backup-maintenance" ''
    set -uo pipefail
    source ${common}
    rc=0
    for app in ${lib.concatStringsSep " " names}; do
      use "$app" || continue
      # One node prunes a repository: the one that writes to it.
      [ -n "$(${stateTool} backup-source "$APP")" ] || continue
      r cat config >/dev/null 2>&1 || { echo "$APP: no repository yet; skipped"; continue; }
      r unlock >/dev/null 2>&1 || true
      r prune --max-unused 10% && r check --read-data-subset=5% || { echo "$APP: prune/check FAILED" >&2; rc=1; }
    done
    exit "$rc"
  '';

  listScript = pkgs.writeShellScript "cluster-state-backup-list-impl" ''
    set -uo pipefail
    source ${common}
    [ $# -gt 0 ] || set -- ${lib.concatStringsSep " " names}
    for app in "$@"; do
      use "$app" || continue
      echo "== $APP ($RESTIC_REPOSITORY)"
      r snapshots --host "$APP" || true
    done
  '';

  restoreScript = pkgs.writeShellScript "cluster-state-restore-impl" ''
    set -uo pipefail
    source ${common}
    usage() { echo "usage: cluster-state-restore <app> [--snapshot ID] [--yes]" >&2; exit 2; }
    [ $# -ge 1 ] || usage
    use "$1" || exit 2
    shift
    snapshot=latest yes=0
    while [ $# -gt 0 ]; do
      case "$1" in
        --snapshot) snapshot=''${2:-}; [ -n "$snapshot" ] || usage; shift 2 ;;
        --yes) yes=1; shift ;;
        *) usage ;;
      esac
    done
    # A database's files cannot be replaced under a running database, here or anywhere.
    if systemctl is-active --quiet "container@$APP.service"; then
      echo "cluster-state-restore: $APP is running on this node; stop it first (nomad job stop app-$APP)" >&2; exit 1
    fi
    elsewhere=$(${stateTool} where "$APP") || { echo "cluster-state-restore: could not ask the other nodes whether $APP is running" >&2; exit 1; }
    [ -z "$elsewhere" ] || { echo "cluster-state-restore: $APP is running on $elsewhere; stop it first (nomad job stop app-$APP)" >&2; exit 1; }

    id=$(r snapshots --host "$APP" --json "$snapshot" | jq -r '.[-1].short_id // empty') \
      || { echo "cluster-state-restore: cannot read $RESTIC_REPOSITORY" >&2; exit 1; }
    [ -n "$id" ] || { echo "cluster-state-restore: no snapshot '$snapshot' of $APP" >&2; exit 1; }
    at=$(r snapshots --host "$APP" --json "$id" | jq -r '.[-1].time')
    echo "restore plan for $APP:"
    echo "  - replace everything in its dataset with snapshot $id, the app's state as of $at"
    echo "  - a ZFS snapshot of what is there now is taken first, and kept"
    echo "  - every node then receives the restored state; start the app again afterwards (nomad job start app-$APP)"
    [ "$yes" = 1 ] || { echo "nothing done; add --yes"; exit 0; }

    ${stateTool} acquire "$APP" || { echo "cluster-state-restore: could not take $APP's state on this node" >&2; exit 1; }
    trap '${stateTool} release "$APP"' EXIT
    ds=$(${stateTool} dataset "$APP") && mount=$(zfs get -H -o value mountpoint "$ds") \
      || { echo "cluster-state-restore: no dataset for $APP" >&2; exit 1; }
    zfs snapshot "$ds@pre-restore-state-$(date +%Y%m%d-%H%M%S)" || exit 1
    r restore "$id:$MNT" --host "$APP" --target "$mount" --delete \
      || { echo "cluster-state-restore: restic restore FAILED; the snapshot taken first has what was there" >&2; exit 1; }
    echo "$APP: restored to $at. Start it: nomad job start app-$APP"
  '';

  credentials = [
    "restic-password:${cfg.credentialFiles.password}"
    "backup-id:${cfg.credentialFiles.id}"
    "backup-secret:${cfg.credentialFiles.secret}"
  ];
  withCreds =
    name: script:
    pkgs.writeShellScriptBin name ''
      exec ${pkgs.systemd}/bin/systemd-run --pipe --wait --collect --quiet \
        --unit="${name}-$$" --property=Type=oneshot \
        ${lib.concatMapStringsSep " " (c: "--property=LoadCredential=${c}") credentials} \
        --property=CacheDirectory=cluster-state-backup \
        ${script} "$@"
    '';
  unit = script: {
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = script;
      LoadCredential = credentials;
      CacheDirectory = "cluster-state-backup";
      Nice = 19;
      IOSchedulingClass = "idle";
      TimeoutStartSec = "6h";
    };
  };
in
{
  options.cluster.stateBackup = {
    repoPathFor = mkOption {
      type = types.functionTo types.str;
      default = n: "state/${n}";
      description = "An app's repository path under `topology.backup.state.target`. modules/backup.nix sets a salted hash of the name.";
    };
    credentialFiles = {
      password = mkOption {
        type = types.str;
        description = "File with the restic repository password.";
      };
      id = mkOption {
        type = types.str;
        description = "File with the state target's access key id.";
      };
      secret = mkOption {
        type = types.str;
        description = "File with the state target's secret.";
      };
    };
    apps = mkOption {
      type = types.listOf types.str;
      readOnly = true;
      internal = true;
      default = lib.optionals enabled names;
      description = "The apps whose state is backed up, for the alert rules.";
    };
  };

  config = lib.mkIf enabled {
    assertions = [
      {
        assertion = target != topology.backup.target;
        message = "topology.backup.state.target is the nightly backup's target. It is a second copy only somewhere else; to back up to one place, leave backup.state out.";
      }
    ];

    systemd.tmpfiles.rules = [ "d ${runDir} 0700 root root -" ];

    systemd.services.cluster-state-backup = unit backupScript // {
      description = "Back up app state to ${target.type}, from this node's replicas";
    };
    systemd.services.cluster-state-backup-maintenance = unit maintenanceScript // {
      description = "Prune and check the app state repositories this node writes";
    };
    systemd.timers.cluster-state-backup = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = scfg.schedule or "hourly";
        Persistent = true;
        RandomizedDelaySec = "5m";
      };
    };
    systemd.timers.cluster-state-backup-maintenance = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = topology.backup.maintenance;
        Persistent = true;
        RandomizedDelaySec = "1h";
      };
    };

    environment.systemPackages = [
      (withCreds "cluster-state-backup" backupScript)
      (withCreds "cluster-state-backup-list" listScript)
      (withCreds "cluster-state-restore" restoreScript)
    ];
  };
}
