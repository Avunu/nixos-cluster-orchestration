# modules/canary-scan.nix — looks for a known string where client data must never be
# in plaintext (design 1.19, Appendix K).
#
# The canary (vars `canary`, modules/vars.nix) is a string nothing else contains. The
# scan plants it as client data is stored, in a file on the JuiceFS volume
# (/mnt/jfs/.canary/<node>), and then looks for it, weekly, in each place that must not
# hold such data in the clear. Each place is a class, the `path_class` of
#
#   cluster_canary_hits{path_class="..."}           CanaryFound fires on > 0
#   cluster_canary_last_run_timestamp_seconds       CanaryScanStale fires after 8 days
#
#   tmp       files under /tmp, /var/tmp, /run/user holding it (PrivateTmp dirs included)
#   coredump  ANY file in the host's or a container's systemd-coredump directory. Cores
#             are zstd: a grep of one finds nothing, whatever it holds [RAN]. No core
#             should exist at all (modules/coredumps-off.nix), so each one counts.
#   journal   lines of the journal holding it, the host's and every container's, read
#             through journalctl. journald compresses large fields, and a grep of the
#             journal files misses what is in them [RAN; the mutant
#             canary-raw-grep-journal proves the test sees the difference].
#   swap      lines holding it on the raw devices UNDER the swap (config.swapDevices'
#             devices, not their random-key mappings). Under dm-crypt that is ciphertext.
#   esp       files on every vfat mount (both ESPs on a node), which are never encrypted.
#   raw       lines holding it on the whole raw disks (disko's), with
#             cluster.canary.rawDisks only: it reads every byte of both disks.
#   s3        lines holding it in the exact objects `juicefs info` names for the planted
#             file, read from the bucket as the provider stores them. On an encrypted
#             volume that is ciphertext. No sampling: the objects that hold it are known.
#
# Every class reports hits; only the class's positive control in tests/canary-scan.nix
# proves that the class could have found anything at all. A class that cannot look (no
# object resolved, a device that will not read, journalctl failing) is not reported as
# 0: its line is left out, the run's timestamp is not moved on, and the unit fails, so
# UnitFailed fires now and CanaryScanStale later. A missing device (a dead disk's swap)
# is skipped with a line in the journal: the disk is somebody else's alert.
#
# The literal never goes on a command line, into the environment, or onto a disk in the
# clear: it is a systemd credential, and every grep reads it with -f. A hit with the
# audit trail on also spools a `canary` event (modules/audit-ship-core.nix) for the
# watchdog Worker. `cluster-canary-seed` writes the timestamp once at a node's first
# boot, so a node whose scan never runs is stale after 8 days rather than silent.
#
# Opted-out nodes scan too: their swap and raw disks are plaintext by declaration, and
# a hit there says client data really reached them in the clear. The opt-out's own
# acknowledgement (insecureFleetKeysOnPlaintextDisk) covers the fleet's keys on that
# disk, not client data; BootSecurityOptedOut fires for the first, CanaryFound for this.
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
  cfg = config.cluster.canary;
  jfs = clusterLib.juicefs;
  os = topology.objectStorage;
  vars = config.clan.core.vars.generators;

  # The scan. Bash, as the listing ran; `set -u` without -e, because a class's failure
  # is handled per class and must not skip the others. Edited only by a mutant
  # (flake.nix canary-raw-grep-journal), through cluster.canary.script.
  text = ''
    set -u
    M=$METRICS_DIR
    F="$CREDENTIALS_DIRECTORY/canary"
    mkdir -p "$M"

    # One line, long enough to be unique. `grep -f` with an empty line in the file
    # matches everything, and a short string matches ordinary data.
    if [ "$(grep -c "" "$F")" -ne 1 ] || [ "$(head -c 64 "$F" | tr -d '\n' | wc -c)" -lt 16 ]; then
      echo "canary-scan: the canary credential is not one line of 16 or more characters; nothing scanned" >&2
      exit 1
    fi

    out=()
    errors=()
    declare -A hits=()
    emit() { out+=("cluster_canary_hits{path_class=\"$1\"} $2"); hits[$1]=$2; echo "class=$1 hits=$2"; }
    cannot() { errors+=("$1"); echo "canary-scan: class=$1 NOT scanned: $2" >&2; }

    # No -a anywhere: with -a, grep holds a whole "line" in memory, and a zeroed device or
    # sparse file is one line as long as itself (RAN: 820 MB of memory for a 400 MB file of
    # zeros, 3 MB without -a, the planted string found both ways). Binary data is searched
    # all the same; NULs end lines. LC_ALL=C (the unit's environment) keeps it bytewise.
    #
    # Lines holding the canary in a device, summed; nonzero status if one would not read.
    # O_DIRECT: swap and dm-crypt write to a device without going through its page cache,
    # so a cached read can be last week's data. It also leaves the cache alone, which a
    # weekly read of both swap partitions would otherwise flush.
    devices() {
      local class=$1 d r n=0
      shift
      for d in "$@"; do
        if [ ! -e "$d" ]; then
          echo "canary-scan: $class device $d is absent; skipped" >&2
          continue
        fi
        r=$(dd if="$d" iflag=direct bs=4M status=none | grep -cF -f "$F"; echo " ''${PIPESTATUS[0]} ''${PIPESTATUS[1]}")
        set -- $r
        if ! { [ "$#" -eq 3 ] && [ "$2" -eq 0 ] && [ "$3" -le 1 ]; }; then
          cannot "$class" "cannot read $d"; return 1
        fi
        n=$((n + $1))
      done
      emit "$class" "$n"
    }

    # Files holding the canary under the directories that exist. FIFOs and sockets are
    # skipped (-D skip): a FIFO in /tmp would hold the scan for ever.
    #
    # grep's status is read, as devices() reads dd's: it exits 2 for a file it could not
    # read (EIO on a failing ESP, a stale mount under /tmp), and that is a place the class
    # did not look, not a clean one. A file that vanished between the directory read and
    # its open (ENOENT, routine in /tmp) is the one error that is not.
    #
    # With `mounted` first, each directory must be a mount point (the ESPs): a nofail ESP
    # that did not mount leaves its empty directory, which is not the ESP. One of them
    # missing is skipped with a line, as a dead disk's swap is; none mounted is a class
    # that could not look.
    files() {
      local class=$1 d dirs=() r err mounts=0
      shift
      if [ "$1" = mounted ]; then mounts=1; shift; fi
      for d in "$@"; do
        if [ "$mounts" -eq 1 ] && ! mountpoint -q "$d"; then
          echo "canary-scan: $class directory $d is not a mount point; skipped" >&2
          continue
        fi
        [ -d "$d" ] && dirs+=("$d")
      done
      if [ "''${#dirs[@]}" -eq 0 ]; then
        if [ "$mounts" -eq 1 ]; then cannot "$class" "none of $* is mounted"; return 1; fi
        emit "$class" 0
        return
      fi
      err=$(mktemp -p /run canary-grep.XXXXXX)
      r=$(grep -rlF -D skip -f "$F" "''${dirs[@]}" 2>"$err" | wc -l; echo " ''${PIPESTATUS[0]}")
      set -- $r
      if [ "$2" -gt 1 ] && { [ ! -s "$err" ] || grep -qv 'No such file or directory' "$err"; }; then
        head -n 3 "$err" >&2
        rm -f "$err"
        cannot "$class" "grep could not read under ''${dirs[*]}"
        return 1
      fi
      rm -f "$err"
      emit "$class" "$1"
    }

    # The journal, through journalctl, which decompresses. Every field (-o export), not
    # only MESSAGE. "$@" picks the journal: nothing for the host's, -D for a container's.
    journal_lines() {
      local r
      r=$(journalctl --no-pager -q -o export "$@" 2>/dev/null | grep -cF -f "$F"; echo " ''${PIPESTATUS[0]} ''${PIPESTATUS[1]}")
      set -- $r
      [ "$#" -eq 3 ] && [ "$2" -eq 0 ] && [ "$3" -le 1 ] || return 1
      echo "$1"
    }

    # ── tmp ────────────────────────────────────────────────────────────────────
    files tmp /tmp /var/tmp /run/user

    # ── coredump ───────────────────────────────────────────────────────────────
    emit coredump "$(find /var/lib/systemd/coredump /var/lib/nixos-containers/*/var/lib/systemd/coredump -type f 2>/dev/null | wc -l)"

    # ── journal ────────────────────────────────────────────────────────────────
    n=0; ok=1
    if c=$(journal_lines); then n=$((n + c)); else ok=0; cannot journal "journalctl failed on the host's journal"; fi
    for d in /var/lib/nixos-containers/*/var/log/journal; do
      [ -d "$d" ] || continue
      if c=$(journal_lines -D "$d"); then n=$((n + c)); else ok=0; cannot journal "journalctl failed on $d"; fi
    done
    [ "$ok" -eq 1 ] && emit journal "$n"

    # ── swap ───────────────────────────────────────────────────────────────────
    # shellcheck disable=SC2086
    devices swap $SWAP_DEVICES

    # ── esp ────────────────────────────────────────────────────────────────────
    # shellcheck disable=SC2086
    [ -n "$ESP_DIRS" ] && files esp mounted $ESP_DIRS

    # ── raw ────────────────────────────────────────────────────────────────────
    # shellcheck disable=SC2086
    [ -n "''${RAW_DEVICES:-}" ] && devices raw $RAW_DEVICES

    # ── s3 ─────────────────────────────────────────────────────────────────────
    s3() {
      local dir="$JFS_MOUNT/.canary" f o r n=0 info objs
      f="$dir/$NODE"
      if ! mountpoint -q "$JFS_MOUNT"; then cannot s3 "$JFS_MOUNT is not mounted"; return; fi
      # Planted once, and again only if the canary changed. Written whole, then renamed.
      if ! cmp -s "$F" "$f"; then
        if ! { mkdir -p -m 0700 "$dir" && cat "$F" > "$f.new" && sync "$f.new" && mv -f "$f.new" "$f"; }; then
          cannot s3 "cannot plant $f"; return
        fi
      fi
      if ! info=$(juicefs info "$f" 2>/dev/null); then cannot s3 "juicefs info failed on $f"; return; fi
      objs=$(printf '%s\n' "$info" | awk -F'|' '/chunks\//{gsub(/ /,"",$3); print $3}')
      if [ -z "$objs" ]; then cannot s3 "juicefs info named no object for $f"; return; fi
      RCLONE_CONFIG_JFS_ACCESS_KEY_ID=$(cat "$CREDENTIALS_DIRECTORY/s3ak")
      RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY=$(cat "$CREDENTIALS_DIRECTORY/s3sk")
      export RCLONE_CONFIG_JFS_ACCESS_KEY_ID RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY
      export RCLONE_CONFIG_JFS_TYPE=s3 RCLONE_CONFIG_JFS_PROVIDER=Other
      export RCLONE_CONFIG_JFS_ENDPOINT="$S3_ENDPOINT" RCLONE_CONFIG_JFS_REGION="$S3_REGION"
      for o in $objs; do
        r=$(rclone cat "jfs:$S3_BUCKET/$o" 2>/dev/null | grep -cF -f "$F"; echo " ''${PIPESTATUS[0]} ''${PIPESTATUS[1]}")
        set -- $r
        if ! { [ "$#" -eq 3 ] && [ "$2" -eq 0 ] && [ "$3" -le 1 ]; }; then
          cannot s3 "cannot read object $o from $S3_BUCKET"; return
        fi
        n=$((n + $1))
      done
      emit s3 "$n"
    }
    [ -n "''${JFS_MOUNT:-}" ] && s3

    # ── report ─────────────────────────────────────────────────────────────────
    now=$(date +%s)
    # A hit is also an event for the off-host trail, in the Worker's `canary` shape.
    if [ -n "''${SPOOL_DIR:-}" ]; then
      for c in "''${!hits[@]}"; do
        [ "''${hits[$c]}" -gt 0 ] || continue
        e="$SPOOL_DIR/$(date +%s%N)-canary-$c.json"
        if ! { mkdir -p -m 0700 "$SPOOL_DIR" \
            && jq -cn --arg node "$NODE" --arg c "$c" --argjson h "''${hits[$c]}" --argjson at "$now" \
              '{kind: "canary", node: $node, path_class: $c, hits: $h, at: $at}' > "$e.tmp" \
            && sync "$e.tmp" && mv "$e.tmp" "$e"; }; then
          cannot "$c" "could not spool its audit event"
        fi
      done
    fi
    # The timestamp says when every class last ran. After a failed class it keeps the
    # last complete run's (or the seed's), so CanaryScanStale can still fire.
    if [ "''${#errors[@]}" -eq 0 ]; then
      out+=("cluster_canary_last_run_timestamp_seconds $now")
    else
      prev=$(sed -n 's/^cluster_canary_last_run_timestamp_seconds //p' "$M/canary.prom" 2>/dev/null)
      [ -n "$prev" ] && out+=("cluster_canary_last_run_timestamp_seconds $prev")
    fi
    printf '%s\n' "''${out[@]}" > "$M/canary.prom.tmp" && mv "$M/canary.prom.tmp" "$M/canary.prom"
    if [ "''${#errors[@]}" -ne 0 ]; then
      echo "canary-scan: FAILED: ''${errors[*]} not scanned" >&2
      exit 1
    fi
  '';
in
{
  imports = [ ./audit-ship-core.nix ];

  options.cluster.canary = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = "The weekly canary scan.";
    };

    rawDisks = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Also read the whole raw disks (`rawDevices`) for the canary, class `raw`. Off by
        default: it reads every byte of both disks each week.
      '';
    };

    rawDevices = mkOption {
      type = types.listOf types.str;
      default = lib.mapAttrsToList (_: d: d.device) (
        lib.attrByPath [ "disko" "devices" "disk" ] { } config
      );
      defaultText = lib.literalExpression "every disko disk's device";
      description = "The disks the `raw` class reads.";
    };

    swapDevices = mkOption {
      type = types.listOf types.str;
      default = map (s: s.device) config.swapDevices;
      defaultText = lib.literalExpression "map (s: s.device) config.swapDevices";
      description = ''
        The devices the `swap` class reads: what is UNDER each swap, so a random-key
        swap is read as the ciphertext it writes, not through its mapping.
      '';
    };

    espDirs = mkOption {
      type = types.listOf types.str;
      default = lib.mapAttrsToList (_: fs: fs.mountPoint) (
        lib.filterAttrs (_: fs: fs.fsType == "vfat") config.fileSystems
      );
      defaultText = lib.literalExpression "every vfat mount point";
      description = "The directories the `esp` class reads: both ESPs on a cluster node.";
    };

    valueFile = mkOption {
      type = types.str;
      default = vars.canary.files.value.path;
      defaultText = lib.literalExpression "the `canary/value` var";
      description = "The canary, read as a systemd credential.";
    };

    s3 = {
      enable = mkOption {
        type = types.bool;
        default = config.systemd.services ? juicefs-mount;
        defaultText = lib.literalExpression "the node mounts JuiceFS";
        description = "The `s3` class: plant the canary on the JuiceFS volume and read its objects from the bucket.";
      };
      bucket = mkOption {
        type = types.str;
        default = os.juicefsBucket;
        defaultText = lib.literalExpression "topology.objectStorage.juicefsBucket";
        description = "The volume's bucket.";
      };
      mount = mkOption {
        type = types.str;
        default = jfs.mountPoint;
        defaultText = lib.literalExpression "clusterLib.juicefs.mountPoint";
        description = "Where the volume is mounted.";
      };
    };

    script = mkOption {
      type = types.str;
      default = text;
      internal = true;
      description = "The scan's text. Only a mutant changes it (flake.nix, canary-raw-grep-journal).";
    };
  };

  config = lib.mkIf cfg.enable {
    # The text, so a mutant can edit it and fail loudly when the listing moves.
    system.build.canaryScanText = text;

    systemd.services.cluster-canary-scan = {
      description = "Look for the canary where client data must not be in plaintext";
      # The volume the s3 class plants on. Not a want: a scan must not mount anything.
      after = [ "juicefs-mount.service" ];
      # Weekly and long (it reads swap and maybe whole disks): a switch must not start it.
      restartIfChanged = false;
      environment = {
        METRICS_DIR = "/var/lib/prometheus-node-exporter-text";
        LC_ALL = "C";
        # The name the Worker knows this node's token by (modules/audit-ship.nix sets it
        # to the clan machine name), and the planted file's name.
        NODE = config.cluster.audit.node;
        SPOOL_DIR = lib.optionalString config.cluster.audit.enable config.cluster.audit.spoolDir;
        SWAP_DEVICES = lib.concatStringsSep " " cfg.swapDevices;
        ESP_DIRS = lib.concatStringsSep " " cfg.espDirs;
        RAW_DEVICES = lib.optionalString cfg.rawDisks (lib.concatStringsSep " " cfg.rawDevices);
      }
      // lib.optionalAttrs cfg.s3.enable {
        JFS_MOUNT = cfg.s3.mount;
        S3_BUCKET = cfg.s3.bucket;
        S3_ENDPOINT = os.endpoint;
        S3_REGION = os.region;
      };
      path = [
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gnused
        pkgs.gawk
        pkgs.findutils
        pkgs.diffutils
        pkgs.util-linux
        pkgs.jq
        pkgs.juicefs
        pkgs.rclone
        config.systemd.package
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "cluster-canary-scan" cfg.script;
        LoadCredential = [
          "canary:${cfg.valueFile}"
        ]
        ++ lib.optionals cfg.s3.enable [
          "s3ak:${vars.ovh-s3.files."access-key".path}"
          "s3sk:${vars.ovh-s3.files."secret-key".path}"
        ];
        Nice = 19;
        IOSchedulingClass = "idle";
        # Not PrivateTmp: the tmp class reads the real /tmp.
        NoNewPrivileges = true;
      };
    };

    systemd.timers.cluster-canary-scan = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = "weekly";
        RandomizedDelaySec = "6h";
        Persistent = true;
      };
    };

    # The first timestamp, at a node's first boot, so CanaryScanStale has something to
    # judge before the first scan has run. Never overwrites a scan's file.
    systemd.services.cluster-canary-seed = {
      description = "Seed the canary scan's timestamp on a new node";
      wantedBy = [ "multi-user.target" ];
      path = [ pkgs.coreutils ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        m=/var/lib/prometheus-node-exporter-text
        [ -e "$m/canary.prom" ] && exit 0
        mkdir -p "$m"
        printf 'cluster_canary_last_run_timestamp_seconds %s\n' "$(date +%s)" > "$m/canary.prom.tmp"
        mv "$m/canary.prom.tmp" "$m/canary.prom"
      '';
    };
  };
}
