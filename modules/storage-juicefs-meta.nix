# modules/storage-juicefs-meta.nix — the JuiceFS metadata engine (singleton).
#
# Assigned to the ONE node tagged `juicefs-meta` via inventory.instances in
# flake.nix, and constrained to maxMachines = 1 by modules/cluster-roles.nix:
# two metadata engines over one S3 bucket is a split-brain filesystem, so it is
# an eval-time error rather than a runbook warning.
#
# There is deliberately no `isBootstrap`-style conditional in this file. Whether
# a node runs it is inventory data (the tag), not module logic — that is the
# whole point of the split.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  ...
}:
let
  jfs = clusterLib.juicefs;
  os = topology.objectStorage;
  vars = config.clan.core.vars.generators;

  # This node IS the metadata node, so the engine is local.
  metaIp = "127.0.0.1";

  loadCreds = jfs.loadCredentials (
    id:
    {
      s3ak = vars.ovh-s3.files."access-key".path;
      s3sk = vars.ovh-s3.files."secret-key".path;
      pgpass = vars.juicefs-pg.files.password.path;
      rsaPem = vars.juicefs-rsa.files."rsa.pem".path;
      rsaPass = vars.juicefs-rsa.files."rsa-passphrase".path;
    }
    .${id}
  );

  # A vars file's ciphertext in the site's repository (as modules/cluster-common.nix):
  # its hash changes when the value is regenerated, and nothing else about the unit does.
  ciphertextHash =
    gen: file:
    let
      f = vars.${gen}.files.${file};
      p = config.clan.core.settings.directory + "/secrets/clan-vars/${f.rel_dir}/${f.name}/${f.name}.age";
    in
    lib.optional (builtins.pathExists p) (builtins.hashFile "sha256" p);

  juicefs = "${pkgs.juicefs}/bin/juicefs";
  rclone = "${pkgs.rclone}/bin/rclone";
  jq = "${pkgs.jq}/bin/jq";
  gate = jfs.assertEncryptedSh jq juicefs;
  psql = "${config.services.postgresql.package}/bin/psql";

  # Through modules/storage-juicefs.nix's test seam, as every JuiceFS script is.
  script = name: text: pkgs.writeShellScript name (config.cluster.juicefs.scriptEdit name text);

  # Not two states but six. The metadata engine lives on this node's LOCAL disk,
  # so a reinstall of the juicefs-meta node wipes it while the bucket keeps every
  # chunk and the metadata dumps JuiceFS writes to <volume>/meta/ (every
  # `jfs.backupMeta`, by the mounts). `juicefs format` refuses a non-empty bucket,
  # which is right: formatting over it would orphan every file on the volume.
  #
  #   metadata knows the volume, encrypted  -> apply settings, put the S3
  #                                            credentials back if needed     exit 0
  #   metadata knows the volume, plaintext  -> REFUSE                         exit 3
  #   no metadata, a recent dump in the     -> RESTORE the newest dump, with
  #     bucket                                 the key (the reinstall case;
  #                                            loses at most one interval)    exit 0, or 1
  #   no metadata, newest dump stale        -> refuse unless an override
  #                                            names that dump; a human decides exit 5
  #   no metadata, objects but no dump      -> refuse, loudly; a human decides exit 5
  #   no metadata, bucket empty             -> format, encrypted (first bring-up)
  #   metadata or object storage unreachable -> no verdict, retried            exit 4
  #
  # Exit 4 is the only one systemd retries (RestartForceExitStatus, below): an outage
  # ends on its own. 3 and 5 are verdicts and stay failed (UnitFailed); 1 is a key that
  # does not open the dump, which no retry fixes either.
  #
  # Every path that creates or restores a volume ends in the gate, so a volume
  # this script leaves behind is an encrypted one or the unit fails. That matters
  # because both creating paths fail OPEN on their own [RAN, design 1.18]: format
  # with --encrypt-rsa-key over existing plaintext metadata exits 0 and stays
  # plaintext, and a load is only as encrypted as the dump it was given.
  #
  # The S3 pair lives in the volume's settings, and every client uses THAT copy, not
  # its own environment (juicefs 1.4.1 s3.go: the stored pair wins whenever it is set),
  # and picks up a new one there while mounted (cmd/mount.go OnReload). So the settings
  # are where a rotated ovh-s3 has to land, and where a dump's redacted secret
  # ("removed") has to be replaced, or every mount dies with
  #   format decrypt: secret was removed; please correct it with `config`
  # Both are checked on EVERY run, not only straight after a load: a restore whose
  # `config` step failed (S3 down for a moment, a crash between the two) left the
  # secret "removed" and the next run used to see a known volume and exit 0, while
  # every mount looped [review finding, jfs-encrypted `interrupted-restore-recovers`].
  # The unit is restarted when ovh-s3's ciphertext changes (restartTriggers below).
  #
  # `config --secret-key` has no environment fallback in 1.4.1, so the secret is on
  # its command line, readable in /proc by any local user for the seconds the storage
  # test takes. It runs only when needed (after a restore, after a rotation, once on a
  # node whose state was lost), never on an ordinary boot. `format` takes the pair from
  # ACCESS_KEY/SECRET_KEY instead, and unsets them itself.
  #
  # `--force` is never passed. The first node1 reinstall (2026-09-21) hit the
  # restore state with the two-state script and stayed down.
  formatScript = script "juicefs-format" ''
    set -euo pipefail
    # Double quotes, and pgpass assigned first: see lib/juicefs.nix.
    pgpass=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.pgpass}")
    META="${jfs.metaUrl metaIp}"
    # Before anything else: format and load need it to open the PEM, and so does
    # the `config --secret-key` after a load. Without it the restore failed on that
    # config step [RAN].
    JFS_RSA_PASSPHRASE="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.rsaPass}")"
    export JFS_RSA_PASSPHRASE
    PEM="$CREDENTIALS_DIRECTORY/${jfs.credIds.rsaPem}"
    s3ak=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3ak}")
    s3sk=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3sk}")
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT

    # The pair last put into the volume's settings, as a hash (StateDirectory, root
    # only). Removed before a load, so a crash after the load leaves it missing.
    applied="$STATE_DIRECTORY/s3-applied"
    want=$(printf '%s\n%s\n' "$s3ak" "$s3sk" | sha256sum | cut -d' ' -f1)
    # An operator's go-ahead for one stale dump, by name (see the restore below).
    override="$STATE_DIRECTORY/restore-stale-dump"

    # The database itself, as the juicefs role, the password in the environment.
    sql() {
      PGPASSWORD="$pgpass" ${psql} -X -q -t -A -v ON_ERROR_STOP=1 \
        -h ${metaIp} -p ${toString jfs.metaPort} -U ${jfs.metaDb} -d ${jfs.metaDb} -c "$1"
    }

    # The secret as the settings hold it: ciphertext, or the literal "removed" a dump
    # leaves. `status` can't tell the two apart: it prints "removed" for both.
    stored_secret() {
      sql "SELECT value FROM jfs_setting WHERE name = 'format'" | ${jq} -er '.SecretKey // ""'
    }

    put_s3_back() {
      echo "putting the object-storage credentials from vars into the volume's settings ($1)" >&2
      if ! ${juicefs} config "$META" --access-key "$s3ak" --secret-key "$s3sk" --yes >"$tmp/config.log" 2>&1; then
        tail -n 5 "$tmp/config.log" >&2
        echo "could not put the object-storage credentials into the volume's settings (object storage unreachable, or refusing the key); retried" >&2
        exit 4
      fi
      printf '%s\n' "$want" > "$applied.tmp"
      mv "$applied.tmp" "$applied"
    }

    if status_err=$(${juicefs} status "$META" 2>&1 >/dev/null); then
      ( ${gate} )
      secret=$(stored_secret) || secret=unreadable
      have=$(cat "$applied" 2>/dev/null || true)
      if [ "$secret" = removed ] || [ "$secret" = unreadable ] || [ "$have" != "$want" ]; then
        if [ "$have" = "$want" ]; then why="the stored secret is $secret"; else why="vars not yet applied"; fi
        put_s3_back "$why"
      fi
      # Settings that `format` would set only on a NEW volume, applied
      # idempotently to the existing one. Trash is the undo for deletions --
      # including the rsync --delete of a cluster-restore -- so keep a week.
      ${juicefs} config "$META" --trash-days ${toString jfs.trashDays} --yes >/dev/null
      exit 0
    fi
    # Only an engine that answered "not formatted" is empty. Anything else (the
    # database not up, the role's password not applied yet) is an outage, and
    # judging the bucket from it would be judging the wrong thing.
    case "$status_err" in
      *"database is not formatted"*) ;;
      *)
        printf '%s\n' "$status_err" | tail -n 3 >&2
        echo "metadata unreachable at this engine; not a judgement on the volume. Nothing done." >&2
        exit 4
        ;;
    esac

    # rclone, configured from the environment (no config file on disk).
    export RCLONE_CONFIG_JFS_TYPE=s3 RCLONE_CONFIG_JFS_PROVIDER=Other
    export RCLONE_CONFIG_JFS_ENDPOINT="${os.endpoint}" RCLONE_CONFIG_JFS_REGION="${os.region}"
    export RCLONE_CONFIG_JFS_ACCESS_KEY_ID="$s3ak" RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY="$s3sk"
    prefix="jfs:${os.juicefsBucket}/${jfs.jfsName}"

    # A listing that FAILED must never read as "empty": that is how a reinstall
    # would format a new volume over a bucket full of files, or skip the dump it
    # should restore. rclone exits 3 for a prefix with nothing under it (S3 has no
    # directories); any other failure is an outage, and nothing is judged from it.
    list() {
      local rc=0
      ${rclone} lsf "$@" 2>"$tmp/lsf.err" || rc=$?
      case "$rc" in
        0 | 3) ;;
        *)
          tail -n 3 "$tmp/lsf.err" >&2
          echo "object storage unreachable (rclone exit $rc); not a judgement on the bucket. Nothing done." >&2
          return 4
          ;;
      esac
    }

    # "Not formatted" with tables in the database: a load that was cut short. LoadMeta
    # creates every table first and writes the format row last, so a reboot, an OOM or a
    # PostgreSQL restart in between leaves tables and no format, and JuiceFS refuses to
    # load into a database that has any table ("is not empty"): every later run would
    # fail the same way. Only JuiceFS's own tables are dropped, and only here, where the
    # engine has just said it holds no volume.
    tables=$(sql "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1") || {
      echo "cannot list the metadata database's tables; nothing done" >&2
      exit 4
    }
    if [ -n "$tables" ]; then
      if printf '%s\n' "$tables" | grep -qvE '^jfs_[a-z0-9_]+$'; then
        echo "refusing: the metadata database holds no volume but has tables that are not JuiceFS's:" $tables >&2
        exit 5
      fi
      echo "the metadata database holds JuiceFS tables but no volume: a restore was interrupted. Dropping them before loading again:" $tables >&2
      sql "DROP TABLE IF EXISTS $(printf '%s\n' "$tables" | paste -sd, -) CASCADE" >/dev/null
    fi

    dumps=$(list "$prefix/meta/" --files-only) || exit $?
    latest=$(printf '%s\n' "$dumps" | grep '^dump-.*\.json\.gz$' | sort | tail -1 || true)
    if [ -n "$latest" ]; then
      # How old the dump is, from its name (dump-2026-09-25-153208.json.gz is UTC), as
      # jfs-meta-dump-age reads it. JuiceFS stops writing dumps on its own in some cases
      # (before --backup-meta was set, it skipped every hourly one above a million
      # inodes, with only a warning), and restoring weeks-old metadata against the live
      # bucket loses every newer file and brings deleted ones back: a human decides.
      stamp=$(printf '%s' "$latest" | sed -E 's/^dump-([0-9-]{10})-([0-9]{2})([0-9]{2})([0-9]{2}).*/\1 \2:\3:\4/')
      ts=$(date -u -d "$stamp" +%s) || {
        echo "refusing to restore $latest: its name carries no date this script can read" >&2
        exit 5
      }
      age=$(( $(date -u +%s) - ts ))
      allowed=$(cat "$override" 2>/dev/null || true)
      if [ "$age" -gt ${
        toString (jfs.restoreMaxDumpAgeHours * 3600)
      } ] && [ "$allowed" != "$latest" ]; then
        echo "refusing to restore: the newest metadata dump, $latest, is $((age / 3600)) hours old (more than ${toString jfs.restoreMaxDumpAgeHours}). Restoring it would lose every file written since and bring back every file deleted since." >&2
        echo "Find out why dumps stopped (the mounts' journals, JuiceFSMetaDumpStale) and look for a newer one. To restore this one anyway: echo $latest > $override, then systemctl restart juicefs-format." >&2
        exit 5
      fi
      echo "metadata engine is empty but the bucket holds volume ${jfs.jfsName} with metadata backups: restoring $latest ($((age / 60)) minutes old)" >&2
      ${rclone} copyto "$prefix/meta/$latest" "$tmp/$latest"
      rm -f "$applied"
      # The dumps the mount writes to the bucket are encrypted with the volume's
      # key, so the load needs it: without these flags it reads ciphertext as gzip
      # ("gzip: invalid header"). A wrong PEM or a planted plaintext dump fails
      # here, before the load creates a single table [RAN].
      ${juicefs} load "$META" "$tmp/$latest" --encrypt-rsa-key "$PEM" --encrypt-algo ${jfs.encryptAlgo}
      # A dump redacts the object-storage secret ("removed"): put the pair back. If this
      # fails the volume is loaded and the next run, seeing "removed", tries again.
      put_s3_back "after a load"
      ( ${gate} )
      rm -f "$override"
      exit 0
    fi

    objects=$(list "$prefix/" --max-depth 1) || exit $?
    if [ -n "$objects" ]; then
      echo "refusing to format: ${os.juicefsBucket}/${jfs.jfsName}/ holds objects but no metadata backup (meta/dump-*.json.gz), so formatting would orphan them." >&2
      echo "Those objects are ciphertext: without metadata and the volume's key nothing can read them, and deleting the prefix (rclone purge $prefix) destroys every file on the volume for good. Look for a dump elsewhere (an older copy of meta/, the offline kit) before deciding they are expendable." >&2
      exit 5
    fi

    # The pair from the environment, not the command line: format reads ACCESS_KEY and
    # SECRET_KEY when the flags are absent, and unsets them (cmd/format.go).
    ACCESS_KEY="$s3ak" SECRET_KEY="$s3sk" ${juicefs} format \
      --trash-days ${toString jfs.trashDays} \
      --storage s3 \
      --bucket "${os.endpoint}/${os.juicefsBucket}" \
      --encrypt-rsa-key "$PEM" \
      --encrypt-algo ${jfs.encryptAlgo} \
      "$META" "${jfs.jfsName}"
    ( ${gate} )
    printf '%s\n' "$want" > "$applied"
  '';

  # md5 auth needs the role to actually have the password. Applying it from the
  # vars file at activation keeps the password out of the Nix store, which
  # `ensureUsers` cannot do.
  setPasswordScript = pkgs.writeShellScript "juicefs-pg-password" ''
    set -euo pipefail
    pw=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.pgpass}")
    ${config.services.postgresql.package}/bin/psql -v ON_ERROR_STOP=1 --no-psqlrc \
      -c "ALTER ROLE ${jfs.metaDb} WITH PASSWORD '$pw';"
  '';
in
{
  services.postgresql = {
    enable = true;
    enableTCPIP = true;
    # Every address, whatever else sets it: see `authentication` below for why.
    settings.listen_addresses = lib.mkForce "*";
    # Collation owned by PostgreSQL, not glibc. With the default (libc,
    # en_US.UTF-8) every glibc bump in nixpkgs changes the sort rules under the
    # text indexes and logs "collation version mismatch" on every connection
    # (2.42 -> 2.44 did, 2026-10). The builtin provider's C.UTF-8 is versioned
    # by PostgreSQL itself, and JuiceFS's few text columns are internal keys
    # (setting/counter/xattr names) that need byte order, not a language's.
    # initdb reads this only when it creates the cluster: an existing one is
    # moved over by dump -> re-init -> restore (see juicefs-format below).
    initdbArgs = [
      "--locale=C.UTF-8"
      "--locale-provider=builtin"
    ];
    ensureDatabases = [ jfs.metaDb ];
    ensureUsers = [
      {
        name = jfs.metaDb;
        ensureDBOwnership = true;
      }
    ];
    # Other nodes' JuiceFS clients reach it over the control mesh, so only from
    # the mesh subnet, with the password.
    #
    # It listens on every address (enableTCPIP: listen_addresses = "*"), NOT on
    # 127.0.0.1 plus the mesh address. PostgreSQL binds its listeners once, at start:
    # if the mesh address is not up yet it warns, starts anyway on loopback alone,
    # and never binds the mesh address when it appears, so every other node loses
    # its metadata while the unit looks healthy [RAN, design 1.16]. What confines it
    # instead is the host firewall (the weak-host rule; 5432 is accepted on the mesh
    # interface only, `juicefs-pg-unreachable-on-vlan`) and this line.
    authentication = lib.mkAfter ''
      host ${jfs.metaDb} ${jfs.metaDb} ${topology.mesh.subnet} scram-sha-256
    '';
  };

  # Set the role password from vars, then format. Ordered before the mount so a
  # cold cluster comes up in one boot: password -> format -> mount.
  systemd.services.juicefs-pg-password = {
    description = "Apply the JuiceFS metadata role password from vars";
    # postgresql-setup.service, NOT postgresql.service: `ensureUsers` creates
    # the role in the SETUP unit, which runs after the server is up. Ordering
    # only on postgresql.service raced it and failed with
    #   ERROR:  role "juicefs" does not exist
    after = [
      "postgresql.service"
      "postgresql-setup.service"
    ];
    requires = [
      "postgresql.service"
      "postgresql-setup.service"
    ];
    before = [ "juicefs-format.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "postgres";
      ExecStart = "${setPasswordScript}";
      LoadCredential = [ "${jfs.credIds.pgpass}:${vars.juicefs-pg.files.password.path}" ];
    };
  };

  # Age of the newest metadata dump JuiceFS wrote to the bucket (every
  # `jfs.backupMeta`, by the mounts). A rebuilt juicefs-meta node restores from it, so
  # its age is how much metadata a reinstall would lose. Written for alerting
  # (JuiceFSMetaDumpStale). A new volume has no dump until the mounts write the first:
  # that is not a failure, and the metric then counts from the first time the bucket
  # was seen without one, so the alert still fires if none ever comes.
  systemd.services.jfs-meta-dump-age = {
    description = "Report the newest JuiceFS metadata dump (metrics)";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      StateDirectory = "jfs-meta-dump-age";
      # The names of the dumps are all it reads, so no key: just the S3 pair.
      LoadCredential = [
        "${jfs.credIds.s3ak}:${vars.ovh-s3.files."access-key".path}"
        "${jfs.credIds.s3sk}:${vars.ovh-s3.files."secret-key".path}"
      ];
      ExecStart = pkgs.writeShellScript "jfs-meta-dump-age" ''
        set -euo pipefail
        s3ak=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3ak}")
        s3sk=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3sk}")
        export RCLONE_CONFIG_JFS_TYPE=s3 RCLONE_CONFIG_JFS_PROVIDER=Other
        export RCLONE_CONFIG_JFS_ENDPOINT="${os.endpoint}" RCLONE_CONFIG_JFS_REGION="${os.region}"
        export RCLONE_CONFIG_JFS_ACCESS_KEY_ID="$s3ak" RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY="$s3sk"
        # A failed listing is not an empty bucket: the unit fails and the metric stays
        # as it was. rclone's 3 is "no such directory", which is a volume with no dump.
        rc=0
        listing=$(${rclone} lsf "jfs:${os.juicefsBucket}/${jfs.jfsName}/meta/" --files-only) || rc=$?
        case "$rc" in
          0 | 3) ;;
          *)
            echo "object storage unreachable (rclone exit $rc); not a judgement on the dumps" >&2
            exit 1
            ;;
        esac
        newest=$(printf '%s\n' "$listing" | grep '^dump-.*\.json\.gz$' | sort | tail -1 || true)
        empty_since="$STATE_DIRECTORY/empty-since"
        if [ -n "$newest" ]; then
          # dump-2026-09-25-153208.json.gz -> 2026-09-25 15:32:08 UTC
          stamp=$(echo "$newest" | sed -E 's/^dump-([0-9-]{10})-([0-9]{2})([0-9]{2})([0-9]{2}).*/\1 \2:\3:\4/')
          ts=$(date -u -d "$stamp" +%s)
          rm -f "$empty_since"
        else
          [ -s "$empty_since" ] || date -u +%s > "$empty_since"
          ts=$(cat "$empty_since")
          echo "no metadata dump in the bucket yet; counting from $(date -u -d "@$ts" +%FT%TZ)" >&2
        fi
        m=/var/lib/prometheus-node-exporter-text
        mkdir -p "$m"
        echo "cluster_jfs_meta_dump_newest_timestamp_seconds $ts" > "$m/jfs_meta_dump.prom.tmp"
        mv "$m/jfs_meta_dump.prom.tmp" "$m/jfs_meta_dump.prom"
      '';
    };
  };
  systemd.timers.jfs-meta-dump-age = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "10min";
      OnUnitActiveSec = "30min";
    };
  };

  systemd.services.juicefs-format = {
    description = "Format JuiceFS volume (idempotent, metadata node)";
    after = [
      "postgresql.service"
      "juicefs-pg-password.service"
      "network-online.target"
    ];
    requires = [ "juicefs-pg-password.service" ];
    wants = [ "network-online.target" ];
    before = [ "juicefs-mount.service" ];
    wantedBy = [ "multi-user.target" ];
    # A new ovh-s3 value has to reach the volume's settings, where every mount reads it
    # (and picks it up while mounted): re-run on a switch that changes its ciphertext.
    restartTriggers = ciphertextHash "ovh-s3" "access-key" ++ ciphertextHash "ovh-s3" "secret-key";
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${formatScript}";
      LoadCredential = loadCreds;
      # The applied S3 pair's hash and an operator's stale-dump override.
      StateDirectory = "juicefs-format";
      StateDirectoryMode = "0700";
      # An outage (exit 4) ends on its own, so it is retried; nothing else is. The unit
      # sits in auto-restart meanwhile, which UnitRestartLoop reports after 15 minutes.
      RestartForceExitStatus = [ 4 ];
      RestartSec = 30;
    };
  };
}
