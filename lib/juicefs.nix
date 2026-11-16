# lib/juicefs.nix — pure JuiceFS naming/URL helpers.
#
# Extracted so the client (modules/storage-juicefs.nix), the volume's format and
# restore (modules/storage-juicefs-format.nix) and the metadata database
# (modules/storage-juicefs-pg.nix), all three on every node, agree on the volume
# name, mountpoint and meta URL without one importing the other.
# No `pkgs`; only `lib`.
{ lib }:
rec {
  metaDb = "juicefs";
  jfsName = "appfs";
  mountPoint = "/mnt/jfs";
  # Days a deleted file stays in /mnt/jfs/.trash (juicefs format/config).
  trashDays = 7;
  cacheDir = "/var/jfsCache";
  # Where a JuiceFS client finds the metadata database: its own node's loopback,
  # always. HAProxy listens there and passes the connection to whichever node holds
  # the primary (modules/storage-juicefs-pg.nix), so no client names a node.
  metaHost = "127.0.0.1";
  metaPort = 5432;
  # The PostgreSQL every member runs, and whose psql the scripts use: the major
  # NixOS itself picks for a state version, so a data directory services.postgresql
  # made is one this opens. One state version for the site (topology.stateVersion),
  # so one major for every member. A major upgrade is pg_upgrade's business, by hand.
  metaPgPackage =
    pkgs: stateVersion:
    if lib.versionAtLeast stateVersion "26.11" then
      pkgs.postgresql_18
    else if lib.versionAtLeast stateVersion "25.11" then
      pkgs.postgresql_17
    else
      pkgs.postgresql_16;

  # The session-level advisory lock juicefs-format holds while it decides and acts,
  # so that two nodes never format or restore at once. Any constant; "jfsf".
  formatLockId = 1785097062;

  # Credential IDs used with systemd LoadCredential. Both halves read the same
  # five, so they are named once here.
  #
  # rsaPem and rsaPass are the volume's encryption key (vars `juicefs-rsa`): the PEM
  # is what `format` and `load` are given; the passphrase is what every client needs
  # to use it, because the PEM itself is stored in the metadata, encrypted with that
  # passphrase. Who needs the passphrase [RAN, design 1.18]: format, mount, gateway,
  # load, gc, fsck, and config with --secret-key. Not status, dump, or config
  # --trash-days.
  credIds = {
    s3ak = "s3ak";
    s3sk = "s3sk";
    pgpass = "pgpass";
    rsaPem = "rsapem";
    rsaPass = "rsapass";
  };

  # How often the mounts dump the metadata to <volume>/meta/ (`juicefs mount
  # --backup-meta`). Above an hour on purpose: JuiceFS 1.4.1 skips every automatic dump
  # of a volume past a million inodes when the interval is an hour or less, with only a
  # warning in the client's log (pkg/vfs/backup.go), and the reinstall path restores
  # from these dumps.
  backupMeta = "2h";
  # The newest dump a reinstall restores without asking: three intervals. An older one
  # means the dumps stopped, and restoring it would lose everything written since.
  restoreMaxDumpAgeHours = 6;

  # The data encryption JuiceFS wraps with the RSA key. A volume's key and algorithm
  # can't be changed once it is formatted: rotating either means a new volume.
  encryptAlgo = "aes256gcm-rsa";

  # The fail-closed gate, shared by the format and mount scripts. Nix evaluation
  # can't see metadata, and every path around a plaintext volume fails open silently
  # without this check [RAN, design 1.18]: `juicefs format --encrypt-rsa-key` on
  # existing plaintext metadata exits 0 and stays plaintext, and mounting plaintext
  # with JFS_RSA_PASSPHRASE set succeeds. Expects $META to be set.
  #
  # Exit 4: `juicefs status` failed, so the metadata engine could not be read. That
  # is an outage (a cold start, the primary changing hands, a node waiting for its passphrase, the
  # mesh down), not a judgement on encryption.
  # Exit 3: status succeeded and the volume is NOT encrypted. A security refusal.
  #
  # Written to run in a subshell (`( gate ) || rc=$?`): it exits.
  assertEncryptedSh = jq: juicefs: ''
    # Distinguish "metadata unreachable" (a Postgres/cold-start outage) from "not
    # encrypted" (a security refusal). Check the status exit code FIRST: piping a
    # failed `status` into jq would misreport an outage as an unencrypted volume,
    # firing a critical security alert at 3am for a database problem.
    st="$(${juicefs} status "$META" 2>/dev/null)" || {
      echo "metadata unreachable at this engine; not a judgement on encryption. Retrying." >&2
      exit 4            # distinct from 3; the mount unit's Restart=on-failure retries
    }
    # Never EncryptAlgo: a plaintext volume reports aes256gcm-rsa too (RAN), and
    # KeyEncrypted true (that flag is about the stored S3 secret). Only EncryptKey
    # tells: status prints "removed" in place of a key that exists, and omits it
    # when there is none.
    if ! printf '%s' "$st" | ${jq} -e '.Setting.EncryptKey == "removed"' >/dev/null; then
      echo "REFUSING: the volume at this metadata engine is NOT encrypted" >&2
      exit 3
    fi
  '';

  # The password-bearing metadata URL. The password is referenced as the shell
  # variable $pgpass rather than an embedded $(cat …): callers assign pgpass
  # first, then interpolate this inside DOUBLE quotes.
  #
  # The previous form embedded a command substitution and every caller wrapped
  # it in SINGLE quotes, so the substitution never ran and juicefs received the
  # literal text:
  #   parse "postgres://juicefs:$(cat \"$CREDENTIALS_DIRECTORY/pgpass\")@…":
  #   invalid port
  # Keeping the expansion at the call site makes that mistake impossible to
  # repeat silently — an unset $pgpass yields an obviously empty password
  # rather than a URL containing shell source.
  volumeUrl = v: "postgres://${v.db}:$pgpass@${metaHost}:${toString metaPort}/${v.db}";

  # ── Volumes ───────────────────────────────────────────────────────────────
  # One for the cluster itself, mounted on every node: the deploy's canary marker,
  # the write probe, the canary scan. No app's files are in it.
  #
  # One for each app that has files on JuiceFS (`juicefsPaths`): its own bucket, its
  # own S3 pair that opens only that bucket, its own key, its own database (and
  # role, of the same name) in the metadata cluster. Mounted where the app runs,
  # for as long as it runs there. A preview slot has no volume: its files are a
  # `juicefs clone` inside the volume of the app it previews.
  #
  # A volume is this record. `files` says where each credential is: generator and file.
  systemVolume = os: {
    app = null;
    name = jfsName;
    db = metaDb;
    inherit mountPoint;
    bucket = os.juicefsBucket;
    suffix = "";
    files = {
      s3ak = [
        "ovh-s3"
        "access-key"
      ];
      s3sk = [
        "ovh-s3"
        "secret-key"
      ];
      pgpass = [
        "juicefs-pg"
        "password"
      ];
      rsaPem = [
        "juicefs-rsa"
        "rsa.pem"
      ];
      rsaPass = [
        "juicefs-rsa"
        "rsa-passphrase"
      ];
    };
  };
  appMountRoot = "/mnt/jfs-app";
  # Bucket names are the provider's namespace, shared with its every customer, so an
  # app's carries the site's: `objectStorage.appBucketPrefix`, or the cluster
  # volume's bucket name.
  appBucket = os: app: "${os.appBucketPrefix or os.juicefsBucket}-${app}";
  appS3Generator = app: "${app}-jfs-s3";
  appKeyGenerator = app: "${app}-jfs";
  appVolume = os: app: {
    inherit app;
    name = app;
    # A PostgreSQL identifier written without quotes.
    db = "jfs_" + lib.replaceStrings [ "-" "." ] [ "_" "_" ] app;
    mountPoint = "${appMountRoot}/${app}";
    bucket = appBucket os app;
    suffix = "-${app}";
    files = {
      s3ak = [
        (appS3Generator app)
        "access-key"
      ];
      s3sk = [
        (appS3Generator app)
        "secret-key"
      ];
      pgpass = [
        (appKeyGenerator app)
        "pg-password"
      ];
      rsaPem = [
        (appKeyGenerator app)
        "rsa.pem"
      ];
      rsaPass = [
        (appKeyGenerator app)
        "rsa-passphrase"
      ];
    };
  };
  # The volumes `clusterApps` asks for, by name: one for each `juicefsVolume` an app
  # with files on JuiceFS names (its own name, unless it says otherwise). A preview
  # slot names the volume of the app it previews.
  volumeApps =
    apps:
    lib.unique (
      lib.mapAttrsToList (_: a: a.juicefsVolume) (lib.filterAttrs (_: a: a.juicefsPaths != { }) apps)
    );
  # Where a volume's credential is on a node, by its key in `credIds`.
  volumeCredPath =
    vars: v: key:
    vars.${lib.head v.files.${key}}.files.${lib.last v.files.${key}}.path;
  volumeLoadCredentials = vars: v: loadCredentials (volumeCredPath vars v);

  # LoadCredential entries given a resolver from credential id -> host path.
  # Stage 2 swapped these from agenix paths to clan vars paths by changing only
  # the resolver passed in here.
  # `pathFor` is given the attribute name (rsaPem); the credential is named by its
  # value (rsapem), which is what the scripts read. The two were equal until WS11.
  loadCredentials = pathFor: lib.mapAttrsToList (key: id: "${id}:${pathFor key}") credIds;
}
