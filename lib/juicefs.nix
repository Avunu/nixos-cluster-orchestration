# lib/juicefs.nix — pure JuiceFS naming/URL helpers.
#
# Extracted so the client half (modules/storage-juicefs.nix, every node) and the
# metadata half (modules/storage-juicefs-meta.nix, the juicefs-meta node) agree
# on the volume name, mountpoint and meta URL without one importing the other.
# No `pkgs`; only `lib`.
{ lib }:
rec {
  metaDb = "juicefs";
  jfsName = "appfs";
  mountPoint = "/mnt/jfs";
  # Days a deleted file stays in /mnt/jfs/.trash (juicefs format/config).
  trashDays = 7;
  cacheDir = "/var/jfsCache";
  metaPort = 5432;

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
  # is an outage (a cold start, the metadata node waiting for its passphrase, the
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
  metaUrl = metaIp: "postgres://${metaDb}:$pgpass@${metaIp}:${toString metaPort}/${metaDb}";

  # LoadCredential entries given a resolver from credential id -> host path.
  # Stage 2 swapped these from agenix paths to clan vars paths by changing only
  # the resolver passed in here.
  # `pathFor` is given the attribute name (rsaPem); the credential is named by its
  # value (rsapem), which is what the scripts read. The two were equal until WS11.
  loadCredentials = pathFor: lib.mapAttrsToList (key: id: "${id}:${pathFor key}") credIds;
}
