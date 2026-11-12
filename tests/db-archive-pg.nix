# VM test: the database archive tier for PostgreSQL, against an S3 server in the VM.
#
# Runs the REAL modules/db-postgres.nix in a plain NixOS system, as an app's
# container runs it, with credential files instead of an app's secrets. rclone
# serves S3 from a directory, over TLS with a certificate made at start, so the
# script reads storage as files.
#
# What it proves:
#   - a fresh data directory on an empty archive starts generation 1 by the
#     timer alone, with its first base backup;
#   - a change reaches storage with nobody asking: PostgreSQL closes the WAL
#     segment itself and hands it over;
#   - what reaches storage is encrypted: every stored object is ciphertext, and a
#     canary that is in the local WAL is in none of them;
#   - no key, no upload;
#   - a data directory without its marker does not adopt an archive that holds
#     data, nor one that could not be listed, nothing is uploaded while that
#     stands, and `next-generation` is the way on, leaving the old generation as
#     it was;
#   - base backups are taken when due and the older ones removed; one restores
#     with the key and not with another, and comes back without a marker;
#   - WAL that cannot be archived is kept up to the limit and dropped beyond it,
#     and the gap that leaves holds the freshness metric still until a base
#     backup, taken without waiting for its interval, has closed it;
#   - the archive catches up after a storage outage, by itself;
#   - a clean stop ships the last WAL, and a stop without storage still stops.
#
# flake.nix's db-archive-pg-* mutants each remove one of those controls.
#
# Run: nix build .#checks.x86_64-linux.db-archive-pg -L   (needs KVM)
{
  pkgs,
  lib,
  mutant ? "",
  extraModule ? { },
}:
let
  s3User = "archiveuser";
  s3Secret = "archivesecret1234";
  # Fixtures. The key is 64 hexadecimal characters, as a generated one is.
  key = lib.concatStrings (lib.genList (_: "0123456789abcdef") 4);
  otherKey = lib.concatStrings (lib.genList (_: "fedcba9876543210") 4);
  canary = "CANARY-db-archive-pg-8e27c4a1b65d4f09";
  creds = "/run/db-creds";
in
pkgs.testers.runNixOSTest {
  name = "cluster-db-archive-pg";

  # The node builds its own pkgs, as a container does.
  node.pkgs = lib.mkForce null;

  nodes.pg =
    { pkgs, ... }:
    {
      imports = [
        ../modules/nixpkgs-overlays.nix
        ../modules/db-postgres.nix
        extraModule
      ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      # An S3 endpoint backed by a directory: each top-level dir is a bucket.
      # One instance: two over one directory each keep their own listing cache.
      # pgBackRest speaks TLS only, so it has a certificate, which nothing checks.
      systemd.services.s3 = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          mkdir -p /srv/s3/dbarchive /var/lib/s3tls
          if [ ! -e /var/lib/s3tls/cert.pem ]; then
            ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 2 \
              -keyout /var/lib/s3tls/key.pem -out /var/lib/s3tls/cert.pem
          fi
          exec ${pkgs.rclone}/bin/rclone serve s3 --addr 127.0.0.1:9000 \
            --cert /var/lib/s3tls/cert.pem --key /var/lib/s3tls/key.pem \
            --auth-key ${s3User},${s3Secret} /srv/s3
        '';
      };

      systemd.tmpfiles.rules = [
        "d ${creds} 0700 root root -"
        "f ${creds}/access-key 0400 root root - ${s3User}"
        "f ${creds}/secret-key 0400 root root - ${s3Secret}"
        "f ${creds}/key 0400 root root - ${key}"
      ];

      services.postgresql = {
        enable = true;
        # As modules/kinds/odoo.nix runs it.
        settings.full_page_writes = false;
      };

      cluster.dbArchive = {
        enable = true;
        s3 = {
          endpoint = "https://127.0.0.1:9000";
          verifyTls = false;
          region = "us-east-1";
          bucket = "dbarchive";
          prefix = "app";
        };
        credentialFiles = {
          accessKey = "${creds}/access-key";
          secretKey = "${creds}/secret-key";
          encryptionKey = "${creds}/key";
        };
        flushSeconds = 10;
        retainBaseBackups = 2;
        # Two 16 MiB segments may wait; a third is over.
        postgres.queueMaxMiB = 40;
      };
    };

  testScript =
    { nodes, ... }:
    lib.concatStringsSep "\n" [
      ''
        MUTANT = "${mutant}"
        CANARY = "${canary}"
        KEY = "${key}"
        OTHER_KEY = "${otherKey}"
        KEY_FILE = "${creds}/key"
        STORAGE = "/srv/s3/dbarchive/app"
        MARKER = "${nodes.pg.cluster.dbArchive.markerFile}"
        METRICS = "${nodes.pg.cluster.dbArchive.metricsFile}"
        DATA_DIR = "${nodes.pg.services.postgresql.dataDir}"
        GAP = "${nodes.pg.services.postgresql.dataDir}/db-archive.gap"
      ''
      (builtins.readFile ./lib/control.py)
      (builtins.readFile ./db-archive-pg.py)
    ];
}
