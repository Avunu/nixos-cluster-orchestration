# VM test: the database archive tier, for real, against an S3 server in the VM.
#
# Runs the REAL modules/db-mariadb.nix in a plain NixOS system, as an app's
# container runs it, with credential files instead of an app's secrets. rclone
# serves S3 from a directory, so the script reads storage as files.
#
# What it proves:
#   - a fresh data directory on an empty archive starts generation 1 by the
#     timer alone, and a push is recorded only once its log is in storage;
#   - what reaches storage is encrypted: a canary that is in the local binary
#     log is in no stored object, and a base backup fetched with the key holds
#     the database while a fetch with another key fails;
#   - neither WAL-G's cache nor its exit status is trusted: with the cache
#     naming the log being written a push still uploads it, and what is recorded
#     as pushed is there;
#   - no key, no upload;
#   - binary logs numbered again from the start are refused;
#   - a data directory without its marker does not adopt an archive that holds
#     data, nor one that could not be listed, and `next-generation` is the way on;
#   - base backups are taken when due and the older ones removed;
#   - the timer keeps running through a storage outage and catches up after it;
#   - a clean stop ships the last log, and a stop without storage still stops.
#
# flake.nix's db-archive-* mutants each remove one of those controls.
#
# Run: nix build .#checks.x86_64-linux.db-archive -L   (needs KVM)
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
  canary = "CANARY-db-archive-5d1f0c7e93ab4628";
  creds = "/run/db-creds";
in
pkgs.testers.runNixOSTest {
  name = "cluster-db-archive";

  # modules/nixpkgs-overlays.nix sets nixpkgs.overlays (wal-g-mysql), so the
  # node builds its own pkgs from it, as a container does.
  node.pkgs = lib.mkForce null;

  nodes.maria =
    { pkgs, ... }:
    {
      imports = [
        ../modules/nixpkgs-overlays.nix
        ../modules/db-mariadb.nix
        extraModule
      ];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;

      # An S3 endpoint backed by a directory: each top-level dir is a bucket.
      # One instance: two over one directory each keep their own listing cache.
      systemd.services.s3 = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          mkdir -p /srv/s3/dbarchive
          exec ${pkgs.rclone}/bin/rclone serve s3 --addr 127.0.0.1:9000 \
            --auth-key ${s3User},${s3Secret} /srv/s3
        '';
      };

      systemd.tmpfiles.rules = [
        "d ${creds} 0700 root root -"
        "f ${creds}/access-key 0400 root root - ${s3User}"
        "f ${creds}/secret-key 0400 root root - ${s3Secret}"
        "f ${creds}/key 0400 root root - ${key}"
      ];

      services.mysql = {
        enable = true;
        package = pkgs.mariadb;
      };

      cluster.dbArchive = {
        enable = true;
        s3 = {
          endpoint = "http://127.0.0.1:9000";
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
        STATE = "${nodes.maria.cluster.dbArchive.stateDir}"
        MARKER = "${nodes.maria.cluster.dbArchive.markerFile}"
        METRICS = "${nodes.maria.cluster.dbArchive.metricsFile}"
        DATA_DIR = "${nodes.maria.services.mysql.dataDir}"
        WALG_CACHE = "${nodes.maria.users.users.root.home}/.walg_mysql_binlogs_cache"
      ''
      (builtins.readFile ./lib/control.py)
      (builtins.readFile ./db-archive.py)
    ];
}
