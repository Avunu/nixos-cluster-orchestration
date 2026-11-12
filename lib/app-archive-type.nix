# lib/app-archive-type.nix — the per-app `archive` option (clusterApps.<n>.archive).
#
# Continuous archiving of the app's database to object storage, client-side
# encrypted: a base backup, and every change since. modules/db-archive.nix reads
# it on the host; modules/db-mariadb.nix and modules/db-postgres.nix do the work
# inside the container.
{ lib }:
let
  inherit (lib) mkOption types;
in
types.submodule {
  options = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Archive this app's database continuously. Needs
        topology.objectStorage.dbArchiveBucket, and a restart of the container
        the first time: the credentials are bind mounts, which a running
        container does not gain on a deploy.
      '';
    };
    flushSeconds = mkOption {
      type = types.ints.between 10 3600;
      default = 60;
      description = ''
        How often changes are closed off and shipped. This is the most that is
        lost when the node is: writes newer than the last shipment exist only
        on its disks.
      '';
    };
    baseIntervalHours = mkOption {
      type = types.ints.between 1 168;
      default = 24;
      description = ''
        How old the newest base backup may get before another is taken. A
        restore replays every change since its base backup, so this bounds the
        replay.
      '';
    };
    retainBaseBackups = mkOption {
      type = types.ints.between 2 30;
      default = 2;
      description = ''
        Base backups kept per generation, with the changes since the oldest of
        them. At least two: with one, the only restorable copy is deleted the
        moment its successor is written, before anything has read it back.
      '';
    };
  };
}
