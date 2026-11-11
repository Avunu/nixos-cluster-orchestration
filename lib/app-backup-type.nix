# lib/app-backup-type.nix — the per-app `backup` option (clusterApps.<n>.backup).
#
# Its own file so tests can declare a minimal clusterApps with the SAME backup
# schema the real one has (tests/backup-roundtrip.nix), rather than a copy.
{ lib }:
let
  inherit (lib) mkOption types;
in
types.submodule {
  options = {
    enable = mkOption {
      type = types.bool;
      default = true;
    };
    engine = mkOption {
      type = types.nullOr (
        types.enum [
          "postgresql"
          "mariadb"
          "none"
        ]
      );
      default = null;
      description = ''
        The database dumped inside the container. null = detected from
        the container's own config (services.postgresql / services.mysql).
      '';
    };
    appUnits = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      example = [ "odoo.service" ];
      description = ''
        Units inside the container that are stopped while its database or
        local state is restored, then started again (which re-runs
        deploy-time migrations). null = every unit ordered after the
        database, transitively, detected from the container config -- so a
        localSnapshot app without a database must list its units.
      '';
    };
    exclude = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "*/sessions" ];
      description = "restic --exclude patterns for this app's JuiceFS paths (and localState, with localSnapshot), on top of the defaults.";
    };
    localSnapshot = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Also back up the app's localState directories, read from a ZFS
        snapshot taken for the purpose -- atomic, so consistent to the
        instant, with the app still running. For state that has no logical
        dump the cluster knows how to take (a directory server, a CA),
        where a crash-consistent copy is what a restore can work with.
        Off by default: a database directory is covered by its dump, and
        shipping it raw as well only costs space.
      '';
    };
    preCommand = mkOption {
      type = types.nullOr types.lines;
      default = null;
      example = "podman exec freeipa ipa-backup --data --online";
      description = ''
        Shell run INSIDE the container (as root, as a transient unit of its
        systemd, so `podman exec` works) before the backup reads anything -- to have the app write its
        own export into its localState, so the snapshot holds it. A failure
        fails the backup.
      '';
    };
    verifyCommand = mkOption {
      type = types.nullOr types.lines;
      default = null;
      example = ''test -s "$ROOT/var/lib/app/ca.crt"'';
      description = ''
        Shell run ON THE HOST during the weekly restore rehearsal of a
        localSnapshot app, against the restored tree: each localState
        directory is at $ROOT/<its guest path>. It must exit 0. null =
        every localState directory came back non-empty.
      '';
    };
    verifyQuery = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        SQL run against every restored database during the weekly
        restore rehearsal; it must return a single number > 0. null =
        "the database has at least one table".
      '';
    };
  };
}
