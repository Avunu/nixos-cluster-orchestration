# tests/lib/jfs-plain-pg.nix — one plain PostgreSQL where JuiceFS expects its metadata.
#
# For the tests that are about the volume and not about the database behind it
# (tests/jfs-encrypted.nix, tests/canary-scan.nix): they import
# modules/storage-juicefs-format.nix and modules/storage-juicefs.nix as production
# has them, and this in place of modules/storage-juicefs-pg.nix, whose Patroni
# wants an etcd and is the business of tests/cluster.nix. It listens where a
# node's HAProxy does (lib/juicefs.nix metaHost:metaPort), so every script under
# test runs unchanged.
{
  config,
  pkgs,
  clusterLib,
  ...
}:
let
  jfs = clusterLib.juicefs;
in
{
  services.postgresql = {
    enable = true;
    enableTCPIP = true;
    settings.port = jfs.metaPort;
    ensureDatabases = [ jfs.metaDb ];
    ensureUsers = [
      {
        name = jfs.metaDb;
        ensureDBOwnership = true;
      }
    ];
    authentication = ''
      host ${jfs.metaDb} ${jfs.metaDb} 0.0.0.0/0 scram-sha-256
    '';
  };

  # The unit name production's juicefs-format is ordered after.
  systemd.services.juicefs-pg-setup = {
    description = "Apply the JuiceFS metadata role password (test engine)";
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
      LoadCredential = [
        "pgpass:${config.clan.core.vars.generators.juicefs-pg.files.password.path}"
      ];
      ExecStart = pkgs.writeShellScript "juicefs-pg-setup" ''
        set -euo pipefail
        pw=$(cat "$CREDENTIALS_DIRECTORY/pgpass")
        ${config.services.postgresql.package}/bin/psql -v ON_ERROR_STOP=1 --no-psqlrc \
          -c "ALTER ROLE ${jfs.metaDb} WITH PASSWORD '$pw';"
      '';
    };
  };
}
