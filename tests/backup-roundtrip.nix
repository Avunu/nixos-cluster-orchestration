# VM test: backup → damage → restore, for real, against an S3 server in the VM.
#
# Runs the REAL modules/backup-core.nix (not a copy) with plain credential
# files instead of clan vars, and two ordinary NixOS containers standing in for
# apps: one on PostgreSQL, one on MariaDB, each with a dummy "app" unit ordered
# after its database -- which cluster-restore must stop and start again. A
# third app has no database, only files. A fourth keeps its state in local
# directories on ZFS (backup.localSnapshot), as a directory server does.
#
# What it proves, end to end:
#   - each app lands in its OWN repository (apps/<name>) on an S3 target
#     (rclone's S3 server here, not MinIO: nixpkgs marks MinIO insecure, and a
#     second S3 implementation is a fair test that nothing assumes MinIO);
#   - dumps come from inside the container, with the container's tools;
#   - a restore brings back rows and files, removes what was added since, keeps
#     excluded paths, and restarts the app units;
#   - --to-scratch extracts without touching anything; no --yes = dry run;
#   - the restore rehearsal (verify) passes, and prune/check runs;
#   - a stopped container fails its backup loudly (status metric 0);
#   - local state comes back from a ZFS snapshot with owners, ACLs and hard
#     links intact, the preCommand's export in it -- with the container up
#     (its appUnits stopped around the copy) and with it down; a snapshot a
#     dead run left behind does not break the next one;
#   - deploy holds are released afterwards.
#
# Run: nix build .#checks.x86_64-linux.backup-roundtrip -L   (needs KVM)
{ pkgs, lib }:
let
  clusterLib = import ../lib { inherit lib; };

  s3User = "backupadmin";
  s3Secret = "backupsecret1234";

  topology = {
    backup = {
      target = {
        type = "s3";
        endpoint = "http://127.0.0.1:9000";
        bucket = "backups";
        region = "us-east-1";
      };
      # Never inside the test's lifetime: the script drives every run itself.
      schedule = "2099-01-01";
      maintenance = "2099-01-01";
      verify = "2099-01-01";
      retention = {
        daily = 7;
        weekly = 4;
        monthly = 12;
      };
      uploadLimitKiB = 0;
    };
  };

  # The subset of clusterApps backup-core reads, with the REAL backup schema.
  stubClusterApps =
    { lib, ... }:
    {
      options.clusterApps = lib.mkOption {
        default = { };
        type = lib.types.attrsOf (
          lib.types.submodule (
            { name, ... }:
            {
              options = {
                name = lib.mkOption {
                  type = lib.types.str;
                  default = name;
                };
                homeNode = lib.mkOption {
                  type = lib.types.nullOr lib.types.str;
                  default = null;
                };
                localState = lib.mkOption {
                  type = lib.types.attrsOf lib.types.str;
                  default = { };
                };
                juicefsPaths = lib.mkOption {
                  type = lib.types.attrsOf lib.types.str;
                  default = { };
                };
                backup = lib.mkOption {
                  type = import ../lib/app-backup-type.nix { inherit lib; };
                  default = { };
                };
              };
            }
          )
        );
      };
    };

  # A stand-in for the app: a long-running unit ordered after the database.
  appUnit = db: {
    description = "stand-in app";
    wantedBy = [ "multi-user.target" ];
    after = [ db ];
    serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
  };
in
pkgs.testers.runNixOSTest {
  name = "cluster-backup-roundtrip";

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [
        stubClusterApps
        ../modules/backup-core.nix
      ];
      _module.args = {
        inherit topology clusterLib;
        node.tags = [ ];
        nodeName = "machine";
      };
      virtualisation.memorySize = 3072;
      virtualisation.cores = 2;

      # An S3 endpoint backed by a directory: each top-level dir is a bucket.
      systemd.services.s3 = {
        wantedBy = [ "multi-user.target" ];
        script = ''
          mkdir -p /srv/s3/backups
          exec ${pkgs.rclone}/bin/rclone serve s3 --addr 127.0.0.1:9000 \
            --auth-key ${s3User},${s3Secret} /srv/s3
        '';
      };
      environment.systemPackages = [
        pkgs.jq
        pkgs.acl
      ];

      # The localSnapshot app's state lives on ZFS, in a file-backed pool the
      # test script creates -- legacy-mounted at /state, as rpool/state is.
      boot.supportedFilesystems = [ "zfs" ];
      networking.hostId = "8425e349";

      cluster.backup.credentialFiles = {
        password = "${pkgs.writeText "restic-password" "correct horse battery staple"}";
        id = "${pkgs.writeText "backup-id" s3User}";
        secret = "${pkgs.writeText "backup-secret" s3Secret}";
      };

      containers.pgapp = {
        autoStart = true;
        config = {
          services.postgresql = {
            enable = true;
            ensureDatabases = [ "pgapp" ];
            ensureUsers = [
              {
                name = "pgapp";
                ensureDBOwnership = true;
              }
            ];
          };
          systemd.services.pgapp-web = appUnit "postgresql.target";
          system.stateVersion = "25.11";
        };
      };
      containers.myapp = {
        autoStart = true;
        config =
          { pkgs, ... }:
          {
            services.mysql = {
              enable = true;
              package = pkgs.mariadb;
              ensureDatabases = [ "myapp" ];
            };
            systemd.services.myapp-web = appUnit "mysql.service";
            system.stateVersion = "25.11";
          };
      };

      # Its bind source is on the pool, which exists only once the script has
      # made it -- so this one is started by hand.
      containers.zfsapp = {
        autoStart = false;
        bindMounts."/var/lib/zfsapp" = {
          hostPath = "/state/clients/zfsapp/data";
          isReadOnly = false;
        };
        config = {
          systemd.services.zfsapp-web = {
            wantedBy = [ "multi-user.target" ];
            serviceConfig.ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          };
          system.stateVersion = "25.11";
        };
      };

      clusterApps = {
        zfsapp = {
          homeNode = "machine";
          localState."/var/lib/zfsapp" = "/state/clients/zfsapp/data";
          backup = {
            engine = "none";
            localSnapshot = true;
            appUnits = [ "zfsapp-web.service" ];
            exclude = [ "*/cache" ];
            # The app exporting itself into its own state, as ipa-backup does.
            preCommand = "date +%s > /var/lib/zfsapp/export.txt";
            verifyCommand = ''
              test -s "$ROOT/var/lib/zfsapp/export.txt"
              grep -qx one "$ROOT/var/lib/zfsapp/a.txt"
            '';
          };
        };
        pgapp = {
          homeNode = "machine";
          localState."/var/lib/postgresql" = "/var/lib/nixos-containers/pgapp/var/lib/postgresql";
          juicefsPaths."/srv" = "clients/pgapp/files";
        };
        myapp = {
          homeNode = "machine";
          localState."/var/lib/mysql" = "/var/lib/nixos-containers/myapp/var/lib/mysql";
          juicefsPaths."/srv" = "clients/myapp/files";
        };
        filesonly = {
          homeNode = "machine";
          juicefsPaths."/srv" = "clients/filesonly/files";
          backup.engine = "none";
        };
        # Pinned elsewhere: must NOT be backed up here.
        elsewhere = {
          homeNode = "some-other-node";
          juicefsPaths."/srv" = "clients/elsewhere/files";
          backup.engine = "none";
        };
      };
    };

  testScript = ''
    import shlex

    # SQL goes in on stdin: nixos-container run passes it straight through,
    # and nothing has to survive two layers of shell quoting.
    def pg(sql):
        return machine.succeed(
            f"printf '%s' {shlex.quote(sql)} | nixos-container run pgapp -- su postgres -c 'psql -XAtq -d pgapp'"
        ).strip()

    def my(sql):
        return machine.succeed(
            f"printf '%s' {shlex.quote(sql)} | nixos-container run myapp -- mariadb -N -B myapp"
        ).strip()

    def metric(name, app):
        return machine.succeed(
            f"grep -h '^{name}{{app=\"{app}\"}}' /var/lib/prometheus-node-exporter-text/*.prom | awk '{{print $2}}'"
        ).strip()

    machine.start()
    machine.wait_for_unit("s3.service")
    machine.wait_for_open_port(9000)
    machine.wait_for_unit("container@pgapp.service")
    machine.wait_for_unit("container@myapp.service")
    machine.wait_until_succeeds("nixos-container run pgapp -- systemctl is-active pgapp-web.service")
    machine.wait_until_succeeds("nixos-container run myapp -- systemctl is-active myapp-web.service")

    with subtest("seed"):
        pg("create table t (v int); insert into t values (1)")
        my("create table t (v int); insert into t values (1)")
        for app in ["pgapp", "myapp", "filesonly", "elsewhere"]:
            machine.succeed(
                f"mkdir -p /mnt/jfs/clients/{app}/files/sessions"
                f" && echo one > /mnt/jfs/clients/{app}/files/a.txt"
                f" && echo keep > /mnt/jfs/clients/{app}/files/sessions/s1"
            )

    with subtest("zfs-backed local state"):
        machine.succeed(
            "truncate -s 512M /var/tmp/pool.img"
            " && zpool create -O mountpoint=none -O acltype=posixacl -O xattr=sa tank /var/tmp/pool.img"
            " && zfs create -o mountpoint=legacy tank/state"
            " && mkdir -p /state && mount -t zfs tank/state /state"
            " && mkdir -p /state/clients/zfsapp/data/cache"
            " && echo one > /state/clients/zfsapp/data/a.txt"
            " && echo junk > /state/clients/zfsapp/data/cache/c"
            " && echo owned > /state/clients/zfsapp/data/owned.txt"
            " && chown 4242:4242 /state/clients/zfsapp/data/owned.txt"
            " && setfacl -m u:4343:r /state/clients/zfsapp/data/owned.txt"
            " && ln /state/clients/zfsapp/data/a.txt /state/clients/zfsapp/data/a-link.txt"
        )
        machine.succeed("systemctl start container@zfsapp.service")
        machine.wait_until_succeeds("nixos-container run zfsapp -- systemctl is-active zfsapp-web.service")
        # A snapshot a crashed run left behind must not break the next one.
        machine.succeed("zfs snapshot tank/state@cluster-backup-zfsapp")

    with subtest("only this node's apps get units"):
        machine.succeed("systemctl cat cluster-backup-pgapp.service cluster-backup-myapp.service cluster-backup-filesonly.service")
        machine.fail("systemctl cat cluster-backup-elsewhere.service")

    with subtest("backup every app"):
        machine.succeed("cluster-backup")
        for app in ["pgapp", "myapp", "filesonly", "zfsapp"]:
            assert metric("cluster_backup_last_status", app) == "1", app
            assert int(metric("cluster_backup_last_success_timestamp_seconds", app)) > 0, app
        # One repository per app.
        repos = machine.succeed("ls /srv/s3/backups/apps/").split()
        for app in ["pgapp", "myapp", "filesonly", "zfsapp"]:
            assert app in repos, repos
        assert "elsewhere" not in repos, repos
        machine.succeed("cluster-backup-list pgapp | grep -q engine:postgresql")
        machine.succeed("cluster-backup-list myapp | grep -q engine:mariadb")
        # The preCommand ran inside the container; the run's snapshot is gone.
        machine.succeed("test -s /state/clients/zfsapp/data/export.txt")
        machine.fail("zfs list -H -t snapshot -o name | grep -q @cluster-backup-")
        # Deploy holds released, staging emptied.
        machine.succeed("test -z \"$(ls -A /run/cluster-upgrade.hold.d 2>/dev/null)\"")
        machine.succeed("test -z \"$(ls -A /var/lib/cluster-backup/staging 2>/dev/null)\"")

    with subtest("damage"):
        pg("update t set v = 2; create table junk (x int)")
        my("update t set v = 2; create table junk (x int)")
        for app in ["pgapp", "myapp", "filesonly"]:
            machine.succeed(
                f"rm /mnt/jfs/clients/{app}/files/a.txt"
                f" && echo two > /mnt/jfs/clients/{app}/files/b.txt"
            )

    with subtest("no --yes is a dry run"):
        out = machine.succeed("cluster-restore pgapp")
        assert "dry run" in out, out
        assert pg("select v from t") == "2"

    with subtest("--to-scratch only extracts"):
        machine.succeed("cluster-restore pgapp --to-scratch /tmp/scratch")
        machine.succeed("test -s /tmp/scratch/var/lib/cluster-backup/staging/pgapp/pgapp.dump")
        machine.succeed("test -s /tmp/scratch/var/lib/cluster-backup/staging/pgapp/globals.sql")
        assert pg("select v from t") == "2"

    with subtest("restore PostgreSQL app"):
        machine.succeed("cluster-restore pgapp --yes")
        assert pg("select v from t") == "1"
        assert pg("select count(*) from information_schema.tables where table_name = 'junk'") == "0"
        machine.succeed("grep -qx one /mnt/jfs/clients/pgapp/files/a.txt")
        machine.fail("test -e /mnt/jfs/clients/pgapp/files/b.txt")
        # Excluded from the backup, so protected from --delete.
        machine.succeed("grep -qx keep /mnt/jfs/clients/pgapp/files/sessions/s1")
        machine.wait_until_succeeds("nixos-container run pgapp -- systemctl is-active pgapp-web.service")

    with subtest("restore MariaDB app"):
        machine.succeed("cluster-restore myapp --yes")
        assert my("select v from t") == "1"
        assert my("select count(*) from information_schema.tables where table_schema = 'myapp' and table_name = 'junk'") == "0"
        machine.succeed("grep -qx one /mnt/jfs/clients/myapp/files/a.txt")
        machine.wait_until_succeeds("nixos-container run myapp -- systemctl is-active myapp-web.service")

    with subtest("restore a files-only app"):
        machine.succeed("cluster-restore filesonly --yes")
        machine.succeed("grep -qx one /mnt/jfs/clients/filesonly/files/a.txt")
        machine.fail("test -e /mnt/jfs/clients/filesonly/files/b.txt")

    with subtest("restore local state, container running"):
        exported = machine.succeed("cat /state/clients/zfsapp/data/export.txt").strip()
        machine.succeed(
            "rm /state/clients/zfsapp/data/a.txt /state/clients/zfsapp/data/owned.txt"
            " && echo two > /state/clients/zfsapp/data/b.txt"
            " && echo 0 > /state/clients/zfsapp/data/export.txt"
            " && echo keep > /state/clients/zfsapp/data/cache/c"
        )
        out = machine.succeed("cluster-restore zfsapp")
        assert "local state: replace /state/clients/zfsapp/data" in out, out
        assert "stop zfsapp-web.service" in out, out
        machine.succeed("cluster-restore zfsapp --yes")
        d = "/state/clients/zfsapp/data"
        machine.succeed(f"grep -qx one {d}/a.txt")
        machine.fail(f"test -e {d}/b.txt")
        assert machine.succeed(f"cat {d}/export.txt").strip() == exported
        assert machine.succeed(f"stat -c %u:%g {d}/owned.txt").strip() == "4242:4242"
        machine.succeed(f"getfacl -n {d}/owned.txt | grep -qx user:4343:r--")
        assert machine.succeed(f"stat -c %h {d}/a.txt").strip() == "2"
        # Excluded, so never backed up -- and so not deleted by the restore.
        machine.succeed(f"grep -qx keep {d}/cache/c")
        # Its safety point, and the app back up.
        machine.succeed("zfs list -H -t snapshot -o name | grep -q '^tank/state@pre-restore-zfsapp-'")
        machine.wait_until_succeeds("nixos-container run zfsapp -- systemctl is-active zfsapp-web.service")

    with subtest("restore local state, container stopped (a rebuilt node)"):
        machine.succeed("systemctl stop container@zfsapp.service")
        machine.succeed("rm -rf /state/clients/zfsapp")
        machine.succeed("cluster-restore zfsapp --yes")
        machine.succeed("grep -qx one /state/clients/zfsapp/data/a.txt")
        machine.succeed("systemctl start container@zfsapp.service")
        machine.wait_until_succeeds("nixos-container run zfsapp -- systemctl is-active zfsapp-web.service")

    with subtest("restore refuses an app that lives elsewhere"):
        out = machine.fail("cluster-restore elsewhere --yes 2>&1")
        assert "some-other-node" in out, out

    with subtest("restore rehearsal and maintenance"):
        machine.succeed("systemctl start cluster-backup-verify.service")
        for app in ["pgapp", "myapp", "zfsapp"]:
            assert int(metric("cluster_backup_verify_last_success_timestamp_seconds", app)) > 0, app
        machine.succeed("systemctl start cluster-backup-maintenance.service")
        assert int(metric("cluster_backup_check_last_success_timestamp_seconds", "pgapp")) > 0

    with subtest("a stopped container fails its backup loudly"):
        machine.succeed("systemctl stop container@myapp.service")
        machine.fail("systemctl start cluster-backup-myapp.service")
        assert metric("cluster_backup_last_status", "myapp") == "0"
        machine.succeed("systemctl start container@myapp.service")
  '';
}
