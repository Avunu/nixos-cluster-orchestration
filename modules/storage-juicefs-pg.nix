# modules/storage-juicefs-pg.nix — the JuiceFS metadata database: one PostgreSQL
# cluster, a member on every node.
#
# Patroni runs PostgreSQL on every node and keeps one of them the primary, by a
# lock in etcd (modules/storage-etcd.nix). The others replicate from it as it
# writes (streaming), and a commit is not acknowledged until at least one of them
# has it too (`synchronous_mode: quorum`): a node that dies takes no acknowledged
# write with it. When the primary's node dies, its lock runs out and a replica
# that holds every acknowledged write is promoted, without anybody's help.
#
# No node is named. A JuiceFS client asks its own loopback (lib/juicefs.nix
# metaHost:metaPort), where HAProxy asks every member's Patroni "are you the
# primary?" and passes the connection to the one that says yes. A member that
# stops being the primary has its connections cut, so a client can't keep writing
# to a demoted one.
#
# What keeps two primaries from both taking writes:
#   - the lock is etcd's, so a partitioned minority can't hold it, and a primary
#     that can't renew it demotes itself before the lock runs out;
#   - a primary alone on the losing side has no replica to acknowledge a commit;
#   - HAProxy passes a connection only to a member whose Patroni answers /primary.
# No watchdog device: a Patroni that hangs while primary is covered by the last two,
# and a watchdog here would reboot a node that also runs everyone's apps.
#
# The roles and the database are made by `juicefs-pg-setup`, on every node, through
# the primary. Patroni's dynamic settings (the `dcs` set below) live in etcd, where
# Patroni reads `bootstrap.dcs` once, at the cluster's creation, and never again:
# the same unit puts the set there on every run, so a change to it here takes effect.
#
# PostgreSQL listens on every address, NOT on the mesh address: it binds once, at
# start, and a mesh address that appears later is never bound [RAN, design 1.16].
# What confines it is the host firewall (the weak-host rule; both ports are
# accepted on the mesh interface only, `juicefs-pg-unreachable-on-vlan`) and
# pg_hba below.
#
# WITHOUT etcd (a site with one Nomad server and no `etcd` tag, which is what a
# site is before it has three voters) there is nothing to hold an election in, and
# nobody to elect: that one server runs a plain PostgreSQL, in the same data
# directory, on the same port, with the same roles, and every node's HAProxy leads
# to it. The commit that tags three nodes `etcd` turns it into the first member:
# Patroni adopts the directory as it is (`voters-take-over` in tests/voter-growth.nix).
#
# Who may CREATE the cluster. Patroni lets whichever member asks first do it, and a
# member with an empty directory creates an empty database, which juicefs-format
# would then fill from a dump up to `jfs.backupMeta` old while the real one sat on
# another node. So a member with no data creates nothing while the bucket holds a
# volume: it waits for the cluster to exist and joins it (`patroni-found`, below).
# That covers the growth above, a site moving from the `juicefs-meta` tag, and a
# cluster whose etcd was lost. When every member's data is gone the bucket still
# holds a volume and nobody has its database: all of them wait, and an operator
# says which one starts empty (README, "Total loss").
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  ...
}:
let
  net = clusterLib.net;
  jfs = clusterLib.juicefs;
  vars = config.clan.core.vars.generators;

  scope = "jfs-meta";
  namespace = "/patroni";
  superuser = "postgres";
  replicator = "replicator";
  restUser = "patroni";

  meshIp = net.meshIp topology node;
  provisioned = lib.filterAttrs (_: nd: nd.provisioned or true) topology.nodes;
  etcdHosts = map (
    name: "${net.meshIp topology topology.nodes.${name}}:${toString net.etcdClientPort}"
  ) (net.etcdMembers topology);

  package = jfs.metaPgPackage pkgs config.system.stateVersion;
  dataDir = "/var/lib/postgresql/${package.psqlSchema}";
  socketDir = "/run/postgresql";
  rest = "http://127.0.0.1:${toString net.patroniPort}";

  # With an etcd, a member on every node. Without, the site's one Nomad server.
  ha = etcdHosts != [ ];
  servers = net.taggedNames topology "nomad-server";
  soleHost = lib.head servers;
  isSoleHost = !ha && nodeName == soleHost;
  members = if ha then provisioned else lib.filterAttrs (name: _: name == soleHost) topology.nodes;

  os = topology.objectStorage;
  rclone = "${pkgs.rclone}/bin/rclone";
  foundStamp = "/var/lib/patroni/found-new-cluster";

  # See "Who may CREATE the cluster", above. Patroni's ExecStartPre, as its user.
  foundScript = pkgs.writeShellScript "patroni-found" ''
    set -euo pipefail
    # A data directory left by services.postgresql has a postgresql.conf that is a
    # symlink into the Nix store. Patroni keeps the file it finds as the base of its
    # own, and that store path is gone after the next collection: PostgreSQL would
    # then not start. An empty file is all Patroni needs there.
    if [ -L ${dataDir}/postgresql.conf ]; then
      rm -f ${dataDir}/postgresql.conf
      : > ${dataDir}/postgresql.conf
    fi
    # A member with data may always start: it joins, or it is what the cluster is
    # made from.
    [ -s ${dataDir}/PG_VERSION ] && exit 0
    if ${pkgs.etcd}/bin/etcdctl --endpoints=${lib.concatStringsSep "," etcdHosts} --command-timeout=5s \
        get ${namespace}/${scope}/initialize --print-value-only 2>/dev/null | grep -q .; then
      exit 0
    fi
    if [ -e ${foundStamp} ]; then
      echo "starting an empty metadata database because ${foundStamp} says so" >&2
      exit 0
    fi
    export RCLONE_CONFIG_JFS_TYPE=s3 RCLONE_CONFIG_JFS_PROVIDER=Other
    export RCLONE_CONFIG_JFS_ENDPOINT="${os.endpoint}" RCLONE_CONFIG_JFS_REGION="${os.region}"
    RCLONE_CONFIG_JFS_ACCESS_KEY_ID=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3ak}")
    RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3sk}")
    export RCLONE_CONFIG_JFS_ACCESS_KEY_ID RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY
    # A listing that failed is not an empty bucket. rclone's 3 is "nothing there".
    rc=0
    objects=$(${rclone} lsf "jfs:${os.juicefsBucket}/${jfs.jfsName}/" --max-depth 1 2>/dev/null) || rc=$?
    case "$rc" in
      0 | 3) ;;
      *)
        echo "object storage unreachable (rclone exit $rc): cannot tell whether a volume exists, so not creating a metadata database. Retried." >&2
        exit 1
        ;;
    esac
    if [ -n "$objects" ]; then
      echo "not creating a metadata database: the bucket holds volume ${jfs.jfsName}, this member has no data, and no cluster exists yet. Waiting for a member that has the database to start it." >&2
      echo "If EVERY member's data is lost: touch ${foundStamp} on ONE node, and juicefs-format restores the newest dump there." >&2
      exit 1
    fi
  '';

  # Patroni's dynamic configuration: in etcd, the same for every member.
  dcs = {
    # A dead primary is replaced after `ttl` at most. ttl >= loop_wait + 2 * retry_timeout.
    ttl = 20;
    loop_wait = 5;
    retry_timeout = 5;
    maximum_lag_on_failover = 1048576;
    # Quorum commit: any one replica's acknowledgement. Not strict: a primary whose
    # replicas are ALL gone keeps taking writes alone (Patroni records that in etcd,
    # and then promotes nobody who missed them), where strict would stop every app
    # on a three-node cluster that is down to one node.
    synchronous_mode = "quorum";
    synchronous_node_count = 1;
    postgresql = {
      use_pg_rewind = true;
      use_slots = true;
      parameters = {
        wal_level = "replica";
        hot_standby = "on";
        wal_log_hints = "on";
        max_wal_senders = 16;
        max_replication_slots = 16;
      };
    };
  };
  dcsFile = pkgs.writeText "patroni-dcs.json" (builtins.toJSON dcs);

  # A vars file's ciphertext in the site's repository: its hash changes when the
  # value is regenerated (as modules/storage-juicefs-format.nix).
  ciphertextHash =
    gen: file:
    let
      f = vars.${gen}.files.${file};
      p = config.clan.core.settings.directory + "/secrets/clan-vars/${f.rel_dir}/${f.name}/${f.name}.age";
    in
    lib.optional (builtins.pathExists p) (builtins.hashFile "sha256" p);

  curl = "${pkgs.curl}/bin/curl";
  psql = "${package}/bin/psql";

  # The roles, their passwords and the database, through the primary. Idempotent.
  # Passwords reach psql through `\set` from the credential files, never a command
  # line, and none of them has punctuation (modules/vars.nix).
  # Every volume's role and database (lib/juicefs.nix, "Volumes"): the cluster's,
  # and one for each app that has a volume. A role and its database share a name.
  volumes = [
    (jfs.systemVolume os)
  ]
  ++ map (jfs.appVolume os) (jfs.volumeApps (config.clusterApps or { }));
  pgCred = v: "pg${v.suffix}";

  setupSql = pkgs.writeText "juicefs-pg-setup.sql" (
    ''
      \set supw `cat "$CREDENTIALS_DIRECTORY/superuser"`
      \set replpw `cat "$CREDENTIALS_DIRECTORY/replication"`
      SELECT 'CREATE ROLE ${replicator} REPLICATION LOGIN'
        WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${replicator}') \gexec
      ALTER ROLE ${replicator} WITH REPLICATION LOGIN PASSWORD :'replpw';
      ALTER ROLE ${superuser} WITH PASSWORD :'supw';
    ''
    + lib.concatMapStrings (v: ''
      \set pw `cat "$CREDENTIALS_DIRECTORY/${pgCred v}"`
      SELECT 'CREATE ROLE ${v.db} LOGIN'
        WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${v.db}') \gexec
      ALTER ROLE ${v.db} WITH LOGIN PASSWORD :'pw';
      SELECT 'CREATE DATABASE ${v.db} OWNER ${v.db}'
        WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${v.db}') \gexec
    '') volumes
  );

  setupScript = pkgs.writeShellScript "juicefs-pg-setup" (
    ''
      set -euo pipefail
      code() { ${curl} -s -o /dev/null -m 5 -w '%{http_code}' "${rest}$1" || true; }
      if ${if ha then ''[ "$(code /primary)" = 200 ]'' else "true"}; then
        # This member is the primary: its socket, as the OS user PostgreSQL trusts
        # there. The one way in before the superuser has a password (a data directory
        # adopted from the single engine has none).
        ${psql} -X -q -v ON_ERROR_STOP=1 -h ${socketDir} -p ${toString net.jfsPgPort} \
          -U ${superuser} -d postgres -f ${setupSql}
      else
        # Wherever the primary is, with the superuser's password. Fails, and is
        # retried, while there is no primary or it has not had its own run yet.
        PGPASSWORD=$(cat "$CREDENTIALS_DIRECTORY/superuser") \
          ${psql} -X -q -v ON_ERROR_STOP=1 -h ${jfs.metaHost} -p ${toString jfs.metaPort} \
          -U ${superuser} -d postgres -f ${setupSql}
      fi
    ''
    + lib.optionalString ha ''
      # The dynamic settings, into etcd through any member's API.
      printf 'user = "%s:%s"\n' ${restUser} "$(cat "$CREDENTIALS_DIRECTORY/restapi")" \
        | ${curl} -sf -m 10 -K - -X PATCH -H 'Content-Type: application/json' \
            -d @${dcsFile} -o /dev/null "${rest}/config"
    ''
  );

  haproxyConfig = ''
    # ── JuiceFS metadata: this node's loopback -> the PostgreSQL primary ──────
    defaults
      mode tcp
      log stdout format short daemon notice warning
      timeout connect 3s
      timeout check 3s
      # A JuiceFS client's pooled connection can sit idle.
      timeout client 1h
      timeout server 1h
      option clitcpka
      option srvtcpka

    listen jfs_meta
      bind ${jfs.metaHost}:${toString jfs.metaPort}
      # A member is given up after five failed checks, about ten seconds: its
      # connections are then cut, so that a client is not left waiting on a dead
      # node for as long as TCP would (a quarter of an hour). Not sooner: a query in
      # flight on a cut connection comes back to the app as an I/O error, and a
      # hiccup of the mesh should cost a stall and no more. A new primary is taken
      # at its first good answer; Patroni's own 20 seconds come first either way.
      default-server inter 2s fastinter 1s fall 5 rise 1 on-marked-down shutdown-sessions
      # With no primary (a failover, the mesh down), hold a new connection for a
      # few seconds and look again, not close it at once: a JuiceFS client gives up
      # on a file operation after some tens of failed connections, which closed at
      # once is half a minute, and an app then sees an I/O error where a stall
      # would have done (`mesh-down-jfs-recovers`). PostgreSQL's client speaks first,
      # so nothing here waits on the server.
      tcp-request inspect-delay 5s
      tcp-request content accept if { nbsrv gt 0 }
      tcp-request content accept if WAIT_END
  ''
  + lib.optionalString ha ''
    # Patroni answers 200 on /primary from the member that holds the lock and
    # runs as primary, and 503 from every other.
    option httpchk GET /primary
    http-check expect status 200
  ''
  + lib.concatStrings (
    lib.mapAttrsToList (
      name: nd:
      "  server ${name} ${net.meshIp topology nd}:${toString net.jfsPgPort} check"
      + lib.optionalString ha " port ${toString net.patroniPort}"
      + "\n"
    ) members
  );

  pgHba = [
    # Patroni asks its own member for its position over a replication connection.
    "host replication ${replicator} 127.0.0.1/32 scram-sha-256"
    "host replication ${replicator} ::1/128 scram-sha-256"
    "host replication ${replicator} ${topology.mesh.subnet} scram-sha-256"
    # pg_rewind, from a former primary coming back as a replica; and
    # juicefs-pg-setup on a node that is not the primary.
    "host all ${superuser} ${topology.mesh.subnet} scram-sha-256"
    # A volume's role, into the database of its own name and no other.
    "host sameuser all ${topology.mesh.subnet} scram-sha-256"
    "host sameuser all 127.0.0.1/32 scram-sha-256"
  ];
  initdbArgs = [
    "--encoding=UTF8"
    "--locale=C.UTF-8"
    "--locale-provider=builtin"
    "--data-checksums"
  ];
in
{
  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = ha || builtins.length servers == 1;
          message =
            "storage-juicefs-pg: no node is tagged `etcd`, and ${toString (builtins.length servers)} are tagged "
            + "`nomad-server`. Without an etcd the JuiceFS metadata database is one PostgreSQL on the "
            + "site's one Nomad server; with more servers than one, tag an odd number of nodes `etcd`, "
            + "at least three (modules/storage-etcd.nix), and it has a member on every node.";
        }
      ];

      warnings = lib.optional (net.taggedNames topology "juicefs-meta" != [ ]) ''
        topology: the `juicefs-meta` tag (on ${lib.concatStringsSep ", " (net.taggedNames topology "juicefs-meta")}) no longer means anything: the JuiceFS
        metadata database has a member on every node. Remove the tag.
      '';

      # The same account, with the same ids, whichever of the two runs PostgreSQL:
      # the data directory passes from one to the other as it is.
      users.users.postgres = {
        isSystemUser = true;
        uid = config.ids.uids.postgres;
        group = "postgres";
        home = lib.mkDefault "/var/lib/postgresql";
      };
      users.groups.postgres.gid = config.ids.gids.postgres;

      services.haproxy = {
        enable = true;
        # After any other module's sections (modules/kinds/attic.nix has a `global`).
        config = lib.mkAfter haproxyConfig;
      };
      systemd.services.haproxy = net.meshBoundUnit;
    }

    # ── with an etcd: a member here ─────────────────────────────────────────
    (lib.mkIf ha {
      services.patroni = {
        enable = true;
        inherit scope namespace;
        name = nodeName;
        nodeIp = meshIp;
        otherNodesIps = [ ];
        postgresqlPackage = package;
        postgresqlPort = net.jfsPgPort;
        restApiPort = net.patroniPort;
        user = "postgres";
        group = "postgres";
        # As credentials: the vars files are root's, and Patroni is not.
        environmentFiles = {
          PATRONI_SUPERUSER_PASSWORD = "/run/credentials/patroni.service/superuser";
          PATRONI_REPLICATION_PASSWORD = "/run/credentials/patroni.service/replication";
          PATRONI_RESTAPI_USERNAME = pkgs.writeText "patroni-rest-user" restUser;
          PATRONI_RESTAPI_PASSWORD = "/run/credentials/patroni.service/restapi";
        };
        settings = {
          etcd3.hosts = etcdHosts;
          # Reading is open to the mesh (HAProxy's check, Prometheus); everything that
          # changes the cluster wants the password.
          restapi.listen = lib.mkForce "0.0.0.0:${toString net.patroniPort}";
          bootstrap = {
            inherit dcs;
            # Collation owned by PostgreSQL, not glibc: with libc's, every glibc bump
            # in nixpkgs changes the sort rules under the text indexes. JuiceFS's few
            # text columns are internal keys that want byte order.
            initdb = map (lib.removePrefix "--") initdbArgs;
          };
          postgresql = {
            listen = lib.mkForce "0.0.0.0:${toString net.jfsPgPort}";
            use_unix_socket = true;
            authentication = {
              superuser.username = superuser;
              replication.username = replicator;
            };
            parameters.unix_socket_directories = socketDir;
            # Patroni writes pg_hba.conf from this, on every member.
            pg_hba = [ "local all all peer" ] ++ pgHba;
          };
        };
      };

      systemd.services.patroni = lib.mkMerge [
        # Its etcd, and its peers, are on the mesh.
        net.meshBoundUnit
        {
          after = [ "etcd.service" ];
          serviceConfig = {
            ExecStartPre = "${foundScript}";
            LoadCredential = [
              "superuser:${vars.juicefs-patroni.files.superuser.path}"
              "replication:${vars.juicefs-patroni.files.replication.path}"
              "restapi:${vars.juicefs-patroni.files.restapi.path}"
              "${jfs.credIds.s3ak}:${vars.ovh-s3.files."access-key".path}"
              "${jfs.credIds.s3sk}:${vars.ovh-s3.files."secret-key".path}"
            ];
            RuntimeDirectory = "postgresql";
            RuntimeDirectoryPreserve = true;
            Restart = lib.mkForce "always";
            # A member waiting to join (patroni-found) asks again this often.
            RestartSec = 10;
          };
        }
      ];

      # Each member's state, for the alerts (lib/alert-rules.nix, group `jfs-meta`).
      services.prometheus.scrapeConfigs = [
        {
          job_name = "patroni";
          static_configs = [
            {
              targets = lib.mapAttrsToList (
                _: nd: "${net.meshIp topology nd}:${toString net.patroniPort}"
              ) provisioned;
            }
          ];
        }
      ];
    })

    # ── without: the one server's PostgreSQL ────────────────────────────────
    (lib.mkIf isSoleHost {
      services.postgresql = {
        enable = true;
        inherit package;
        enableTCPIP = true;
        settings.port = net.jfsPgPort;
        settings.listen_addresses = lib.mkForce "*";
        inherit initdbArgs;
        authentication = lib.mkAfter (lib.concatStringsSep "\n" pgHba);
      };
    })

    (lib.mkIf (ha || isSoleHost) {
      systemd.services.juicefs-pg-setup = {
        description = "JuiceFS metadata database: roles, passwords, Patroni's settings";
        after = [
          "patroni.service"
          "postgresql.service"
          "postgresql-setup.service"
          "haproxy.service"
        ];
        wants = [ (if ha then "patroni.service" else "postgresql.service") ];
        wantedBy = [ "multi-user.target" ];
        restartTriggers = [
          dcsFile
        ]
        ++ [ setupSql ]
        ++ lib.concatMap (v: ciphertextHash (lib.head v.files.pgpass) (lib.last v.files.pgpass)) volumes
        ++ lib.concatMap (ciphertextHash "juicefs-patroni") [
          "superuser"
          "replication"
          "restapi"
        ];
        unitConfig.StartLimitIntervalSec = 0;
        serviceConfig = {
          # Not a oneshot: one that keeps failing and restarting, in turn with
          # juicefs-format behind it, always has a start job pending, and a boot
          # with no primary to be had (no mesh key, no etcd quorum) then never
          # reaches multi-user.target (`missing-wg-key-boots`). juicefs-format
          # retries by itself, so nothing needs this unit's end to wait on.
          Type = "exec";
          RemainAfterExit = true;
          User = "postgres";
          ExecStart = "${setupScript}";
          LoadCredential = [
            "superuser:${vars.juicefs-patroni.files.superuser.path}"
            "replication:${vars.juicefs-patroni.files.replication.path}"
            "restapi:${vars.juicefs-patroni.files.restapi.path}"
          ]
          ++ map (v: "${pgCred v}:${jfs.volumeCredPath vars v "pgpass"}") volumes;
          # No primary yet, or it is changing hands: again, until there is one.
          Restart = "on-failure";
          RestartSec = 5;
        };
      };
    })
  ];
}
