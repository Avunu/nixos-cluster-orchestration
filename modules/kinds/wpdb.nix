# modules/kinds/wpdb.nix — clusterApps.<name>.wpdb: the shared WordPress database.
#
#   wpdb = { address; port; clientHosts; bufferPoolSize; package; };
#
# ONE MariaDB for every WordPress site on the cluster, not one per site. A
# split-plane site is two containers that must read and write the same database,
# and a per-site MariaDB would put that database inside one of them -- so the
# public face could not serve a request while the admin face was restarting. One
# instance is also one thing to tune, one dump to verify in the restore
# rehearsal, and several hundred megabytes of resident memory per site saved.
#
# Databases and users are NOT declared in this file. Each WordPress site
# contributes an entry to `wordpressDatabases` (modules/kinds/wordpress.nix) and
# a oneshot in this container creates the database, the user and the grant from
# that site's own stored password. Adding a site therefore stays one file, and
# this app needs no edit.
#
# Addressing. App containers take their br-app address by DHCP, which is fine
# for workloads nothing connects TO -- the tunnel reaches them through a socket.
# A database is the exception, so this one pins a static address below the DHCP
# pool (PoolOffset = 10, so .2-.9 are free) and MariaDB binds that address only.
# The container's own firewall opens the port on br-app alone: the WAN veth is
# bridged, bridged frames bypass the host's ip/ip6 netfilter hooks, and a
# globally-opened port would therefore be reachable from the internet.
# skip-name-resolve keeps grant matching on addresses rather than on whatever
# reverse DNS happens to return.
{
  lib,
  pkgs,
  config,
  topology,
  ...
}:
let
  inherit (lib) mkOption types;

  # Bound outside the submodule, so it is the TOP-LEVEL config: the sites that
  # want a database. Only the `wordpress` option of other apps is ever read
  # through this, never their `module`, so it cannot recurse into this app.
  sites = config.wordpressDatabases;

  wpdbType = types.submodule {
    options = {
      address = mkOption {
        type = types.str;
        example = "10.20.1.2";
        description = ''
          Static IPv4 for this container on br-app, and the only address MariaDB
          binds. Must sit below the home node's DHCP pool (appDhcpPoolOffset) and
          above the bridge gateway, i.e. .2 through .9 with the defaults.

          This is the host every WordPress plane is handed as DB_HOST, so
          changing it means rewriting every site's database.host.
        '';
      };

      port = mkOption {
        type = types.port;
        default = 3306;
        description = "MariaDB's port on `address`.";
      };

      clientHosts = mkOption {
        type = types.listOf types.str;
        default = [ "10.20.%" ];
        description = ''
          MySQL host patterns each site's user is granted from — the app bridges,
          not the world. One grant is issued per pattern. With
          skip-name-resolve on, these match addresses only.
        '';
      };

      bufferPoolSize = mkOption {
        type = types.str;
        default = "2G";
        description = ''
          innodb_buffer_pool_size. The working set of every site at once, so size
          it against `resources.memoryMB` rather than against one site.
        '';
      };

      package = mkOption {
        type = types.package;
        default = pkgs.mariadb;
        defaultText = lib.literalExpression "pkgs.mariadb";
        description = "The MariaDB package.";
      };
    };
  };

  dbRefType = types.submodule {
    options = {
      database = mkOption {
        type = types.str;
        description = "Database name.";
      };
      user = mkOption {
        type = types.str;
        description = "The MySQL user created for this site.";
      };
      secret = mkOption {
        type = types.attrsOf types.str;
        example = {
          generator = "wp-example";
          file = "db-password";
        };
        description = ''
          Where the site's database password lives, as a clusterApps secret
          reference. The same stored value is handed to the site's own planes, so
          the two can never drift.
        '';
      };
    };
  };
in
{
  options = {
    # Declared here rather than in the WordPress kind so this app can be read
    # without the WordPress kind being loaded at all.
    wordpressDatabases = mkOption {
      type = types.attrsOf dbRefType;
      default = { };
      description = ''
        The per-site databases the shared MariaDB provisions, keyed by site slug.
        Populated by modules/kinds/wordpress.nix; consumed here.
      '';
    };

    clusterApps = mkOption {
      type = types.attrsOf (
        types.submodule (
          { name, config, ... }:
          let
            w = config.wpdb;
            node = topology.nodes.${config.homeNode};
            prefix = lib.last (lib.splitString "/" node.appSubnet);
          in
          {
            options.wpdb = mkOption {
              type = types.nullOr wpdbType;
              default = null;
              description = "The shared WordPress database (modules/kinds/wpdb.nix).";
            };

            config = lib.mkIf (config.wpdb != null) {
              # Its data is on local disk, so it cannot move node.
              tier = lib.mkDefault "monolith";

              module = {
                services.mysql = {
                  enable = true;
                  package = w.package;
                  settings.mysqld = {
                    bind-address = w.address;
                    port = w.port;
                    # Match grants on addresses, and never block a connection on
                    # a reverse lookup.
                    skip-name-resolve = 1;
                    innodb_buffer_pool_size = w.bufferPoolSize;
                    # DB-on-ZFS: recordsize=16k = InnoDB page, and ZFS record
                    # writes are atomic, so the doublewrite buffer is overhead.
                    innodb_doublewrite = 0;
                    # utf8mb4 throughout: WordPress wants it, and a site
                    # migrated off a utf8mb3 host should not inherit that.
                    character-set-server = "utf8mb4";
                    collation-server = "utf8mb4_unicode_ci";
                  };
                };

                # br-app only. NOT networking.firewall.allowedTCPPorts, which
                # would also open the bridged WAN interface.
                networking.firewall.interfaces.eth0.allowedTCPPorts = [ w.port ];

                # A static address in place of the framework's DHCP, and DNS
                # from the bridge gateway since the lease no longer supplies it.
                systemd.network.networks."10-eth0" = {
                  networkConfig = {
                    DHCP = lib.mkForce "no";
                    DNS = [ node.appBridgeIp ];
                  };
                  address = [ "${w.address}/${prefix}" ];
                  routes = [ { Gateway = node.appBridgeIp; } ];
                };

                systemd.services.wpdb-provision = {
                  description = "Create each WordPress site's database, user and grant";
                  after = [ "mysql.service" ];
                  requires = [ "mysql.service" ];
                  wantedBy = [ "multi-user.target" ];
                  path = [
                    w.package
                    pkgs.coreutils
                    pkgs.gnused
                  ];
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                  };
                  # Idempotent, and re-run on every deploy: ALTER USER applies a
                  # rotated password, and a site added to the catalogue is
                  # provisioned by the reload that brings its own containers up.
                  script = ''
                    set -euo pipefail

                    CLIENT_HOSTS=${lib.escapeShellArgs w.clientHosts}

                    provision() {
                      db="$1"
                      user="$2"
                      pwfile="$3"

                      if [ ! -r "$pwfile" ]; then
                        echo "wpdb: $db has no readable password at $pwfile -- skipping" >&2
                        return 0
                      fi

                      # The generator makes hex, but quote for a SQL string
                      # literal anyway rather than trusting that.
                      pw=$(tr -d '\r\n' < "$pwfile" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g")

                      mysql -u root <<SQL
                    CREATE DATABASE IF NOT EXISTS \`$db\`
                      CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                    SQL

                      for h in $CLIENT_HOSTS; do
                        mysql -u root <<SQL
                    CREATE USER IF NOT EXISTS '$user'@'$h' IDENTIFIED BY '$pw';
                    ALTER USER '$user'@'$h' IDENTIFIED BY '$pw';
                    GRANT ALL PRIVILEGES ON \`$db\`.* TO '$user'@'$h';
                    SQL
                      done

                      echo "wpdb: provisioned $db for $user"
                    }

                    ${lib.concatStringsSep "\n" (
                      lib.mapAttrsToList (
                        slug: d:
                        "provision ${lib.escapeShellArg d.database} ${lib.escapeShellArg d.user} "
                        + lib.escapeShellArg "/run/secrets/${slug}-db-password"
                      ) sites
                    )}
                  '';
                };
              };

              # Every site's password, so the provisioner can set it. The planes
              # get the same stored value, so they cannot disagree.
              secrets = lib.mapAttrs' (slug: d: lib.nameValuePair "${slug}-db-password" d.secret) sites;

              # Local disk on the home node, on the auto-snapshotted dataset.
              localState."/var/lib/mysql" = "/state/clients/${name}/mysql";

              # backup-core detects `mariadb` from services.mysql.enable inside
              # the container and ships a logical dump of every database, which
              # is the whole fleet's WordPress content in one snapshot.
              backup.enable = lib.mkDefault true;

              resources = {
                cpu = lib.mkDefault 2000;
                memoryMB = lib.mkDefault 4096;
              };

              # Nothing inbound from Cloudflare: this is reached on br-app only.
              service = {
                inherit name;
                port = w.port;
              };
            };
          }
        )
      );
    };
  };
}
