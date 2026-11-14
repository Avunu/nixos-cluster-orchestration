# modules/kinds/odoo.nix — clusterApps.<name>.odoo: an Odoo project.
#
#   odoo = { package; hostname; workers; … };
#
# A Tier-0 monolith: Odoo (odoo-nix) + nginx over a unix socket + a local
# PostgreSQL with socket peer auth, in one container pinned to its homeNode.
# The filestore and runtime odoo.conf are on JuiceFS (they follow the app);
# PostgreSQL's data is on the node's local ZFS, never JuiceFS.
#
# The database is not initialised (autoInit stays off): it is restored once
# from the development instance after the first start -- README "Adding an
# app". Deploys migrate it (odoo-nix's odoo-migrate, changed modules only).
{
  inputs,
  lib,
  pkgs,
  config,
  ...
}:
let
  inherit (lib) mkOption types;

  odooType = types.submodule {
    options = {
      package = mkOption {
        type = types.package;
        description = "The project's built Odoo (OCB + its addons + Python env), e.g. inputs.<project>.packages.x86_64-linux.default.";
      };
      hostname = mkOption {
        type = types.str;
        description = "Public hostname, served on the app's tunnel.";
      };
      dbName = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "The one database Odoo serves (no manager listing). null = the app's name.";
      };
      workers = mkOption {
        type = types.int;
        default = 4;
      };
      maxCronThreads = mkOption {
        type = types.int;
        default = 2;
      };
      serverWideModules = mkOption {
        type = types.listOf types.str;
        default = [
          "base"
          "web"
        ];
        description = "queue_job's runner only starts as a server-wide module; a dev shell's dev_mailcatch must not be one.";
      };
      clientMaxBodySize = mkOption {
        type = types.str;
        default = "128m";
      };
    };
  };

  # Not the preview slots: a slot reads the secrets of the app it copies.
  apps = lib.filterAttrs (_: a: a.odoo != null && a.preview.of == null) config.clusterApps;
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          o = config.odoo;
          socket = "/run/odoo-${name}/nginx.sock";
          # On a preview slot these name the app it copies (modules/app-container.nix).
          pv = config.preview;
          isPreview = pv.of != null;
          dbName = if o.dbName != null then o.dbName else pv.base;
        in
        {
          options.odoo = mkOption {
            type = types.nullOr odooType;
            default = null;
            description = "An Odoo project (modules/kinds/odoo.nix).";
          };

          config = lib.mkIf (config.odoo != null) {
            tier = lib.mkDefault "monolith";

            # A slot's database is production's, a moment ago: its mail servers, its
            # scheduled actions, its payment providers and webhooks. Odoo's own
            # `neutralize` switches those off, each module for what it added. Before
            # the migration, which is before the app: a failure here leaves the
            # preview stopped, never running with them on. Once per copy: the marker
            # is in the copy's files, and a new copy has none. Odoo 16 and later;
            # earlier has no such command, and so no preview.
            module = lib.mkMerge [
              (lib.mkIf isPreview (
                { pkgs, ... }:
                {
                  systemd.services.odoo-migrate.serviceConfig.ExecStartPre = [
                    (pkgs.writeShellScript "preview-neutralize" ''
                      set -eu
                      marker=/var/lib/odoo/.preview-neutralized
                      [ -e "$marker" ] && exit 0
                      ${o.package}/bin/odoo neutralize -d ${lib.escapeShellArg dbName}
                      ${pkgs.coreutils}/bin/touch "$marker"
                    '')
                  ];
                }
              ))
              {
                imports = [ inputs.odoo-nix.nixosModules.default ];
                services.odoo-nix = {
                  enable = true;
                  inherit (o) package workers maxCronThreads;
                  inherit dbName;
                  # Pinned database, no manager listing; the master password
                  # still guards backup/restore/drop through the manager.
                  listDb = false;
                  withoutDemo = true;
                  database.createLocally = true;
                  adminPasswordFile = "/run/secrets/admin-passwd";
                  settings.options.server_wide_modules = lib.concatStringsSep "," o.serverWideModules;
                  # To the journal, not a file: modules/logging.nix ships it to
                  # Loki from there, labelled with the app's name.
                  logging.level = "info";
                  # nginx serves the public side over a unix socket -- the
                  # tunnel's origin; Odoo itself stays on loopback TCP behind it.
                  nginx = {
                    enable = true;
                    socketPath = socket;
                    inherit (o) clientMaxBodySize;
                  };
                };
                # DB-on-ZFS: 8k records match PostgreSQL pages; full-page writes
                # are then redundant (ZFS record writes are atomic).
                services.postgresql.settings.full_page_writes = false;
              }
            ];

            preview.origin = "unix:${socket}";
            preview.socketGroups = [ "odoo" ];
            preview.healthPath = lib.mkDefault "/web/health";

            # Runtime odoo.conf + the filestore -- shared, follows the app.
            juicefsPaths."/var/lib/odoo" = "${pv.jfsRoot}/odoo";
            # PostgreSQL data -- local disk on the home node, never JuiceFS.
            localState."/var/lib/postgresql" = "${pv.stateRoot}/clients/${pv.base}/postgresql";

            secrets.admin-passwd = {
              generator = pv.base;
              file = "admin-passwd";
            };

            # Conditions on the leaves, not on `tunnel`: a condition on the
            # whole option would need tunnel.id to decide tunnel.id.
            tunnel = {
              ingress = lib.mkIf (config.tunnel.id != "") { ${o.hostname} = "unix:${socket}"; };
              # The socket dir is 0770 odoo:odoo.
              socketGroups = lib.mkIf (config.tunnel.id != "") [ "odoo" ];
            };

            service = {
              inherit name;
              port = 80;
            };
          };
        }
      )
    );
  };

  # The database manager's master password. Not a database password: the
  # local PostgreSQL uses socket peer auth, so there is none. share = true:
  # one value for the fleet, so it follows the app to any node.
  config.clan.core.vars.generators = lib.mapAttrs (_: _: {
    share = true;
    files.admin-passwd = { };
    runtimeInputs = [
      pkgs.coreutils
      pkgs.openssl
    ];
    script = ''
      openssl rand -base64 30 | tr -d '\n=/+' > "$out/admin-passwd"
    '';
  }) apps;
}
