# modules/kinds/frappe.nix — clusterApps.<name>.frappe: a Frappe/ERPNext bench.
#
#   frappe = { package; site; webThreads; };
#
# A Tier-0 monolith: frappe-nix's bench + a local MariaDB + a local Redis in
# one container pinned to its homeNode, nginx serving the site over a unix
# socket. The site directory (sites/, uploads, site_config, backups) is on
# JuiceFS and follows the app; MariaDB's data is on the node's local ZFS.
#
# frappe-nix re-synthesises site_config.json on every activation, so the
# database password and the Fernet encryption key come from stored secrets:
# if the key ever changed, everything Frappe encrypted would be unreadable.
#
# The site is not created here: after the first start, provision it once by
# hand (bench new-site, install-app …, migrate).
{
  inputs,
  lib,
  pkgs,
  config,
  ...
}:
let
  inherit (lib) mkOption types;

  frappeType = types.submodule {
    options = {
      package = mkOption {
        type = types.package;
        description = "The bench (apps + Python/Node env), e.g. inputs.<bench>.packages.x86_64-linux.default.";
      };
      site = mkOption {
        type = types.str;
        example = "erp.example.com";
        description = "The site's name, which is also its public hostname.";
      };
      webThreads = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = "gunicorn workers; null = frappe-nix's default.";
      };
      settings = mkOption {
        type = types.attrsOf types.anything;
        default = { };
        example = {
          allow_tests = false;
        };
        description = ''
          Non-secret keys merged into site_config.json (frappe-nix's
          sites.<site>.settings). Secrets go in the clan-var secrets above,
          never here: this is a Nix value and lands in the store.
        '';
      };
      renamedApps = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          legacy_app = "renamed_app";
        };
        description = ''
          Apps renamed in place, OLD = NEW (frappe-nix's sites.<site>.renamedApps):
          the migrate unit runs frappe-rename-app on the site before
          `bench migrate`, inside its snapshot and rollback. Set it in the same
          change that moves the bench input to the renamed apps; a no-op once the
          site names NEW, so drop the entries after that deploy.
        '';
      };
      replacedApps = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          old_app = "new_app";
        };
        description = ''
          Apps replaced by a new app, OLD = NEW (frappe-nix's
          sites.<site>.replacedApps): where OLD is installed, the migrate unit
          installs NEW and uninstalls OLD before migrating. Both apps must be in
          the bench package.
        '';
      };
    };
  };

  apps = lib.filterAttrs (_: a: a.frappe != null) config.clusterApps;

  # cloud-storage is prompted, not generated: the S3 credentials are issued by
  # the provider. Its value is a JSON object deep-merged into site_config.json,
  # i.e. { "cloud_storage_settings": { region, endpoint_url, access_key,
  # secret, bucket, folder, ... } } -- see cloud_storage/docs/configuration.md.
  # Set it BEFORE the first deploy that references it, or the build fails:
  #   clan vars set node1 <name>-cloud-storage/cloud-storage < settings.json
  cloudStorageGenerators = lib.mapAttrs' (
    name: _:
    lib.nameValuePair "${name}-cloud-storage" {
      share = true;
      prompts.cloud-storage = {
        description = "${name}: site_config.json fragment, { \"cloud_storage_settings\": {...} } (JSON)";
        type = "multiline-hidden";
        persist = true;
      };
    }
  ) apps;
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          f = config.frappe;
          nginxSocket = "/run/frappe-${name}/nginx.sock";
        in
        {
          options.frappe = mkOption {
            type = types.nullOr frappeType;
            default = null;
            description = "A Frappe bench serving one site (modules/kinds/frappe.nix).";
          };

          config = lib.mkIf (config.frappe != null) {
            tier = lib.mkDefault "monolith";

            module = {
              imports = [ inputs.frappe-nix.nixosModules.default ];
              services.frappe-nix = {
                enable = true;
                inherit (f) package;
                runtime.webThreads = lib.mkIf (f.webThreads != null) f.webThreads;
                # The Standard print format and every classic (Jinja) one render
                # with wkhtmltopdf, which frappe-nix leaves off: without it on the
                # units' PATH, every such PDF fails. (A devenv bench always has it,
                # so it works locally.) An app's own `module` can turn it off.
                wkhtmltopdf.enable = lib.mkDefault true;
                # Cache, queue and socketio -- ephemeral, inside the container.
                redis.createLocally = true;
                sites.${f.site} = {
                  enable = true;
                  database.createLocally = true;
                  database.passwordFile = "/run/secrets/db-password";
                  encryptionKeyFile = "/run/secrets/encryption-key";
                  # Merged into site_config.json at activation: the
                  # cloud_storage_settings block (see frappeCloudStorage below).
                  settingsFiles = [ "/run/secrets/cloud-storage" ];
                  inherit (f) settings renamedApps replacedApps;
                  # nginx serves the public side over a unix socket and reaches
                  # gunicorn over a second one: no TCP in the request path. Its
                  # loopback :80 listener stays for SocketIO's session callback.
                  nginx.enable = true;
                  nginx.socketPath = nginxSocket;
                  web.socketPath = "/run/frappe-${name}/web.sock";
                };
              };
              # DB-on-ZFS: recordsize=16k = InnoDB page, and ZFS record writes
              # are atomic, so the doublewrite buffer is pure overhead.
              services.mysql.settings.mysqld.innodb_doublewrite = 0;
            };

            # The whole site directory -- shared, follows the app.
            juicefsPaths."/var/lib/frappe/${f.site}" = "clients/${name}/frappe";
            # MariaDB data -- local disk on the home node, never JuiceFS.
            localState."/var/lib/mysql" = "/state/clients/${name}/mysql";

            secrets = {
              db-password = {
                generator = name;
                file = "db-password";
              };
              encryption-key = {
                generator = name;
                file = "encryption-key";
              };
              cloud-storage = {
                generator = "${name}-cloud-storage";
                file = "cloud-storage";
              };
            };

            # Conditions on the leaves, not on `tunnel` (see kinds/odoo.nix).
            tunnel = {
              ingress = lib.mkIf (config.tunnel.id != "") { ${f.site} = "unix:${nginxSocket}"; };
              socketGroups = lib.mkIf (config.tunnel.id != "") [ "frappe" ];
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

  # share = true: one value for the fleet, never per machine. The encryption
  # key must never change (a per-machine generator would mint a new one the
  # first time the app moved), and the tier ladder ends with the app running
  # on any node.
  config.clan.core.vars.generators =
    cloudStorageGenerators
    // lib.mapAttrs (_: _: {
      share = true;
      files.db-password = { };
      files.encryption-key = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      # The encryption key is a Fernet key: 32 url-safe-base64 bytes.
      script = ''
        openssl rand -hex 24 | tr -d '\n' > "$out/db-password"
        openssl rand -base64 32 | tr -d '\n=' | tr '+/' '-_' > "$out/encryption-key"
      '';
    }) apps;
}
