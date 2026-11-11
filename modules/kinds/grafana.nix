# modules/kinds/grafana.nix — clusterApps.<name>.grafana: Grafana over the
# cluster's logs (Loki) and metrics (Prometheus), signed in through the IdP.
#
#   grafana = { hostname; adminGroup; editorGroup; };
#   oidc.idp = "<the FreeIPA app whose Authelia signs users in>";
#
# A monolith pinned to the `metrics` node, where Loki and Prometheus run, with
# its own tunnel. Nothing about it is special to the platform: it is one more
# container, which may reach those two services on that node's mesh address and
# nothing else on the host (network.hostAccess; modules/overlay-network.nix).
#
# ── sign-in ─────────────────────────────────────────────────────────────────
# OpenID Connect against Authelia in the IdP's container, which checks
# FreeIPA passwords plus a second factor. The app's `oidc` registers the
# client there (modules/kinds/freeipa.nix collects every app's) -- redirect
# URI, secret generator and all -- so declaring the app is the whole change.
#
# Access control is IPA group membership and nothing else: `adminGroup` ->
# Admin, `editorGroup` -> Editor (Explore needs Editor), anyone else is
# refused (role_attribute_strict). No Cloudflare Access in front: Authelia is
# the gate, and Grafana calls it back over the public hostname, as any
# client does.
#
# Break-glass, for when the IdP is down: the built-in `admin` user, password
# in `clan vars get <node> <name>/admin-password`, at
# https://<hostname>/login?disableAutoLogin=true (or basic auth on the API).
#
# ── first start ─────────────────────────────────────────────────────────────
#   cloudflared tunnel create <name>
#   set tunnel.id; clan vars set <node> <name>-cf/cloudflared < ~/.cloudflared/<id>.json
#   cloudflared tunnel route dns <name> <hostname>
#   clan vars generate <node>        # <name>/*, <idp>-oidc-<name>/*
#   -> deploy, `nomad job run` app-<name>; and `nomad job restart app-<idp>`
#      so Authelia mounts the new client secret.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  clusterSite,
  ...
}:
let
  inherit (lib) mkOption types;
  net = clusterLib.net;
  hostApps = config.clusterApps;

  metricsNode = net.soleTaggedNode topology "metrics";

  socket = "/run/grafana/grafana.sock";
  dataDir = "/var/lib/grafana";
  # LoadCredential's directory: the bind-mounted secrets are root 0400, and
  # Grafana runs as its own user.
  creds = "/run/credentials/grafana.service";

  guestModule = name: g: authHost: {
    services.grafana = {
      enable = true;
      inherit dataDir;
      # Grafana 13 no longer bundles the Loki and Prometheus datasources; nixpkgs ships
      # them as plugins. Without these the provisioned datasources below exist but
      # every query fails with "Unable to find datasource plugin" [RAN, WS9's
      # container-isolation: the plugin list held alertmanager, azure-monitor,
      # graphite and testdata only].
      declarativePlugins = [
        pkgs.grafanaPlugins.loki
        pkgs.grafanaPlugins.prometheus
      ];

      settings = {
        server = {
          protocol = "socket";
          inherit socket;
          domain = g.hostname;
          root_url = "https://${g.hostname}/";
        };

        security = {
          secret_key = "$__file{${creds}/secret-key}";
          admin_user = "admin";
          admin_password = "$__file{${creds}/admin-password}";
          cookie_secure = true;
        };

        users.allow_sign_up = false;
        analytics = {
          reporting_enabled = false;
          check_for_updates = false;
        };

        auth = {
          disable_login_form = true;
          signout_redirect_url = "https://${authHost}/logout";
        };
        "auth.anonymous".enabled = false;

        "auth.generic_oauth" = {
          enabled = true;
          name = g.loginName;
          icon = "signin";
          client_id = name;
          client_secret = "$__file{${creds}/oidc-client-secret}";
          scopes = "openid profile email groups";
          auth_url = "https://${authHost}/api/oidc/authorization";
          token_url = "https://${authHost}/api/oidc/token";
          # Authelia releases email/groups from userinfo, not the ID token,
          # unless a claims policy says otherwise.
          api_url = "https://${authHost}/api/oidc/userinfo";
          # Authelia's clients are rendered with require_pkce, and a
          # confidential one authenticates with client_secret_basic.
          use_pkce = true;
          auth_style = "InHeader";
          login_attribute_path = "preferred_username";
          email_attribute_path = "email";
          name_attribute_path = "name";
          groups_attribute_path = "groups";
          role_attribute_path = "contains(groups[*], '${g.adminGroup}') && 'Admin' || contains(groups[*], '${g.editorGroup}') && 'Editor'";
          role_attribute_strict = true;
          allow_sign_up = true;
          auto_login = true;
        };
      };

      provision = {
        enable = true;
        datasources.settings = {
          apiVersion = 1;
          datasources = [
            {
              name = "Loki";
              type = "loki";
              uid = "loki";
              isDefault = true;
              # On the metrics node's mesh address: the container is on that node,
              # and the host firewall lets this app's bridge port, and no other
              # container's, reach these two ports there (network.hostAccess).
              url = "http://${net.meshIp topology metricsNode}:${toString net.lokiPort}";
              jsonData.maxLines = 5000;
            }
            {
              name = "Prometheus";
              type = "prometheus";
              uid = "prometheus";
              url = "http://${net.meshIp topology metricsNode}:${toString net.prometheusPort}";
            }
          ];
        };
        dashboards.settings = {
          apiVersion = 1;
          providers = [
            {
              name = "cluster";
              disableDeletion = true;
              options.path = clusterSite.grafanaDashboards;
            }
          ];
        };
      };
    };

    systemd.services.grafana.serviceConfig.LoadCredential = [
      "secret-key:/run/secrets/grafana-secret-key"
      "admin-password:/run/secrets/grafana-admin-password"
      "oidc-client-secret:/run/secrets/oidc-client-secret"
    ];

    # The state directory is a bind mount the host created as root; the
    # module only creates it when it is missing.
    systemd.tmpfiles.rules = [ "d ${dataDir} 0700 grafana grafana -" ];
  };

  grafanaType = types.submodule {
    options = {
      hostname = mkOption {
        type = types.str;
        example = "grafana.example.com";
        description = "Where Grafana is served, on its own tunnel.";
      };
      loginName = mkOption {
        type = types.str;
        default = "Single sign-on";
        description = "What Grafana calls the identity provider on its sign-in button.";
      };
      adminGroup = mkOption {
        type = types.str;
        default = "grafana-admins";
        description = "IPA group whose members are Grafana Admins.";
      };
      editorGroup = mkOption {
        type = types.str;
        default = "developers";
        description = "IPA group whose members are Grafana Editors (Explore needs Editor). Anyone in neither group is refused.";
      };
    };
  };

  apps = lib.filterAttrs (_: a: a.grafana != null) hostApps;
  idpOf = a: hostApps.${a.oidc.idp};
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          g = config.grafana;
        in
        {
          options.grafana = mkOption {
            type = types.nullOr grafanaType;
            default = null;
            description = "Grafana over the cluster's logs and metrics (modules/kinds/grafana.nix).";
          };

          config = lib.mkIf (config.grafana != null) {
            tier = lib.mkDefault "monolith";
            # Beside Loki and Prometheus, which it reaches on that node's mesh address.
            homeNode = lib.mkDefault metricsNode.hostName;
            # The only host ports it may reach, by its bridge port: so its name is at
            # most 12 characters, and it stays on a metrics node (both asserted).
            network.hostAccess = [
              net.lokiPort
              net.prometheusPort
            ];
            resources = {
              cpu = lib.mkDefault 500;
              memoryMB = lib.mkDefault 512;
            };
            oidc = {
              name = "Grafana";
              redirectUris = [ "https://${g.hostname}/login/generic_oauth" ];
            };
            # Users, preferences and hand-made dashboards; everything
            # provisioned is rebuilt from this repo on start.
            localState.${dataDir} = "/state/clients/${name}/lib";
            secrets = {
              grafana-secret-key = {
                generator = name;
                file = "secret-key";
              };
              grafana-admin-password = {
                generator = name;
                file = "admin-password";
              };
              oidc-client-secret = {
                generator = "${config.oidc.idp}-oidc-${name}";
                file = "secret";
              };
            };
            # Conditions on the leaves, not on `tunnel` (see kinds/odoo.nix).
            tunnel = {
              ingress = lib.mkIf (config.tunnel.id != "") { ${g.hostname} = "unix:${socket}"; };
              # The socket is grafana:grafana 0660.
              socketGroups = lib.mkIf (config.tunnel.id != "") [ "grafana" ];
            };
            backup = {
              engine = "none";
              localSnapshot = true;
              appUnits = [ "grafana.service" ];
              verifyCommand = ''test -s "$ROOT${dataDir}/data/grafana.db"'';
            };
            module = guestModule name g (hostApps.${config.oidc.idp}.freeipa.authelia.hostname);
          };
        }
      )
    );
  };

  config = {
    assertions = lib.mapAttrsToList (n: a: {
      assertion =
        a.oidc != null
        && hostApps ? ${a.oidc.idp}
        && (idpOf a).freeipa != null
        && (idpOf a).freeipa.authelia.enable;
      message = "clusterApps.${n}: Grafana signs in through oidc.idp, which must name a FreeIPA app with authelia.enable.";
    }) apps;

    clan.core.vars.generators = lib.mapAttrs (_: _: {
      share = true;
      files.secret-key = { };
      files.admin-password = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      # secret_key encrypts datasource secrets in grafana.db: never rotate
      # it, or they become unreadable.
      script = ''
        openssl rand -hex 32 | tr -d '\n' > "$out/secret-key"
        openssl rand -base64 30 | tr -d '\n=/+' > "$out/admin-password"
      '';
    }) apps;
  };
}
