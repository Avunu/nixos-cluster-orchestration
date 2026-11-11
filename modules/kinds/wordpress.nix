# modules/kinds/wordpress.nix — clusterApps.<name>.wordpress: one plane of a
# split-plane WordPress site.
#
# A site is TWO containers from one file in apps/. modules/apps.nix does that
# split (a kind is a submodule of one entry and cannot declare a sibling), giving
# each entry a `wordpress` section with a `role` of "public" or "admin" and the
# site's `slug`. Everything else about the plane comes from
# lib/mk-wordpress-site.nix, which this file only wires in.
#
# The section stays UNTYPED (attrsOf anything) because the provisioning tool
# writes it as JSON, and the builder tells an optional parameter set -- r2,
# email -- by its presence rather than by a null default.
#
# Three things are resolved here rather than in the builder, because they need
# the module's `config`:
#
#   * the shared database's address, from whichever app is the wpdb kind, so a
#     site file never repeats it;
#   * `wordpressDatabases`, the contract wpdb consumes to create each database,
#     user and grant -- emitted once per site, from the admin plane only;
#   * the tunnel hostname, which must stay conditional on the tunnel id: a site
#     is declared, and its vars generated, before its tunnel exists.
{
  inputs,
  lib,
  pkgs,
  config,
  ...
}:
let
  inherit (lib) mkOption types;

  mkSite = import ../../lib/mk-wordpress-site.nix { inherit inputs lib pkgs; };

  # Only the `wordpress` / `wpdb` OPTION of other apps is read through config
  # here, never their `module`, so none of this recurses.
  planes = lib.filterAttrs (_: a: a.wordpress != null) config.clusterApps;
  adminPlanes = lib.filterAttrs (_: a: a.wordpress.role == "admin") planes;

  dbApps = lib.filterAttrs (_: a: a.wpdb != null) config.clusterApps;
  dbApp = if dbApps == { } then null else lib.head (lib.attrValues dbApps);
  dbAppName = lib.head (lib.attrNames dbApps);

  # Built once per plane and reused by every consumer below.
  built = app: mkSite (app.wordpress // { dbHost = app.wordpress.dbHost or dbHost; });
  dbHost = if dbApp == null then null else dbApp.wpdb.address;
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          site = built config;
        in
        {
          options.wordpress = mkOption {
            type = types.nullOr (types.attrsOf types.anything);
            default = null;
            description = ''
              One plane of a split-plane WordPress site
              (modules/kinds/wordpress.nix). Written by the provisioning tool;
              modules/apps.nix adds `role` and `slug`.
            '';
          };

          config = lib.mkIf (config.wordpress != null) (
            site.plane
            // {
              # Conditions on the leaves, not on `tunnel` itself (see kinds/odoo.nix):
              # a hostname declared without a tunnel id fails to evaluate, and a site
              # exists in the catalogue before its tunnel is created.
              tunnel = {
                ingress = lib.mkIf (config.tunnel.id != "") site.plane.tunnel.ingress;
                socketGroups = lib.mkIf (config.tunnel.id != "") site.plane.tunnel.socketGroups;
                accessProtected = lib.mkIf (config.tunnel.id != "") site.plane.tunnel.accessProtected;
              };
              # The shared database, on its one port: the only container a plane may
              # reach (container default-deny, modules/overlay-network.nix). Not when
              # the site names its own database host, which is then not this app.
              network.peerAccess = lib.optional (dbApp != null && !(config.wordpress ? dbHost)) {
                app = dbAppName;
                port = dbApp.wpdb.port;
              };
            }
          );
        }
      )
    );
  };

  config = {
    # One set per SITE, from the admin plane only -- the two planes would
    # otherwise define the same generators twice.
    clan.core.vars.generators = lib.mkMerge (
      lib.mapAttrsToList (_: a: (built a).generators) adminPlanes
    );

    # What modules/kinds/wpdb.nix creates: one database, user and grant per site.
    wordpressDatabases = lib.mapAttrs' (
      _: a: lib.nameValuePair a.wordpress.slug (built a).database
    ) adminPlanes;

    assertions = [
      {
        assertion = planes == { } || dbApp != null;
        message =
          "clusterApps: a WordPress site needs the shared database — add an app with the"
          + " `wpdb` kind (apps/wpdb.nix), which is what hands every plane its DB_HOST.";
      }
      {
        assertion = lib.length (lib.attrValues dbApps) <= 1;
        message =
          "clusterApps: more than one app declares the `wpdb` kind, so a site's DB_HOST"
          + " would be ambiguous. One shared database per cluster.";
      }
    ]
    ++ lib.mapAttrsToList (n: a: {
      # MySQL caps user names at 32 bytes and truncation would silently collide.
      assertion = lib.stringLength (built a).database.user <= 32;
      message =
        "clusterApps.${n}: the database user derived from the slug is"
        + " ${toString (lib.stringLength (built a).database.user)} characters, over MySQL's"
        + " 32-byte limit. Set wordpress.dbUser to something shorter.";
    }) adminPlanes;
  };
}
