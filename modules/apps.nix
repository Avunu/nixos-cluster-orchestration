# modules/apps.nix — the app catalogue: one file per app under mkCluster's
# `appsDir` (conventionally apps/). With no appsDir the catalogue is empty.
#
#   apps/<name>.nix    the clusterApps.<name> entry itself, as a function of
#                      { inputs, lib, pkgs, name }
#   apps/<name>.json   the same, as data -- what tooling writes (a provisioning
#                      tool can write WordPress sites with jq)
#
# The file name is the app name. A .nix and a .json of the same name are two
# definitions of one app and merge, so a tool-written site can still be
# extended by hand; use lib.mkForce to override what the JSON sets.
#
# `enable = false;` in a file leaves the app out entirely -- declared, with
# its parameters, but not deployed (e.g. while its tunnel does not exist).
#
# What an app IS comes from its kind, a typed namespace on the entry --
# `odoo`, `frappe`, `freeipa`, `wpdb`, `wordpress` (modules/kinds/) -- which
# fills in the container, paths, sockets, secrets, backups and ingress. A file
# only carries what differs between apps; every generic clusterApps option
# (modules/app-container.nix) stays available beside the kind.
#
# One kind is the exception to "one file, one app": a `wordpress` file becomes
# TWO entries, `<name>` (the public face) and `<name>-admin` (the admin face).
# See wordpressPlanes below.
{
  inputs,
  lib,
  pkgs,
  config,
  clusterSite,
  ...
}:
let
  inherit (clusterSite) appsDir;
  entries = if appsDir != null && builtins.pathExists appsDir then builtins.readDir appsDir else { };
  files = ext: lib.filterAttrs (f: kind: kind == "regular" && lib.hasSuffix ext f) entries;

  # A WordPress site is TWO containers from one file: the read-only public face
  # on the site's real hostname, and the writable admin face on a private one. A
  # kind cannot declare a sibling app -- it is a submodule of one entry -- so the
  # split happens here, in the catalogue.
  #
  # `public` and `admin` are ordinary clusterApps fragments applied to the
  # matching plane. Each plane's own tunnel id goes there, because the two faces
  # cannot share a tunnel: Cloudflare steers to the closest connector without
  # route awareness, so one tunnel serving both hostnames would cross them.
  wordpressPlanes =
    name: e:
    let
      base = removeAttrs e [
        "enable"
        "wordpress"
        "public"
        "admin"
      ];
      site = removeAttrs e.wordpress [
        "role"
        "slug"
      ];
      plane =
        role: suffix:
        lib.nameValuePair "${name}${suffix}" (
          lib.recursiveUpdate (
            base
            // {
              wordpress = site // {
                inherit role;
                slug = name;
              };
            }
          ) (e.${role} or { })
        );
    in
    lib.listToAttrs [
      (plane "public" "")
      (plane "admin" "-admin")
    ];

  # An app switched off with `enable = false` is not defined at all.
  entry =
    name: e:
    lib.optionalAttrs (e.enable or true) (
      if e ? wordpress then wordpressPlanes name e else { ${name} = removeAttrs e [ "enable" ]; }
    );

  fromNix = lib.mapAttrsToList (
    f: _:
    let
      name = lib.removeSuffix ".nix" f;
    in
    entry name (
      import (appsDir + "/${f}") {
        inherit
          inputs
          lib
          pkgs
          name
          ;
      }
    )
  ) (files ".nix");

  fromJson = lib.mapAttrsToList (
    f: _: entry (lib.removeSuffix ".json" f) (builtins.fromJSON (builtins.readFile (appsDir + "/${f}")))
  ) (files ".json");

  # The tunnel credentials every app gets unless it names its own:
  # <name>-cf/cloudflared (modules/app-container.nix). Issued by Cloudflare,
  # so prompted, and apart from any generated generator of the app's (filling
  # it must not re-run that one's script). Declared once the tunnel id is set:
  #   cloudflared tunnel create <name>
  #   clan vars set <node> <name>-cf/cloudflared < ~/.cloudflared/<id>.json
  #   cloudflared tunnel route dns <name> <hostname>
  # then commit the id and the var together.
  defaultCreds = n: {
    generator = "${n}-cf";
    file = "cloudflared";
  };
  withDefaultCreds = lib.filterAttrs (
    n: a: a.tunnel.id != "" && a.tunnel.credentials == defaultCreds n
  ) config.clusterApps;
in
{
  config = {
    clusterApps = lib.mkMerge (fromNix ++ fromJson);

    clan.core.vars.generators = lib.mapAttrs' (
      n: _:
      lib.nameValuePair "${n}-cf" {
        share = true;
        prompts.cloudflared = {
          description = "${n}: tunnel credentials JSON (cloudflared tunnel create)";
          type = "multiline-hidden";
          persist = true;
        };
      }
    ) withDefaultCreds;
  };
}
