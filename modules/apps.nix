# modules/apps.nix — the app catalogue: one file per app under mkCluster's
# `appsDir` (conventionally apps/). With no appsDir the catalogue is empty.
#
#   apps/<name>.nix    the clusterApps.<name> entry itself, as a function of
#                      { inputs, lib, pkgs, name }
#   apps/<name>.json   the same, as data -- what tooling writes (`avc cloud` a
#                      tunnel's id, `wordpress-nix edge provision` a site's tunnel)
#
# The file name is the app name. A .nix and a .json of the same name are two
# definitions of one app and merge, so a tool-written site can still be
# extended by hand; use lib.mkForce to override what the JSON sets.
#
# `enable = false;` in a file leaves the app out entirely -- declared, with
# its parameters, but not deployed (e.g. while its tunnel does not exist).
#
# What an app IS comes from its kind, a typed namespace on the entry --
# `odoo`, `frappe`, `freeipa`, `grafana`, `attic`, `wordpress` (modules/kinds/) -- which
# fills in the container, paths, sockets, secrets, backups and ingress. A file
# only carries what differs between apps; every generic clusterApps option
# (modules/app-container.nix) stays available beside the kind.
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

  # `preview.slots = N` makes N more entries from the same file, `<name>-pv1` to
  # `<name>-pvN`: the containers a pull request's preview runs in
  # (modules/ci-agent.nix). The same kind with the same parameters, so the same
  # mounts, limits and firewall, each named for the app whose data it gets a copy
  # of (`preview.of`). What a slot must not share with the app is left out: its
  # tunnel and hostname (a preview's are made per branch), its backups
  # (a copy of production is not worth keeping), and its sign-in as
  # an OIDC client.
  previewSlots =
    name: e:
    lib.listToAttrs (
      lib.genList (
        i:
        lib.nameValuePair "${name}-pv${toString (i + 1)}" (
          removeAttrs e [
            "enable"
            "tunnel"
            "oidc"
          ]
          // {
            preview = (e.preview or { }) // {
              slots = 0;
              of = name;
            };
            backup.enable = false;
          }
        )
      ) (e.preview.slots or 0)
    );

  # An app switched off with `enable = false` is not defined at all.
  entry =
    name: e:
    lib.optionalAttrs (e.enable or true) (
      { ${name} = removeAttrs e [ "enable" ]; } // previewSlots name e
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
  #   agenix edit -i ~/.cloudflared/<id>.json secrets/shared/<name>-cf/cloudflared.age
  #   cloudflared tunnel route dns <name> <hostname>
  # then commit the id and the secret together.
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

    cluster.secrets.generators = lib.mapAttrs' (
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
