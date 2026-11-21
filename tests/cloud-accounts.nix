# Eval-level check of tunnel.accountId (lib/cloud.nix, modules/app-container.nix): what
# `avc cloud` makes for an app whose tunnel is in the cluster's Cloudflare account, and
# what it leaves alone for one whose tunnel is in another (a client zone's, made by
# `wordpress-nix edge provision`).
#
# lib/cloud.nix reads only the reference node's `cluster.nomadApps` and the site's name,
# so the apps here are plain attribute sets of the fields it reads: no node is
# evaluated. The assertion that keeps such an app's hostnames out of the cluster's zones
# lives in modules/app-container.nix and is checked by tests/container-tunnel.nix.
#
# Run: nix build .#checks.<system>.cloud-accounts
{
  pkgs,
  lib,
  clusterLib,
}:
let
  own = "00000000000000000000000000000000";
  client = "11111111111111111111111111111111";

  topology = {
    nodes.node1 = {
      index = 1;
      tags = [ "nomad-server" ];
    };
    cloud.cloudflare = {
      accountId = own;
      zones."example.com" = "zone-example-com";
    };
  };

  app = accountId: id: hosts: {
    tunnel = {
      inherit id accountId;
      ingress = lib.genAttrs hosts (_: "unix:/run/app/app.sock");
      credentials = null;
    };
  };

  cloudFor =
    apps:
    import ../lib/cloud.nix {
      inherit lib topology clusterLib;
      nixosConfigurations.node1 = {
        config.cluster.nomadApps = apps;
        _module.specialArgs.clusterSite.name = "accounts";
      };
    };

  c = cloudFor {
    # The cluster's account, by default and by name: made here.
    default = app null "" [ "default.example.com" ];
    named = app own "00000000-0000-4000-8000-000000000020" [ "named.example.com" ];
    # Another account, with an id and without: nothing made here.
    client = app client "00000000-0000-4000-8000-000000000021" [
      "client.example.org"
      "www.client.example.org"
    ];
    unprovisioned = app client "" [ "pending.example.org" ];
  };
  res = c.config.resource;
  tunnels = res.cloudflare_zero_trust_tunnel_cloudflared;
  records = res.cloudflare_dns_record;
  imports = map (i: i.to) c.config."import";

  # Only apps in another account: no tunnel or DNS resource at all, nothing to import.
  onlyClients = cloudFor {
    client = app client "00000000-0000-4000-8000-000000000021" [ "client.example.org" ];
  };

  checks = [
    {
      name = "an app with no accountId gets its tunnel and its record in a listed zone";
      ok =
        tunnels ? default
        && tunnels.default.account_id == own
        && records ? default_example_com
        && c.writeback.tunnels ? default
        && !c.writeback.tunnels.default.known;
    }
    {
      name = "an app whose accountId is the cluster's is treated as one with none: made, and its id imported";
      ok =
        tunnels ? named
        && records ? named_example_com
        && lib.elem "cloudflare_zero_trust_tunnel_cloudflared.named" imports
        && c.writeback.tunnels.named.known;
    }
    {
      name = "an app in another account gets no tunnel, no import and no record";
      ok =
        !(tunnels ? client)
        && !(tunnels ? unprovisioned)
        && !(res.random_bytes ? tunnel_client)
        && !(lib.any (lib.hasSuffix "client") imports)
        && !(records ? client_example_org)
        && !(records ? www_client_example_org)
        && !(records ? pending_example_org);
    }
    {
      name = "an app in another account has nothing written back, and no output";
      ok =
        !(c.writeback.tunnels ? client)
        && !(c.writeback.tunnels ? unprovisioned)
        && !(c.config.output ? tunnel_client)
        && !(c.config.output ? tunnel_unprovisioned);
    }
    {
      name = "its hostnames are reported as someone else's to make";
      ok =
        lib.sort lib.lessThan c.writeback.unmanagedHosts == [
          "client.example.org"
          "pending.example.org"
          "www.client.example.org"
        ];
    }
    {
      name = "a site whose only tunnels are in other accounts asks OpenTofu for no Cloudflare resource";
      ok =
        !(onlyClients.config ? resource)
        && !(onlyClients.config ? "import")
        && onlyClients.writeback.tunnels == { }
        && onlyClients.writeback.unmanagedHosts == [ "client.example.org" ];
    }
  ];

  failed = lib.filter (x: !x.ok) checks;
in
pkgs.runCommand "cloud-accounts-checks" { } (
  if failed == [ ] then
    ''
      echo "${toString (builtins.length checks)} tunnel.accountId checks passed"
      touch $out
    ''
  else
    ''
      echo "FAILED:" >&2
      ${lib.concatMapStringsSep "\n" (x: ''echo "  - ${x.name}" >&2'') failed}
      exit 1
    ''
)
