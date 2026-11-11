# lib/app-network-type.nix — the per-app `network` option (clusterApps.<n>.network):
# what a container may reach besides the internet, its node's DHCP and DNS.
#
# Its own file because two modules declare it: modules/app-container.nix, for
# `clusterApps.<n>.network`, and modules/overlay-network.nix, for the internal
# `cluster.appFirewall.apps` it renders the host ruleset from. A test that runs the
# real overlay-network without containers (tests/jumbo-mtu.nix) sets the latter with
# the same schema, rather than a copy.
#
# Container to host is default-deny (design WS9, Appendix E). Everything here is a
# hole in it, named by the container's bridge port, not its address: a container
# holds CAP_NET_ADMIN and can take any address and MAC it likes.
{ lib }:
let
  inherit (lib) mkOption types;
in
types.submodule {
  options = {
    hostAccess = mkOption {
      type = types.listOf types.port;
      default = [ ];
      example = [
        3100
        9090
      ];
      description = ''
        TCP ports this app may reach on the `metrics` node's mesh address (Loki,
        Prometheus). Only from the metrics node itself: no other node routes a
        container to a mesh address. So the app must be pinned there (`homeNode`
        carrying the `metrics` tag), and its name must be at most 12 characters,
        because its identity is nspawn's veth `vb-<name>`, which nspawn shortens
        unpredictably beyond that. Both are asserted.
      '';
    };
    peerAccess = mkOption {
      type = types.listOf (
        types.submodule {
          options = {
            app = mkOption {
              type = types.str;
              description = "The app reached: a clusterApps name.";
            };
            port = mkOption {
              type = types.port;
              description = "The TCP port it serves this app on.";
            };
          };
        }
      );
      default = [ ];
      example = [
        {
          app = "wpdb";
          port = 3306;
        }
      ];
      description = ''
        Other apps this app may reach, each on one TCP port: on the same node over
        the bridge, and on any other node over the app VLAN. Nothing else between
        containers is allowed, and nothing in the other direction but the replies.
        Both ends get a br-app veth named `vp-<iid>` (lib/net.nix appPeerPort) in
        place of nspawn's `vb-<name>`, so any name length works.
      '';
    };
  };
}
