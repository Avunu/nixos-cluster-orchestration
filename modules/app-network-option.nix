# modules/app-network-option.nix — what the host firewall lets each container reach.
#
# Set from clusterApps.<n>.network by modules/app-container.nix and read by
# modules/overlay-network.nix, which renders the host ruleset from it. Declared here,
# and imported by both, so either module works without the other: a test that runs
# the real overlay-network with no containers (tests/jumbo-mtu.nix) sets it directly.
# A module imported by path is only loaded once.
{ lib, ... }:
{
  options.cluster.appFirewall.apps = lib.mkOption {
    type = lib.types.attrsOf (import ../lib/app-network-type.nix { inherit lib; });
    default = { };
    internal = true;
    description = "<app> -> its clusterApps.<app>.network, as the host firewall reads it.";
  };
}
