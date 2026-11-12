# The fixture topology with node1 NOT opted out, and with what such a node must
# have on top. node2 and node3 stay opted out: nothing evaluates them.
let
  base = import ../topology.nix;
in
base
// {
  nodes = base.nodes // {
    node1 = builtins.removeAttrs base.nodes.node1 [ "insecurePlaintextBoot" ] // {
      initrdNicModules = [
        "virtio_net"
      ];
    };
  };
}
