# modules/cluster-roles.nix — the cluster's singleton roles, as a clan service.
#
# Exported as `clan.modules.cluster-roles` (see flake.nix) and instantiated from
# `inventory.instances.cluster-roles`, which maps each role onto the machines
# carrying the matching tag in the topology.
#
# This exists to replace `nodeName == head (attrNames topology.nodes)`, which
# appeared in three modules and silently elected whichever node happened to sort
# first — so renaming a node, or adding one that sorted earlier, would move the
# metadata engine without anyone touching it.
#
# The value clan adds over a plain `lib.mkIf (elem tag node.tags)` is
# `constraints` — but be precise about what they are: they surface through
# `clanInternals.cliChecks` (severity "error"), which the clan CLI reads. They
# are NOT forced by evaluating nixosConfigurations, so they will not by
# themselves stop a `nixos-rebuild`.
#
# The eval-time backstop is clusterLib.net.soleTaggedNode, which throws while
# building the JuiceFS client config on every node. Verified: tagging two nodes
# `juicefs-meta` produces
#   error: topology: 2 nodes are tagged "juicefs-meta" (node1, node2); …
# from the throw, and
#   Role 'juicefs-meta' … allows at most 1 machine(s) but 2 are assigned.
# from cliChecks. Keep both: the throw is what protects a pull-deployed node
# that never runs the CLI, the constraint is what tells a human why.
{ ... }:
{
  _class = "clan.service";

  manifest = {
    name = "cluster-roles";
    description = "Singleton cluster roles (the JuiceFS metadata engine).";
    categories = [ "System" ];
    readme = builtins.readFile ./cluster-roles.README.md;

    # One role, and a singleton: two metadata engines over one bucket is a
    # split-brain filesystem, i.e. silent data loss. Registering jobs was the other
    # one, for no better reason than churn; every Nomad server does it now
    # (modules/nomad-register.nix).
    constraints.roles.juicefs-meta.maxMachines = 1;
  };

  roles.juicefs-meta = {
    description = "Hosts the JuiceFS metadata PostgreSQL and formats the volume.";
    perInstance = { ... }: { nixosModule = ./storage-juicefs-meta.nix; };
  };
}
