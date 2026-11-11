# modules/cluster-roles.nix — the cluster's singleton roles, as a clan service.
#
# Exported as `clan.modules.cluster-roles` (see flake.nix) and instantiated from
# `inventory.instances.cluster-roles`, which maps each role onto the machines
# carrying the matching tag in the topology.
#
# This exists to replace `nodeName == head (attrNames topology.nodes)`, which
# appeared in three modules and silently elected whichever node happened to sort
# first — so renaming a node, or adding one that sorted earlier, would move the
# metadata engine and the job registrar without anyone touching them.
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
    description = "Singleton cluster roles (metadata engine, job registrar, metrics).";
    categories = [ "System" ];
    readme = builtins.readFile ./cluster-roles.README.md;

    # Every role here is a singleton, for a different reason:
    #   juicefs-meta — two metadata engines over one bucket is a split-brain
    #                  filesystem, i.e. silent data loss.
    #   nomad-leader — job submission is idempotent, so N registrars are merely
    #                  pointless churn against the raft leader on every deploy.
    #   metrics      — two autoscaler agents would both act on the same scaling
    #                  policies; a second needs leader election first.
    constraints.roles = {
      juicefs-meta.maxMachines = 1;
      nomad-leader.maxMachines = 1;
      metrics.maxMachines = 1;
    };
  };

  roles.juicefs-meta = {
    description = "Hosts the JuiceFS metadata PostgreSQL and formats the volume.";
    perInstance = { ... }: { nixosModule = ./storage-juicefs-meta.nix; };
  };

  roles.nomad-leader = {
    description = "Registers rendered Nomad jobspecs after raft leadership.";
    perInstance = { ... }: { nixosModule = ./nomad-bootstrap-leader.nix; };
  };

  roles.metrics = {
    description = "Runs Prometheus and the Nomad autoscaler.";
    perInstance = { ... }: { nixosModule = ./monitoring-server.nix; };
  };
}
