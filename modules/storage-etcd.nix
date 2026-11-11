# modules/storage-etcd.nix — 3-node etcd cluster (Phase 3).
#
# A tiny, low-churn keyspace (etcd's sweet spot) for coordination: Patroni's DCS,
# and host-side leases. NOT a JuiceFS metadata store. Peers and clients on the
# WireGuard control mesh (modules/mesh-control-core.nix), derived from
# clusterLib.net.etcdInitialCluster.
#
# Plain http, on purpose: the mesh authenticates the machine (design D1), and a
# machine on the VLAN without a mesh key reaches nothing here (`etcd-unreachable`
# in checks.control-plane-attack). Any process on a node can use it; that is the
# mesh's stated limit, not etcd's.
#
# No `member add`: the cluster is created once, from the tags, and so the tags are
# asserted below: no node, or an odd number of at least three, added in ONE commit.
# Why one at a time can't work: a member's data directory, once it exists, makes
# etcd ignore --initial-cluster, so a one-member etcd stays one member for ever.
# Tag two more nodes later and those two, each "new" with a three-member
# initial-cluster, are 2 of 3 of a cluster of their own: they elect a leader, the
# first node refuses them (cluster ID mismatch), every endpoint reports healthy, and
# a client given all three URLs (net.etcdClientUrls) sees two keyspaces. Tag them
# one at a time and the second never has a quorum. Both are refused here.
#
# One member is allowed only under `topology.insecureSingleMemberEtcd = "<reason>"`,
# which the VM fixtures set (a single test node that still needs an etcd). A site
# that sets it can never grow that etcd: it must remove the tag (and the data
# directory) before tagging three.
#
# Only on nodes tagged `etcd`. It used to run on every node, and a member that
# is not in --initial-cluster refuses to start ("couldn't find local name"), so
# a worker-only node would have come up with a failed etcd.service.
{
  lib,
  topology,
  node,
  nodeName,
  clusterLib,
  ...
}:
let
  net = clusterLib.net;
  peerUrl = net.etcdPeerUrl topology node;
  clientUrl = net.etcdClientUrl topology node;

  members = net.etcdMembers topology;
  count = builtins.length members;
  singleReason = topology.insecureSingleMemberEtcd or null;
  singleAllowed = builtins.isString singleReason && singleReason != "";
in
lib.mkMerge [
  # On every node, tagged or not: a topology is wrong for all of them.
  {
    assertions = [
      {
        assertion = count == 0 || (count >= 3 && lib.mod count 2 == 1) || (count == 1 && singleAllowed);
        message =
          "storage-etcd: ${toString count} node(s) are tagged `etcd` (${lib.concatStringsSep ", " members}). "
          + "etcd is created once from the tags and never grows (no member add): tag no node, "
          + "or an odd number of at least 3, all in the same commit. A member added later "
          + "starts a second cluster beside the first (split brain) or never finds a quorum. "
          + "One member only for tests, under topology.insecureSingleMemberEtcd = \"<reason>\".";
      }
    ];
  }

  (lib.mkIf (net.hasTag "etcd" node) {
    services.etcd = {
      enable = true;
      name = nodeName;

      listenPeerUrls = [ peerUrl ];
      initialAdvertisePeerUrls = [ peerUrl ];

      listenClientUrls = [
        clientUrl
        "http://127.0.0.1:${toString net.etcdClientPort}"
      ];
      advertiseClientUrls = [ clientUrl ];

      initialCluster = net.etcdInitialCluster topology;
      initialClusterState = "new";
      initialClusterToken = "orchestration-etcd";
    };

    # Binds the mesh address, which exists only once wg-ctrl is up.
    systemd.services.etcd = net.meshBoundUnit;
  })
]
