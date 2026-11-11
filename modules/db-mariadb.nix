# modules/db-mariadb.nix — per-client MariaDB HA (Phase 6).
#
# Default posture: per-client 2-node Galera + `garbd` arbitrator (auto-failover
# with quorum, no external orchestrator). DDL-under-TOL stalls are contained to
# that one client's own migrations. Data on LOCAL ZFS; rejoin via SST/IST. App
# reaches the current writer via a per-client endpoint (VIP / local node).
{ ... }:
{
  # TODO(Phase 6): services.mysql.galeraCluster per client + garbd + PITR
  #   (mariadb-backup + binlog shipping to OVH S3).
}
