# modules/db-postgres.nix — per-client PostgreSQL HA (Phase 6).
#
# Default posture: per-client Patroni pair (primary + streaming replica) using
# the shared etcd DCS; automatic failover; data on LOCAL ZFS (never JuiceFS).
# A rejoining node clones from the current leader (pg_basebackup/pg_rewind), so
# the DB "follows" to whatever node it lands on. App reaches the primary via a
# per-client endpoint (HAProxy checking Patroni /primary, or a Patroni callback).
# Also hosts the infra metadata DB for JuiceFS (a dedicated scope).
{ ... }:
{
  # TODO(Phase 6): services.patroni per-client scope; endpoint; PITR via pgBackRest.
}
