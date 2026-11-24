# lib/wordpress.nix — what the wordpress kind (modules/kinds/wordpress.nix) and the
# providers' configuration (lib/cloud.nix) must agree on: the names of the two
# cluster-wide buckets a WordPress site's nightly backup copies into, and the
# generators holding their key pairs.
#
# Both buckets are in topology.objectStorage, beside the apps' JuiceFS buckets, one of
# each for the whole fleet, each site under a prefix of its own:
#
#   <prefix>-wordpress-media         the sites' media, copied nightly from each site's
#                                    R2 bucket with a read-only key (`rclone copy`,
#                                    never `sync`). Versioned, and its user cannot
#                                    delete a version: what a compromised site deletes
#                                    in R2 stays here for noncurrentDays.
#   <prefix>-wordpress-dev-restore   each site's nightly database dump, gzipped, for a
#                                    developer's `wp restore` (wordpress-nix devenv),
#                                    whose read key opens this bucket and no other.
{ lib }:
let
  prefix = os: os.appBucketPrefix or os.juicefsBucket;
  self = {
    # Under the prefix the apps' JuiceFS buckets have (`<prefix>-<volume>`), so no volume
    # may take these names: the kind asserts it.
    mediaMirrorName = "wordpress-media";
    devRestoreName = "wordpress-dev-restore";
    mediaMirrorBucket = os: "${prefix os}-${self.mediaMirrorName}";
    devRestoreBucket = os: "${prefix os}-${self.devRestoreName}";

    # Prompted (`avc cloud apply` writes them where the topology has `cloud.ovh`), on
    # every node: the backup runs on whichever node runs the site. Never in a container.
    mediaMirrorGenerator = "wordpress-media-mirror";
    devRestoreGenerator = "wordpress-dev-restore";

    # The apps of the wordpress kind that want each copy.
    mirroredApps =
      apps:
      lib.filterAttrs (
        _: a: (a.wordpress or null) != null && a.wordpress.media != null && a.wordpress.media.backup
      ) apps;
    devRestoreApps =
      apps: lib.filterAttrs (_: a: (a.wordpress or null) != null && a.wordpress.devRestore) apps;

    # The names of the fleet buckets these apps make, after the prefix.
    fleetBucketNames =
      apps:
      lib.optional (self.mirroredApps apps != { }) self.mediaMirrorName
      ++ lib.optional (self.devRestoreApps apps != { }) self.devRestoreName;
  };
in
self
