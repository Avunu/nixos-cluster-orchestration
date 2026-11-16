# modules/backup.nix — backups, wired to clan vars.
#
# Everything that decides WHAT is backed up and HOW lives in
# modules/backup-core.nix, which knows nothing about clan (so it can be tested
# in a VM against an S3 server with plain credential files). This file only adds the
# secrets: where the repository password and the target's credentials come from.
#
# ── operator verbs (on the node running the app) ──────────────────────────────────
#   cluster-backup [app…]        back up now (all apps here, or the named ones)
#   cluster-backup-list [app…]   list each app's snapshots
#   cluster-restore <app> …      restore; prints the plan, --yes to run it
#
# Timers: nightly backup (topology.backup.schedule), weekly prune + check
# (.maintenance), weekly restore rehearsal (.verify). And, where the topology has
# `backup.state`, the frequent one to a second target (modules/state-backup-core.nix):
# each app's local state from a replica, hourly, with verbs of its own. Each writes node_exporter
# textfile metrics under /var/lib/prometheus-node-exporter-text.
#
# ── deliberately not backed up ──────────────────────────────────────────────
#   - Raw database directories, by this backup: dumps are what survive a version
#     bump. The copies for the last hours are the replicas (modules/app-state.nix)
#     and the state backup above, which is the raw directory, from a snapshot.
#   - The JuiceFS metadata engine: it dumps itself hourly into its own bucket
#     (modules/storage-juicefs-format.nix restores the newest one on a rebuilt
#     node). Restoring a stale copy against a live bucket would orphan chunks.
#   - Nomad and etcd state: declarative (re-registered from this flake) or empty.
#   - Cloudflare D1/R2 (WordPress): Cloudflare's own Time Travel covers D1 for
#     30 days; an export step belongs here once a site is live.
#
# ── repository paths ────────────────────────────────────────────────────────
# Each app's repository is `apps/<sha256 of topology.backup.repoSalt + app>` on the
# target, not `apps/<app>`: app names are often client names, and the target's
# provider sees every object path. The salt is site data, not a secret, but it must
# be the site's own (a shared or guessable salt makes the hash a lookup of likely
# names), so the template's placeholder is refused. Never change it on a running site:
# every app would start a new, empty repository and the old ones would be found by
# nothing (`restic copy` per app moves history, as for a target swap). To go back to
# plain names, drop the `repoPathFor` line below: backup-core's default is `apps/<app>`.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  ...
}:
let
  vars = config.clan.core.vars.generators;
  salt = topology.backup.repoSalt or null;
  state = topology.backup.state or null;
in
{
  imports = [
    ./backup-core.nix
    ./state-backup-core.nix
  ];

  clan.core.vars.generators = {
    # The repository password. Generated, not prompted -- losing it means
    # losing every backup, so it lives in vars (in git, encrypted) rather than
    # in someone's password manager. One password, but every app's repository
    # has its own master key; `restic key` rotates per repository.
    restic = {
      share = true;
      files.password = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      script = ''
        openssl rand -hex 32 | tr -d '\n' > "$out/password"
      '';
    };

    # Credentials for topology.backup.target -- issued by whoever runs the
    # target (for MinIO: a user limited to the backup bucket, WITHOUT
    # s3:DeleteObjectVersion, so versioning keeps history this cluster cannot
    # erase; see README "Backups"). Prompted, so swapping targets is
    # `clan vars set <node> backup-target/access-key` + `/secret-key`.
    backup-target = {
      share = true;
      prompts = {
        access-key = {
          description = "Backup target access key id (S3 access key / B2 account id / rest-server user)";
          persist = true;
        };
        secret-key = {
          description = "Backup target secret";
          type = "hidden";
          persist = true;
        };
      };
    };
  };

  # Credentials for topology.backup.state.target, the frequent backup's own target
  # (modules/state-backup-core.nix): a different place from the nightly one's, so a
  # different pair. Declared only where the topology names that target.
  clan.core.vars.generators.backup-state-target = lib.mkIf (state != null) {
    share = true;
    prompts = {
      access-key = {
        description = "State backup target access key id (topology.backup.state.target)";
        persist = true;
      };
      secret-key = {
        description = "State backup target secret";
        type = "hidden";
        persist = true;
      };
    };
  };

  cluster.stateBackup = lib.mkIf (state != null) {
    repoPathFor = lib.mkIf (builtins.isString salt) (clusterLib.backupTarget.stateRepoPath salt);
    credentialFiles = {
      password = vars.restic.files.password.path;
      id = vars.backup-state-target.files.access-key.path;
      secret = vars.backup-state-target.files.secret-key.path;
    };
  };

  assertions = [
    {
      assertion =
        builtins.isString salt && builtins.stringLength salt >= 16 && !(lib.hasInfix "REPLACE-ME" salt);
      message = "topology.backup.repoSalt must be this site's own string of at least 16 characters (`openssl rand -hex 16`), not the template's REPLACE-ME. It salts the hashed restic repository paths; set it once, before the first backup, and never change it.";
    }
  ];

  cluster.backup.repoPathFor = lib.mkIf (builtins.isString salt) (
    clusterLib.backupTarget.appRepoPath salt
  );

  cluster.backup.credentialFiles = {
    password = vars.restic.files.password.path;
    id = vars.backup-target.files.access-key.path;
    secret = vars.backup-target.files.secret-key.path;
  };
}
