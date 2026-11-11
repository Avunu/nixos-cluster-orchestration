# modules/storage-juicefs.nix — universal shared FS client (Phase 4).
#
# JuiceFS over OVH Object Storage (S3), mounted at /mnt/jfs on EVERY node.
# The metadata engine (PostgreSQL) is the other half of this pair and lives in
# modules/storage-juicefs-meta.nix, assigned to the single `juicefs-meta`-tagged
# node through inventory.instances. This file has no leader conditional in it:
# it is what every node runs, unconditionally.
#
# TODO(HA): the metadata PG is still a single instance and therefore the
# cluster's top SPOF — its loss strands /mnt/jfs on every node. Wrap it in
# Patroni (modules/db-postgres.nix) once >=2 real nodes exist.
#
# The volume is encrypted (vars `juicefs-rsa`), and every mount refuses one that
# isn't: see `assertEncryptedSh` in lib/juicefs.nix. Nothing at evaluation can see
# what the metadata engine holds, so the check is at run time, on every start, and
# it fails closed. tests/jfs-encrypted.nix proves it, with a plaintext volume in the
# same run as the positive control.
{
  config,
  lib,
  pkgs,
  topology,
  node,
  clusterLib,
  ...
}:
let
  jfs = clusterLib.juicefs;
  vars = config.clan.core.vars.generators;

  # The metadata engine's address is derived from the tag, not from a position
  # in `topology.nodes`. Every node needs it (they all mount), so this is
  # cross-node data rather than a role guard. It is on the control mesh, and
  # comes from one helper, so an engine that moves (a primary that changes) is a
  # change to lib/net.nix alone.
  metaIp = clusterLib.net.jfsMetaHost topology;

  loadCreds = jfs.loadCredentials (
    id:
    {
      s3ak = vars.ovh-s3.files."access-key".path;
      s3sk = vars.ovh-s3.files."secret-key".path;
      pgpass = vars.juicefs-pg.files.password.path;
      rsaPem = vars.juicefs-rsa.files."rsa.pem".path;
      rsaPass = vars.juicefs-rsa.files."rsa-passphrase".path;
    }
    .${id}
  );

  juicefs = "${pkgs.juicefs}/bin/juicefs";

  # Every JuiceFS script is made through here, so a mutant can edit one by name
  # (see the option below). The identity outside the tests.
  script = name: text: pkgs.writeShellScript name (config.cluster.juicefs.scriptEdit name text);

  textfileDir = "/var/lib/prometheus-node-exporter-text";

  mountScript = script "juicefs-mount" ''
    set -euo pipefail
    # Double quotes, and pgpass assigned first: see lib/juicefs.nix.
    pgpass=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.pgpass}")
    META="${jfs.metaUrl metaIp}"
    export AWS_ACCESS_KEY_ID="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3ak}")"
    export AWS_SECRET_ACCESS_KEY="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3sk}")"
    # The volume's PEM is in the metadata, encrypted with this. Without it the
    # mount fails with "passphrase is required to private key".
    JFS_RSA_PASSPHRASE="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.rsaPass}")"
    export JFS_RSA_PASSPHRASE
    # A client that died under its mount (node1, 2026-10-30: a switch stopped the
    # local metadata PG out from under it) leaves a dead FUSE endpoint behind.
    # Every stat of it fails with ENOTCONN, so the mkdir below fails and
    # Restart= loops forever while every container bound to it stays down.
    # Detach it so the restart can recover on its own. On a first boot the
    # stat fails because the dir is absent, and the umount is a quiet no-op.
    if ! stat ${jfs.mountPoint} >/dev/null 2>&1 \
      && ${pkgs.util-linux}/bin/umount -l ${jfs.mountPoint} 2>/dev/null; then
      echo "juicefs-mount: detached a dead mount at ${jfs.mountPoint}" >&2
    fi
    # Refuse a volume that is not encrypted, before mounting it: JuiceFS itself
    # mounts plaintext happily with the passphrase set [RAN]. Exit 3 is that refusal
    # and the only thing that writes cluster_jfs_encrypted 0 (the unit then stays
    # failed: RestartPreventExitStatus). Exit 4 is an unreadable metadata engine, an
    # outage rather than a verdict: no metric, and Restart= retries until it answers.
    rc=0
    ( ${jfs.assertEncryptedSh "${pkgs.jq}/bin/jq" juicefs} ) || rc=$?
    jfs_metric() {
      mkdir -p ${textfileDir}
      printf 'cluster_jfs_encrypted %s\n' "$1" > ${textfileDir}/jfs_encrypted.prom.tmp
      mv ${textfileDir}/jfs_encrypted.prom.tmp ${textfileDir}/jfs_encrypted.prom
    }
    case "$rc" in
      0) jfs_metric 1 ;;
      3) jfs_metric 0; exit 3 ;;
      *) exit "$rc" ;;
    esac
    mkdir -p ${jfs.mountPoint}
    # NO --writeback: with writeback, writes ack once staged in the local cache
    # dir and are lost forever if the node dies pre-upload. Synchronous S3
    # uploads are the durability-correct default for client uploads; apps that
    # feel the latency can offload to S3 directly (WP media plugin / Frappe
    # cloud-storage) instead.
    exec ${juicefs} mount "$META" ${jfs.mountPoint} \
      --cache-dir ${jfs.cacheDir} \
      --backup-meta ${jfs.backupMeta} \
      --no-usage-report
  '';
in
{
  # A test seam, not a setting: every JuiceFS script's text passes through it on
  # its way to the store, here and in modules/storage-juicefs-meta.nix. The named
  # mutants of tests/jfs-encrypted.nix (flake.nix, legacyPackages.mutants) use it to
  # remove or fake one control and prove that the test notices. Declared here
  # because every node imports this module, the metadata node included.
  options.cluster.juicefs.scriptEdit = lib.mkOption {
    type = lib.types.functionTo (lib.types.functionTo lib.types.str);
    default = _name: text: text;
    internal = true;
    description = "Edits a JuiceFS script's text by name. Tests only.";
  };

  config = {
    environment.systemPackages = [ pkgs.juicefs ];

    systemd.services.juicefs-mount = {
      description = "Mount JuiceFS (${jfs.jfsName}) at ${jfs.mountPoint}";
      # The metadata engine is reached over the mesh. With the mesh down a mount
      # survives and its writes hang until it returns (`mesh-down-jfs-recovers`), and
      # a mount that could not start retries until it can.
      after = [
        "network-online.target"
        "juicefs-format.service"
        "${clusterLib.net.meshIf}-ready.service"
      ];
      wants = [
        "network-online.target"
        "${clusterLib.net.meshIf}-ready.service"
      ];
      wantedBy = [ "multi-user.target" ];
      # The cache dir is its own dataset on ZFS hosts — wait for it.
      unitConfig.RequiresMountsFor = [ jfs.cacheDir ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${mountScript}";
        LoadCredential = loadCreds;
        Restart = "on-failure";
        RestartSec = 5;
        # A plaintext volume is refused for good, not retried every five seconds: the
        # unit stays failed (UnitFailed) next to cluster_jfs_encrypted 0. Everything
        # else, including an unreachable metadata engine (exit 4), is retried.
        RestartPreventExitStatus = [ 3 ];
      };
    };

    # Containers that bind-mount /mnt/jfs order After this (mkAppContainer);
    # Nomad only schedules JuiceFS-bound allocs where it succeeds.
    systemd.services.jfs-health = {
      description = "Assert JuiceFS is mounted + writable";
      after = [ "juicefs-mount.service" ];
      requires = [ "juicefs-mount.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        # Wait for a live mount rather than test once. juicefs-mount is
        # Type=simple, so this runs as soon as the client is spawned, before it
        # has mounted; it also runs on every juicefs-mount restart, before the
        # mount script has detached a dead mount (ENOTCONN) and remounted.
        # `mountpoint` turns down both the dead mount and the bare directory
        # between the detach and the remount. (Not ConditionPathIsMountPoint:
        # that skipped this unit on boot, and a skip counts as success, so
        # jfs-nomad-meta advertised a mount nothing had checked.)
        ExecStart = pkgs.writeShellScript "jfs-health" ''
          set -uo pipefail
          for _ in $(seq 120); do
            ${pkgs.util-linux}/bin/mountpoint -q ${jfs.mountPoint} && test -w ${jfs.mountPoint} && exit 0
            sleep 0.5
          done
          echo "jfs-health: ${jfs.mountPoint} not a writable mount after 60s" >&2
          exit 1
        '';
        # Every client's files are under here, and a raw_exec task (nomad-apps, with
        # Nomad's stray supplementary gid 0) must not read them: root only. Nothing on
        # the host needs it otherwise: containers get their own subdirectories bound
        # in by nspawn as root. The mode lives in JuiceFS's metadata, so it survives a
        # remount and holds on every node [RAN, the design's spike]; setting it on
        # each start costs nothing and repairs a drift. Its own step, so that a failure
        # fails this unit (and every container@ that requires it) rather than passing
        # quietly, and so that the mutant `state-clients-0755` can drop it alone.
        ExecStartPost = [ "${pkgs.coreutils}/bin/chmod 0700 ${jfs.mountPoint}" ];
      };
    };

    # Flip the Nomad scheduling gate once the mount is healthy. Separate unit
    # (not jfs-health) so it can retry until the local agent is up, and
    # `wants`, not `requires`, jfs-health: a failed dependency fails this unit's
    # start job without Restart= ever retrying it, which left a node un-ready
    # for good whenever jfs-health failed or was stopped by a client exit. It
    # checks jfs-health is up instead, and each retry pulls it in again.
    #
    # Needs a token: WRITING node metadata is privileged, so once ACLs are bootstrapped
    # this 403s without one. That failure is quiet in the worst way — the node simply
    # never advertises jfs_ready=true, so every JuiceFS-bound job sits in `pending`
    # forever against a constraint that looks like a scheduling problem rather than an
    # auth one. The token is the `node-meta` role's (node:write and nothing else,
    # modules/nomad-acl.nix), from nomad-login@node-meta; Restart= covers the boot
    # race where that login has not succeeded yet.
    systemd.services.jfs-nomad-meta = {
      description = "Advertise jfs_ready=true to the local Nomad agent";
      after = [
        "jfs-health.service"
        "nomad.service"
        "nomad-login@node-meta.service"
      ];
      wants = [
        "jfs-health.service"
        "nomad-login@node-meta.service"
      ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        Restart = "on-failure";
        RestartSec = 10;
        # The CLI's client certificate: the API refuses a handshake without one.
        Environment = lib.mapAttrsToList (k: v: "${k}=${v}") (clusterLib.nomadPki.cliTlsFor vars).env;
        ExecStart = pkgs.writeShellScript "jfs-nomad-meta" ''
          set -euo pipefail
          systemctl is-active --quiet jfs-health.service
          NOMAD_TOKEN=$(cat ${clusterLib.nomadPki.tokenDir}/node-meta); export NOMAD_TOKEN
          exec ${config.services.nomad.package}/bin/nomad node meta apply \
            -address ${clusterLib.net.nomadAddr node} jfs_ready=true
        '';
      };
    };

    systemd.tmpfiles.rules = [ "d ${jfs.cacheDir} 0700 root root -" ];

    # Is /mnt/jfs actually writable right now? jfs-health answers that once, at
    # start, because container@ units Requires= it and must not be restarted by a
    # flapping check. This is the continuous version, for alerting: write, read
    # back, remove, under a timeout -- a hung FUSE mount fails by timing out
    # rather than hanging the probe forever.
    #
    # Only a JuiceFS mount counts. With the mount gone (a client looping on exit 4 after
    # its dead-mount detach), /mnt/jfs is a plain directory on the root disk, the write
    # lands there, and the probe used to report 1 for exactly the state it exists for.
    # Checked inside the timeout: a hung FUSE mount hangs a stat as well.
    systemd.services.jfs-probe = {
      description = "Probe that JuiceFS is writable (metrics)";
      serviceConfig.Type = "oneshot";
      serviceConfig.ExecStart = script "jfs-probe" ''
        set -u
        export PATH=${
          lib.makeBinPath [
            pkgs.coreutils
            pkgs.util-linux
          ]
        }:$PATH
        m=/var/lib/prometheus-node-exporter-text
        f=${jfs.mountPoint}/.probe/$(${pkgs.hostname}/bin/hostname)
        ok=0
        if timeout 60 ${pkgs.bash}/bin/bash -c "
             mountpoint -q ${jfs.mountPoint} && [ \"\$(findmnt -n -o FSTYPE -M ${jfs.mountPoint})\" = fuse.juicefs ] \
             && mkdir -p ${jfs.mountPoint}/.probe && date +%s > '$f.tmp' && mv '$f.tmp' '$f' && test -s '$f'"; then
          ok=1
        fi
        mkdir -p "$m"
        printf 'cluster_jfs_probe_success %s\ncluster_jfs_probe_timestamp_seconds %s\n' "$ok" "$(date +%s)" > "$m/jfs_probe.prom.tmp"
        mv "$m/jfs_probe.prom.tmp" "$m/jfs_probe.prom"
        [ "$ok" = 1 ]
      '';
    };
    systemd.timers.jfs-probe = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "5min";
        OnUnitActiveSec = "5min";
      };
    };
  };
}
