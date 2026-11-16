# modules/storage-juicefs.nix — universal shared FS client (Phase 4).
#
# JuiceFS over OVH Object Storage (S3), mounted at /mnt/jfs on EVERY node.
# Its metadata is a PostgreSQL database with a member on every node
# (modules/storage-juicefs-pg.nix), and the volume is formatted, or restored, by
# modules/storage-juicefs-format.nix, also on every node. No file of the three names
# a node.
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

  os = topology.objectStorage;
  system = jfs.systemVolume os;
  # The apps with a volume of their own (lib/juicefs.nix, "Volumes"). Empty where
  # the app catalogue is not imported (the tests that are about the volume alone).
  volumeAppNames = jfs.volumeApps (config.clusterApps or { });
  appVolumes = map (jfs.appVolume os) volumeAppNames;

  juicefs = "${pkgs.juicefs}/bin/juicefs";

  # Every JuiceFS script is made through here, so a mutant can edit one by name
  # (see the option below). The identity outside the tests.
  script = name: text: pkgs.writeShellScript name (config.cluster.juicefs.scriptEdit name text);

  textfileDir = "/var/lib/prometheus-node-exporter-text";

  # The cluster volume's metric has no label, as it always had; an app's names it.
  metricName =
    v: if v.app == null then "cluster_jfs_encrypted" else "cluster_jfs_encrypted{volume=\"${v.name}\"}";

  mountScript =
    v:
    script "juicefs-mount" ''
      set -euo pipefail
      # Double quotes, and pgpass assigned first: see lib/juicefs.nix.
      pgpass=$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.pgpass}")
      META="${jfs.volumeUrl v}"
      export AWS_ACCESS_KEY_ID="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3ak}")"
      export AWS_SECRET_ACCESS_KEY="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.s3sk}")"
      # The volume's PEM is in the metadata, encrypted with this. Without it the
      # mount fails with "passphrase is required to private key".
      JFS_RSA_PASSPHRASE="$(cat "$CREDENTIALS_DIRECTORY/${jfs.credIds.rsaPass}")"
      export JFS_RSA_PASSPHRASE
      # A client that died under its mount (node1, 2026-10-30: a switch stopped the
      # metadata PG out from under it) leaves a dead FUSE endpoint behind.
      # Every stat of it fails with ENOTCONN, so the mkdir below fails and
      # Restart= loops forever while every container bound to it stays down.
      # Detach it so the restart can recover on its own. On a first boot the
      # stat fails because the dir is absent, and the umount is a quiet no-op.
      if ! stat ${v.mountPoint} >/dev/null 2>&1 \
        && ${pkgs.util-linux}/bin/umount -l ${v.mountPoint} 2>/dev/null; then
        echo "juicefs-mount: detached a dead mount at ${v.mountPoint}" >&2
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
        printf '${metricName v} %s\n' "$1" > ${textfileDir}/jfs_encrypted${v.suffix}.prom.tmp
        mv ${textfileDir}/jfs_encrypted${v.suffix}.prom.tmp ${textfileDir}/jfs_encrypted${v.suffix}.prom
      }
      case "$rc" in
        0) jfs_metric 1 ;;
        3) jfs_metric 0; exit 3 ;;
        *) exit "$rc" ;;
      esac
      mkdir -p ${v.mountPoint}
      # NO --writeback: with writeback, writes ack once staged in the local cache
      # dir and are lost forever if the node dies pre-upload. Synchronous S3
      # uploads are the durability-correct default for client uploads; apps that
      # feel the latency can offload to S3 directly (WP media plugin / Frappe
      # cloud-storage) instead.
      exec ${juicefs} mount "$META" ${v.mountPoint} \
        --cache-dir ${jfs.cacheDir} \
        --backup-meta ${jfs.backupMeta} \
        --no-usage-report
    '';

  # An app's mount is up when this returns: the client is spawned first, and mounts
  # a moment later. Root only, as the cluster volume is (jfs-health says why).
  mountedScript =
    v:
    pkgs.writeShellScript "juicefs-mounted" ''
      for _ in $(seq 240); do
        if ${pkgs.util-linux}/bin/mountpoint -q ${v.mountPoint}; then
          exec ${pkgs.coreutils}/bin/chmod 0700 ${v.mountPoint}
        fi
        sleep 0.5
      done
      echo "${v.mountPoint} is not a mount after 120s" >&2
      exit 1
    '';

in
{
  # A test seam, not a setting: every JuiceFS script's text passes through it on
  # its way to the store, here and in modules/storage-juicefs-format.nix. The named
  # mutants of tests/jfs-encrypted.nix (flake.nix, legacyPackages.mutants) use it to
  # remove or fake one control and prove that the test notices. Declared here
  # because every node imports this module.
  options.cluster.juicefs.scriptEdit = lib.mkOption {
    type = lib.types.functionTo (lib.types.functionTo lib.types.str);
    default = _name: text: text;
    internal = true;
    description = "Edits a JuiceFS script's text by name. Tests only.";
  };

  config = lib.mkMerge [
    {
      environment.systemPackages = [ pkgs.juicefs ];

      systemd.services.juicefs-mount = {
        description = "Mount JuiceFS (${system.name}) at ${system.mountPoint}";
        # The metadata primary is reached over the mesh unless it is this node's member.
        # With the mesh down a mount survives and its writes hang until it returns
        # (`mesh-down-jfs-recovers`), and a mount that could not start retries until it can.
        # Not after juicefs-format: see there. Until the volume is formatted the
        # gate below exits 4 and this is started again.
        after = [
          "network-online.target"
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
          ExecStart = "${mountScript system}";
          LoadCredential = jfs.volumeLoadCredentials vars system;
          # `always`, not `on-failure`: after some minutes without its metadata database
          # the client's own watchdog ends it, cleanly ("exit successfully"), and
          # on-failure then left the node without /mnt/jfs for good once the database
          # was back (`meta-database-grows`). A `systemctl stop` is still a stop.
          Restart = "always";
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
        # `wants`, not `requires`: a required unit that systemd is restarting takes
        # this one round with it, every five seconds, and then this unit always has
        # a start job pending. jfs-nomad-meta, nomad-bootstrap and multi-user.target
        # wait behind that job, so a node whose mount could not start (no way to the
        # metadata database) never finished booting (`missing-wg-key-boots`). It
        # looks once, for a minute; jfs-nomad-meta's timer has it look again.
        wants = [ "juicefs-mount.service" ];
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
      # modules/nomad-acl.nix), from nomad-login@node-meta; the timer covers the boot
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
          # No Restart= here: systemd keeps the start job of a oneshot it is
          # restarting, and nomad-bootstrap and multi-user.target, ordered after this
          # unit, then wait for as long as /mnt/jfs is not there. A node that could
          # not reach the metadata database never finished booting
          # (`missing-wg-key-boots`). It fails once, and the timer below asks again.
          #
          # A flag that arrives late: the jobs registered meanwhile may have been
          # evaluated without it (modules/nomad-register.nix), so registration runs
          # again where this node does it. Nothing on a node that does not.
          ExecStartPost = "-${config.systemd.package}/bin/systemctl try-restart --no-block nomad-bootstrap.service";
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

      # Until it has succeeded (RemainAfterExit: starting an active unit does nothing).
      systemd.timers.jfs-nomad-meta = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "2min";
          OnUnitInactiveSec = "30s";
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
    }

    # ── each app's own volume ────────────────────────────────────────────────
    {
      systemd.tmpfiles.rules = [ "d ${jfs.appMountRoot} 0700 root root -" ];

      systemd.services = lib.listToAttrs (
        map (
          v:
          lib.nameValuePair "juicefs-mount${v.suffix}" {
            description = "Mount ${v.app}'s JuiceFS volume at ${v.mountPoint}";
            # Started by the app's container (lib/mk-app-container.nix), on the node
            # Nomad put it on, and stopped when the container no longer needs it. The
            # volume is formatted, or found formatted, first.
            after = [
              "network-online.target"
              "juicefs-format${v.suffix}.service"
              "${clusterLib.net.meshIf}-ready.service"
            ];
            requires = [ "juicefs-format${v.suffix}.service" ];
            wants = [ "network-online.target" ];
            unitConfig = {
              RequiresMountsFor = [ jfs.cacheDir ];
              StopWhenUnneeded = true;
            };
            serviceConfig = {
              Type = "simple";
              ExecStart = "${mountScript v}";
              # Active once it is mounted, so what is ordered after it finds a mount.
              ExecStartPost = "${mountedScript v}";
              ExecStopPost = "-${pkgs.util-linux}/bin/umount -l ${v.mountPoint}";
              LoadCredential = jfs.volumeLoadCredentials vars v;
              # Not restarted here: a client that ends takes the container bound to it
              # down (BindsTo), Nomad starts the app again, and that starts this.
              Restart = "no";
            };
          }
        ) appVolumes
      );

      # Each app's volume has its own key and its own database role, generated, and
      # its own S3 pair, which opens its bucket and no other: issued by the provider,
      # so prompted, or written by `avc cloud apply` where the topology has
      # `cloud.ovh`. Shared: any node may be the one the app runs on.
      #
      # NEVER regenerate the key: as `juicefs-rsa` (modules/vars.nix), for this app's
      # files alone.
      clan.core.vars.generators = lib.listToAttrs (
        lib.concatMap (app: [
          (lib.nameValuePair (jfs.appKeyGenerator app) {
            share = true;
            files."rsa.pem" = { };
            files."rsa-passphrase" = { };
            files."pg-password" = { };
            runtimeInputs = [
              pkgs.openssl
              pkgs.coreutils
            ];
            script = ''
              openssl rand -hex 32 | tr -d '\n' > "$out/rsa-passphrase"
              openssl genrsa -aes256 -passout file:"$out/rsa-passphrase" -out "$out/rsa.pem" 4096
              openssl rand -hex 32 | tr -d '\n' > "$out/pg-password"
            '';
          })
          (lib.nameValuePair (jfs.appS3Generator app) {
            share = true;
            prompts."access-key" = {
              description = "S3 access key for ${app}'s bucket (${jfs.appBucket os app})";
              persist = true;
            };
            prompts."secret-key" = {
              description = "S3 secret key for ${app}'s bucket (${jfs.appBucket os app})";
              type = "hidden";
              persist = true;
            };
          })
        ]) volumeAppNames
      );

      assertions = map (v: {
        assertion =
          builtins.stringLength v.bucket <= 63
          && builtins.match "[a-z0-9][a-z0-9-]*[a-z0-9]" v.bucket != null;
        message = "${v.app}: its JuiceFS bucket would be `${v.bucket}`, which is not a bucket name (lowercase letters, digits and hyphens, 63 at most). Shorten `objectStorage.appBucketPrefix` or the app's name.";
      }) appVolumes;
    }
  ];
}
