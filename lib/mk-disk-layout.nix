# lib/mk-disk-layout.nix — the universal dual-NVMe + mirrored-rpool disk layout.
#
# One function, two layouts:
#
#   encrypted = false   lib/disk-layout.nix, for nodes that carry a reason in
#                       insecurePlaintextBoot, and for tests/install-boot.nix.
#   encrypted = true    every other node. Each leg of the mirror sits inside LUKS and
#                       swap takes a random key per boot.
#
# A plain function, not a module. A module function's argument defaults are ignored
# by the module system (`key ? "/tmp/k"` fails with `attribute 'key' missing`), and a
# layout chosen in `imports` from `node` is suspected of recursing, since `node`
# comes from the module arguments that `imports` would need to resolve first. So
# modules/zfs-host.nix selects the layout in `config`.
#
# Contracts other files rely on:
#   - The mapping names `crypt-a` and `crypt-b`. modules/boot-security.nix refuses
#     anything else, and boot.zfs.devNodes = /dev/mapper only finds what is opened.
#   - The partition labels disko derives from these names, `disk-nvme0-luks` and so on.
#   - The plain layout's partition keeps the name `zfs`, so nothing moves on a node
#     that has opted out.
{
  lib,
  encrypted,
  devices ? {
    a = "/dev/nvme0n1";
    b = "/dev/nvme1n1";
  },
  # Encrypted only: where disko reads the initial LUKS passphrase. Null would make
  # disko ask at the terminal, which a remote install has no one to answer.
  passwordFile ? null,
}:
assert lib.assertMsg (
  encrypted -> passwordFile != null
) "mk-disk-layout: the encrypted layout needs passwordFile";
let
  # zswap (modules/zfs-host.nix) needs a real disk-backed swap device behind
  # it — a swapfile on a zvol deadlocks under memory pressure (the zvol's own
  # write path can need to allocate memory), which is why the previous layout
  # used zramSwap instead of any disk swap at all. A dedicated partition, one
  # per NVMe, sidesteps that without giving up the throughput headroom zswap
  # wants for its overflow tier.
  #
  # 32G × 2 = 64G total: generous relative to the 32GB RAM on the real node
  # (node1), sized for zswap's usage pattern of spilling to disk only once its
  # compressed pool (20% of RAM, see zfs-host.nix) is exhausted.
  swapSizePerDiskGiB = 32;

  swapContent = {
    type = "swap";
    # Identical on both partitions: with matching priority the kernel
    # interleaves writes across them (effectively RAID0 for swap) instead of
    # draining one disk before ever touching the other. No mirroring needed —
    # swap is transient, and losing an NVMe is a failover event either way.
    priority = 100;
    mountOptions = [
      "defaults"
      "nofail" # a missing/degraded swap partition must not block boot
    ]
    # With a random key the swap device is a mapping that only appears if its service
    # could run, and sysinit waits for it even under nofail: 90 seconds, by default, of a
    # boot on one good disk. The mapping takes about a second when it does appear.
    ++ lib.optional encrypted "x-systemd.device-timeout=30s";
  }
  // (
    if encrypted then
      {
        # A new key every boot, so what memory held is gone at power-off. No discard
        # policy: disko forwards it as randomEncryption.allowDiscards, and TRIM
        # through this mapping would show which pages were ever swapped.
        randomEncryption = true;
      }
    else
      {
        discardPolicy = "once"; # trim once at swapon; matches the NVMes' TRIM support
      }
  );

  # nofail on the encrypted layout only: a dead disk has to leave the node bootable
  # from the other one, and a node that cannot mount an ESP still has its root.
  # systemd-boot-random-seed waits for the first ESP's mount (boot-security-core.nix) and
  # sysinit waits for it, so a dead disk's ESP gets the swap's 30 seconds below, not the
  # default 90: the two run out together, and a boot on one disk waits no longer than it
  # did. The partition was already found in the initrd, so a healthy one is there at once.
  espContent = mountpoint: {
    type = "filesystem";
    format = "vfat";
    inherit mountpoint;
    mountOptions = [
      "umask=0077"
    ]
    ++ lib.optionals encrypted [
      "nofail"
      "x-systemd.device-timeout=30s"
    ];
  };

  poolLeg =
    letter:
    if encrypted then
      {
        type = "luks";
        name = "crypt-${letter}";
        inherit passwordFile;
        extraFormatArgs = [
          "--type"
          "luks2"
        ];
        settings = {
          # zpool trim needs it, and autotrim silently does nothing without it. It
          # reveals which blocks are free, which is accepted (D13).
          allowDiscards = true;
          crypttabExtraOpts = [
            # A person at a console mistyping must not fail the unit, which would
            # give this leg up and import the pool DEGRADED.
            "tries=0"
            # A dead disk must not stop the boot; modules/boot-security-core.nix's
            # gate decides when to stop waiting for it.
            "nofail"
            "x-systemd.device-timeout=30s"
          ];
        };
        content = {
          type = "zfs";
          pool = "rpool";
        };
      }
    else
      {
        type = "zfs";
        pool = "rpool";
      };

  # ESP on BOTH drives, because losing NVMe 0 must not leave an unbootable machine
  # with an intact mirror. Who keeps the second one current depends on the boot chain:
  # lib/esp-sync-hook.nix for systemd-boot, the guarded hook for Lanzaboote. 1G on an
  # encrypted node (D8), where each generation carries a whole signed kernel and initrd.
  mkDisk = device: espMount: letter: {
    type = "disk";
    inherit device;
    content = {
      type = "gpt";
      partitions = {
        ESP = {
          size = if encrypted then "1G" else "512M";
          type = "EF00";
          content = espContent espMount;
        };
        swap = {
          size = "${toString swapSizePerDiskGiB}G";
          content = swapContent;
        };
        ${if encrypted then "luks" else "zfs"} = {
          size = "100%";
          content = poolLeg letter;
        };
      };
    };
  };
in
{
  # ── Disk layout (disko) ──────────────────────────────────────────────────────
  disko.devices = {
    disk = {
      nvme0 = mkDisk devices.a "/boot" "a";
      nvme1 = mkDisk devices.b "/boot-fallback" "b";
    };

    zpool.rpool = {
      type = "zpool";
      mode = "mirror";
      options = {
        ashift = "12";
        autotrim = "on";
      };
      # Pool-root properties, inherited unless a dataset overrides them.
      rootFsOptions = {
        compression = "zstd";
        atime = "off";
        xattr = "sa";
        acltype = "posixacl";
        mountpoint = "none";
        "com.sun:auto-snapshot" = "false";
      };
      datasets = {
        root = {
          type = "zfs_fs";
          mountpoint = "/";
          options.mountpoint = "legacy";
        };
        nix = {
          type = "zfs_fs";
          mountpoint = "/nix";
          options.mountpoint = "legacy";
        };
        state = {
          type = "zfs_fs";
          mountpoint = "/state";
          options = {
            mountpoint = "legacy";
            recordsize = "16k"; # InnoDB page size — client DB dirs inherit
            compression = "lz4";
            "com.sun:auto-snapshot" = "true";
          };
        };
        postgresql = {
          type = "zfs_fs";
          mountpoint = "/var/lib/postgresql";
          options = {
            mountpoint = "legacy";
            recordsize = "16k";
            compression = "lz4";
            "com.sun:auto-snapshot" = "true";
          };
        };
        etcd = {
          type = "zfs_fs";
          mountpoint = "/var/lib/etcd";
          options = {
            mountpoint = "legacy";
            recordsize = "16k";
            "com.sun:auto-snapshot" = "true";
          };
        };
        jfscache = {
          type = "zfs_fs";
          mountpoint = "/var/jfsCache";
          options = {
            mountpoint = "legacy";
            compression = "lz4";
            quota = "100G";
          };
        };
        nomad = {
          type = "zfs_fs";
          mountpoint = "/var/lib/nomad";
          options.mountpoint = "legacy";
        };
        containers = {
          type = "zfs_fs";
          mountpoint = "/var/lib/nixos-containers";
          options.mountpoint = "legacy";
        };
        # Loki's chunks, index and WAL (modules/logging-server.nix): plaintext log
        # lines, client data among them, so on the encrypted pool and nowhere else.
        # On every node, so the `metrics` tag can move without a disk change. The
        # quota keeps a flood of logs from filling the pool under everything else;
        # Loki's retention, not the quota, is what bounds it normally. No automatic
        # snapshots: one would keep lines past retention.
        loki = {
          type = "zfs_fs";
          mountpoint = "/var/lib/loki";
          options = {
            mountpoint = "legacy";
            quota = "50G";
            "com.sun:auto-snapshot" = "false";
          };
        };
        # Unmounted floor so the CoW pool never fills to the throughput cliff.
        reserved = {
          type = "zfs_fs";
          options = {
            mountpoint = "none";
            refreservation = "16G";
          };
        };
      };
    };
  };
}
