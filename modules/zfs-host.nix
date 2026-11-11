# modules/zfs-host.nix — universal ZFS host: policy + disk layout (all nodes).
#
# Every node is the same shape: dual NVMe (`nodes.<n>.disks`, by default
# nvme0n1/nvme1n1) → ESP on BOTH drives + a mirrored zpool `rpool` + a dedicated swap
# partition on each drive (lib/mk-disk-layout.nix), fronted by zswap below. Two
# layouts of that shape:
#
#   encrypted   every node unless it says otherwise: each leg of the mirror inside
#               LUKS, swap on a random key per boot. modules/boot-security-core.nix
#               does what booting it takes, including the bootloader settings.
#   plain       a node with `insecurePlaintextBoot`: raw zfs partitions, plain swap,
#               systemd-boot, with the second ESP kept in step by lib/esp-sync-hook.nix.
#
# Either way, per-dataset tuning:
#   root/nix        zstd, atime=off (Nix store compresses ~2x)
#   state           recordsize=16k, lz4, auto-snapshot — per-client DB dirs
#                   inherit InnoDB-page-sized records (write-amp fix);
#                   per-client child DATASETS (granular snapshots) come with
#                   the Phase-6b dataset-manager.
#   postgresql      recordsize=16k (PG pages are 8k — 16k trades slight
#                   amplification for compression; flip a heavy client to
#                   8k + full_page_writes=off only if measured)
#   etcd            recordsize=16k, fsync-heavy raft WAL
#   jfsCache        lz4, 100G quota — JuiceFS cache lives on the mirror
#   loki            50G quota, never snapshotted — Loki's store (logging-server.nix)
#   reserved        16G refreservation — CoW pools degrade when near-full
#
# Device naming: bare /dev/nvme{0,1}n1 by default (all nodes are dual-NVMe, and
# enumeration is stable on this hardware class). Hardware where it isn't sets
# `nodes.<n>.disks` to /dev/disk/by-id paths.
{
  config,
  lib,
  pkgs,
  node,
  ...
}:
let
  # The same test modules/boot-security.nix makes. The layout is chosen here, in
  # `config`, never in `imports`: see lib/mk-disk-layout.nix.
  encrypted = (node.insecurePlaintextBoot or null) == null;
in
{
  # ── ZFS policy ───────────────────────────────────────────────────────────────
  # Unique 8-hex-char machine id per node (from topology).
  networking.hostId = node.hostId;

  boot.supportedFilesystems = [ "zfs" ];
  boot.zfs.forceImportRoot = false;

  services.zfs = {
    autoScrub.enable = true; # weekly integrity pass over the mirror
    trim.enable = true;

    # Declared explicitly because clanCore/zfs.nix turns this on unconditionally
    # (it is NOT gated by clan.core.enableRecommendedDefaults), and an inherited
    # snapshot policy is the kind of thing that should be a decision rather than
    # a discovery. Stating it here also means `services.zfs.autoSnapshot.enable`
    # keeps its value if the clan input is ever dropped.
    #
    # This is wanted: the per-dataset `com.sun:auto-snapshot` properties below
    # were already set (false at the root, true on state/postgresql/etcd) but
    # nothing consumed them, so the intent recorded in this file's header was
    # never actually running. zfs-auto-snapshot honours those properties, so
    # only the three opted-in DB datasets are snapshotted.
    autoSnapshot = {
      enable = true;
      frequent = 4; # 4×15min — covers an "undo the last few minutes" mistake
      hourly = 24;
      daily = 7;
      weekly = 4;
      monthly = 1; # off-box retention is Phase 6's backup job, not snapshots
    };
  };

  # Cap ARC at 8GiB: leave the InnoDB buffer pools, PG shared_buffers and app
  # heap the rest of the RAM. ZFS would otherwise happily take half of it.
  boot.kernelParams = [
    "zfs.zfs_arc_max=8589934592"

    # ── zswap ──────────────────────────────────────────────────────────────
    # A RAM-resident compressed cache in front of the disk swap partitions
    # (lib/mk-disk-layout.nix): pages get compressed into it first and only
    # spill to disk once the pool is full, so the partitions are reached
    # under real pressure rather than on every swap-out. No swap-on-zvol
    # here — a swapfile on a zvol is deadlock-prone (the zvol's own write
    # path can need to allocate memory), which is why this used to be
    # zramSwap instead; a real partition avoids that without giving up
    # zswap's benefit over plain zram (see nixos-micro-desktop's
    # modules/system/storage.nix, where this same config is proven out).
    #
    # lz4 over the zstd default: cheap decompression matters more than
    # ratio when CPU is shared with Nomad workloads.
    #
    # zsmalloc is the only allocator left as of 6.10 (z3fold and zbud were
    # both removed) — named explicitly rather than left to whatever the
    # kernel still defaults to.
    "zswap.enabled=1"
    "zswap.compressor=lz4"
    "zswap.zpool=zsmalloc"
    "zswap.max_pool_percent=20"
    "zswap.shrinker_enabled=1"
  ];

  # zswap benefits from eager swapping: a page sent to swap lands in its
  # RAM-resident compressed pool first, which is nearly as cheap as not
  # swapping at all, and only spills to the disk swap partitions once that
  # pool fills. 100 favors swap over reclaim and avoids OOM before the pool
  # is exhausted (same reasoning as nixos-micro-desktop's memory.nix).
  boot.kernel.sysctl."vm.swappiness" = 100;

  # ── Bootloader ───────────────────────────────────────────────────────────────
  # Only the plain layout's. An encrypted node's comes from boot-security-core.nix.
  boot.loader = lib.mkMerge [
    (lib.mkIf (!encrypted) {
      systemd-boot.enable = true;
      efi.canTouchEfiVariables = true;
      # The 512M ESP fits ~8 kernel+initrd pairs (~59M each); cap entries so
      # kernel updates don't fill it.
      systemd-boot.configurationLimit = 5;
      # systemd-boot writes only the primary ESP; keep the second drive bootable.
      systemd-boot.extraInstallCommands = import ../lib/esp-sync-hook.nix { inherit pkgs; };
    })
    {
      # Unconditional. It defaults to true, and a key press at the boot menu then gives
      # anyone at the console root through init=/bin/sh.
      systemd-boot.editor = false;
    }
  ];

  # Not nix.gc: its --delete-older-than deletes the booted generation's link on a node that
  # has run for weeks without a reboot, and the next bootloader install then drops the one
  # entry known to boot. lib/generation-gc.nix keeps it.
  nix.gc.automatic = false;
  systemd.services.cluster-generation-gc = {
    description = "Collect old generations and garbage, keeping the booted and running ones";
    serviceConfig.Type = "oneshot";
    script = lib.getExe (import ../lib/generation-gc.nix { inherit pkgs; nix = config.nix.package; });
    startAt = "weekly";
  };
  systemd.timers.cluster-generation-gc.timerConfig.Persistent = true;

  # The layout lives in lib/mk-disk-layout.nix so tests/install-boot.nix and the boot
  # tests can install and boot it in a VM without dragging in the rest of a node. An
  # encrypted layout's passphrase path comes from the `luks` generator, which only a
  # node that has not opted out declares (modules/boot-security.nix).
  disko.devices =
    (import ../lib/mk-disk-layout.nix (
      {
        inherit lib encrypted;
        passwordFile = if encrypted then config.clan.core.vars.generators.luks.files.passphrase.path else null;
      }
      // lib.optionalAttrs (node ? disks) { devices = node.disks; }
    )).disko.devices;
}
