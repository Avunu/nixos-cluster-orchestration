# Install-and-BOOT test for the universal disk layout (lib/disk-layout.nix).
#
# This exists because node1 was bricked by a config that installed perfectly and
# then panicked on the first boot:
#
#   no filesystem could mount root, tried:
#   Kernel panic - not syncing: VFS: Unable to mount root fs on "" or unknown-block(0,0)
#
# Every check we had passed, because every check we had was an EVALUATION check.
# A layout that partitions cleanly and produces an unbootable system is
# invisible until you reboot a remote machine that has no console — so this test
# does the only thing that actually proves it: partition with the real disko
# config, install a system, REBOOT, and require the machine to come back.
#
# disko's makeDiskoTest rewrites `disk.<n>.device` to the VM's /dev/vdX, so the
# hardcoded /dev/nvme{0,1}n1 in the layout is not a problem here. What is
# preserved — and what is actually under test — is the shape: TWO ESPs, a
# mirrored rpool, `mountpoint = legacy` on every dataset, and systemd-boot.
{
  pkgs,
  lib,
  diskoSrc,
  espMounts ? [
    "/boot"
    "/boot-fallback"
  ],
}:
let
  # disko's test harness picks how to stage its test key by reading
  # boot.initrd.systemd.enable, which nixpkgs removed with the scripted
  # initrd -- reading it now fails evaluation. A systemd initrd is the only
  # kind left, so answer it as true, in the one place that asks: the `config`
  # its installed-system module is handed. Patching disko's source instead would
  # be import-from-derivation, which `nix flake check --no-build` cannot
  # evaluate. Drop once disko stops reading it.
  answerInitrd =
    config:
    config
    // {
      boot = config.boot // {
        initrd = config.boot.initrd // {
          systemd = config.boot.initrd.systemd // {
            enable = true;
          };
        };
      };
    };
  withInitrdAnswer =
    m:
    if lib.isFunction m then
      lib.setFunctionArgs (args: m (args // { config = answerInitrd args.config; })) (lib.functionArgs m)
    else
      m;
  evalConfig = import "${pkgs.path}/nixos/lib/eval-config.nix";
  # The hook the nodes run (modules/zfs-host.nix), as a boot-time install runs it and
  # as a command, so the subtests below can call it with one ESP missing.
  espSyncHook = import ../lib/esp-sync-hook.nix { inherit pkgs; };
  espSyncCommand = pkgs.writeShellScriptBin "esp-sync-hook" espSyncHook;
  diskoLib = pkgs.callPackage "${diskoSrc}/lib/tests.nix" {
    inherit lib;
    makeTest = import "${pkgs.path}/nixos/tests/make-test-python.nix";
    eval-config = args: evalConfig (args // { modules = map withInitrdAnswer args.modules; });
    # qemu-common.nix takes { lib, stdenv }, and tests.nix calls this as
    # `qemu-common-lib pkgs`, so route it through callPackage.
    qemu-common-lib = p: p.callPackage "${p.path}/nixos/lib/qemu-common.nix" { };
  };
in
diskoLib.makeDiskoTest {
  inherit pkgs;
  name = "install-boot";
  disko-config = ../lib/disk-layout.nix;

  # UEFI, because that is how the real nodes boot and because systemd-boot is
  # EFI-only: on a legacy-BIOS machine it installs "successfully" and leaves
  # nothing bootable, which is one of the shapes the node1 failure could have had.
  efi = true;

  # ZFS needs a hostId before the pool can be imported, and the installed system
  # is built by makeDiskoTest rather than from our nixosConfigurations — so the
  # bits of modules/zfs-host.nix that make the pool importable have to be
  # restated for the test system.
  extraSystemConfig = {
    networking.hostId = "f0000001";
    boot.supportedFilesystems = [ "zfs" ];
    boot.zfs.forceImportRoot = false;
    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;
    # The real nodes rsync ESP #1 onto ESP #2 after every bootloader install so
    # the second NVMe stays bootable. Exercised here so a broken hook fails the
    # test rather than a datacentre.
    boot.loader.systemd-boot.extraInstallCommands = espSyncHook;
    environment.systemPackages = [ espSyncCommand ];
  };

  extraInstallerConfig = {
    networking.hostId = "f0000001";
    boot.supportedFilesystems = [ "zfs" ];

    # disko's harness hardcodes 4 GB per disk, which cannot hold the layout's
    # 16 GB `reserved` refreservation — `zfs create rpool/reserved` fails with
    # "out of space" before the install even starts. 40960 (40G) was sized to
    # leave real room above that floor; the extra 32768 (32G) here is exactly
    # the swap partition lib/disk-layout.nix now carves out of each disk, so
    # the zfs partition — and its margin above the reserved floor — is
    # unchanged from before swap existed. The images are sparse qcow2, so
    # this is nearly free.
    #
    # mkForce because `virtualisation.emptyDiskImages` is a list option: a plain
    # definition would CONCATENATE with the harness's, giving four small disks
    # instead of two large ones.
    virtualisation.emptyDiskImages = lib.mkForce [
      73728
      73728
    ];
  };

  # makeDiskoTest already asserts the machine boots; these assert it booted the
  # way we intended rather than merely surviving.
  extraTestScript = ''
    machine.succeed("test -e /dev/disk/by-label/* || true")

    with subtest("root is the ZFS dataset, not a fallback"):
        root = machine.succeed("findmnt -no SOURCE /").strip()
        assert root == "rpool/root", f"root is {root!r}, expected 'rpool/root'"

    with subtest("the pool really is a mirror"):
        status = machine.succeed("zpool status rpool")
        assert "mirror" in status, f"rpool is not mirrored:\n{status}"

    with subtest("every declared dataset is mounted"):
        for mp in ["/nix", "/state", "/var/lib/postgresql", "/var/lib/etcd",
                   "/var/jfsCache", "/var/lib/nomad", "/var/lib/nixos-containers",
                   "/var/lib/loki"]:
            machine.succeed(f"mountpoint -q {mp}")

    with subtest("BOTH ESPs are populated and bootable"):
        # The failure this guards: systemd-boot writes only the primary ESP, so
        # without the rsync hook the second NVMe is an empty FAT partition and
        # the machine is unbootable the moment disk 1 dies.
        for esp in ${builtins.toJSON espMounts}:
            machine.succeed(f"mountpoint -q {esp}")
            machine.succeed(f"test -f {esp}/EFI/systemd/systemd-bootx64.efi")
            machine.succeed(f"test -d {esp}/loader/entries")
            machine.succeed(f"ls {esp}/loader/entries/*.conf >/dev/null")

    with subtest("the ESP hook copies when both ESPs are mounted"):
        machine.succeed("touch /boot/esp-sync-marker")
        machine.succeed("esp-sync-hook")
        machine.succeed("test -f /boot-fallback/esp-sync-marker")
        machine.succeed("rm /boot/esp-sync-marker")
        machine.succeed("esp-sync-hook")
        machine.fail("test -e /boot-fallback/esp-sync-marker")

    with subtest("the ESP hook does not erase the survivor when /boot is not mounted"):
        # What the guard is for: rsync --delete from an empty /boot.
        machine.succeed("umount /boot")
        out = machine.succeed("esp-sync-hook 2>&1")
        assert "WARN" in out, f"no warning with /boot unmounted:\n{out}"
        machine.succeed("test -f /boot-fallback/EFI/systemd/systemd-bootx64.efi")
        machine.succeed("ls /boot-fallback/loader/entries/*.conf >/dev/null")
        machine.succeed("mount /boot")

    with subtest("the ESP hook writes nothing to root when /boot-fallback is not mounted"):
        machine.succeed("umount /boot-fallback")
        out = machine.succeed("esp-sync-hook 2>&1")
        assert "WARN" in out, f"no warning with /boot-fallback unmounted:\n{out}"
        machine.succeed("test -z \"$(ls -A /boot-fallback)\"")
        machine.succeed("mount /boot-fallback")

    with subtest("the boot entry names a kernel AND an initrd"):
        # A generated entry missing `initrd` boots a kernel with no ZFS driver,
        # which is exactly the VFS panic we are testing for.
        entry = machine.succeed("cat /boot/loader/entries/*.conf")
        assert "linux " in entry, f"no kernel in boot entry:\n{entry}"
        assert "initrd " in entry, f"NO INITRD in boot entry:\n{entry}"

    with subtest("the reserved floor exists and is unmounted"):
        machine.succeed("zfs list rpool/reserved")
        machine.fail("mountpoint -q /rpool/reserved")

    with subtest("both dedicated swap partitions are active with equal priority"):
        # Equal priority is what makes the kernel interleave writes across
        # both NVMes instead of draining one before the other; a typo that
        # dropped priority from one partition would silently pass a bare
        # "is swap on" check.
        swapon_out = machine.succeed("swapon --show=NAME,PRIO --noheadings")
        lines = [l.split() for l in swapon_out.strip().splitlines()]
        assert len(lines) == 2, f"expected 2 swap devices, got:\n{swapon_out}"
        priorities = {p for _, p in lines}
        assert priorities == {"100"}, f"expected both partitions at priority 100:\n{swapon_out}"
  '';
}
