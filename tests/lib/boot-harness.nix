# What the boot-* VM tests share: a target installed with the real disko script onto
# disks that live outside the VMs, an installer VM that does it, and a peer VM to
# reach the initrd from. Mechanics in tests/lib/boot-harness.py.
#
# Literal values only. The target imports modules/boot-security-core.nix directly, as
# the core is written to allow, which is also how it keeps specialisations
# modules/boot-security.nix would refuse on a real node. Every secret here is a
# throwaway that exists for these VMs and opens nothing else.
#
# The target boots through Lanzaboote with the keys the disko hook made. A fresh set of
# firmware variables is Setup Mode, so nothing is enforcing until a test enrolls them,
# and the signed boot chain is the same with or without that. Each leg is then bound to
# the target's TPM. The `peer` VM is where initrd SSH comes from, and where the audit
# receiver runs for the tests that check the boot report.
{
  pkgs,
  lib,
  diskoModule,
  lanzabooteModule,
}:
let
  passphrase = "boot-harness-luks-passphrase";
  emergencyPassword = "boot-harness-emergency-password";
  # printf %s "$emergencyPassword" | openssl passwd -6 -salt fixturesalt -stdin
  emergencyHash = "$6$fixturesalt$dg7TavERzcB8gSqfMGH8lCpnLIYTtnZNxGqE20eACOd865zrKEQpQosTjx3j3TVhrUVhHFf93mcQ6b00hOBrB1";
  identitySecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  # printf %s "$identitySecret" | sha256sum
  identityHash = "a8ae6e6ee929abea3afcfc5258c8ccd6f85273e0d4626d26c7279f3250f77c8e";

  # 73728 MiB as in tests/install-boot.nix: the layout's `reserved` refreservation needs
  # real room above the swap partition, and sparse images are nearly free.
  diskMiB = 73728;
  # What `devices` in lib/mk-disk-layout.nix gets, from the serials below.
  devices = {
    a = "/dev/disk/by-id/virtio-nvme-a";
    b = "/dev/disk/by-id/virtio-nvme-b";
  };
  # In the shell of QEMU's start script, so the Python side picks the disk set per boot.
  drives =
    map
      (letter: {
        name = letter;
        file = ''"$BOOT_DISKS"/${letter}.qcow2'';
        driveExtraOpts = {
          format = "qcow2";
          cache = "writeback";
          werror = "report";
          discard = "unmap";
        };
        deviceExtraOpts.serial = "nvme-${letter}";
      })
      [
        "a"
        "b"
      ];

  hostId = "f0000b00";

  # Where clan uploads partitioning secrets for a machine called target.
  partitioningSecret = gen: file: "/run/partitioning-secrets/per-machine/target/${gen}/${file}";
  passwordFile = partitioningSecret "luks" "passphrase";
  identitySecretFile = partitioningSecret "volume-identity" "secret";
  hostKeyFile = partitioningSecret "initrd-ssh" "ssh_host_ed25519_key";

  # The WAN NIC, on the one VLAN of the test network. eth0 is QEMU's user network.
  wan = {
    interface = "eth1";
    address4 = "192.0.2.10";
    gateway4 = "192.0.2.1";
  };

  sshKeys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  sshPort = 2222;

  # The audit trail's receiver: the real Worker (tests/lib/audit-stub.mjs) on the peer VM,
  # at the WAN gateway's address, and the target's token for it. Throwaway, as the rest.
  audit = {
    port = 8080;
    token = "boot-harness-audit-token";
    out = "/var/lib/audit-stub";
    # Stage 2's own address on the WAN NIC: the initrd's /32 is flushed at switch-root
    # (boot-fallback's flush-leaves-no-initrd-address), and this one is another.
    stage2Address = "192.0.2.20";
  };

in
{
  # The boot report and the audit trail, for the tests that check them (boot-install,
  # boot-fallback): the target reports each boot to the real Worker on the peer VM. Not
  # in the shared target, so the other boot tests stay as they are.
  audit = {
    inherit (audit) port out stage2Address;
    target =
      { pkgs, ... }:
      {
        imports = [ ../../modules/boot-report.nix ];
        cluster.audit = {
          enable = true;
          url = "http://${wan.gateway4}:${toString audit.port}/event";
          tokenFile = "${pkgs.writeText "boot-harness-audit-token" audit.token}";
          node = "target";
        };
        # Before the test framework's 40-eth1, which leaves the NIC without an address and
        # would otherwise win: the first file in sort order matching a link is the one used.
        systemd.network.networks."25-stage2-wan" = {
          matchConfig.Name = wan.interface;
          address = [ "${audit.stage2Address}/24" ];
          networkConfig.LinkLocalAddressing = "no";
        };
      };
    peer =
      { pkgs, ... }:
      {
        networking.firewall.interfaces.${wan.interface}.allowedTCPPorts = [ audit.port ];
        systemd.services.audit-stub = {
          description = "The off-host audit receiver: the real Worker, on files";
          wantedBy = [ "multi-user.target" ];
          environment = {
            WORKER = "${../../workers/cluster-watchdog}/src/index.js";
            PORT = toString audit.port;
            OUT = audit.out;
            AUDIT_TOKENS = builtins.toJSON {
              ${audit.token} = {
                sender = "target";
                kinds = [
                  "boot"
                  "deploy"
                  "ssh_login"
                  "canary"
                ];
              };
            };
          };
          serviceConfig.ExecStart = "${pkgs.nodejs_22}/bin/node ${./audit-stub.mjs}";
        };
      };
  };

  # testScript gets the helpers and these constants before its own text, and runs
  # main() through control.py's MutationProven handling.
  mkTest =
    {
      name,
      script,
      mutant ? "",
      extraModule ? { },
      targetModule ? { },
      # The mutant that leaves the keys unenrolled, so that nothing is enforcing.
      skipEnroll ? false,
      globalTimeout ? 3600,
      # What the target's seal tool is built from, for the mutant that takes a refusal out.
      sealEdit ? null,
      # More for the peer VM: the audit receiver (`audit.peer`), in the tests that use it.
      peerModule ? { },
    }:
    pkgs.testers.runNixOSTest {
      inherit name globalTimeout;
      # The script drives VMs from threads and reaches into the driver's machine objects.
      skipLint = true;
      skipTypeCheck = true;

      nodes.peer =
        { lib, ... }:
        {
          imports = [ peerModule ];
          virtualisation.memorySize = 768;
          virtualisation.vlans = [ 1 ];
          networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
            {
              address = wan.gateway4;
              prefixLength = 24;
            }
          ];
          environment.systemPackages = [ pkgs.openssh ];
        };

      nodes.installer =
        { nodes, ... }:
        {
          virtualisation.memorySize = 4096;
          virtualisation.cores = 2;
          virtualisation.qemu.drives = drives;
          # In the VM's Nix database, so nixos-install can copy it to the new root.
          virtualisation.additionalPaths = [
            nodes.target.system.build.toplevel
            nodes.target.system.build.diskoScript
          ];
          networking.hostId = hostId;
          boot.supportedFilesystems = [ "zfs" ];
          boot.zfs.forceImportRoot = false;
          nix.settings.substituters = lib.mkForce [ ];
          environment.systemPackages = [
            # What a person at a rescue system, or an attacker with the disks, would use.
            pkgs.binutils
            pkgs.cryptsetup
            pkgs.dosfstools
            pkgs.gptfdisk
            pkgs.jq
            pkgs.nixos-install-tools
            pkgs.openssh
            pkgs.sbsigntool
            pkgs.util-linux
            pkgs.zstd
          ];
          nix.settings.experimental-features = [ "nix-command" ];
        };

      nodes.target =
        { config, lib, ... }:
        {
          imports = [
            diskoModule
            lanzabooteModule
            ../../modules/boot-security-core.nix
            extraModule
            targetModule
          ];

          disko.devices =
            (import ../../lib/mk-disk-layout.nix {
              inherit lib devices passwordFile;
              encrypted = true;
            }).disko.devices;

          cluster.boot = {
            enable = true;
            identity.hash = identityHash;
            emergency.passwordHash = emergencyHash;
            ssh = {
              port = sshPort;
              authorizedKeys = [ sshKeys.snakeOilEd25519PublicKey ];
            };
            network = {
              inherit wan;
              kernelModules = [
                "virtio_net"
                "virtio_pci"
              ];
            };
            install = { inherit identitySecretFile hostKeyFile; };
            sealPackage = lib.mkIf (sealEdit != null) (
              lib.mkForce (
                config.system.build.sealPackageFor (
                  let
                    edited = sealEdit config.system.build.sealText;
                  in
                  # Fails loudly when the listing moves, rather than proving nothing.
                  assert edited != config.system.build.sealText;
                  edited
                )
              )
            );
          };

          # Test nodes leave this off unless they have a specialisation, and nixos-install
          # runs it to install the bootloader.
          system.switch.enable = true;

          boot.supportedFilesystems = [ "zfs" ];
          boot.zfs.forceImportRoot = false;
          networking.hostId = hostId;

          # A real boot of a real disk: firmware, ESP, initrd, no 9p store, no kernel
          # handed to QEMU. virtualisation.fileSystems is forced empty so the qemu-vm
          # module's mkVMOverride stands aside and disko's fileSystems are the ones used.
          virtualisation = {
            memorySize = 4096;
            cores = 2;
            vlans = [ 1 ];
            tpm.enable = true;
            directBoot.enable = false;
            mountHostNixStore = false;
            useDefaultFilesystems = false;
            useEFIBoot = true;
            diskImage = null;
            fileSystems = lib.mkForce { };
            sharedDirectories = lib.mkForce { };
            qemu.drives = drives;
          };
          # qemu-vm forces this false, and initrd SSH's host key is an initrd secret.
          boot.loader.supportsInitrdSecrets = lib.mkOverride 9 true;
          # The test framework's panic-on-fail hides emergency mode.
          boot.initrd.systemd.services.panic-on-fail.enable = lib.mkForce false;

          # The test backdoor needs networkd in stage 2. useDHCP stays off because the
          # default would add a DHCP network to the initrd as well.
          networking.useNetworkd = true;
          networking.useDHCP = false;
          networking.firewall.enable = false;

          environment.systemPackages = [
            # The test's own reading of the TPM, the LUKS headers and the keyring.
            pkgs.cryptsetup
            pkgs.dosfstools
            pkgs.gptfdisk
            pkgs.jq
            pkgs.keyutils
            pkgs.lvm2
            pkgs.sbsigntool
            pkgs.tpm2-tools
            pkgs.util-linux
          ];
        };

      testScript =
        { nodes, ... }:
        ''
          MUTANT = "${mutant}"
          SKIP_ENROLL = ${if skipEnroll then "True" else "False"}
          QEMU_IMG = "${pkgs.qemu_kvm}/bin/qemu-img"
          TOPLEVEL = "${nodes.target.system.build.toplevel}"
          DISKO = "${nodes.target.system.build.diskoScript}"
          DISK_MIB = ${toString diskMiB}
          PASSPHRASE = "${passphrase}"
          EMERGENCY_PASSWORD = "${emergencyPassword}"
          EMERGENCY_HASH = "${emergencyHash}"
          PASSWORD_FILE = "${passwordFile}"
          IDENTITY_SECRET = "${identitySecret}"
          IDENTITY_SECRET_FILE = "${identitySecretFile}"
          IDENTITY_PATH = "${nodes.target.cluster.boot.identity.path}"
          IDENTITY_HASH = "${identityHash}"
          HOST_KEY_FILE = "${hostKeyFile}"
          HOST_KEY_PATH = "${nodes.target.cluster.boot.ssh.hostKeyPath}"
          PKI_BUNDLE = "${nodes.target.cluster.boot.pkiBundle}"
          SSH_KEY = "${sshKeys.snakeOilEd25519PrivateKey}"
          SSH_PORT = ${toString sshPort}
          WAN_INTERFACE = "${wan.interface}"
          WAN_ADDRESS = "${wan.address4}"
          LUKS_DEVICES = ${builtins.toJSON (lib.mapAttrs (_: v: v.device) nodes.target.boot.initrd.luks.devices)}
          TPM2_PLUGINS = "${nodes.target.systemd.package}/lib/cryptsetup"
          VIRT_FW_VARS = "${pkgs.python3Packages.virt-firmware}/bin/virt-fw-vars"
          OPENSSL = "${pkgs.openssl}/bin/openssl"
          IOMMU_PARAMS = ${builtins.toJSON nodes.target.cluster.boot.iommuParams}
          ${builtins.readFile ./control.py}
          ${builtins.readFile ./boot-harness.py}
          ${script}

          run_main(main)
        '';
    };
}
