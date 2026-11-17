# VM test: a node installed the way `avc boot install` installs one, with nothing of that
# path replaced that a VM lets run.
#
#   operator  The operator's machine: avc (its `stage_node`, the function `avc boot stage`
#             is), nixos-install-helper's `deploy` app as mkProject builds it with a
#             pre-install hook, nixos-anywhere, age, and a site whose secrets are real
#             ciphertext under a master key (the fixture's: a file, where a site's is a
#             YubiKey). No TPM.
#   rescue    The machine as its provider hands it over: some Linux with sshd, two blank
#             disks, a TPM. Not the installer and not the node.
#   target    The same machine afterwards: the same disks, firmware variables and TPM,
#             booted from the disks.
#   installer A rescue boot of those disks on some other machine (tests/lib/boot-harness.nix).
#
# What runs is the real thing: `deploy` kexecs the rescue system into the NixOS installer,
# runs the hook, and then partitions and installs. The hook makes the node's age identity
# on the machine's TPM, writes the recipient and the encrypted identity file to the site,
# rekeys what the node reads, stages the identity file for the new root and decrypts the
# partitioning secrets into a tmpfs, from where nixos-anywhere sends them into the
# installer's memory. disko runs the layout's hooks there: a key that never leaves that
# memory formats each leg, enrolls a TPM slot bound to no PCR and adds the recovery key,
# and is removed.
#
# What a VM does not let run, and what stands in for it:
#
#   - `avc boot install` itself evaluates the site's flake (its preflight, and `nix run
#     .#install-<node>`), which a VM without a network cannot. The test starts the same
#     `deploy` app with the environment `avc boot install` gives it, and its hook calls
#     `stage_node` with the site's export given instead of evaluated
#     (tools/avc/tests/test_boot.py holds `install` to that environment and command).
#   - The system is built before the test, so it cannot hold what was rekeyed during it.
#     The one secret the node reads is rekeyed by the hook to the identity it has just
#     made, and reaches the node beside the identity file; on a site it is in the closure,
#     built after the hook (tests/secrets-tpm.nix is that half). The node's agenix is the
#     library's (modules/secrets.nix): its identity path, its age, its /run/secrets.
#   - The rescue system is NixOS, not a provider's Debian. nixos-anywhere's kexec is the
#     same from either.
#
# Run: nix build .#checks.x86_64-linux.install-node -L   (needs KVM)
{
  pkgs,
  lib,
  diskoModule,
  lanzabooteModule,
  secretsModule,
  # The library's nixos-install-helper input, and the nixpkgs flake it builds with.
  installHelper,
  nixpkgs,
  # The operations tool (lib/avc.nix).
  avc,
  mutant ? "",
  extraModule ? { },
}:
let
  harness = import ./lib/boot-harness.nix {
    inherit
      pkgs
      lib
      diskoModule
      lanzabooteModule
      ;
  };
  system = pkgs.stdenv.hostPlatform.system;
  fixture = import ./fixtures/agenix;
  canary = "CANARY-install-node";
  site = "/root/site";
  # Where this test's node reads the one secret it is given. See the header.
  rekeyedOnNode = "/var/lib/install-test/canary.age";

  # nixos-anywhere's installer, as a tarball it can be given instead of downloading one
  # (a site's install downloads nixos-images' release). Built here from nixos-images'
  # own modules, on this flake's nixpkgs, with one of them replaced: see
  # ./lib/kexec-restore-remote-access.nix.
  nixosImages = installHelper.inputs.nixos-anywhere.inputs.nixos-images;
  kexecInstaller = "${
    (pkgs.nixos [
      nixosImages.nixosModules.kexec-installer
      nixosImages.nixosModules.noninteractive
      {
        system.kexec-installer.name = "nixos-kexec-installer-noninteractive";
        disabledModules = [ "${nixosImages}/nix/restore-remote-access.nix" ];
        imports = [ ./lib/kexec-restore-remote-access.nix ];
      }
    ]).config.system.build.kexecInstallerTarball
  }/nixos-kexec-installer-noninteractive-${system}.tar.gz";

  # The site's `clusterSecrets`, as modules/secrets.nix exports it for a node that
  # declares these generators: what `avc boot stage` reads to know what to decrypt, and
  # where each file goes.
  exportFor =
    nodes:
    let
      file =
        rel: name: attrs:
        {
          secret = true;
          deploy = true;
          neededFor = "services";
          owner = "root";
          group = "root";
          mode = "0400";
          storedAs = "secrets/${rel}/${name}.age";
          path = "/run/secrets/${rel}/${name}";
        }
        // attrs;
      generator = share: name: files: {
        inherit share;
        dependencies = [ ];
        validationHash = null;
        validationStoredAs = "secrets/${rel share}/${name}/.validation-hash";
        prompts = { };
        files = lib.mapAttrs (n: a: file "${rel share}/${name}" n a) files;
      };
      rel = share: if share then "shared" else "per-machine/target";
      partitioning = path: {
        neededFor = "partitioning";
        inherit path;
      };
    in
    {
      target = {
        machine = "target";
        recipient = null;
        recipientStoredAs = "secrets/recipients/target.pub";
        identityStoredAs = "secrets/identities/target.age";
        inherit (nodes.target.cluster.secrets) identityPath;
        masterIdentities = [
          {
            identity = "/root/master-identity.txt";
            pubkey = fixture.masterPubkey;
          }
        ];
        extraRecipients = [ ];
        generators = {
          luks = generator false "luks" { passphrase = partitioning harness.passwordFile; };
          volume-identity = generator false "volume-identity" {
            secret = partitioning harness.identitySecretFile;
          };
          initrd-ssh = generator false "initrd-ssh" {
            ssh_host_ed25519_key = partitioning harness.hostKeyFile;
          };
          canary = generator true "canary" { value = { }; };
        };
      };
    };

  # The pre-install hook: `avc boot stage`, with the export given.
  stage =
    nodes:
    pkgs.writers.writePython3Bin "cluster-pre-install"
      {
        libraries = [ (pkgs.python3.pkgs.toPythonModule avc) ];
        flakeIgnore = [ "E501" ];
      }
      ''
        import json
        import os
        import shlex
        import shutil
        from pathlib import Path

        from avc.core.secretstore import Store
        from avc.flows import boot

        root = Path("${site}")
        export = json.loads(Path("${pkgs.writeText "install-node-export.json" (builtins.toJSON (exportFor nodes))}").read_text())
        store = Store(root, export)
        extra = Path(os.environ["IH_EXTRA_FILES"])
        installer = boot.Installer(
            os.environ["IH_TARGET"],
            shlex.split(os.environ[boot.INSTALL_SSH_ENV]),
            Path("/run/install-test-ssh"),
        )
        try:
            # No flake to evaluate here: the rekeyed files are the runner's own, which the
            # flake's `agenix rekey` would find already made (tests/secrets-tpm.nix).
            recipient = boot.stage_node(
                store, "target", installer, extra, Path(os.environ["IH_DISK_KEYS"]),
                rekey=store.fill_rekeyed,
            )
        finally:
            installer.close()
        # This test's own: the system was built before this identity existed, so what
        # was rekeyed to it travels beside it. On a site it is in the closure.
        (rekeyed,) = store.rekeyed_dir("target").rglob("*.age")
        there = extra / "${lib.removePrefix "/" rekeyedOnNode}"
        there.parent.mkdir(parents=True)
        shutil.copy(rekeyed, there)
        print(f"staged for {recipient}")
      '';

  project =
    nodes:
    installHelper.lib.mkProject {
      inherit nixpkgs system;
      # Never evaluated: the system is handed over built (IH_STORE_PATHS).
      self = {
        outPath = "${pkgs.emptyDirectory}";
      };
      installModules = [ ];
      hostAttr = "target";
      diskName = null;
      questionnaire = false;
      lifecycle = false;
      guided = false;
      preInstall = stage nodes;
    };
in
harness.mkTest {
  name = "install-node";
  inherit mutant extraModule;

  extraNodes.rescue =
    { lib, ... }:
    {
      virtualisation = {
        memorySize = 4096;
        cores = 2;
        vlans = [ 1 ];
        qemu.drives = harness.drives;
        tpm.enable = true;
      };
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        {
          address = harness.wan.address4;
          prefixLength = 24;
        }
      ];
      networking.firewall.enable = false;
      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [ harness.sshKeys.snakeOilEd25519PublicKey ];
      # kexec's tarball is unpacked in memory.
      boot.tmp.useTmpfs = false;
    };

  peerModule =
    { nodes, ... }:
    {
      virtualisation.memorySize = lib.mkForce 3072;
      virtualisation.cores = 2;
      # In the VM's Nix database, so that `nix copy` can send them to the installer.
      virtualisation.additionalPaths = [
        nodes.target.system.build.toplevel
        nodes.target.system.build.diskoScript
        pkgs.age
        pkgs.age-plugin-tpm
      ];
      nix.settings.experimental-features = [ "nix-command" ];
      nix.settings.substituters = lib.mkForce [ ];
      environment.systemPackages = [
        pkgs.age
        pkgs.age-plugin-tpm
        pkgs.jq
      ];
      environment.etc."install-test/kexec-installer.tar.gz".source = kexecInstaller;
    };

  targetModule =
    { config, ... }:
    {
      imports = [ secretsModule ];
      # The library's agenix, as on a node: this identity path, this age, /run/secrets.
      cluster.secrets = {
        directory = "${pkgs.emptyDirectory}";
        machine = "target";
        masterIdentities = [
          {
            identity = "/var/empty/install-node-master";
            pubkey = fixture.masterPubkey;
          }
        ];
      };
      age.secrets."shared/canary/value".file = rekeyedOnNode;
    };

  prelude = nodes: ''
    DEPLOY = "${(project nodes).apps.${system}.deploy.program}"
    KEXEC = "/etc/install-test/kexec-installer.tar.gz"
    AGE = "${pkgs.age}"
    AGE_PLUGIN_TPM = "${pkgs.age-plugin-tpm}"
    MASTER_IDENTITY = "${fixture.masterIdentity}"
    MASTER_PUB = "${fixture.masterPubkey}"
    SITE = "${site}"
    CANARY = "${canary}"
    CANARY_PATH = "${nodes.target.age.secrets."shared/canary/value".path}"
    NODE_IDENTITY_PATH = "${nodes.target.cluster.secrets.identityPath}"
    REKEYED_ON_NODE = "${rekeyedOnNode}"
  '';

  script = builtins.readFile ./install-node.py;
}
