# lib/mk-cluster.nix — `lib.mkCluster`: one site's machines, from this library's modules.
#
#   site = inputs.cluster.lib.mkCluster {
#     inherit self inputs topology;
#     directory = ./.;
#     meta.name = "my-cluster";
#     masterIdentities = [ ./secrets/master/yubikey-1.pub ];
#     admins = [ "ssh-ed25519 AAAA… me@laptop" ];
#     appsDir = ./apps;
#     hostsDir = ./hosts;
#   };
#   # site.{nixosConfigurations,agenix-rekey,secrets,machineModules}
#
# See README.md "The interface".
#
# A node's disks are encrypted, and it boots through Secure Boot and unlocks from its TPM. A node
# that does not end up that way fails to evaluate (modules/boot-security.nix). The
# one opt-out is topology data, not an argument here:
#
#   topology.nodes.<n>.insecurePlaintextBoot = "<reason>";
#
# The topology is the SINGLE SOURCE OF TRUTH: one NixOS system per key of
# `topology.nodes`, and nothing here is a second place to list machines.
{
  lib,
  # This library's own flake inputs: nixpkgs, agenix, agenix-rekey, disko, and the
  # payload flakes the kinds import (wordpress-nix, frappe-nix, odoo-nix).
  libraryInputs,
  clusterLib,
  clusterModules,
}:
{
  # The consumer's flake. Its `inputs.nixpkgs` is what the machines are built from
  # (this library's, without one): keep a consumer on the tested revision with
  # `inputs.nixpkgs.follows = "cluster/nixpkgs"`. `agenix rekey` writes below it.
  self,
  # The consumer's flake inputs, which app files see as `inputs.<name>`. They win
  # over this library's own, so a consumer can bring its own frappe-nix; what it
  # does not set falls through to the library's.
  inputs ? { },
  # Where the site's secrets live (lib/secrets-layout.nix).
  directory,
  topology,
  # { name; }. The name signs alert emails and names the cache's signing key.
  meta,
  # The operators' age identities, as agenix-rekey's `age.rekey.masterIdentities`
  # takes them: every secret in the repository is encrypted to them, and `agenix
  # rekey` decrypts with one. A YubiKey's is the identity file age-plugin-yubikey
  # writes, which holds no private key and belongs in the repository.
  masterIdentities,
  # age recipients every secret is also encrypted to, and that nothing decrypts with
  # day to day: the offline one.
  extraRecipients ? [ ],
  # SSH public keys of the operators: root's and `admin`'s authorized_keys.
  admins,
  # One file per app (modules/apps.nix). null = no apps.
  appsDir ? null,
  # Per-machine `<name>.nix`, each optional. null = none.
  hostsDir ? null,
  # What the grafana kind provisions.
  grafanaDashboards ? ../configs/grafana-dashboards,
  # NixOS modules imported on every machine.
  extraModules ? [ ],
}:
let
  nixpkgs = self.inputs.nixpkgs or libraryInputs.nixpkgs;

  hostModule =
    name:
    lib.optional (hostsDir != null && builtins.pathExists (hostsDir + "/${name}.nix")) (
      hostsDir + "/${name}.nix"
    );

  # Site-wide args only. `node` and `nodeName` are per machine and CANNOT go here
  # (specialArgs is shared by every machine, so it would be wrong for all but one);
  # they are injected per machine via `_module.args` below.
  specialArgs = {
    inherit topology clusterLib;
    inputs = libraryInputs // inputs // { inherit self; };
    # What differs per site and is not topology. A separate attrset so modules
    # imported directly by tests need only the args they actually read.
    # modules/boot-security.nix reads `admins`, for the initrd's SSH keys.
    clusterSite = {
      inherit admins appsDir grafanaDashboards;
      inherit (meta) name;
    };
  };

  # A machine as a module, so a test can boot it with what a VM needs on top
  # (tests/lib/cluster-harness.nix). nixosConfigurations.<name> is this and nothing else.
  machineModules = lib.mapAttrs (
    name: node:
    { ... }:
    {
      _module.args = {
        inherit node;
        nodeName = name;
      };
      imports = clusterModules ++ hostModule name ++ extraModules;

      nixpkgs.hostPlatform = "x86_64-linux";

      cluster.secrets = {
        inherit directory masterIdentities;
        machine = name;
        extraEncryptionPubkeys = extraRecipients;
      };

      # The library-side half of the boot stack (modules/pull-deploy-core.nix, design D22):
      # the inputs this library's modules come from, as this site's lock resolved them,
      # and this library's own modules/ and lib/. The same on every node, and a bump of any
      # is a new boot stack, which a follower activates only after the canary has booted
      # it. modules/pull-deploy.nix adds nixpkgs and the kernel.
      #
      # Every value must be a pure function of the sources, the same on every evaluation
      # and on every Nix, or followers never match the canary's key and per-closure
      # approval, skip and the rollback denylist stop holding. So the inputs are named
      # by their lock's narHash, never by `outPath`: with lazy trees (Determinate Nix's
      # default) an input's outPath is a virtual store path that differs on every
      # evaluation, and with its context discarded nothing ever turns it into the real
      # one. checks.security-policy holds each value to the lock.
      #
      # modules/ and lib/ rather than the whole library: a bump that changes only the
      # README, the tests or avc changes nothing a node boots, and must not hold the fleet
      # for a canary reboot. It also keeps this flake's own VM checks cached across such
      # edits, which the whole source would not.
      cluster.deploy.bootStack =
        lib.mapAttrs
          (
            n: i:
            i.narHash
              or (throw "mkCluster: the library input ${n} has no narHash, so it cannot name a boot stack the same way on every node.")
          )
          {
            # agenix and agenix-rekey: what decrypts a node's secrets at every boot.
            inherit (libraryInputs)
              agenix
              agenix-rekey
              lanzaboote
              disko
              ;
          }
        // {
          # A copy into the store, so a content-addressed path, the same on every
          # evaluation (lazy or not). A plain string: it pulls nothing into the closure.
          library = builtins.unsafeDiscardStringContext (
            toString (
              builtins.path {
                name = "cluster-library-modules";
                path = ../.;
                filter =
                  let
                    root = toString ../.;
                    under = d: p: p == "${root}/${d}" || lib.hasPrefix "${root}/${d}/" p;
                  in
                  p: _: under "modules" p || under "lib" p;
              }
            )
          );
        };
    }
  ) topology.nodes;

  nixosConfigurations = lib.mapAttrs (
    _: module:
    nixpkgs.lib.nixosSystem {
      inherit specialArgs;
      modules = [ module ];
    }
  ) machineModules;
in
{
  inherit nixosConfigurations machineModules;

  # What `agenix rekey`, `edit` and `view` read: a site's flake exports it as its own
  # `agenix-rekey` output, and `nix run .#agenix -- rekey` (this library's
  # `packages.agenix`, which a site re-exports) finds it there.
  agenix-rekey = libraryInputs.agenix-rekey.configure {
    userFlake = self;
    inherit nixosConfigurations;
  };

  # Every machine's generators as data (modules/secrets.nix, `cluster.secrets.export`),
  # for the tool that runs them. A site's flake exports it as `clusterSecrets`.
  secrets = lib.mapAttrs (_: s: s.config.cluster.secrets.export) nixosConfigurations;
}
