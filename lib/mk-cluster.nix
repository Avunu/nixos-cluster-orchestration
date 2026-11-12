# lib/mk-cluster.nix — `lib.mkCluster`: one site's clan, from this library's modules.
#
#   clan = inputs.cluster.lib.mkCluster {
#     inherit self inputs topology;
#     directory = ./.;
#     meta = { name = "my-cluster"; domain = "example.com"; };
#     recipients = [ "age1…" ];
#     admins = [ "ssh-ed25519 AAAA… me@laptop" ];
#     appsDir = ./apps;
#     hostsDir = ./hosts;
#   };
#   # clan.config.{nixosConfigurations,clanInternals,nixosModules}
#
# Returns what clan-core's `lib.clan` returns. See README.md "The interface".
#
# A node's disks are encrypted, and it boots through Secure Boot and unlocks from its TPM. A node
# that does not end up that way fails to evaluate (modules/boot-security.nix). The
# one opt-out is topology data, not an argument here:
#
#   topology.nodes.<n>.insecurePlaintextBoot = "<reason>";
#
# clan-core owns the machine registry and role assignment; this library keeps
# the orchestration layer (nspawn + Nomad + tunnels + JuiceFS), for which clan
# has no analogue.
#
# The topology remains the SINGLE SOURCE OF TRUTH. The inventory is a mechanical
# projection of it, not a second place to edit: clan's `inventory.machines`
# submodule has a FIXED schema with no freeform type, so it structurally cannot
# hold wanInterface / public6Prefix / appDhcpPoolOffset — those stay in topology,
# and lib/net.nix keeps deriving from topology rather than the inventory so the
# two cannot drift.
{
  lib,
  # This library's own flake inputs: clan-core, and the payload flakes the kinds
  # import (wordpress-nix, frappe-nix, odoo-nix).
  libraryInputs,
  clusterLib,
  clusterModules,
}:
{
  # The consumer's flake. clan reads `self.inputs.nixpkgs` for nixosSystem (with
  # clan-core's, so this library's, as the fallback): keep a consumer on the
  # tested revision with `inputs.nixpkgs.follows = "cluster/nixpkgs"`.
  self,
  # The consumer's flake inputs, which app files see as `inputs.<name>`. They win
  # over this library's own, so a consumer can bring its own frappe-nix; what it
  # does not set falls through to the library's.
  inputs ? { },
  # Where the site's clan state lives: vars/, secrets/, inventory.json.
  directory,
  topology,
  # { name; domain; }, handed to clan as `meta`.
  meta,
  # age public keys of the operators, who can decrypt every vars secret.
  recipients,
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
  hostModule =
    name:
    lib.optional (hostsDir != null && builtins.pathExists (hostsDir + "/${name}.nix")) (
      hostsDir + "/${name}.nix"
    );
in
libraryInputs.clan-core.lib.clan {
  inherit self directory meta;

  # Local clan services. `module.input = "self"` resolves against THIS option,
  # never against the consumer flake's `clan.modules` output: clan's `self`
  # option rewrites `inputs.self` to `{ clan = <clan config>; }`, so "self" means
  # "this clan", not "the flake it was called from". That is why a consumer does
  # not have to re-export the service.
  modules.cluster-roles = ../modules/cluster-roles.nix;

  # Plain `age` decryption, no sops-nix in the loop — see modules/vars.nix and
  # modules/nixpkgs-overlays.nix for why. Recipients are declared here rather
  # than via `clan secrets users add`: anyone listed can `clan vars generate` /
  # `clan machines update` for every machine (no per-machine override is
  # configured, so there is one fleet-wide admin list).
  vars.settings.secretStore = "age";
  vars.settings.recipients.default = recipients;

  # Clan-WIDE args only — these are node-independent. `node` and `nodeName` are
  # per-machine and CANNOT go here (specialArgs is shared by every machine, so it
  # would be wrong for all but one); they are injected per machine via
  # `_module.args` below.
  specialArgs = {
    inherit topology clusterLib;
    inputs = libraryInputs // inputs // { inherit self; };
    # What differs per site and is not topology. A separate attrset so modules
    # imported directly by tests need only the args they actually read.
    # modules/boot-security.nix reads `admins`, for the initrd's SSH keys.
    clusterSite = { inherit admins appsDir grafanaDashboards; };
  };

  inventory.machines = lib.mapAttrs (_name: node: {
    description = node.fqdn;
    deploy.targetHost = "root@${node.deployHost}";
    inherit (node) tags;
  }) topology.nodes;

  # Singleton roles, assigned by tag. This is what replaced the
  # `head (attrNames topology.nodes)` guard that used to appear in
  # modules/{nomad-bootstrap,storage-juicefs,monitoring}.nix — see
  # modules/cluster-roles.nix for why each role is a singleton.
  inventory.instances.cluster-roles = {
    module = {
      name = "cluster-roles";
      input = "self";
    };
    roles.juicefs-meta.tags = [ "juicefs-meta" ];
    roles.nomad-leader.tags = [ "nomad-leader" ];
    roles.metrics.tags = [ "metrics" ];
  };

  machines = lib.mapAttrs (
    name: node:
    { ... }:
    {
      _module.args = {
        inherit node;
        nodeName = name;
      };
      imports = clusterModules ++ hostModule name ++ extraModules;

      # clan's nixosSystem call passes no `system` argument (unlike the
      # lib.nixosSystem this replaced), so the platform must come from a module
      # or it falls back to builtins.currentSystem.
      nixpkgs.hostPlatform = "x86_64-linux";

      # Mandatory, not stylistic: clanCore's recommended defaults instantiate a
      # `99-ethernet-default-dhcp` networkd unit on a host where
      # modules/overlay-network.nix hand-writes every unit and
      # modules/cluster-common.nix sets useDHCP = false. checks.clan-coexist
      # asserts the result.
      clan.core.enableRecommendedDefaults = false;
      # stateVersion is fleet-wide topology data (modules/cluster-common.nix),
      # not a per-machine generated var.
      clan.core.settings.state-version.enable = false;

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
            inherit (libraryInputs) clan-core lanzaboote disko;
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
}
