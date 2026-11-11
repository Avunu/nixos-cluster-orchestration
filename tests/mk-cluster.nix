# Eval-level check of the consumer interface (lib/mk-cluster.nix), with mkCluster
# called the way a private flake calls it.
#
# `self` here exports NOTHING: no `clan.modules`, no nixosConfigurations. That is
# the point of the first check. If the local clan service were resolved through
# the calling flake's outputs rather than clan's `modules` option, a consumer
# would have to re-export it, and this eval would throw.
#
# The second half runs the template's own flake.nix `outputs` function, so the
# template cannot drift from the interface it documents. The template does not opt
# out of boot security, and must not evaluate until a site has done that work
# (modules/boot-security.nix): the wrapper below opts out only to check the rest, and
# the last check here proves the template's own refusal.
#
# Run: nix build .#checks.<system>.mk-cluster
{
  pkgs,
  lib,
  mkCluster,
  mkOpsIndex,
}:
let
  topology = import ./fixtures/topology.nix;

  privatePayload = pkgs.runCommand "private-marker" { } "touch $out";
  dashboards = pkgs.writeTextDir "custom.json" "{}";

  # What `inputs` looks like in a consumer flake.
  consumerInputs = {
    private-flake.marker = privatePayload;
    frappe-nix = {
      marker = "the consumer's frappe-nix";
    };
  };

  # An app file that fails to evaluate unless the consumer's input reached it.
  appsDir = ./fixtures/mk-cluster/apps;

  clan = mkCluster {
    self = {
      inputs = { };
      outPath = ./fixtures;
    };
    inputs = consumerInputs;
    directory = toString ./fixtures/mk-cluster; # see tests/fixtures/default.nix
    inherit topology appsDir;
    meta = {
      name = "consumer";
      domain = "example.org";
    };
    recipients = [ "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar" ];
    admins = [ "ssh-ed25519 AAAA-consumer-test-key" ];
    hostsDir = ./fixtures/mk-cluster/hosts;
    grafanaDashboards = dashboards;
    extraModules = [ { environment.etc."consumer-extra-module".text = "yes"; } ];
  };

  node1 = clan.config.nixosConfigurations.node1;
  node2 = clan.config.nixosConfigurations.node2;
  c = node1.config;
  args = node1._module.specialArgs;

  bare = mkCluster {
    self = {
      inputs = { };
      outPath = ./fixtures;
    };
    directory = toString ./fixtures/mk-cluster; # see tests/fixtures/default.nix
    inherit topology;
    meta.name = "bare";
    recipients = [ "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar" ];
    admins = [ "ssh-ed25519 AAAA-consumer-test-key" ];
  };

  # The template's own flake outputs, over a stand-in for the library input.
  mkTemplate = mkTemplateWith { };
  mkTemplateWith =
    {
      libraryNixpkgs ? "/nix/store/00000000000000000000000000000000-source",
    }:
    wrapTopology:
    (import ../templates/cluster/flake.nix).outputs {
      self = {
        inputs = { };
        outPath = ../templates/cluster;
      };
      nixpkgs = {
        outPath = "/nix/store/00000000000000000000000000000000-source";
        legacyPackages.x86_64-linux = pkgs;
      };
      cluster = {
        # Stand-ins: the template only re-exports these.
        checks.x86_64-linux = {
          boot-install = "the library's boot-install";
          boot-fallback = "the library's boot-fallback";
          boot-attack = "not re-exported";
        };
        inputs.nixpkgs.outPath = libraryNixpkgs;
        lib = {
          inherit mkOpsIndex;
          # The template's `directory = ./.` is its flake's root in real use, and a
          # path below this flake's root here (see tests/fixtures/default.nix).
          mkCluster =
            args:
            mkCluster (
              args
              // {
                directory = toString args.directory;
                topology = wrapTopology args.topology;
              }
            );
        };
        packages = { };
        devShells = { };
      };
    };
  template = mkTemplate (
    t:
    lib.recursiveUpdate t {
      nodes.node1.insecurePlaintextBoot = "mk-cluster test wrapper";
      insecureFleetKeysOnPlaintextDisk = "mk-cluster test wrapper";
      # The template ships REPLACE-ME, which modules/backup.nix refuses (see the last check).
      backup.repoSalt = "mk-cluster-test-wrapper-salt";
    }
  );
  templateNode = template.nixosConfigurations.node1;

  # As shipped. See the last check.
  shippedTemplateNode = (mkTemplate (t: t)).nixosConfigurations.node1;
  shippedFailedAssertions = map (a: a.message) (
    lib.filter (a: !a.assertion) shippedTemplateNode.config.assertions
  );

  checks = [
    {
      name = "module.input = self resolves with a self that exports no clan.modules";
      # The three roles of the local service, assigned by tag, are what put these here.
      ok =
        c.systemd.services ? juicefs-format
        && c.systemd.services ? nomad-bootstrap
        && c.services.prometheus.enable
        && !(node2.config.systemd.services ? juicefs-format);
    }
    {
      name = "meta reaches clan";
      ok = c.clan.core.settings.name == "consumer";
    }
    {
      name = "the age backend, with the consumer's recipients";
      ok = c.clan.core.vars.settings.secretStore == "age";
    }
    {
      name = "the consumer's directory holds its vars";
      ok = c.clan.core.settings.directory == toString ./fixtures/mk-cluster;
    }
    {
      name = "admins reach root and admin";
      ok =
        c.users.users.root.openssh.authorizedKeys.keys == [ "ssh-ed25519 AAAA-consumer-test-key" ]
        && c.users.users.admin.openssh.authorizedKeys.keys == [ "ssh-ed25519 AAAA-consumer-test-key" ];
    }
    {
      name = "inputs: a consumer input reaches app files, and `self` is the consumer's";
      ok =
        c.clusterApps.probe.resources.memoryMB == 256
        && args.inputs ? private-flake
        && args.inputs.self.outPath == ./fixtures;
    }
    {
      name = "inputs: the consumer's payload flake wins";
      ok = args.inputs.frappe-nix.marker or null == "the consumer's frappe-nix";
    }
    {
      name = "inputs: the library's payload flakes fill in what the consumer did not set";
      ok =
        args.inputs ? wordpress-nix
        && args.inputs ? odoo-nix
        && bare.config.nixosConfigurations.node1._module.specialArgs.inputs.frappe-nix ? nixosModules;
    }
    {
      name = "hostsDir: a node's file is imported, and a missing one is fine";
      ok =
        c.environment.etc ? "consumer-host-node1"
        && !(node2.config.environment.etc ? "consumer-host-node1");
    }
    {
      name = "extraModules reach every machine";
      ok =
        c.environment.etc ? "consumer-extra-module"
        && node2.config.environment.etc ? "consumer-extra-module";
    }
    {
      name = "grafanaDashboards overrides the default";
      ok = args.clusterSite.grafanaDashboards == dashboards;
    }
    {
      name = "with no appsDir or hostsDir the catalogue is empty and the node still evaluates";
      ok = bare.config.nixosConfigurations.node1.config.clusterApps == { };
    }
    {
      name = "the operations index reads the consumer's topology and apps";
      ok =
        let
          index = mkOpsIndex { inherit clan topology; };
        in
        index.leader == "node1" && index.flakeUrl == topology.deploy.flakeUrl && index.apps ? probe;
    }
    {
      name = "the template's flake evaluates, and enable = false leaves its example app out";
      ok = templateNode.config.clusterApps == { } && template ? clanInternals && template ? opsIndex;
    }
    # .github/workflows/merge-gate.yml builds these at the site's own lock (WS17).
    {
      name = "the template re-exports the library's boot-install and boot-fallback, and holds nixpkgs to the library's";
      ok =
        let
          checks = template.checks.x86_64-linux;
          diverged =
            ((mkTemplateWith { libraryNixpkgs = "/nix/store/11111111111111111111111111111111-source"; }) (t: t))
            .checks.x86_64-linux.nixpkgs-follows-library;
        in
        lib.attrNames checks == [
          "boot-fallback"
          "boot-install"
          "nixpkgs-follows-library"
        ]
        && checks.boot-install == "the library's boot-install"
        && checks.boot-fallback == "the library's boot-fallback"
        && checks.nixpkgs-follows-library.buildCommand == "touch $out"
        && lib.hasInfix "exit 1" diverged.buildCommand;
    }
    {
      name = "the template, without the wrapper's opt-out, fails closed and names the opt-out";
      ok =
        !(builtins.tryEval shippedTemplateNode.config.system.build.toplevel.drvPath).success
        && lib.any (lib.hasInfix "insecurePlaintextBoot") shippedFailedAssertions;
    }
    {
      name = "the template's placeholder backup salt is refused, and the wrapper's own salt is not";
      ok =
        lib.any (lib.hasInfix "topology.backup.repoSalt") shippedFailedAssertions
        && !lib.any (lib.hasInfix "topology.backup.repoSalt") (
          map (a: a.message) (lib.filter (a: !a.assertion) templateNode.config.assertions)
        );
    }
  ];

  failed = lib.filter (x: !x.ok) checks;
in
# Forcing the toplevels' drvPaths is what proves the clans evaluate through their
# assertions, which fire there. Discarding the context keeps this an eval-level
# check: nothing is built.
pkgs.runCommand "mk-cluster-checks"
  {
    toplevels = map builtins.unsafeDiscardStringContext [
      node1.config.system.build.toplevel.drvPath
      bare.config.nixosConfigurations.node1.config.system.build.toplevel.drvPath
      templateNode.config.system.build.toplevel.drvPath
    ];
  }
  (
    if failed == [ ] then
      ''
        echo "${toString (builtins.length checks)} mkCluster checks passed"
        touch $out
      ''
    else
      ''
        echo "FAILED:" >&2
        ${lib.concatMapStringsSep "\n" (x: ''echo "  - ${x.name}" >&2'') failed}
        exit 1
      ''
  )
