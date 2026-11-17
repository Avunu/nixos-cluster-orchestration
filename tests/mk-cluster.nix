# Eval-level check of the consumer interface (lib/mk-cluster.nix), with mkCluster
# called the way a private flake calls it.
#
# `self` here exports NOTHING: mkCluster builds a consumer's machines from its
# arguments, never from the calling flake's outputs.
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

  site = mkCluster {
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
    masterIdentities = import ./fixtures/master-identities.nix;
    admins = [ "ssh-ed25519 AAAA-consumer-test-key" ];
    hostsDir = ./fixtures/mk-cluster/hosts;
    grafanaDashboards = dashboards;
    extraModules = [ { environment.etc."consumer-extra-module".text = "yes"; } ];
  };

  node1 = site.nixosConfigurations.node1;
  node2 = site.nixosConfigurations.node2;
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
    masterIdentities = import ./fixtures/master-identities.nix;
    admins = [ "ssh-ed25519 AAAA-consumer-test-key" ];
  };

  # A site with the cluster-ci Worker: its nodes read GitHub through it
  # (modules/github-access.nix).
  withWorker = mkCluster {
    self = {
      inputs = { };
      outPath = ./fixtures;
    };
    directory = toString ./fixtures/mk-cluster; # see tests/fixtures/default.nix
    topology = topology // {
      ci.url = "https://cluster-ci.example.org/";
    };
    meta.name = "with-worker";
    masterIdentities = import ./fixtures/master-identities.nix;
    admins = [ "ssh-ed25519 AAAA-consumer-test-key" ];
    extraModules = [ { cluster.github.repositories = [ "customer/private-addons" ]; } ];
  };
  w = withWorker.nixosConfigurations.node1.config;

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
      name = "every node runs the whole of it: no service is one tagged node's";
      ok =
        c.systemd.services ? juicefs-format
        && c.systemd.services ? nomad-bootstrap
        && c.services.prometheus.enable
        && node2.config.systemd.services ? juicefs-format
        && node2.config.services.haproxy.enable;
    }
    {
      name = "meta.name reaches the modules";
      ok = args.clusterSite.name == "consumer" && c.cluster.alerting.clusterName == "consumer";
    }
    {
      name = "the consumer's master identities are what agenix-rekey encrypts to";
      ok =
        map (i: i.pubkey) c.age.rekey.masterIdentities
        == map (i: i.pubkey) (import ./fixtures/master-identities.nix)
        && c.age.rekey.storageMode == "local";
    }
    {
      name = "the consumer's directory holds its secrets, each machine's under its own name";
      ok =
        c.cluster.secrets.directory == toString ./fixtures/mk-cluster
        && c.cluster.secrets.machine == "node1"
        && node2.config.cluster.secrets.machine == "node2"
        &&
          toString c.age.rekey.localStorageDir == toString ./fixtures/mk-cluster + "/secrets/rekeyed/node1";
    }
    {
      name = "mkCluster returns what a site's flake exports: the machines, agenix-rekey's apps, the generators";
      ok =
        site ? machineModules
        && site.agenix-rekey.x86_64-linux ? rekey
        && site.agenix-rekey.x86_64-linux ? edit-view
        && site.secrets.node1.generators ? nomad-tls
        &&
          site.secrets.node1.generators.nomad-tls.files."agent.key".storedAs
          == "secrets/per-machine/node1/nomad-tls/agent.key.age";
    }
    {
      # One installer per node, each nixos-install-helper's `deploy` for the site's own
      # system of that name, and nothing of the installer a cluster does not use.
      name = "mkCluster returns an installer per node: its deploy app, for the node's own system, with avc's step as its hook";
      ok =
        let
          apps = site.apps.x86_64-linux;
          installer = site.installers.node1;
          program = builtins.unsafeDiscardStringContext apps.install-node1.program;
          hook = installer.apps.x86_64-linux.deploy.program;
        in
        lib.attrNames apps == map (n: "install-${n}") (lib.attrNames topology.nodes)
        && lib.all (a: a.type == "app") (lib.attrValues apps)
        && lib.hasSuffix "/bin/deploy" program
        && hook == apps.install-node1.program
        # No ISO, no questionnaire: a node is installed over the network, from its topology.
        && !(installer.packages.x86_64-linux ? installerIso)
        && !(installer.packages.x86_64-linux ? guidedIso)
        && !(installer.apps.x86_64-linux ? configure)
        && installer.resolvedRoots == [ ]
        && installer.checks.x86_64-linux == { };
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
        && bare.nixosConfigurations.node1._module.specialArgs.inputs.frappe-nix ? nixosModules;
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
      ok = bare.nixosConfigurations.node1.config.clusterApps == { };
    }
    {
      name = "the operations index reads the consumer's topology and apps";
      ok =
        let
          index = mkOpsIndex { inherit site topology; };
        in
        index.reference == "node1" && index.flakeUrl == topology.deploy.flakeUrl && index.apps ? probe;
    }
    {
      name = "the template's flake evaluates, and enable = false leaves its example app out";
      ok =
        templateNode.config.clusterApps == { }
        && template ? agenix-rekey
        && template ? clusterSecrets
        && template ? opsIndex
        # `avc boot install node1` runs this.
        && template.apps.x86_64-linux ? install-node1;
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
          "github-repos"
          "nixpkgs-follows-library"
        ]
        && checks.boot-install == "the library's boot-install"
        && checks.boot-fallback == "the library's boot-fallback"
        && checks.nixpkgs-follows-library.buildCommand == "touch $out"
        && lib.hasInfix "exit 1" diverged.buildCommand;
    }
    # What the nodes may read at GitHub besides the lock's inputs (lib/github-repos.nix).
    {
      name = "github-repos.json is held to what the site fetches outside its lock: absent for nothing, refused when it differs";
      ok =
        let
          gh = (import ../lib { inherit lib; }).githubRepos;
          check =
            directory: repos:
            (gh.check {
              inherit pkgs directory repos;
            }).buildCommand;
          listed = pkgs.writeTextDir "github-repos.json" (builtins.toJSON [
            "customer/content"
            "acme/addons"
          ]);
        in
        site.githubRepos == [ ]
        && site.checks.x86_64-linux.github-repos.buildCommand == "touch $out"
        && template.checks.x86_64-linux.github-repos.buildCommand == "touch $out"
        && lib.hasInfix "avc ci repos" (check ./fixtures/mk-cluster [ "customer/content" ])
        && lib.hasInfix "exit 1" (check ./fixtures/mk-cluster [ "customer/content" ])
        # Order is not part of it; one name more or less is.
        && check listed [
          "acme/addons"
          "customer/content"
        ] == "touch $out"
        && lib.hasInfix "exit 1" (check listed [ "acme/addons" ])
        && lib.hasInfix "exit 1" (check listed [
          "acme/addons"
          "customer/content"
          "customer/more"
        ]);
    }
    {
      name = "with ci.url a node asks the Worker for its GitHub tokens: on a timer and before each pull, never as part of boot";
      ok =
        let
          svc = w.systemd.services.cluster-github-token;
          timer = w.systemd.timers.cluster-github-token;
          up = w.systemd.services.cluster-upgrade;
          helper = (lib.head w.programs.git.config).credential."https://github.com";
        in
        w.cluster.github.enable
        && svc.environment.GITHUB_ACCESS_URL == "https://cluster-ci.example.org/agent/token"
        && svc.serviceConfig.LoadCredential == [ "token:/run/secrets/per-machine/node1/ci/token" ]
        # A oneshot nothing at boot waits for, and that systemd never holds a start job
        # of: no Restart=, and a bound on how long one run may take.
        && svc.serviceConfig.Type == "oneshot"
        && !(svc.serviceConfig ? Restart)
        && svc.serviceConfig ? TimeoutStartSec
        && svc.wantedBy == [ ]
        && svc.requiredBy == [ ]
        && timer.wantedBy == [ "timers.target" ]
        # Wanted, so a Worker that is away does not stop a pull; after, so the pull
        # reads what the refresh wrote.
        && lib.elem "cluster-github-token.service" up.wants
        && lib.elem "cluster-github-token.service" up.after
        && !(lib.elem "cluster-github-token.service" (up.requires or [ ]))
        && lib.hasInfix "!include /run/cluster-github/nix.conf" w.nix.extraOptions
        && helper.useHttpPath
        && lib.hasSuffix " credential" helper.helper
        && withWorker.githubRepos == [ "customer/private-addons" ]
        && (mkOpsIndex {
          site = withWorker;
          inherit topology;
        }).githubRepos == [ "customer/private-addons" ];
    }
    {
      name = "the App's key is the operators' and the Worker's: no node is given it, and no node holds a GitHub token of its own";
      ok =
        let
          gens = w.cluster.secrets.generators;
          app = gens.github-app.files;
        in
        !app.private-key.deploy
        && !app.webhook-secret.deploy
        && !app.app-id.secret
        && !(lib.any (f: f.generator == "github-app") w.cluster.secrets.deployed)
        && !(gens ? github-token)
        && !(c.cluster.secrets.generators ? github-token)
        && !(w.nix.settings ? netrc-file)
        && !(lib.any (lib.hasInfix "netrc") w.systemd.tmpfiles.rules);
    }
    {
      name = "without ci.url a node has no tokens and nothing that asks for them: public repositories only";
      ok =
        !c.cluster.github.enable
        && !(c.systemd.services ? cluster-github-token)
        && !(c.systemd.timers ? cluster-github-token)
        && !(lib.hasInfix "!include" c.nix.extraOptions)
        && !(c.nix.settings ? netrc-file)
        && !(c.cluster.secrets.generators ? github-app)
        && !(lib.elem "cluster-github-token.service" c.systemd.services.cluster-upgrade.wants);
    }
    {
      name = "a github.com URL is its repository, over https, ssh or git's scp form, and nothing else is";
      ok =
        let
          inherit ((import ../lib { inherit lib; }).githubRepos) repoOf;
        in
        repoOf "https://github.com/acme/shop.git" == "acme/shop"
        && repoOf "https://github.com/Acme/shop" == "Acme/shop"
        && repoOf "git+https://github.com/acme/shop.git?ref=main&submodules=1" == "acme/shop"
        && repoOf "ssh://git@github.com/acme/shop.git" == "acme/shop"
        && repoOf "git@github.com:acme/shop.git" == "acme/shop"
        && repoOf "https://git.example.net/demo/site.git" == null
        && repoOf "https://github.com.example.net/acme/shop.git" == null
        && repoOf "https://example.net/github.com/acme/shop" == null
        && repoOf "https://github.com/acme" == null
        && repoOf "" == null;
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
# Forcing the toplevels' drvPaths is what proves the sites evaluate through their
# assertions, which fire there. Discarding the context keeps this an eval-level
# check: nothing is built.
pkgs.runCommand "mk-cluster-checks"
  {
    toplevels = map builtins.unsafeDiscardStringContext [
      node1.config.system.build.toplevel.drvPath
      bare.nixosConfigurations.node1.config.system.build.toplevel.drvPath
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
