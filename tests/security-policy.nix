# Eval-level check of the boot security posture (modules/boot-security.nix) and its
# one opt-out, with mkCluster called the way a private flake calls it.
#
# A refusal only proves something if the same node, without that one change, is not
# refused for that reason. So every subtest compares against a baseline that
# satisfies the posture, and matches the message of the assertion it expects:
# "evaluation failed" alone could mean anything, and a misspelt option or a stale
# fixture would pass.
#
# Memory. Nearly every subtest below is its own evaluation of a clan and a NixOS system,
# about 250 MB each, and evaluating this file used to peak at 19 GB because they stayed
# reachable until the end. The evaluator frees a system once nothing refers to it, so
# the rule here is that nothing does once its subtests have run:
#   - `compact` keeps only a passing subtest's name, not the thunks that could still
#     read the system it looked at.
#   - A system shared by several subtests belongs to those subtests, through `sharing` or
#     a `let` around them, not to the top-level `let`, which lives until the end. Only
#     `baseline` is up there, because every refusal reads it.
#   - A list of subtests is not bound to a name, for the same reason.
#   - The `map` around `checks`: see the comment there.
#   - Reaching a toplevel costs far more than reading assertions: 4.5 GB allocated for a
#     fixture node with its apps' containers, against 250 MB. So the three fixture
#     toplevels are a check of their own, tests/security-policy-fixture.nix, and `baseline`
#     is never asked for one: its subtest evaluates the same node again.
# Run: nix build .#checks.<system>.security-policy
{
  pkgs,
  lib,
  mkCluster,
  mkOpsIndex,
  # The fixture site over another topology (tests/fixtures).
  mkFixtureCluster,
  fixtureCluster,
  fixtureTopology,
  # This library's flake inputs the boot stack names (clan-core, lanzaboote, disko,
  # nixpkgs), to hold each stack value to the lock.
  libraryInputs,
}:
let
  # ── the secure fixture ────────────────────────────────────────────────────
  mkSecure = import ./fixtures/secure {
    inherit mkCluster;
    self = {
      inputs = { };
      outPath = ./fixtures/secure;
    };
  };
  secureTopology = import ./fixtures/secure/topology.nix;

  # A consumer's node1, with these modules imported the way a host file is.
  secureNode =
    {
      topology ? secureTopology,
      modules ? [ ],
    }:
    (mkSecure {
      inherit topology;
      extraModules = modules;
    }).config.nixosConfigurations.node1;

  # ── the baseline ──────────────────────────────────────────────────────────
  # The secure fixture with nothing added: the core is complete, so this is what
  # modules/boot-security-core.nix produces, and every refusal below compares against it.
  # (Until WS4 a stand-in set what the core didn't yet. It is gone, and the final subtest is
  # the proof that nothing needed it.)
  plainLayout = (import ../lib/disk-layout.nix { inherit lib; }).disko.devices;
  encryptedLayout =
    (import ../lib/mk-disk-layout.nix {
      inherit lib;
      encrypted = true;
      passwordFile = "/run/partitioning-secrets/passphrase";
    }).disko.devices;

  # What a consumer's host file would do, against that baseline.
  secureWith = modules: secureNode { inherit modules; };

  baseline = secureWith [ ];

  # ── reading a node ────────────────────────────────────────────────────────
  failedMessages = system: map (a: a.message) (lib.filter (a: !a.assertion) system.config.assertions);
  fails = system: needle: lib.any (lib.hasInfix needle) (failedMessages system);
  evaluates = system: (builtins.tryEval system.config.system.build.toplevel.drvPath).success;

  # The change under test, and only it, makes this assertion fail, and the node then
  # does not evaluate.
  refuses = name: system: needle: {
    name = "refused: ${name}";
    ok = !fails baseline needle && fails system needle && !evaluates system;
    detail = failedMessages system;
  };

  # Several refusals of one node, each [ name needle ]. A node with several fields wrong
  # is one evaluation instead of several.
  sharing = system: map (c: refuses (builtins.elemAt c 0) system (builtins.elemAt c 1));

  # See "Memory" at the top: what is left of a subtest once it has run.
  compact =
    c:
    let
      name = c.name;
    in
    builtins.seq name (
      if c.ok then
        {
          inherit name;
          ok = true;
        }
      else
        {
          inherit name;
          ok = false;
          detail = c.detail;
        }
    );

  bootGenerators = [
    "luks"
    "volume-identity"
    "initrd-ssh"
    "emergency-access"
  ];

  templateTopology = import ../templates/cluster/topology.nix;

  # ── the opted-out fixture ─────────────────────────────────────────────────
  fixtureNodes = lib.attrNames fixtureTopology.nodes;
  fixtureNode = name: fixtureCluster.config.nixosConfigurations.${name};

  optedOutWith =
    reason:
    secureNode {
      topology = lib.recursiveUpdate secureTopology {
        nodes.node1.insecurePlaintextBoot = reason;
      };
    };

  # ── topology refusals ─────────────────────────────────────────────────────
  # Each value here is wrong in a way some subtest below names.
  withTopology =
    topology:
    secureNode {
      inherit topology;
    };

  # ── raw_exec's uid gap ────────────────────────────────────────────────────
  # The deny list leaves uid 4096 and everything above 65535. The first sweep reads
  # every account a shipped configuration has, whatever the assertion says; the
  # second proves a host file cannot add one.
  uidGap =
    system:
    lib.filter (u: u.uid != null && (u.uid >= 65536 || (u.uid == 4096 && u.name != "nomad-apps"))) (
      lib.attrValues system.config.users.users
    );
  uidNeedle = "raw_exec's denied_host_uids";

  # ── Nomad's bootstrap_expect ──────────────────────────────────────────────
  # What a node's server block must be: a server exactly when tagged nomad-server, and
  # then expecting every voter the topology has. Counted here from the tags, not with
  # lib/net.nix, so a wrong helper can't agree with itself.
  voterNames =
    topology:
    lib.filter (n: lib.elem "nomad-server" (topology.nodes.${n}.tags or [ ])) (
      lib.attrNames topology.nodes
    );
  serverBlockWant =
    topology: name:
    if lib.elem name (voterNames topology) then
      {
        enabled = true;
        expect = lib.length (voterNames topology);
      }
    else
      {
        enabled = false;
        expect = null;
      };
  serverBlockHave =
    system:
    let
      s = system.config.services.nomad.settings.server or { };
    in
    {
      enabled = s.enabled or false;
      expect = s.bootstrap_expect or null;
    };
  expectNeedle = "Nomad server block must be the topology's";
  etcdNeedle = "node(s) are tagged `etcd`";

  # ── partitioning secrets ──────────────────────────────────────────────────
  # clan uploads these only at install, and the pull loop never does, so each one is
  # a decision. New ones must be added here on purpose.
  partitioningSecrets =
    system:
    lib.sort lib.lessThan (
      lib.concatMap (
        g:
        lib.mapAttrsToList (fn: _: "${g.name}/${fn}") (
          lib.filterAttrs (_: f: f.neededFor == "partitioning") g.files
        )
      ) (lib.attrValues system.config.clan.core.vars.generators)
    );

  # ── the positive case ─────────────────────────────────────────────────────
  # The secure fixture with nothing added must evaluate. Flipped in WS4, when the core
  # became what satisfies the posture. While false, the subtest required the
  # failure, so it could not be forgotten.
  securePositiveEnabled = true;

  # The outer map is not a no-op. RAN, Determinate Nix 2.35.3: the same subtests and the
  # same result peak at 11.4 GB without it and 4.9 GB with it, and the GC's statistics show
  # the systems staying live until `failed` has finished. Why a wrapper changes that is
  # not established, so measure before you tidy this.
  checks = map (x: x) (
    map compact (
      lib.concatLists [
        # ── the staged rollout (design D22, modules/pull-deploy.nix) ─────────────
        (
          let
            stackKeys = [
              "clan-core"
              "disko"
              "kernel"
              "lanzaboote"
              "library"
              "nixpkgs"
            ];
            canaryOf = n: (fixtureNode n).config.cluster.deploy.canary;
            # node2 made real, so the site has two nodes.
            twoNodes = lib.recursiveUpdate secureTopology { nodes.node2.provisioned = true; };
            withoutCanary = lib.recursiveUpdate twoNodes { nodes.node1.canary = false; };
          in
          [
            {
              name = "the fixture's canary is node1, the others follow it, all on the /mnt/jfs mount";
              ok =
                map (n: (canaryOf n).role) fixtureNodes == [
                  "canary"
                  "follower"
                  "follower"
                ]
                && lib.all (
                  n:
                  (canaryOf n).markerMount == "/mnt/jfs"
                  && (canaryOf n).markerDir == "/mnt/jfs/.cluster-deploy/canary-booted"
                ) fixtureNodes
                # Opted out, so there is no unlock to prove; with boot security there is.
                && !(canaryOf "node1").requireCleanUnlock
                && baseline.config.cluster.deploy.canary.role == "canary"
                && baseline.config.cluster.deploy.canary.requireCleanUnlock
                && baseline.config.cluster.deploy.canary.requireReport
                && baseline.config.systemd.timers ? cluster-deploy-canary-publish
                && !((fixtureNode "node2").config.systemd.services ? cluster-deploy-canary-publish);
              detail = map canaryOf fixtureNodes;
            }
            {
              name = "every fixture node renders one boot stack, naming its sources by the lock and holding no store reference";
              ok =
                let
                  stacks = map (n: (fixtureNode n).config.cluster.deploy.bootStack) fixtureNodes;
                  first = builtins.head stacks;
                  c = (fixtureNode "node1").config;
                  # The real, content-addressed store path of a source. Under lazy trees
                  # an input's outPath is a virtual path that differs per evaluation; this
                  # is the path its narHash names, the same on every evaluation.
                  stored =
                    p:
                    builtins.unsafeDiscardStringContext (
                      toString (
                        builtins.path {
                          path = p;
                          name = "source";
                        }
                      )
                    );
                in
                lib.all (x: x == first) stacks
                && lib.attrNames first == stackKeys
                # The library inputs by the lock's narHash, never by outPath: an outPath
                # with its context discarded is, under lazy trees, a path that exists in
                # no store and changes on every evaluation, so no follower would ever
                # match the canary's key.
                && lib.all (n: first.${n} == libraryInputs.${n}.narHash && lib.hasPrefix "sha256-" first.${n}) [
                  "clan-core"
                  "disko"
                  "lanzaboote"
                ]
                # nixpkgs (the fixture's is the library's) by the store path the lock names.
                && first.nixpkgs == stored libraryInputs.nixpkgs.outPath
                && first.nixpkgs == stored pkgs.path
                && first.kernel == toString c.boot.kernelPackages.kernel
                && lib.hasSuffix "-cluster-library-modules" first.library
                && lib.all (v: lib.hasPrefix builtins.storeDir v) [
                  first.nixpkgs
                  first.kernel
                  first.library
                ]
                && lib.all (v: !builtins.hasContext v) (lib.attrValues first)
                # The secure node shares it: boot security changes no source.
                && baseline.config.cluster.deploy.bootStack == first;
              detail = map (n: (fixtureNode n).config.cluster.deploy.bootStack) fixtureNodes;
            }
            (refuses "two canaries" (withTopology (
              lib.recursiveUpdate twoNodes { nodes.node2.canary = true; }
            )) "at most one node may set canary = true")
            (refuses "a placeholder as the canary" (withTopology (
              lib.recursiveUpdate secureTopology {
                nodes.node1.canary = false;
                nodes.node2.canary = true;
              }
            )) "is a placeholder (provisioned = false)")
            (refuses "a site of two nodes without a canary" (withTopology withoutCanary) "needs a canary")
            (refuses "a site of two nodes without a canary, and a blank reason" (withTopology (
              withoutCanary
              // {
                deploy = withoutCanary.deploy // {
                  withoutCanary = " ";
                };
              }
            )) "needs a canary")
            (refuses "withoutCanary beside a canary" (withTopology (
              lib.recursiveUpdate twoNodes { deploy.withoutCanary = "both"; }
            )) "only on a site with no canary node")
            (refuses "an opted-out canary while another node has boot security" (withTopology (
              lib.recursiveUpdate twoNodes {
                nodes.node1.canary = false;
                nodes.node2.canary = true;
              }
            )) "opted out of boot security (insecurePlaintextBoot) while other nodes did not")
            {
              name = "a site of two nodes may go without a canary, with a reason, and then nothing waits";
              ok =
                let
                  system = withTopology (lib.recursiveUpdate withoutCanary { deploy.withoutCanary = "lab"; });
                in
                !fails system "needs a canary"
                && !fails system "deploy.withoutCanary"
                && system.config.cluster.deploy.canary.role == "none";
              detail = [ ];
            }
          ]
        )

        # ── the template fails closed ───────────────────────────────────────────
        (
          let
            template =
              ((import ../templates/cluster/flake.nix).outputs {
                self = {
                  inputs = { };
                  outPath = ../templates/cluster;
                };
                cluster = {
                  lib = {
                    inherit mkOpsIndex;
                    # See tests/mk-cluster.nix on `directory`.
                    mkCluster = args: mkCluster (args // { directory = toString args.directory; });
                  };
                  packages = { };
                  devShells = { };
                };
              }).nixosConfigurations.node1;
          in
          [
            {
              name = "the template, as shipped, does not evaluate";
              ok = !evaluates template;
              detail = [ ];
            }
            {
              name = "the template's failed assertions name the opt-out";
              ok = fails template "insecurePlaintextBoot";
              detail = failedMessages template;
            }
            {
              name = "the template tags no etcd, and is not refused for it";
              ok =
                lib.all (n: !lib.elem "etcd" (n.tags or [ ])) (lib.attrValues templateTopology.nodes)
                && !fails template etcdNeedle;
              detail = failedMessages template;
            }
            {
              name = "the template's failure says to generate vars, which nothing else can say";
              ok = fails template "clan vars generate node1";
              detail = failedMessages template;
            }

            {
              name = "the template's failure names the way out, and it did not need a plain layout";
              ok =
                lib.any (lib.hasInfix "insecurePlaintextBoot") (failedMessages template)
                && !lib.any (lib.hasInfix "disko.devices has") (failedMessages template)
                && template.config.disko.devices.disk.nvme0.content.partitions.luks.content.type == "luks";
              detail = failedMessages template;
            }
            # The reason these are assertions rather than throws. `clan vars generate` evaluates
            # the machine to discover its generators, before any of their values exist, and a
            # throw on this path would stop a new site from ever generating them.
            {
              name = "a new site can still discover and build its boot generators";
              ok = lib.all (
                g:
                let
                  generator = template.config.clan.core.vars.generators.${g};
                in
                (builtins.tryEval generator.finalScript.drvPath).success
                && lib.all (f: !f.exists) (lib.filter (f: !f.secret) (lib.attrValues generator.files))
              ) bootGenerators;
              detail = [ ];
            }

            # What `clan vars generate` reads of every generator before it runs any (its
            # `clan select` of share, dependencies, prompts and validationHash, and of each
            # file's secret, deploy, owner, group, mode and neededFor). Nothing in a system
            # build forces these, so a generator whose `validation` clan's type refuses (a
            # list, WS16) evaluated everywhere here and failed only on a real site's S0.
            {
              name = "clan vars generate can read every generator of a new site";
              ok =
                let
                  gens = template.config.clan.core.vars.generators;
                  readable =
                    g:
                    (builtins.tryEval (
                      builtins.deepSeq [
                        gens.${g}.share
                        gens.${g}.dependencies
                        gens.${g}.prompts
                        gens.${g}.validationHash
                        (lib.mapAttrsToList (_: f: [
                          f.secret
                          f.deploy
                          f.owner
                          f.group
                          f.mode
                          f.neededFor
                        ]) gens.${g}.files)
                      ] true
                    )).success;
                in
                lib.all readable (lib.attrNames gens) && gens ? nomad-login && gens ? nomad-tls;
              detail =
                let
                  gens = template.config.clan.core.vars.generators;
                in
                lib.filter (g: !(builtins.tryEval (builtins.deepSeq gens.${g}.validationHash true)).success) (
                  lib.attrNames gens
                );
            }

            # ── raw_exec's uid gap, part one ────────────────────────────────────────
            # Here because it reads the template too.
            {
              name = "no account in any shipped configuration falls in raw_exec's uid gap";
              ok = lib.all (s: uidGap s == [ ]) (
                map fixtureNode fixtureNodes
                ++ [
                  template
                  baseline
                ]
              );
              detail = map (u: u.name) (
                lib.concatMap uidGap (
                  map fixtureNode fixtureNodes
                  ++ [
                    template
                    baseline
                  ]
                )
              );
            }
            # What the gap is measured against: the deny list as shipped, the one account
            # it leaves, and no group list (any denied_host_gids with 0 in it denies every
            # task, modules/cluster-common.nix). The assertion above only means something
            # if these hold.
            {
              name = "every shipped configuration denies raw_exec every uid to 65535 but nomad-apps' 4096";
              ok = lib.all (
                s:
                let
                  c = s.config.services.nomad.settings;
                  rawExec = c.plugin.raw_exec.config;
                in
                rawExec.denied_host_uids == "0-4095,4097-65535"
                && !(rawExec ? denied_host_gids)
                && c.client.options."driver.allowlist" == "raw_exec"
                && s.config.users.users.nomad-apps.uid == 4096
                && s.config.users.groups.nomad-apps.gid == 4096
                && !s.config.users.users.nomad-apps.isNormalUser
              ) (map fixtureNode fixtureNodes ++ [ template ]);
              detail = map (
                s:
                let
                  c = s.config.services.nomad.settings;
                in
                {
                  raw_exec = c.plugin.raw_exec.config;
                  allowlist = c.client.options."driver.allowlist" or null;
                  uid = s.config.users.users.nomad-apps.uid or null;
                }
              ) (map fixtureNode fixtureNodes ++ [ template ]);
            }

            # ── bootstrap_expect, on what a new site starts from ────────────────────
            {
              name = "the template's node1 expects exactly the template's voters";
              ok = serverBlockHave template == serverBlockWant templateTopology "node1";
              detail = [
                (serverBlockHave template)
                (serverBlockWant templateTopology "node1")
              ];
            }
          ]
        )

        # ── Nomad's bootstrap_expect (design WS10) ────────────────────────────────
        # A fresh server whose expect is below the voters it can see elects itself and
        # accepts a second `acl bootstrap` (`trap-two-expect-1-diverge` in
        # checks.voter-growth). So expect is the voter count, the same on every node of a
        # topology, and nothing else: then two servers expecting 1 can't come from one
        # topology. Every node of three topologies: the fixture (one voter), the
        # single-voter site of checks.voter-growth (node2 absent, node3 an installed
        # worker), and three voters.
        (
          let
            voter = {
              provisioned = true;
              tags = [
                "worker"
                "nomad-server"
                "etcd"
              ];
            };
            sites = {
              fixture = fixtureTopology;
              single-voter-and-worker = fixtureTopology // {
                nodes = removeAttrs fixtureTopology.nodes [ "node2" ] // {
                  node1 = fixtureTopology.nodes.node1 // {
                    tags = lib.remove "etcd" fixtureTopology.nodes.node1.tags;
                  };
                  node3 = fixtureTopology.nodes.node3 // {
                    provisioned = true;
                  };
                };
              };
              three-voters = lib.recursiveUpdate fixtureTopology {
                nodes.node2 = voter;
                nodes.node3 = voter;
              };
            };
            rows = lib.concatLists (
              lib.mapAttrsToList (
                site: topology:
                let
                  clan = if site == "fixture" then fixtureCluster else mkFixtureCluster topology;
                in
                map (name: {
                  inherit site name;
                  have = serverBlockHave clan.config.nixosConfigurations.${name};
                  want = serverBlockWant topology name;
                }) (lib.attrNames topology.nodes)
              ) sites
            );
            # A host file on a worker making it a server that expects only itself: the trap,
            # made by hand.
            workerAsServer = (fixtureNode "node2").extendModules {
              modules = [
                {
                  services.nomad.settings.server = {
                    enabled = true;
                    bootstrap_expect = 1;
                  };
                }
              ];
            };
          in
          [
            {
              name = "bootstrap_expect is the voter count on every node, and only voters are servers";
              ok =
                lib.all (r: r.have == r.want) rows
                # The comparison covers both sides: one voter and three, servers and workers.
                && lib.any (r: r.want.expect == 1) rows
                && lib.any (r: r.want.expect == 3) rows
                && lib.any (r: !r.want.enabled) rows
                && lib.length rows == 8;
              detail = rows;
            }
            (refuses "a host file setting bootstrap_expect to anything but the voter count" (secureWith [
              { services.nomad.settings.server.bootstrap_expect = lib.mkForce 3; }
            ]) expectNeedle)
            {
              name = "refused: a host file making a worker a server that expects 1";
              ok =
                !fails (fixtureNode "node2") expectNeedle
                && fails workerAsServer expectNeedle
                && !evaluates workerAsServer;
              detail = failedMessages workerAsServer;
            }
          ]
        )

        # ── Nomad's reload triggers (review fix after WS10) ───────────────────────
        # A reissued agent certificate reaches the running agent through SIGHUP, which
        # the unit's X-Reload-Triggers sends on a switch (modules/cluster-common.nix).
        # Only their presence was checked (control-plane-attack), and the CA's hash alone
        # keeps a line there. So: exactly the three ciphertexts' hashes, computed here
        # from the files, not by the module's helper. The fixture's placeholders are all
        # the same text, which can't tell the three apart, so the same node also reads a
        # site directory whose three files differ (tests/fixtures/reload-triggers).
        (
          let
            hashes =
              dir:
              map (builtins.hashFile "sha256") [
                (dir + "/secrets/clan-vars/per-machine/node1/nomad-tls/agent.crt/agent.crt.age")
                (dir + "/secrets/clan-vars/per-machine/node1/nomad-tls/agent.key/agent.key.age")
                (dir + "/secrets/clan-vars/shared/nomad-ca/ca.crt/ca.crt.age")
              ];
            triggers = system: system.config.systemd.services.nomad.reloadTriggers;
            distinct = (fixtureNode "node1").extendModules {
              modules = [ { clan.core.settings.directory = lib.mkForce ./fixtures/reload-triggers; } ];
            };
          in
          [
            {
              name = "Nomad reloads when its agent certificate, its key or the CA is reissued";
              ok =
                triggers (fixtureNode "node1") == hashes ./fixtures
                && triggers distinct == hashes ./fixtures/reload-triggers
                && lib.length (lib.unique (hashes ./fixtures/reload-triggers)) == 3;
              detail = [
                { fixture = triggers (fixtureNode "node1"); }
                { distinct = triggers distinct; }
                { want = hashes ./fixtures/reload-triggers; }
              ];
            }
          ]
        )

        # ── etcd's member count (review fix after WS10) ───────────────────────────
        # etcd has no member add: it is created once from the tags, and a one-member etcd
        # tagged two more nodes later becomes two clusters (modules/storage-etcd.nix). So
        # the tags carry no etcd, or an odd number from 3; one only under the fixtures'
        # `insecureSingleMemberEtcd`. The table runs the module alone over each count
        # (cheap); the two refusals after it run the real site.
        (
          let
            clusterLib = import ../lib { inherit lib; };
            # A fourth and fifth node, for the counts the fixture's three can't make.
            extraNode =
              i:
              fixtureTopology.nodes.node3
              // {
                index = i;
                hostName = "node${toString i}";
              };
            withEtcdOn =
              names: override:
              let
                base = removeAttrs fixtureTopology [ "insecureSingleMemberEtcd" ];
                all = fixtureTopology.nodes // {
                  node4 = extraNode 4;
                  node5 = extraNode 5;
                };
              in
              base
              // lib.optionalAttrs (override != null) { insecureSingleMemberEtcd = override; }
              // {
                nodes = lib.mapAttrs (
                  n: v:
                  v
                  // {
                    tags = lib.remove "etcd" (v.tags or [ ]) ++ lib.optional (lib.elem n names) "etcd";
                  }
                ) all;
              };
            # modules/storage-etcd.nix's assertions on one node, with nothing else evaluated.
            assertionsOn =
              topology: nodeName:
              (lib.evalModules {
                modules = [
                  ../modules/storage-etcd.nix
                  {
                    options = {
                      assertions = lib.mkOption {
                        type = lib.types.listOf lib.types.unspecified;
                        default = [ ];
                      };
                      services.etcd = lib.mkOption {
                        type = lib.types.anything;
                        default = { };
                      };
                      systemd.services = lib.mkOption {
                        type = lib.types.lazyAttrsOf lib.types.anything;
                        default = { };
                      };
                    };
                    config._module.args = {
                      inherit topology nodeName clusterLib;
                      node = topology.nodes.${nodeName};
                    };
                  }
                ];
              }).config.assertions;
            refusedOn =
              topology: nodeName:
              lib.any (a: !a.assertion && lib.hasInfix etcdNeedle a.message) (assertionsOn topology nodeName);
            # [ members override want-refused ], each asked of a tagged node and of node5,
            # which carries etcd only in the five-member row.
            table = [
              [
                [ ]
                null
                false
              ]
              [
                [ "node1" ]
                null
                true
              ]
              [
                [ "node1" ]
                "fixture: a test"
                false
              ]
              [
                [ "node1" ]
                ""
                true
              ]
              [
                [
                  "node1"
                  "node2"
                ]
                null
                true
              ]
              [
                [
                  "node1"
                  "node2"
                ]
                "fixture: a test"
                true
              ]
              [
                [
                  "node1"
                  "node2"
                  "node3"
                ]
                null
                false
              ]
              [
                [
                  "node1"
                  "node2"
                  "node3"
                  "node4"
                ]
                null
                true
              ]
              [
                [
                  "node1"
                  "node2"
                  "node3"
                  "node4"
                  "node5"
                ]
                null
                false
              ]
            ];
            rows = map (
              r:
              let
                names = builtins.elemAt r 0;
                topology = withEtcdOn names (builtins.elemAt r 1);
                want = builtins.elemAt r 2;
              in
              {
                inherit names want;
                override = builtins.elemAt r 1;
                have = map (refusedOn topology) [
                  "node1"
                  "node5"
                ];
              }
            ) table;
            twoMembers = withTopology (
              lib.recursiveUpdate secureTopology {
                nodes.node2.tags = fixtureTopology.nodes.node2.tags ++ [ "etcd" ];
              }
            );
          in
          [
            {
              name = "etcd: no member, or an odd number from 3; one only under the fixtures' override";
              ok =
                lib.all (
                  r:
                  r.have == [
                    r.want
                    r.want
                  ]
                ) rows
                && lib.length rows == 9;
              detail = rows;
            }
            (refuses "a site with one etcd member and no insecureSingleMemberEtcd" (withTopology (
              removeAttrs secureTopology [ "insecureSingleMemberEtcd" ]
            )) etcdNeedle)
            (refuses "a second etcd member added to a one-member site, even under the override" twoMembers
              etcdNeedle
            )
            {
              name = "the fixture's single etcd is the override's, and nothing else in it is refused for etcd";
              ok =
                fixtureTopology.insecureSingleMemberEtcd or null != null
                && lib.all (n: !fails (fixtureNode n) etcdNeedle) fixtureNodes;
              detail = map (n: failedMessages (fixtureNode n)) fixtureNodes;
            }
          ]
        )

        (
          let
            # A site that has generated nothing. The core reads the hash it does not have, and
            # has to ask first: see haveEmergencyHash there and the emergencyAccess assertion
            # in modules/boot-security.nix.
            noVars =
              (mkCluster {
                self = {
                  inputs = { };
                  outPath = ./fixtures/secure;
                };
                directory = toString ./fixtures/mk-cluster;
                topology = secureTopology;
                meta.name = "no-vars";
                recipients = [ "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar" ];
                admins = import ./fixtures/admins.nix;
              }).config.nixosConfigurations.node1;
          in
          [
            {
              name = "a site with no vars is told so, not given a missing-option error";
              ok = fails noVars "clan vars generate node1" && !evaluates noVars;
              detail = failedMessages noVars;
            }
          ]
        )

        # ── the opt-out ─────────────────────────────────────────────────────────
        [
          # "The opted-out fixture evaluates on every node" is tests/security-policy-fixture.nix.
          {
            name = "the opted-out fixture warns, naming the node and the reason";
            ok = lib.all (
              n:
              lib.any (
                w: lib.hasInfix "node ${n} " w && lib.hasInfix fixtureTopology.nodes.${n}.insecurePlaintextBoot w
              ) (fixtureNode n).config.warnings
            ) fixtureNodes;
            detail = (fixtureNode "node1").config.warnings;
          }
          {
            name = "an opted-out node has no boot security and declares none of its generators";
            ok =
              let
                c = (fixtureNode "node1").config;
              in
              !c.cluster.boot.enable
              && !c.boot.lanzaboote.enable
              && lib.all (g: !(c.clan.core.vars.generators ? ${g})) bootGenerators;
            detail = [ ];
          }
          # The required mounts as well: a new dataset halts any node at its next boot,
          # opted out or not.
          {
            name = "an opted-out node's boot contract says so, lists its required mounts, and nothing else";
            ok = lib.all (
              n:
              let
                c = (fixtureNode n).config;
                contract = c.cluster.deploy.bootContract;
              in
              lib.attrNames contract == [
                "insecurePlaintextBoot"
                "requiredMounts"
              ]
              && contract.insecurePlaintextBoot
              && lib.any (lib.hasPrefix "/ ") contract.requiredMounts
              && lib.any (
                m: lib.hasPrefix "/var/lib/loki " m && lib.hasSuffix "/loki zfs" m
              ) contract.requiredMounts
            ) fixtureNodes;
            detail = (fixtureNode "node1").config.cluster.deploy.bootContract;
          }

          # Loki's store is on every node, and only the metrics node's Loki applies its
          # retention: the others age out what a former Loki left, at the same retention.
          {
            name = "a node without Loki ages out a retired Loki store at the log retention";
            ok =
              let
                hasLoki = n: (fixtureNode n).config.services.loki.enable;
                sweep = n: (fixtureNode n).config.systemd.services.loki-retired-store or null;
                withLoki = lib.filter hasLoki fixtureNodes;
                without = lib.filter (n: !hasLoki n) fixtureNodes;
              in
              fixtureTopology.logging.retention == "720h"
              && withLoki != [ ]
              && without != [ ]
              && lib.all (n: sweep n == null || !(sweep n).enable) withLoki
              && lib.all (
                n:
                sweep n != null
                && (sweep n).enable
                && lib.hasInfix "-mmin +43200 " (sweep n).script
                && (fixtureNode n).config.systemd.timers.loki-retired-store.enable
              ) without;
            detail = [ ];
          }

          # ── what every node gets from the safety net ────────────────────────────
          {
            name = "every node's boot menu editor is off, whatever else it opted out of";
            ok = lib.all (n: !(fixtureNode n).config.boot.loader.systemd-boot.editor) fixtureNodes;
            detail = [ ];
          }
          {
            name = "an opted-out node syncs its second ESP through the guarded hook";
            ok = lib.all (
              n:
              let
                hook = (fixtureNode n).config.boot.loader.systemd-boot.extraInstallCommands;
              in
              lib.hasInfix "mountpoint -q /boot " hook
              && lib.hasInfix "mountpoint -q /boot-fallback" hook
              && lib.hasInfix "rsync -a --delete /boot/ /boot-fallback/" hook
            ) fixtureNodes;
            detail = [ ];
          }
          {
            name = "every node runs the watchdog settings tests/deploy-safety.nix proves";
            ok = lib.all (
              n:
              lib.filterAttrs (
                name: _: name == "RuntimeWatchdogSec" || name == "RebootWatchdogSec"
              ) (fixtureNode n).config.systemd.settings.Manager == import ../lib/watchdog-settings.nix
            ) fixtureNodes;
            detail = [ ];
          }
          {
            name = "every node's deploy builds its own attribute of the site's flake, with --refresh";
            ok = lib.all (
              n:
              let
                c = (fixtureNode n).config;
              in
              lib.hasPrefix "nix build --refresh --no-link --print-out-paths " c.cluster.deploy.targetCommand
              && lib.hasInfix "${fixtureTopology.deploy.flakeUrl}#nixosConfigurations.${c.networking.hostName}.config.system.build.toplevel" c.cluster.deploy.targetCommand
            ) fixtureNodes;
            detail = [ ];
          }
          # "Every node's closure carries its boot contract" is tests/security-policy-fixture.nix.
          # Everything an unlock depends on, each from where the initrd reads it. Whether
          # the contract moves when they do, and stays when the kernel does, is
          # checks.boot-closure's job.
          {
            name = "a secure node's boot contract is what an unlock depends on, and no more";
            ok =
              let
                c = baseline.config;
                node = secureTopology.nodes.node1;
                contract = c.cluster.deploy.bootContract;
              in
              contract == {
                # Every mount without nofail, as "mountpoint device fsType", sorted.
                requiredMounts = lib.sort lib.lessThan (
                  lib.mapAttrsToList (_: fs: "${fs.mountPoint} ${toString fs.device} ${fs.fsType}") (
                    lib.filterAttrs (
                      _: fs: !(lib.elem "nofail" fs.options) && !(lib.elem "noauto" fs.options)
                    ) c.fileSystems
                  )
                );
                luksDevices = lib.mapAttrs (_: d: d.device) c.boot.initrd.luks.devices;
                # Each leg's crypttab options, written out: the layout's, with the TPM last.
                unlock = {
                  tpm2 = true;
                  crypttabExtraOpts = lib.genAttrs [ "crypt-a" "crypt-b" ] (_: [
                    "tries=0"
                    "nofail"
                    "x-systemd.device-timeout=30s"
                    "tpm2-device=auto"
                  ]);
                };
                identityHash = c.clan.core.vars.generators.volume-identity.files.hash.value;
                identityPath = "/var/lib/volume-identity/secret";
                hostKeyPath = "/var/lib/initrd-ssh/ssh_host_ed25519_key";
                espMounts = [
                  "/boot"
                  "/boot-fallback"
                ];
                initrdSshPort = 2222;
                wan = {
                  interface = node.wanInterface;
                  address4 = node.publicIp4;
                  gateway4 = node.publicGw4;
                };
                initrdKernelModules = node.initrdNicModules;
                authorizedKeysSha256 = builtins.hashString "sha256" (
                  lib.concatStringsSep "\n" (lib.sort lib.lessThan (import ./fixtures/admins.nix))
                );
              }
              &&
                lib.attrNames contract.luksDevices == [
                  "crypt-a"
                  "crypt-b"
                ]
              # Keys don't belong in a closure's text.
              && !lib.hasInfix "ssh-" (builtins.toJSON contract);
            detail = [ ];
          }

          {
            name = "the opt-out needs a reason: an empty one is refused";
            ok = fails (optedOutWith "") "insecurePlaintextBoot must be a non-empty string";
            detail = failedMessages (optedOutWith "");
          }
          {
            name = "the opt-out needs a reason: blank is not one";
            ok = fails (optedOutWith "  ") "insecurePlaintextBoot must be a non-empty string";
            detail = failedMessages (optedOutWith "  ");
          }
          {
            name = "the opt-out needs a reason: true is not one";
            ok = fails (optedOutWith true) "insecurePlaintextBoot must be a non-empty string";
            detail = failedMessages (optedOutWith true);
          }
          # The opt-out's second reason. Every node holds the fleet's shared keys, so one
          # opted-out node's disk reads every client's data: the site says so, or the
          # node does not evaluate. The fixture's acknowledgement is what lets
          # optedOutWith pass the cases above for their own reasons only.
          {
            name = "an opted-out node needs the site's fleet-keys acknowledgement";
            ok =
              let
                needle = "an opted-out node exposes every client's data";
                optedOut = lib.recursiveUpdate secureTopology {
                  nodes.node1.insecurePlaintextBoot = "lab machine";
                };
                without = withTopology (builtins.removeAttrs optedOut [ "insecureFleetKeysOnPlaintextDisk" ]);
                blank = withTopology (optedOut // { insecureFleetKeysOnPlaintextDisk = " "; });
                acknowledged = withTopology optedOut;
              in
              fails without needle
              && !evaluates without
              && fails blank needle
              && !fails acknowledged needle
              && !fails baseline needle;
            detail = [ ];
          }
          # The warning and the alert used to say "keep client data off it", which
          # protects nothing: the keys to all of it are on the disk regardless.
          {
            name = "the opt-out's warning and alert name the fleet's keys, and promise nothing";
            ok =
              let
                warnings = (fixtureNode "node1").config.warnings;
                optOutRule = lib.findFirst (r: r.alert == "BootSecurityOptedOut") null (
                  lib.concatMap (g: g.rules) (import ../lib/alert-rules.nix { inherit lib; }).groups
                );
                says =
                  text: lib.hasInfix "every client's files" text && !lib.hasInfix "Keep client data off it" text;
              in
              lib.any (w: lib.hasInfix "opted out of boot security" w && says w) warnings
              && optOutRule != null
              && says optOutRule.annotations.description;
            detail = (fixtureNode "node1").config.warnings;
          }
          # null is how the module reads "not set", so it must not read as opted out.
          {
            name = "the opt-out needs a reason: null is no opt-out at all";
            ok =
              let
                system = optedOutWith null;
              in
              system.config.cluster.boot.enable
              && system.config.boot.lanzaboote.enable
              && system.config.boot.initrd.systemd.tpm2.enable
              && system.config.clan.core.vars.generators ? luks
              && !lib.any (lib.hasInfix "opted out of boot security") system.config.warnings
              # Nothing refused: null is read as "not set", so the whole posture is in force
              # and the core satisfies it.
              && failedMessages system == [ ];
            detail = failedMessages (optedOutWith null);
          }

          # ── the baseline really satisfies the posture ───────────────────────────
          # Without this, every `refuses` below could pass with the assertion stuck on.
          {
            name = "baseline: no assertion fails, from any module";
            ok = failedMessages baseline == [ ];
            detail = failedMessages baseline;
          }
          # And the whole node evaluates. `refuses` relies on this: "does not evaluate" says
          # nothing about a change if the node did not evaluate without it either.
          {
            # A second evaluation of the same node, so that `baseline`, which every refusal
            # keeps reading, does not carry its whole toplevel to the end. See "Memory".
            name = "baseline: the toplevel evaluates, through Lanzaboote";
            ok = evaluates (secureWith [ ]);
            detail = [ ];
          }
          {
            name = "baseline: the layout gives what the posture reads";
            ok =
              let
                c = baseline.config;
              in
              lib.sort lib.lessThan (lib.attrNames c.boot.initrd.luks.devices) == [
                "crypt-a"
                "crypt-b"
              ]
              && lib.all (s: s.randomEncryption.enable) c.swapDevices
              && c.swapDevices != [ ];
            detail = [ ];
          }

          # ── the disk layout a secure node gets ──────────────────────────────────
          {
            name = "a secure node's LUKS legs ask forever, survive a dead disk, and pass TRIM";
            ok =
              let
                devices = baseline.config.boot.initrd.luks.devices;
              in
              lib.all (
                n:
                devices.${n}.allowDiscards
                &&
                  devices.${n}.crypttabExtraOpts == [
                    "tries=0"
                    "nofail"
                    "x-systemd.device-timeout=30s"
                    "tpm2-device=auto"
                  ]
              ) (lib.attrNames devices)
              && devices.crypt-a.device == "/dev/disk/by-partlabel/disk-nvme0-luks"
              && devices.crypt-b.device == "/dev/disk/by-partlabel/disk-nvme1-luks";
            detail = lib.mapAttrsToList (
              n: d: "${n}: ${d.device} ${toString d.crypttabExtraOpts}"
            ) baseline.config.boot.initrd.luks.devices;
          }
          {
            name = "a secure node's layout reads the luks generator's passphrase, at install only";
            ok =
              let
                c = baseline.config;
                parts = c.disko.devices.disk.nvme1.content.partitions;
                want = "/run/partitioning-secrets/per-machine/node1/luks/passphrase";
              in
              c.clan.core.vars.generators.luks.files.passphrase.path == want
              && parts.luks.content.passwordFile == want
              && !(c.boot.initrd.luks.devices.crypt-b ? passwordFile);
            detail = [ ];
          }
          {
            name = "a secure node's ESPs are 1G and nofail, and its swap takes no discards";
            ok =
              let
                c = baseline.config;
                parts = (d: d.content.partitions) c.disko.devices.disk.nvme0;
              in
              parts.ESP.size == "1G"
              && lib.elem "nofail" parts.ESP.content.mountOptions
              && parts.swap.content.discardPolicy == null
              && lib.all (s: !s.randomEncryption.allowDiscards) c.swapDevices;
            detail = [ ];
          }
          {
            name = "a secure node takes its disks from the topology, and by default the two NVMe";
            ok =
              let
                diskOf = system: name: system.config.disko.devices.disk.${name}.device;
                moved = secureNode {
                  topology = lib.recursiveUpdate secureTopology {
                    nodes.node1.disks = {
                      a = "/dev/disk/by-id/fixture-a";
                      b = "/dev/disk/by-id/fixture-b";
                    };
                  };
                };
              in
              diskOf baseline "nvme0" == "/dev/nvme0n1"
              && diskOf baseline "nvme1" == "/dev/nvme1n1"
              && diskOf moved "nvme0" == "/dev/disk/by-id/fixture-a"
              && diskOf moved "nvme1" == "/dev/disk/by-id/fixture-b";
            detail = [ ];
          }
          {
            name = "an opted-out node gets the plain layout, with its zfs partitions and the small ESP";
            ok =
              let
                c = (optedOutWith "fixture: plain").config;
                parts = c.disko.devices.disk.nvme0.content.partitions;
              in
              parts.zfs.content.type == "zfs"
              && !(parts ? luks)
              && parts.ESP.size == "512M"
              && parts.swap.content.discardPolicy == "once"
              && c.boot.initrd.luks.devices == { }
              && c.boot.loader.systemd-boot.enable
              && c.boot.loader.efi.canTouchEfiVariables;
            detail = [ ];
          }
          {
            name = "the encrypted layout will not be built without a passphrase file, so disko can't ask";
            ok =
              !(builtins.tryEval
                (import ../lib/mk-disk-layout.nix {
                  inherit lib;
                  encrypted = true;
                }).disko.devices.disk.nvme0.device
              ).success;
            detail = [ ];
          }
          {
            name = "a secure node's initrd is reachable, hashed, and flushes what it set";
            ok =
              let
                c = baseline.config;
                i = c.boot.initrd;
                t = secureTopology.nodes.node1;
              in
              i.network.ssh.enable
              && i.network.ssh.port == 2222
              && i.network.ssh.authorizedKeys == import ./fixtures/admins.nix
              && i.network.ssh.hostKeys == [ c.cluster.boot.ssh.hostKeyPath ]
              && i.systemd.network.networks."30-wan".address == [ "${t.publicIp4}/32" ]
              # The WAN NIC only: an unlock needs no network, so nothing here names the vRack's.
              && !lib.any (lib.hasInfix t.vrackInterface) (
                lib.attrNames i.systemd.network.networks ++ lib.attrNames i.systemd.network.netdevs
              )
              && lib.hasPrefix "$" i.systemd.emergencyAccess
              && lib.all (m: lib.elem m i.availableKernelModules) t.initrdNicModules
              && lib.all (p: lib.elem p c.boot.kernelParams) (
                c.cluster.boot.iommuParams
                ++ [
                  "systemd.import_credentials=no"
                  "noresume"
                ]
              );
            detail = [ ];
          }
          {
            name = "the unlock gate holds the pool's import, with no timeout of its own";
            ok =
              let
                gate = baseline.config.boot.initrd.systemd.services.rpool-unlock-gate;
              in
              lib.elem "zfs-import-rpool.service" gate.requiredBy
              && lib.elem "zfs-import-rpool.service" gate.before
              && gate.serviceConfig.TimeoutStartSec == "infinity"
              && lib.hasInfix "systemd-cryptsetup@crypt\\x2da.service" gate.script
              && lib.hasInfix "systemd-cryptsetup@crypt\\x2db.service" gate.script;
            detail = [ ];
          }
          {
            name = "the disko hook places both partitioning secrets, from the generators' paths";
            ok =
              let
                c = baseline.config;
                hook = c.disko.devices.zpool.rpool.datasets.root.postMountHook;
              in
              lib.hasInfix "place ${c.cluster.boot.install.identitySecretFile} ${c.cluster.boot.identity.path} 0400" hook
              && lib.hasInfix "place ${c.cluster.boot.install.hostKeyFile} ${c.cluster.boot.ssh.hostKeyPath} 0400" hook
              && lib.hasInfix "refusing to install" hook;
            detail = [ ];
          }

          {
            name = "the disko hook makes the signing keys in the new root, and refuses if it can't";
            ok =
              let
                c = baseline.config;
                hook = c.disko.devices.zpool.rpool.datasets.root.postMountHook;
                root = "${c.disko.rootMountPoint}${c.cluster.boot.pkiBundle}";
              in
              lib.hasInfix "--disable-landlock --config /tmp/sbctl.conf create-keys" hook
              && lib.hasInfix ''[ ! -e "${root}/keys" ]'' hook
              && lib.hasInfix "sbctl create-keys failed; refusing to install" hook;
            detail = [ ];
          }
          {
            name = "Lanzaboote is on from the core, on both ESPs, with the fleet's limit";
            ok =
              let
                c = baseline.config;
                l = c.boot.loader;
              in
              c.boot.lanzaboote.enable
              && c.boot.lanzaboote.pkiBundle == "/var/lib/sbctl"
              && c.boot.lanzaboote.configurationLimit == 5
              && c.boot.lanzaboote.extraEfiSysMountPoints == [ "/boot-fallback" ]
              && l.efi.efiSysMountPoint == "/boot"
              && l.timeout == 0
              && !l.systemd-boot.enable
              && !l.efi.canTouchEfiVariables;
            detail = [ ];
          }
          {
            name = "the guarded hook replaces Lanzaboote's own";
            ok = lib.hasInfix "lzbt-guarded" (toString baseline.config.boot.loader.external.installHook);
            detail = toString baseline.config.boot.loader.external.installHook;
          }
          {
            # nixpkgs gives bootctl the ESP by SYSTEMD_ESP_PATH, which it then does not check,
            # and nofail takes the ESPs' mounts out of local-fs.target, all the unit waited for.
            name = "the boot loader's random seed waits for the first ESP's mount, and is skipped without it";
            ok =
              let
                c = baseline.config;
                seed = c.systemd.services.systemd-boot-random-seed;
                espOptions = d: c.disko.devices.disk.${d}.content.partitions.ESP.content.mountOptions;
              in
              lib.elem "boot.mount" seed.after
              && (seed.unitConfig.ConditionPathIsMountPoint or null) == "/boot"
              && c.boot.loader.efi.efiSysMountPoint == "/boot"
              && lib.all (d: lib.elem "x-systemd.device-timeout=30s" (espOptions d)) [
                "nvme0"
                "nvme1"
              ];
            detail = baseline.config.systemd.services.systemd-boot-random-seed.after;
          }
          {
            name = "sbctl on the node finds the keys where the hook put them";
            ok =
              baseline.config.environment.etc."sbctl/sbctl.conf".text == ''
                keydir: /var/lib/sbctl/keys
                guid: /var/lib/sbctl/GUID
              '';
            detail = baseline.config.environment.etc."sbctl/sbctl.conf".text;
          }
          {
            name = "the identity check runs before anything comes from the root, and has no failure action";
            ok =
              let
                check = baseline.config.boot.initrd.systemd.services.volume-identity-check;
              in
              lib.all (u: lib.elem u check.before) [
                "initrd-root-fs.target"
                "initrd-parse-etc.service"
                "initrd-find-nixos-closure.service"
                "initrd-nixos-activation.service"
                "initrd-switch-root.target"
              ]
              && check.requiredBy == [ "initrd-root-fs.target" ]
              && check.after == [ "sysroot.mount" ]
              && check.requires == [ "sysroot.mount" ]
              && check.serviceConfig.TimeoutStartSec == "30s"
              # Only a verdict halts: a stalled read must not, and this would make it.
              && !(check.unitConfig ? FailureAction)
              && lib.hasInfix "/sysroot/var/lib/volume-identity/secret" check.script;
            detail = [ ];
          }
          {
            name = "the identity hash is plain content in the signed initrd, and not an initrd secret";
            ok =
              let
                c = baseline.config;
              in
              c.boot.initrd.systemd.contents."/etc/volume-identity.sha256".text
              == c.cluster.boot.identity.hash + "\n"
              && !(c.boot.initrd.secrets ? "/etc/volume-identity.sha256")
              && !(c.boot.initrd.secrets ? ${c.cluster.boot.identity.path});
            detail = [ ];
          }
          {
            name = "the ESP budget is a build gate";
            ok = lib.any (d: d.name == "check-esp-budget") baseline.config.system.checks;
            detail = map (d: d.name) baseline.config.system.checks;
          }
          {
            name = "the boot audit runs on a timer, and checks what a vdev really is";
            ok =
              let
                c = baseline.config;
                text = c.system.build.auditText;
              in
              c.systemd.timers.cluster-boot-audit.timerConfig.OnUnitActiveSec == "5min"
              && lib.elem "timers.target" c.systemd.timers.cluster-boot-audit.wantedBy
              && lib.hasInfix "zpool list -vHP rpool" text
              && lib.hasInfix "/dev/mapper/crypt-*" text
              && lib.hasInfix "grep -q ' crypt '" text
              && lib.all (m: lib.hasInfix m text) [
                "cluster_zpool_plain_vdevs"
                "cluster_esp_mounted"
                "cluster_boot_tpm_tokens"
                "cluster_iommu_groups"
                "cluster_watchdog_device"
                "cluster_core_pattern_ok"
              ];
            detail = [ ];
          }

          # ── the TPM unlock, the burn, and leaving the initrd ────────────────────
          {
            name = "every leg tries its TPM slot before it asks, and the initrd can open one";
            ok =
              let
                c = baseline.config;
                devices = c.boot.initrd.luks.devices;
              in
              c.boot.initrd.systemd.tpm2.enable
              &&
                lib.attrNames devices == [
                  "crypt-a"
                  "crypt-b"
                ]
              && lib.all (
                d:
                lib.all (o: lib.elem o d.crypttabExtraOpts) [
                  "tpm2-device=auto"
                  # A mistyped passphrase or a dead disk must not give the leg up.
                  "tries=0"
                  "nofail"
                ]
              ) (lib.attrValues devices);
            detail = lib.mapAttrsToList (n: d: "${n}: ${toString d.crypttabExtraOpts}") baseline.config.boot.initrd.luks.devices;
          }
          {
            name = "the initrd-contents check is a build gate";
            ok = lib.any (d: d.name == "check-initrd-contents") baseline.config.system.checks;
            detail = map (d: d.name) baseline.config.system.checks;
          }
          {
            name = "the burn runs before any shell, pulls in the TPM, and leaves a marker in /run";
            ok =
              let
                i = baseline.config.boot.initrd.systemd;
                burn = i.services.emergency-pcr-burn;
              in
              lib.all (u: lib.elem u burn.requiredBy && lib.elem u burn.before) [
                "emergency.service"
                "rescue.service"
              ]
              && lib.all (u: lib.elem u burn.wants && lib.elem u burn.after) [
                "tpm2.target"
                "systemd-modules-load.service"
              ]
              && lib.hasInfix "tpm2_pcrextend 7:sha256=" burn.script
              # The marker comes after the extend, so a burn that failed leaves none.
              && lib.hasInfix "/run/cluster-boot/pcr7-burned" burn.script
              &&
                builtins.match ".*tpm2_pcrextend.*pcr7-burned.*" (lib.replaceStrings [ "\n" ] [ " " ] burn.script)
                != null
              && lib.any (p: lib.hasSuffix "/bin/tpm2_pcrextend" (toString p.source)) i.storePaths;
            detail = [ ];
          }
          {
            name = "the cached passphrase is purged from root's user keyring before stage 2";
            ok =
              let
                i = baseline.config.boot.initrd.systemd;
                p = i.services.initrd-keyring-purge;
              in
              lib.hasInfix "keyctl purge user cryptsetup" p.script
              # Otherwise the purge searches a private session keyring and finds nothing.
              && p.serviceConfig.KeyringMode == "shared"
              && lib.elem "initrd.target" p.before
              && lib.elem "cryptsetup.target" p.after
              && lib.any (p: lib.hasSuffix "/bin/keyctl" (toString p.source)) i.storePaths;
            detail = [ ];
          }
          {
            name = "the operations index tells avc how to reach a secure node's initrd, and an opted-out one has none";
            ok =
              let
                secure =
                  (mkOpsIndex {
                    clan = mkSecure { topology = secureTopology; };
                    topology = secureTopology;
                  }).nodes;
                pub = baseline.config.clan.core.vars.generators.initrd-ssh.files."ssh_host_ed25519_key.pub".value;
                optedOut =
                  (mkOpsIndex {
                    clan = fixtureCluster;
                    topology = fixtureTopology;
                  }).nodes.node1.boot;
              in
              secure.node1.boot.enabled
              && secure.node1.boot.sshPort == 2222
              && secure.node1.boot.hostKeyPub == pub
              && lib.hasPrefix "ssh-ed25519 " pub
              && !secure.node2.boot.enabled
              && !optedOut.enabled
              && optedOut.hostKeyPub == null;
            detail = [ ];
          }
          # Pull deploys never reboot, so the generation a node booted is old long before it
          # is replaced. nix.gc would delete its link, and Lanzaboote then drops its entry.
          # And a console rollback is refused by the node itself, before the first tick.
          {
            name = "the weekly GC keeps the booted generation, and a rollback is refused at boot";
            ok =
              let
                c = baseline.config;
                gc = c.systemd.services.cluster-generation-gc;
                guard = c.systemd.services.cluster-upgrade-rollback-guard;
              in
              !c.nix.gc.automatic
              && lib.hasInfix "-cluster-generation-gc/bin/cluster-generation-gc" gc.script
              && lib.toList gc.startAt == [ "weekly" ]
              && lib.elem "cluster-upgrade-rollback-guard.service" c.systemd.services.cluster-upgrade.requires
              && lib.elem "cluster-upgrade-rollback-guard.service" c.systemd.services.cluster-upgrade.after
              && lib.elem "multi-user.target" guard.wantedBy
              && !guard.restartIfChanged;
            detail = [ ];
          }
          {
            name = "the seal tool is on the node, and knows its devices and identity";
            ok =
              let
                c = baseline.config;
                text = c.system.build.sealText;
              in
              lib.any (p: p.name or "" == "cluster-boot-seal") c.environment.systemPackages
              && lib.hasInfix "identity_hash=${c.cluster.boot.identity.hash}" text
              && lib.all (d: lib.hasInfix d.device text) (lib.attrValues c.boot.initrd.luks.devices)
              && lib.all (f: lib.hasInfix f text) [
                "need_enforcing"
                "need_unburned"
                "need_own_authority_only\n"
                "need_identity"
                "--tpm2-device=auto --tpm2-pcrs=7 "
                "--token-only --token-type systemd-tpm2"
                "/run/cluster-boot/pcr7-burned"
                "db_cert=/var/lib/sbctl/keys/db/db.pem\n"
              ]
              # Option ROMs go in db by their hashes, and Microsoft's CA is a site's choice.
              && lib.hasInfix "sbctl enroll-keys --tpm-eventlog" text
              && !lib.hasInfix "enroll-keys --microsoft" text
              && !c.cluster.boot.enrollMicrosoftKeys;
            detail = [ ];
          }

          # ── a host file cannot undo it ──────────────────────────────────────────
          (refuses "a host file forcing boot.lanzaboote.enable = false" (secureWith [
            { boot.lanzaboote.enable = lib.mkForce false; }
          ]) "boot.lanzaboote.enable must be true")
          (refuses "a host file putting Lanzaboote's own install hook back" (secureWith [
            { boot.loader.external.installHook = lib.mkOverride 10 "/nix/store/upstream-lzbt"; }
          ]) "boot.loader.external.installHook must be the guarded hook")
          (refuses "a host file turning the identity check off" (secureWith [
            { boot.initrd.systemd.services.volume-identity-check.enable = lib.mkForce false; }
          ]) "volume-identity-check must run")
          (refuses "a host file turning the PCR burn off" (secureWith [
            { boot.initrd.systemd.services.emergency-pcr-burn.enable = lib.mkForce false; }
          ]) "emergency-pcr-burn must run")
          (refuses "a host file letting a shell start when the burn fails" (secureWith [
            { boot.initrd.systemd.services.emergency-pcr-burn.requiredBy = lib.mkForce [ ]; }
          ]) "emergency-pcr-burn must run")
          (refuses "a host file ordering the identity check late" (secureWith [
            {
              boot.initrd.systemd.services.volume-identity-check.before = lib.mkForce [
                "initrd-switch-root.target"
              ];
            }
          ]) "volume-identity-check must run")
          # One clause each, with every other clause of its assertion still true, so that no
          # clause is proven only because a neighbouring one always caught the value first.
          (refuses "a host file letting the shell start alongside the burn" (secureWith [
            { boot.initrd.systemd.services.emergency-pcr-burn.before = lib.mkForce [ ]; }
          ]) "emergency-pcr-burn must run")
          (refuses "a host file no longer requiring the identity check" (secureWith [
            { boot.initrd.systemd.services.volume-identity-check.requiredBy = lib.mkForce [ ]; }
          ]) "volume-identity-check must run")
          # The core's copy, which the posture's own message would otherwise stand in for.
          (refuses "the core refuses Lanzaboote off" (secureWith [
            { boot.lanzaboote.enable = lib.mkForce false; }
          ]) "cluster.boot: boot.lanzaboote.enable must stay on")
          # Two devices, so the count clause holds and only the name does not.
          (refuses "the core refuses a LUKS device outside the crypt- names" (secureWith [
            {
              boot.initrd.luks.devices = lib.mkForce {
                crypt-a.device = "/dev/sdy";
                other.device = "/dev/sdz";
              };
            }
          ]) "cluster.boot: needs at least two LUKS devices, each named crypt-*")
        ]
        (sharing (secureWith [ { disko.devices = lib.mkForce plainLayout; } ]) [
          [
            "a host file with a plain disko.devices"
            "disko.devices has a plain zfs partition"
          ]
          [
            "a plain disko.devices also leaves no encrypted legs"
            "fewer than two LUKS partitions"
          ]
        ])
        [
          # mkForce to replace the layout modules/zfs-host.nix sets, not to add to it.
          (refuses "a host file adding a whole disk of plain zfs" (secureWith [
            {
              disko.devices = lib.mkForce (
                lib.recursiveUpdate encryptedLayout {
                  disk.extra = {
                    type = "disk";
                    device = "/dev/sdz";
                    content = {
                      type = "zfs";
                      pool = "rpool";
                    };
                  };
                }
              );
            }
          ]) "disko.devices has a plain zfs partition")
          (refuses "a host file keeping only one encrypted leg" (secureWith [
            {
              disko.devices = lib.mkForce (
                encryptedLayout
                // {
                  disk = builtins.removeAttrs encryptedLayout.disk [ "nvme1" ];
                }
              );
            }
          ]) "fewer than two LUKS partitions")
          # In LUKS, but not a leg of the pool, so it must not count as one.
          (refuses "a host file with LUKS around something other than zfs" (secureWith [
            {
              disko.devices = lib.mkForce (
                lib.updateManyAttrsByPath [
                  {
                    path = [
                      "disk"
                      "nvme1"
                      "content"
                      "partitions"
                      "luks"
                      "content"
                      "content"
                    ];
                    update = _: {
                      type = "filesystem";
                      format = "ext4";
                    };
                  }
                ] encryptedLayout
              );
            }
          ]) "fewer than two LUKS partitions")
          (refuses "a host file leaving one LUKS device in the initrd" (secureWith [
            { boot.initrd.luks.devices = lib.mkForce { crypt-only.device = "/dev/sdz"; }; }
          ]) "boot.initrd.luks.devices has fewer than two devices")
          (refuses "a host file adding a LUKS device outside the crypt- names" (secureWith [
            { boot.initrd.luks.devices.other.device = "/dev/sdz"; }
          ]) "a name without the crypt- prefix")
          (refuses "a host file scanning more than /dev/mapper for the pool" (secureWith [
            { boot.zfs.devNodes = lib.mkForce "/dev/disk/by-id"; }
          ]) "boot.zfs.devNodes must be /dev/mapper")
          (refuses "a host file adding plaintext swap" (secureWith [
            { swapDevices = [ { device = "/dev/sdz"; } ]; }
          ]) "swapDevices has an entry without randomEncryption")
          (refuses "a host file taking the TPM option off one leg" (secureWith [
            {
              boot.initrd.luks.devices.crypt-b.crypttabExtraOpts = lib.mkForce [
                "tries=0"
                "nofail"
              ];
            }
          ]) "boot.initrd.luks.devices has a device without tpm2-device=auto")
          (refuses "a host file forcing boot.initrd.systemd.tpm2.enable = false" (secureWith [
            { boot.initrd.systemd.tpm2.enable = lib.mkForce false; }
          ]) "boot.initrd.systemd.tpm2.enable must be true")
          (refuses "a host file turning on the boot menu's editor" (secureWith [
            { boot.loader.systemd-boot.editor = lib.mkForce true; }
          ]) "boot.loader.systemd-boot.editor must be false")
          (refuses "a host file letting the node write EFI variables" (secureWith [
            { boot.loader.efi.canTouchEfiVariables = lib.mkForce true; }
          ]) "boot.loader.efi.canTouchEfiVariables must be false")
          (refuses "a host file keeping initrd addresses into stage 2" (secureWith [
            { boot.initrd.network.flushBeforeStage2 = lib.mkForce false; }
          ]) "boot.initrd.network.flushBeforeStage2 must be true")
          (refuses "a host file forcing emergencyAccess = true" (secureWith [
            { boot.initrd.systemd.emergencyAccess = lib.mkForce true; }
          ]) "boot.initrd.systemd.emergencyAccess must be a crypt(3) hash")
          (refuses "a host file forcing emergencyAccess = \"\"" (secureWith [
            { boot.initrd.systemd.emergencyAccess = lib.mkForce ""; }
          ]) "boot.initrd.systemd.emergencyAccess must be a crypt(3) hash")
          (refuses "a host file forcing emergencyAccess to a plain password" (secureWith [
            { boot.initrd.systemd.emergencyAccess = lib.mkForce "hunter2"; }
          ]) "boot.initrd.systemd.emergencyAccess must be a crypt(3) hash")
          (refuses "a host file forcing cluster.boot.enable = false" (secureWith [
            { cluster.boot.enable = lib.mkForce false; }
          ]) "cluster.boot.enable was forced off")
          (refuses "a host file adding a specialisation" (secureWith [
            { specialisation.unprotected.configuration = { }; }
          ]) "specialisation is set")

          # ── the topology has to make sense ──────────────────────────────────────
        ]
        # The core's own copies, for whoever imports it without modules/boot-security.nix.
        # All at once on one node: each needle names only the core's message.
        (sharing
          (secureWith [
            {
              boot.initrd.luks.devices = lib.mkForce { only.device = "/dev/sdz"; };
              boot.zfs.devNodes = lib.mkForce "/dev/disk/by-id";
              swapDevices = [ { device = "/dev/sdz"; } ];
              boot.initrd.systemd.emergencyAccess = lib.mkForce "hunter2";
              boot.loader.systemd-boot.editor = lib.mkForce true;
              boot.loader.efi.canTouchEfiVariables = lib.mkForce true;
              boot.initrd.network.flushBeforeStage2 = lib.mkForce false;
              boot.initrd.systemd.tpm2.enable = lib.mkForce false;
            }
          ])
          [
            [
              "the core refuses a leg without the TPM option"
              "cluster.boot: every LUKS device needs tpm2-device=auto"
            ]
            [
              "the core refuses an initrd without TPM support"
              "cluster.boot: boot.initrd.systemd.tpm2.enable must stay on"
            ]
            [
              "the core refuses LUKS devices that are too few or misnamed"
              "cluster.boot: needs at least two LUKS devices"
            ]
            [
              "the core refuses a wider zfs scan"
              "cluster.boot: zfs must scan only /dev/mapper"
            ]
            [
              "the core refuses plaintext swap"
              "cluster.boot: every swap device needs randomEncryption"
            ]
            [
              "the core refuses an emergencyAccess that is not a hash"
              "cluster.boot: initrd emergencyAccess has to be a crypt(3) hash"
            ]
            [
              "the core refuses the boot menu's editor"
              "cluster.boot: the boot menu's editor grants root"
            ]
            [
              "the core refuses NVRAM writes"
              "cluster.boot: no NVRAM writes"
            ]
            [
              "the core refuses keeping initrd addresses"
              "cluster.boot: flushBeforeStage2 has to stay on"
            ]
          ]
        )
        [
          (refuses "no initrd NIC modules" (withTopology (
            lib.recursiveUpdate secureTopology {
              nodes.node1.initrdNicModules = [ ];
            }
          )) "initrdNicModules must list")
          (refuses "initrdNicModules that is not a list" (withTopology (
            lib.recursiveUpdate secureTopology {
              nodes.node1.initrdNicModules = "virtio_net";
            }
          )) "initrdNicModules must list")
          (refuses "a null auditUrl" (withTopology (
            lib.recursiveUpdate secureTopology {
              alerting.auditUrl = null;
            }
          )) "topology.alerting.auditUrl is null")
        ]
        # What a topology can simply leave out. The core's own copy is for whoever imports
        # it without modules/boot-security.nix.
        (sharing
          (withTopology (
            secureTopology
            // {
              alerting = builtins.removeAttrs secureTopology.alerting [ "auditUrl" ];
              nodes = secureTopology.nodes // {
                node1 = builtins.removeAttrs secureTopology.nodes.node1 [ "initrdNicModules" ];
              };
            }
          ))
          [
            [
              "no initrdNicModules"
              "initrdNicModules must list"
            ]
            [
              "the core refuses to run without the initrd's NIC drivers"
              "cluster.boot: network.kernelModules must be set"
            ]
            [
              "no auditUrl"
              "topology.alerting.auditUrl is null"
            ]
          ]
        )
        [
          # ── the wiring ──────────────────────────────────────────────────────────
          # The refusals above read results. This is the other half: what the core will be
          # given, because a wrong value here would pass every assertion and fail at boot.
          {
            name = "the wiring hands the core the topology's and the vars' values";
            ok =
              let
                b = baseline.config.cluster.boot;
                gens = baseline.config.clan.core.vars.generators;
              in
              b.enable
              && b.identity.hash == gens.volume-identity.files.hash.value
              && builtins.match "[0-9a-f]{64}" b.identity.hash != null
              && b.emergency.passwordHash == gens.emergency-access.files.hash.value
              && lib.hasPrefix "$" b.emergency.passwordHash
              && b.ssh.port == 2222
              && b.ssh.authorizedKeys == import ./fixtures/admins.nix
              && b.network.wan.interface == secureTopology.nodes.node1.wanInterface
              && b.network.wan.address4 == secureTopology.nodes.node1.publicIp4
              && b.network.wan.gateway4 == secureTopology.nodes.node1.publicGw4
              && b.network.kernelModules == secureTopology.nodes.node1.initrdNicModules
              && b.install.identitySecretFile == gens.volume-identity.files.secret.path
              &&
                b.install.identitySecretFile == "/run/partitioning-secrets/per-machine/node1/volume-identity/secret"
              && b.install.hostKeyFile == gens.initrd-ssh.files."ssh_host_ed25519_key".path
              &&
                b.install.hostKeyFile
                == "/run/partitioning-secrets/per-machine/node1/initrd-ssh/ssh_host_ed25519_key";
            detail = [ ];
          }
          {
            name = "security.initrdSshPort reaches the core";
            ok =
              (secureNode {
                topology = lib.recursiveUpdate secureTopology {
                  security.initrdSshPort = 2200;
                };
              }).config.cluster.boot.ssh.port == 2200;
            detail = [ ];
          }

          # ── partitioning secrets ────────────────────────────────────────────────
          {
            name = "partitioning secrets on the secure fixture are exactly the allowlist";
            ok =
              partitioningSecrets baseline == [
                "initrd-ssh/ssh_host_ed25519_key"
                "luks/passphrase"
                "volume-identity/secret"
              ];
            detail = partitioningSecrets baseline;
          }

          # ── raw_exec's uid gap ──────────────────────────────────────────────────
          {
            name = "a host file cannot add one: uid 70000, or uid 4096 under another name";
            ok =
              let
                uidHostFile = secureWith [
                  {
                    # nomad-apps already holds 4096 on every node, so nixpkgs' own uniqueness
                    # assertion would refuse the squatter too, and print `trace: Duplicate uid
                    # 4096` on every evaluation of this check while it worked that out. Off, so
                    # that the refusal named below is the only one standing between this host
                    # file and a node, and the trace is gone.
                    users.enforceIdUniqueness = false;
                    users.users.high = {
                      uid = 70000;
                      isSystemUser = true;
                      group = "high";
                    };
                    users.groups.high = { };
                    users.users.squatter = {
                      uid = 4096;
                      isSystemUser = true;
                      group = "high";
                    };
                  }
                ];
              in
              !fails baseline uidNeedle
              && fails uidHostFile "high (70000)"
              && fails uidHostFile "squatter (4096)"
              && !evaluates uidHostFile;
            detail = [ ];
          }
          {
            name = "the gap starts at exactly 65536, and 4096 is the only hole below it";
            ok =
              let
                # Either side of each edge of the gap. Only 65536 may be listed.
                uidBoundary = secureWith [
                  {
                    users.users =
                      lib.mapAttrs
                        (_: uid: {
                          inherit uid;
                          isSystemUser = true;
                          group = "boundary";
                        })
                        {
                          below-nomad-apps = 4095;
                          above-nomad-apps = 4097;
                          last-covered = 65535;
                          first-gap = 65536;
                        };
                    users.groups.boundary = { };
                  }
                ];
              in
              lib.any (lib.hasSuffix "Offending accounts: first-gap (65536)") (failedMessages uidBoundary)
              && !evaluates uidBoundary;
            detail = [ ];
          }
          {
            name = "the gap applies to a normal user as well as a system one";
            ok =
              let
                uidNormalUser = secureWith [
                  {
                    users.users.person = {
                      uid = 65536;
                      isNormalUser = true;
                    };
                  }
                ];
              in
              fails uidNormalUser "person (65536)" && !evaluates uidNormalUser;
            detail = [ ];
          }
          {
            name = "nomad-apps may hold uid 4096";
            ok =
              let
                uidAllowed = secureWith [
                  {
                    users.users.nomad-apps = {
                      uid = 4096;
                      isSystemUser = true;
                      group = "nomad-apps";
                    };
                    users.groups.nomad-apps = { };
                  }
                ];
              in
              !fails uidAllowed uidNeedle;
            detail = [ ];
          }
          {
            name = "an opted-out node gets no exemption from the uid gap";
            ok =
              let
                optedOutUid = secureNode {
                  topology = lib.recursiveUpdate secureTopology {
                    nodes.node1.insecurePlaintextBoot = "fixture";
                  };
                  modules = [
                    {
                      users.users.high = {
                        uid = 70000;
                        isSystemUser = true;
                        group = "high";
                      };
                      users.groups.high = { };
                    }
                  ];
                };
              in
              fails optedOutUid "high (70000)";
            detail = [ ];
          }

          # ── jumbo frames: site data ─────────────────────────────────────────────
          # The values a new site starts from, and the ones the VM tests must not. What the
          # modules do with them is checks.jumbo-mtu's job.
          {
            name = "the template asks for MTU 9000 on every VLAN";
            ok =
              lib.mapAttrsToList (_: v: v.mtu) templateTopology.vlans == [
                9000
                9000
                9000
              ];
            detail = lib.mapAttrsToList (n: v: "${n}: ${toString v.mtu}") templateTopology.vlans;
          }
          # Left to its default, so a site that falls back to 1500 takes the mesh with it.
          {
            name = "the template leaves mesh.mtu to follow the VLAN";
            ok = !(templateTopology.mesh ? mtu);
            detail = [ ];
          }
          # A switch that drops large frames silently would hang the cluster tests, not fail
          # them, and nothing would point at this file.
          {
            name = "the fixtures stay at MTU 1500 and 1420, which the test switch can carry";
            ok =
              lib.all
                (
                  t:
                  lib.all (v: v.mtu == 1500) (lib.attrValues t.vlans)
                  && lib.length (lib.attrNames t.vlans) == 3
                  && t.mesh.mtu == 1420
                )
                [
                  fixtureTopology
                  secureTopology
                ];
            detail = [ ];
          }

          # ── the positive case: the final subtest ────────────────────────────────
          (
            let
              securePositive = secureNode { };
            in
            if securePositiveEnabled then
              {
                name = "the secure fixture, with nothing added, evaluates";
                ok = failedMessages securePositive == [ ] && evaluates securePositive;
                detail = failedMessages securePositive;
              }
            else
              {
                name = "the secure fixture does not evaluate yet: when it does, set securePositiveEnabled";
                # Refused by the posture and nothing else, so a stray failure from some other
                # module cannot hold this subtest down once the core is complete.
                ok =
                  !evaluates securePositive
                  && failedMessages securePositive != [ ]
                  && lib.all (lib.hasPrefix "boot security: node node1: ") (failedMessages securePositive);
                detail = failedMessages securePositive;
              }
          )
        ]
      ]
    )
  );

  failed = lib.filter (x: !x.ok) checks;

  # The helper's four outcomes, in the plain Python its tests will splice it into.
  # A broken helper would turn every mutant green, so it is worth one second here.
  controlSelfTest = pkgs.writeText "control-self-test.py" ''
    source = open("${./lib/control.py}").read()

    def run(mutant, name, ok):
        scope = {"MUTANT": mutant}
        exec(source, scope)
        try:
            scope["control"](name, ok, "detail")
        except scope["MutationProven"]:
            return "proven"
        except Exception:
            return "failed"
        return "passed"

    assert run("", "x", True) == "passed", "a control that holds must pass"
    assert run("", "x", False) == "failed", "a control that does not hold must fail"
    assert run("y", "x", True) == "passed", "another mutant's control that holds must pass"
    assert run("y", "x", False) == "failed", "another mutant's control must still fail"
    assert run("x", "x", True) == "failed", "a removed control that still passes must fail the mutant"
    assert run("x", "x", False) == "proven", "a removed control that goes false proves the mutant"

    # run_main, which every test's script ends with. A mutant is proven only by its own
    # control going false: a run that never reaches that control proves nothing.
    def run_main(mutant, calls):
        scope = {"MUTANT": mutant}
        exec(source, scope)
        def main():
            for name, ok in calls:
                scope["control"](name, ok, "detail")
        try:
            scope["run_main"](main)
        except Exception:
            return "failed"
        return "passed"

    assert run_main("", [("x", True)]) == "passed", "a normal run that holds must pass"
    assert run_main("", []) == "passed", "a normal run with no controls is not a mutant's business"
    assert run_main("", [("x", False)]) == "failed", "a normal run that fails must fail"
    assert run_main("x", [("y", True), ("x", False)]) == "passed", "a mutant whose control flips is proven"
    assert run_main("x", [("y", True)]) == "failed", "a mutant whose control is never reached must fail"
    assert run_main("x", []) == "failed", "a mutant with no controls at all must fail"
    assert run_main("x", [("x", True)]) == "failed", "a mutant whose control still holds must fail"
    print("control.py: all outcomes as documented")
  '';

  # How the boot-* tests read the serial console (tests/lib/boot-harness.py, ConsoleReader).
  # A prompt they don't see fails a control for nothing, and a payload's or a shell's marker
  # they don't see passes one that must fail, so the reading is checked here, on lines as
  # the driver records them: no VM can be made to cut a prompt on demand. The first case is
  # the boot-fallback run that failed `wrong-then-right` with "0 wrong answers taken"; the
  # ones after it are other lines these tests' runs really printed.
  bootConsoleSelfTest = pkgs.writeText "boot-console-self-test.py" ''
    import re
    source = open("${./lib/boot-harness.py}").read()
    scope = {"SSH_PORT": 0}
    exec(source, scope)

    class Machine:
        def __init__(self, lines):
            self.full_console_log = list(lines)
            self.logged = []
        def log(self, message):
            self.logged.append(message)

    PROMPT, ANY_PROMPT = scope["PROMPT"], scope["ANY_PROMPT"]
    LEG = re.compile(r"Please enter passphrase for disk \S+ \((crypt-[ab])\)")
    wait, match = scope["wait_console"], scope["wait_console_match"]
    seen, findall = scope["console_seen"], scope["console_findall"]

    def check(ok, what):
        assert ok, what

    cut = [
        "[    2.784161] usb 1-1: Product: QEMU USB Tablet",
        "Please enter pas[    2.785062] usb 1-1: Manufacturer: QEMU",
        "sphrase for disk[    2.785913] usb 1-1: SerialNumber: 28754-0000:00:1d.7-1",
        " disk-nvme0-luks (crypt-a): [    2.551702] systemd-tty-ask-password-agent[212]: Starting password query on /dev/ttyS0.",
        "[    2.555245] systemd[1]: Found device /dev/disk/by-partlabel/disk-nvme1-luks.",
        "(press TAB for no echo) [    2.559593] systemd-tty-ask-password-agent[213]: Starting password query on /dev/tty1.",
        "[    2.561443] systemd[1]: Started SSH Daemon.",
    ]
    m = Machine(cut)
    check(not any(PROMPT.search(l) for l in cut), "the recorded lines must not hold a whole prompt, or this proves nothing")
    check(wait(m, PROMPT, 0) == 3, "a prompt cut by kernel records is found, on the line where it ends")
    found, leg = match(m, LEG, 0)
    check(found == 4 and leg.group(1) == "crypt-a", f"the leg of a cut prompt is read: {found} {leg}")
    check(any("found only with the records that ended their lines taken out, lines 2 to 4" in l for l in m.logged), f"a match only the joining found is logged, with its lines: {m.logged}")
    check(wait(m, PROMPT, 0, start=3) is None, "a prompt that ended before `start` is not found again")
    check(wait(m, PROMPT, 0, start=2) is None, "nor one that began before `start`")
    check(wait(m, re.compile("Starting password query on /dev/ttyS0"), 0) == 4, "a record is still found in its line")
    check(wait(m, ANY_PROMPT, 0) == 3, "and the prompt first, by what typing waits for")

    # A record cut by records: its text resumes at the start of the next lines and its newline
    # comes later, here as an empty line (boot-no-gate, FLAKE3 verification). The joined text
    # is the console less the records that ended their lines, every other character kept in
    # its order: the prompt, then the agent's record from its own start, and nothing else.
    recut = [
        "[    2.706831] ata1: SATA max UDMA/133 abar m4096@0x81040000 port 0x81040100 irq 45 lpm-pol 1",
        "Please enter passphrase for disk disk-nvme1-luks (crypt-b): (press TAB for no echo) [    2.475782] systemd[1]: Started Dispatch Password Requests to Console.",
        "[    2.477353] systemd-tty-ask-p[    2.712832] ata2: SATA max UDMA/133 abar m4096@0x81040000 port 0x81040180 irq 45 lpm-pol 1",
        "assword-agent[190]: Starting pas[    2.714659] ata3: SATA max UDMA/133 abar m4096@0x81040000 port 0x81040200 irq 45 lpm-pol 1",
        "sword query on /dev/ttyS0.[    2.716188] ata4: SATA max UDMA/133 abar m4096@0x81040000 port 0x81040280 irq 45 lpm-pol 1",
        "",
        "[    2.717718] ata5: SATA max UDMA/133 abar m4096@0x81040000 port 0x81040300 irq 45 lpm-pol 1",
    ]
    AGENT = re.compile("Starting password query on /dev/ttyS0")
    joined = [(i, t) for i, t, cuts in scope["ConsoleReader"](Machine(recut)).texts() if cuts is not None]
    check(
        joined[-1] == (5, "Please enter passphrase for disk disk-nvme1-luks (crypt-b): (press TAB for no echo) "
                       "[    2.477353] systemd-tty-ask-password-agent[190]: Starting password query on /dev/ttyS0."),
        f"a record cut by records is put back together from its own start: {joined}",
    )
    check(not seen(Machine(recut[:6] + ["sphrase for disk"]), re.compile(r"ttyS0\.sphrase")), "the empty line ends that text")
    check(not any(AGENT.search(l) for l in recut), "no single recorded line holds the agent's line, or this proves nothing")
    m = Machine(recut)
    check(wait(m, AGENT, 0) == 5, "the agent's line, cut by records, is found where it ends")
    check(any("lines 2 to 5" in l for l in m.logged), f"and logged with the lines it came from: {m.logged}")
    check(wait(Machine(recut), ANY_PROMPT, 0) == 2, "what typing waits for still finds the prompt on its own line first")
    check(not seen(Machine(recut), re.compile(r"echo\) assword")), "a cut record's tail is not joined to the text before the record began")

    # A record between the pieces that starts its line at once, and two of them.
    for between in (1, 2):
        lines = ["Please enter pas[    2.785062] usb 1-1: a"]
        lines += [f"[    2.78600{n}] usb 1-1: b" for n in range(between)]
        lines += ["sphrase for disk disk-nvme0-luks (crypt-a): [    2.551702] x: y"]
        found, leg = match(Machine(lines), LEG, 0)
        check(found == len(lines) and leg.group(1) == "crypt-a", f"a prompt with {between} whole record line(s) inside it is found: {found}")

    # A relayed record that the prompt ran into, its own tail never printed, then the prompt cut
    # by a driver record (boot-install, WS13-era run). The prompt starts after a record start,
    # and is found all the same.
    runin = [
        "[    2.449390] systemd[1]: Started Dispatch Password Requests to Console.",
        "[    2.451479] systemd-tty-ask-password-agent[210]: Starting password query on /Please enter passphrase for disk disk-nvme0-luks[    2.686383] usb 2-1: new high-speed USB device number 2 using ehci-pci",
        " (crypt-a): (press TAB for no echo) [    2.455159] systemd-tty-ask-password-agent[209]: Starting password query on /dev/ttyS0.",
        "[    2.475219] systemd-networkd[206]: Failed to open nftables netlink socket. IPMasquerade= and NFTSet= settings will not be applied. Ignoring: Protocol not supported",
    ]
    check(not any(LEG.search(l) for l in runin), "no single line names the leg, or this proves nothing")
    found, leg = match(Machine(runin), LEG, 0)
    check(found == 3 and leg.group(1) == "crypt-a", f"the leg of a prompt that ran into a record is read: {found} {leg}")

    # A relayed systemd line that a check must not see, cut by records the same way, is seen.
    check(
        seen(Machine(["[    5.000001] systemd[1]: Swi[    5.200001] ata1: x", "tching root.[    5.200002] ata2: x", ""]), scope["SWITCHED"]),
        "a relayed record cut by records is seen",
    )

    whole = Machine([
        "[    4.770000] systemd[1]: Started Dispatch Password Requests to Console.",
        "Please enter passphrase for disk disk-nvme1-luks (crypt-b): [    4.780000] systemd[1]: Starting x...",
    ])
    check(wait(whole, PROMPT, 0) == 2, "a prompt in one piece is found on its line, as before")
    check(whole.logged == [], "and is not reported as joined")

    # What a check must NOT see, cut the same way, is seen.
    payload = Machine(["FORGED-PAY[   12.000001] usb 1-1: x", "LOAD-RAN"])
    check(seen(payload, re.compile("FORGED-PAYLOAD-RAN")), "a payload marker cut by a record is seen")
    stolen = Machine([
        "STOLEN-KEY-a=" + "0" * 30 + "[   12.000001] usb 1-1: x",
        "0" * 34,
        "STOLEN-KEY-b=" + "1" * 64,
    ])
    keys = {k.group(1): k.group(2) for k in findall(stolen, re.compile(r"STOLEN-KEY-([ab])=([0-9a-f]{64})"))}
    check(keys == {"a": "0" * 64, "b": "1" * 64}, f"findall reads a cut key and a whole one: {keys}")
    pieces = Machine([
        "STOLEN-KEY-a=" + "0" * 20 + "[   12.000001] usb 1-1: x",
        "0" * 20 + "[   12.000002] usb 1-1: x",
        "0" * 24 + "[   12.000003] usb 1-1: x",
        "and the rest of that text",
        "STOLEN-KEY-b=" + "1" * 30 + "[   12.000004] usb 1-1: x",
        "[   12.000005] usb 1-1: x",
        "1" * 34,
    ])
    keys = [(k.group(1), k.group(2)) for k in findall(pieces, re.compile(r"STOLEN-KEY-([ab])=([0-9a-f]{64})"))]
    check(
        sorted(keys) == [("a", "0" * 64), ("b", "1" * 64)],
        f"findall gives a key in three pieces once, and one with a whole record line inside it: {keys}",
    )
    twice = Machine([
        "Dependency failed for Local Encrypted Volumes.[    3.000001] x: y",
        "more[    3.000002] x: y",
        "end",
    ])
    lost = findall(twice, re.compile("Dependency failed for Local Encrypted Volumes"))
    check(len(lost) == 1, f"findall gives each match once: {[l.string for l in lost]}")

    # And no more than that: nothing across a newline that ended a line with no record on it,
    # nothing out of records that ended their lines, and systemd's status column is not a record.
    check(not seen(Machine(["FORGED-PAY", "LOAD-RAN"]), re.compile("FORGED-PAYLOAD-RAN")), "nothing is joined across a newline")
    check(
        not seen(Machine(["FORGED-PAY[    1.000001] x: y", " and the rest of that line", "LOAD-RAN"]), re.compile("FORGED-PAYLOAD-RAN")),
        "nor across one that ends text a record cut",
    )
    check(
        not seen(Machine(["[    1.000001] FORGED-PAY[    1.000002] x: y", "", "LOAD-RAN"]), re.compile("FORGED-PAYLOAD-RAN")),
        "nor across the newline that ends a record records cut",
    )
    check(
        not seen(Machine(["[    1.000001] FORGED-PAY", "[    1.000002] LOAD-RAN"]), re.compile("FORGED-PAYLOAD-RAN")),
        "nothing is joined out of records that ended their lines",
    )
    check(
        not seen(Machine(["FORGED-PAY[    1.000001] LOAD-RAN"]), re.compile("FORGED-PAYLOAD-RAN")),
        "a record that ended its line is never part of the joined text",
    )
    status = Machine(["[\x1b[0;32m  OK  \x1b[0m] Reached target Emergency Mode.", "[  OK  ] Started x."])
    check(wait(status, scope["EMERGENCY"], 0) == 1, "a status line is a line")
    check(all(scope["KERNEL_RECORD"].search(l) is None for l in status.full_console_log), "and not a kernel record")

    # A log read as it grows, as the driver appends to it: the part before a record is kept
    # from one read to the next.
    growing = Machine(cut[:2])
    reader = scope["ConsoleReader"](growing)
    check(reader.search(PROMPT) is None, "two lines are not yet a prompt")
    growing.full_console_log.append(cut[2])
    found = reader.search(PROMPT)
    check(found is not None and found[0] == 3, f"the third line, read later, completes it: {found}")
    print("boot console reading: all outcomes as documented")
  '';

  # The same for the script that runs the mutants: a run that cannot list them, or
  # cannot build one, must not read as a clean run. Nor may it go back to one evaluator
  # per mutant, each held for its whole VM test, which is what this memory rule is for.
  # It is run as it ships, against a stand-in for nix that does what a broken flake or a
  # failing mutant does. jq is not on this PATH, so a listing that came to need it again
  # fails here too. What nix itself makes of the listing's expression can't be asked from
  # a sandbox.
  stubNix = pkgs.writeShellScriptBin "nix" ''
    case "$1" in
      eval)
        echo eval >>"$STUB_LOG"
        case " $* " in
          *" --impure "*)
            [ "''${STUB_FAIL:-}" != system ] || { echo "error: stub: no system" >&2; exit 1; }
            printf test-system
            ;;
          *attrNames*)
            [ "''${STUB_FAIL:-}" != list ] || { echo "error: stub: flake does not evaluate" >&2; exit 1; }
            names=''${STUB_NAMES:-}
            [ -z "$names" ] || printf '%s' "$names" | sed 's|.*|/nix/store/mutant-&.drv|'
            ;;
          *)
            [ "''${STUB_FAIL:-}" != named ] || { echo "error: stub: no such mutant" >&2; exit 1; }
            # What the script asked for, from its expression: the "\n" is not a name.
            printf '%s' "$*" | grep -oE '"[A-Za-z0-9_-]+"' | tr -d '"' | sed 's|.*|/nix/store/mutant-&.drv|'
            ;;
        esac
        ;;
      build)
        echo "build $*" >>"$STUB_LOG"
        rc=0
        for arg in "$@"; do
          case "$arg" in
            /nix/store/mutant-*.drv^\*)
              name=''${arg#/nix/store/mutant-}
              name=''${name%.drv^\*}
              echo "$name" >>"$STUB_BUILDS"
              [ "$name" != "''${STUB_FAIL:-}" ] || { echo "error: stub: build of $arg failed" >&2; rc=1; }
              ;;
            .\#* | *.mutants.*) echo "error: stub: a build must not evaluate: $arg" >&2; exit 3 ;;
          esac
        done
        exit "$rc"
        ;;
      *) echo "error: stub: unexpected nix $*" >&2; exit 2 ;;
    esac
  '';
  runMutantsSelfTest = pkgs.writeShellScript "run-mutants-self-test" ''
    set -eu
    export PATH=${stubNix}/bin:$PATH STUB_BUILDS=$PWD/stub-builds STUB_LOG=$PWD/stub-log

    run() {
      : >"$STUB_BUILDS"
      : >"$STUB_LOG"
      rc=0
      out=$(bash ${./run-mutants.sh} "$@" 2>&1) || rc=$?
      built=$(sort "$STUB_BUILDS" | tr '\n' ' ')
      evals=$(grep -c '^eval$' "$STUB_LOG" || true)
      builds=$(grep -c '^build ' "$STUB_LOG" || true)
    }
    wrong() {
      printf 'run-mutants.sh: %s\n  rc=%s built=[%s] evals=%s builds=%s\n  %s\n' \
        "$1" "$rc" "$built" "$evals" "$builds" "$out" >&2
      exit 1
    }
    says() { case "$out" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

    STUB_FAIL=list STUB_NAMES=a run
    [ "$rc" -ne 0 ] || wrong "a failed listing must fail the run"
    ! says "no mutants defined" || wrong "a failed listing is not an empty one"
    [ -z "$built" ] || wrong "a failed listing must build nothing"

    STUB_FAIL=system STUB_NAMES=a run
    [ "$rc" -ne 0 ] || wrong "not knowing the system must fail the run"

    run
    [ "$rc" -eq 0 ] || wrong "an empty list is a clean run"
    says "no mutants defined" || wrong "an empty list must say so"
    [ -z "$built" ] || wrong "an empty list must build nothing"

    STUB_NAMES=$'a\nb' run
    [ "$rc" -eq 0 ] || wrong "every mutant green is a clean run"
    [ "$built" = "a b " ] || wrong "every listed mutant must be built, once"
    says "2 mutant(s) proven" || wrong "the count must be what was built"
    # The system's one-liner, and one evaluation for all the mutants.
    [ "$evals" -eq 2 ] || wrong "the mutants must be evaluated once, not per mutant"
    [ "$builds" -eq 1 ] || wrong "the .drv files go to one build, which -j then schedules"

    STUB_NAMES=$'a\nb\nc\nd' run -j 3 
    [ "$evals" -eq 2 ] || wrong "more mutants must not mean more evaluations"
    [ "$built" = "a b c d " ] || wrong "-j must not change what is built"
    grep -q -- '--max-jobs 3 ' "$STUB_LOG" || wrong "-j must be the build's parallelism"

    STUB_NAMES=$'a\nb' STUB_FAIL=b run
    [ "$rc" -ne 0 ] || wrong "a listed mutant that fails must fail the run"
    ! says "proven" || wrong "a failed run must not claim proof"
    [ "$built" = "a b " ] || wrong "a failing mutant must not cost the others' proof"

    STUB_FAIL=list run -j 2 a b
    [ "$rc" -eq 0 ] || wrong "named mutants do not need the listing"
    [ "$built" = "a b " ] || wrong "named mutants must be built, once"
    [ "$evals" -eq 2 ] || wrong "named mutants must be evaluated once, not per mutant"

    STUB_FAIL=named run a
    [ "$rc" -ne 0 ] || wrong "a named mutant that does not exist must fail the run"
    ! says "proven" || wrong "a failed evaluation must not claim proof"
    [ -z "$built" ] || wrong "a failed evaluation must build nothing"

    STUB_FAIL=b run a b
    [ "$rc" -ne 0 ] || wrong "a named mutant that fails must fail the run"
    ! says "proven" || wrong "a failed run must not claim proof"

    run ""
    [ "$rc" -ne 0 ] || wrong "an empty name must fail the run"
    ! says "proven" || wrong "an empty name must not claim proof"

    run a '"; throw "x'
    [ "$rc" -ne 0 ] || wrong "a name that is not a name must fail the run"
    [ "$evals" -le 1 ] || wrong "a name that is not a name must not reach an expression"

    echo "run-mutants.sh: all outcomes as documented"
  '';
in
pkgs.runCommand "security-policy-checks"
  {
    nativeBuildInputs = [ pkgs.python3 ];
  }
  (
    if failed == [ ] then
      ''
        python3 ${controlSelfTest}
        python3 ${bootConsoleSelfTest}
        ${runMutantsSelfTest}
        echo "${toString (builtins.length checks)} security policy checks passed"
        touch $out
      ''
    else
      ''
        echo "FAILED:" >&2
        ${lib.concatMapStringsSep "\n" (x: ''
          echo ${lib.escapeShellArg "  - ${x.name}"} >&2
          ${lib.concatMapStringsSep "\n" (
            # A detail can be a set (the deny-list and bootstrap_expect subtests): shown as JSON,
            # where toString would abort the report with "cannot coerce a set". One that is not
            # a list at all (a string, the whole boot contract) is shown as a single line.
            d: "echo ${lib.escapeShellArg "      ${if builtins.isString d then d else builtins.toJSON d}"} >&2"
          ) (lib.toList x.detail)}
        '') failed}
        exit 1
      ''
  )
