{
  description = "NixOS module library for clusters of systemd-nspawn containers, run by Nomad, on JuiceFS, behind Cloudflare Tunnels, on clan-core";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # clan-core — the fleet substrate (machine registry + role tags, vars/secrets,
    # state+backup contract). Pinned BY REV, not by branch: `main` is clan's
    # unstable channel (their VERSION file literally says "unstable") and a fleet
    # built on this library auto-applies from git, so the lock file is the only
    # thing standing between an upstream push and every node. Bump this input
    # ALONE, never alongside others, so each bump is one reviewable commit —
    # and `nix flake check` runs tests/clan-coexist.nix against it.
    clan-core = {
      url = "git+https://git.clan.lol/clan/clan-core?rev=7b287df580ac32a1e14c5ca62df708e3f501216b";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
      inputs.disko.follows = "disko";
    };

    # Lanzaboote: Secure Boot for encrypted nodes (modules/boot-security-core.nix).
    # Pinned BY REV for the same reason as clan-core: nodes auto-apply, so a bump
    # must be one reviewable commit. This rev, not a release, because it is the one
    # carrying `protectedSystem`, and the one the boot tests ran against.
    lanzaboote = {
      url = "github:nix-community/lanzaboote/4b98333073bdaf9b1b5dd7d87c2dab96883b234e";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Payload modules, imported by the kinds (modules/kinds/). A consumer can set
    # its own input of the same name, and mkCluster prefers it.
    wordpress-nix = {
      url = "github:Avunu/wordpress";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # frappe-nix provides the services.frappe NixOS module; the built bench (the
    # site's apps) is a package from the consumer's own flake.
    #
    # Tracks `main`: modules/kinds/frappe.nix asks for `sites.<n>.nginx.socketPath`
    # / `web.socketPath`, the socket origins this library's tunnel design needs.
    frappe-nix = {
      url = "github:Avunu/frappe-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # odoo-nix provides the services.odoo-nix NixOS module; the built Odoo is a
    # package from the consumer's own flake (the same arrangement as frappe).
    odoo-nix = {
      url = "github:Avunu/odoo-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      clan-core,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      clusterLib = import ./lib { inherit lib; };

      # Everything mkCluster imports on every machine. `nixosModules` is the wider
      # set a consumer can reach, and a module for a host that is not a cluster node
      # (none yet) belongs only in the wider one.
      clusterModuleSet = {
        zfsHost = ./modules/zfs-host.nix;
        bootSecurity = ./modules/boot-security.nix;
        clusterCommon = ./modules/cluster-common.nix;
        overlayNetwork = ./modules/overlay-network.nix;
        # The WireGuard control mesh every service but Nomad listens on.
        meshControl = ./modules/mesh-control.nix;
        storageEtcd = ./modules/storage-etcd.nix;
        storageJuicefs = ./modules/storage-juicefs.nix;
        dbPostgres = ./modules/db-postgres.nix;
        dbMariadb = ./modules/db-mariadb.nix;
        monitoring = ./modules/monitoring.nix;
        logging = ./modules/logging.nix;
        vars = ./modules/vars.nix;
        pullDeploy = ./modules/pull-deploy.nix;
        appContainer = ./modules/app-container.nix;
        # The app catalogue (apps/, one file per app) and the kinds an
        # app can be (modules/kinds/). Keys order the module list, so
        # `freeipa` and `grafana` keep theirs.
        apps = ./modules/apps.nix;
        freeipa = ./modules/kinds/freeipa.nix;
        grafana = ./modules/kinds/grafana.nix;
        odoo = ./modules/kinds/odoo.nix;
        frappe = ./modules/kinds/frappe.nix;
        # wpdb declares `wordpressDatabases`, which the wordpress kind fills
        # in, so it is listed first.
        wpdb = ./modules/kinds/wpdb.nix;
        wordpress = ./modules/kinds/wordpress.nix;
        nomadBootstrap = ./modules/nomad-bootstrap.nix;
        # Namespaces, policies, and every node's scoped-token logins; the ACL bootstrap
        # on the nomad-leader node.
        nomadAcl = ./modules/nomad-acl.nix;
        # The off-host audit trail (SSH logins, deploys, Nomad ACL changes) and each
        # boot's report on how it unlocked.
        auditShip = ./modules/audit-ship.nix;
        bootReport = ./modules/boot-report.nix;
        # The weekly look for the canary where client data must not be in plaintext.
        canaryScan = ./modules/canary-scan.nix;
        backup = ./modules/backup.nix;
        nixpkgsOverlays = ./modules/nixpkgs-overlays.nix;
      };
      nixosModules = clusterModuleSet // {
        # A Tang-only host, for a separate private repo: not a cluster node, so not in
        # the module set (design 1.22).
        tangServer = ./modules/tang-server.nix;
      };

      # `lib.mkCluster` (lib/mk-cluster.nix): a consumer's clan, from these modules.
      # clanCore already imports sops-nix and disko into every machine, so
      # neither is listed here.
      mkCluster = import ./lib/mk-cluster.nix {
        inherit lib clusterLib;
        libraryInputs = inputs;
        # Lanzaboote's module only acts under `boot.lanzaboote.enable`, so it changes
        # nothing on a node that opts out of boot security.
        clusterModules = lib.attrValues clusterModuleSet ++ [ inputs.lanzaboote.nixosModules.lanzaboote ];
      };

      # What the operations tool reads (lib/ops-index.nix): nodes, apps, and
      # which vars generators each app consumes.
      mkOpsIndex =
        { clan, topology }:
        import ./lib/ops-index.nix {
          inherit lib topology clusterLib;
          inherit (clan.config) nixosConfigurations;
        };

      # The fixture cluster (tests/fixtures): what this flake's checks and its
      # nixosConfigurations are built from. A function of the topology so
      # tests/cluster.nix can build the SAME clan over a test topology. Nothing
      # forces it unless a check or its outputs do, so a consumer never pays.
      fixtureTopology = import ./tests/fixtures/topology.nix;
      mkFixtureCluster = import ./tests/fixtures { inherit self mkCluster; };
      fixtureCluster = mkFixtureCluster fixtureTopology;
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      perSystem =
        { system, self', ... }:
        let
          # Every check is `detach (_: <the check>)`: once its .drv path is known, nothing
          # the flake keeps refers to its evaluation, so `nix flake check` holds one check's
          # systems at a time instead of all of them (tests/lib/detached-check.nix). A check
          # written without it still works, and costs its whole evaluation until the end.
          detach = import ./tests/lib/detached-check.nix;

          # The boot-* VM tests share this much. Each provisions for itself.
          bootTest =
            file: args:
            import file (
              {
                inherit pkgs;
                lib = nixpkgs.lib;
                diskoModule = inputs.disko.nixosModules.disko;
                lanzabooteModule = inputs.lanzaboote.nixosModules.lanzaboote;
              }
              // args
            );
          # Nomad + nomad-autoscaler are BSL-licensed (unfree); allow them.
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };

          # The cluster VM tests' harness over the fixture topology (tests/lib/cluster-harness.nix).
          fixtureHarness = import ./tests/lib/cluster-harness.nix {
            inherit pkgs lib;
            topology = fixtureTopology;
          };
          # A machine on the control VLAN against the real node1 (tests/control-plane-attack.nix).
          controlPlaneAttack =
            args:
            import ./tests/control-plane-attack.nix (
              {
                inherit pkgs lib;
                clan = fixtureCluster;
                harness = fixtureHarness;
              }
              // args
            );

          # The real modules at MTU 9000, on a link that carries it and on one that doesn't
          # (tests/jumbo-mtu.nix).
          jumboMtu =
            args:
            import ./tests/jumbo-mtu.nix (
              {
                inherit pkgs mkCluster;
                lib = nixpkgs.lib;
              }
              // args
            );

          # Three nodes, as a topology is once node2/node3 are real voters (tests/cluster.nix).
          clusterTest =
            args:
            import ./tests/cluster.nix (
              {
                inherit pkgs lib;
                mkClan = mkFixtureCluster;
                topology = fixtureTopology;
                harnessFor =
                  topology:
                  import ./tests/lib/cluster-harness.nix {
                    inherit pkgs lib topology;
                  };
              }
              // args
            );

          # One voter to three on the real modules: a single-voter site and the commit that
          # adds two voters, switched on the running nodes (tests/voter-growth.nix).
          voterGrowth =
            args:
            import ./tests/voter-growth.nix (
              {
                inherit pkgs lib;
                mkClan = mkFixtureCluster;
                topology = fixtureTopology;
                harnessFor =
                  harnessArgs: import ./tests/lib/cluster-harness.nix ({ inherit pkgs lib; } // harnessArgs);
              }
              // args
            );

          # Container default-deny on node1 and an installed node2, with probe apps and
          # the fixture's real Grafana (tests/container-isolation.nix).
          containerIsolation =
            args:
            import ./tests/container-isolation.nix (
              {
                inherit pkgs lib;
                mkClan = mkFixtureCluster;
                topology = fixtureTopology;
                harnessFor =
                  topology:
                  import ./tests/lib/cluster-harness.nix {
                    inherit pkgs lib topology;
                  };
                clanCoreModule = clan-core.nixosModules.clanCore;
              }
              // args
            );

          # The canary scan, every class with its positive control: the real module, with the
          # real JuiceFS modules for its s3 class (tests/canary-scan.nix).
          canaryScan =
            args:
            import ./tests/canary-scan.nix (
              {
                inherit pkgs lib;
                topology = fixtureTopology;
                harnessFor =
                  topology:
                  import ./tests/lib/cluster-harness.nix {
                    inherit pkgs lib topology;
                  };
                clanCoreModule = clan-core.nixosModules.clanCore;
              }
              // args
            );

          # The Tang host module: its surface, key guard, key tool, probe and /rec events,
          # against a stock Tang that shows each hazard (tests/tang-server.nix).
          tangServer =
            args:
            import ./tests/tang-server.nix (
              {
                inherit pkgs;
                lib = nixpkgs.lib;
              }
              // args
            );

          # The JuiceFS volume's encryption, its refusals and its restore path: the real
          # JuiceFS modules on one VM, S3 on another (tests/jfs-encrypted.nix).
          jfsEncrypted =
            args:
            import ./tests/jfs-encrypted.nix (
              {
                inherit pkgs lib;
                topology = fixtureTopology;
                harnessFor =
                  topology:
                  import ./tests/lib/cluster-harness.nix {
                    inherit pkgs lib topology;
                  };
                clanCoreModule = clan-core.nixosModules.clanCore;
              }
              // args
            );

          # clan-core passes "--unset LD_LIBRARY_PATH" as ONE makeWrapperArgs
          # element, which only worked through word-splitting. nixpkgs now
          # enables __structuredAttrs for Python apps, which keeps it as a
          # single arg and makeWrapper dies ("doesn't understand the arg
          # --unset ..."), so the devShell never builds. Split such elements
          # here; drop this once clan-core does.
          #
          # The pinned clan-core also builds clan-cli with nixVersions.nix_2_31
          # (an A/B pin of theirs), which nixpkgs has since removed; give it
          # nixpkgs' default nix. Drop this with a clan-core bump that no
          # longer pins it.
          clan-cli =
            (clan-core.packages.${system}.clan-cli.override { nix = pkgs.nix; }).overrideAttrs
              (old: {
                makeWrapperArgs = pkgs.lib.concatMap (
                  arg:
                  if pkgs.lib.hasPrefix "--unset " arg then
                    [
                      "--unset"
                      (pkgs.lib.removePrefix "--unset " arg)
                    ]
                  else
                    [ arg ]
                ) old.makeWrapperArgs;
              });
        in
        {
          _module.args.pkgs = pkgs;

          # The operations tool: status, sites, apps, secrets, deploys.
          # `.override { siteProvisioner = …; }` enables `avc site …` (lib/avc.nix).
          packages.avc = pkgs.callPackage ./lib/avc.nix { inherit clan-cli; };
          packages.default = self'.packages.avc;

          # Its tests (policy gate, ship ordering, registry) run in the build.
          checks.avc = self'.packages.avc;

          devShells.default = pkgs.mkShell {
            packages = [
              # Fleet: machine registry, secrets (vars), install, backups.
              # Replaces colmena (deploy) and the old per-file secret scripts.
              clan-cli
              pkgs.nomad
              pkgs.nomad-autoscaler
              pkgs.juicefs
              pkgs.jq
              pkgs.hcl2json
              pkgs.nixfmt
              pkgs.age
              pkgs.openssh
              # day-to-day operations (lib/avc.nix)
              self'.packages.avc
            ];
            shellHook = ''
              echo "nixos-cluster-orchestration devshell — clan / nomad / juicefs"
              echo "  avc           → start here: status, sites, apps, secrets, deploys"
              echo "  clan          → machines, vars (secrets), backups, install"
            '';
          };

          formatter = pkgs.nixfmt;

          # Eval-level checks for the container/tunnel wiring. The payload flakes
          # carry the runtime (VM) tests; what regresses here is generated config.
          checks.container-tunnel = detach (
            _:
            import ./tests/container-tunnel.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              topology = fixtureTopology;
              clusterLib = import ./lib { inherit (nixpkgs) lib; };
              clanCoreModule = clan-core.nixosModules.clanCore;
              appContainerModule = ./modules/app-container.nix;
              overlayNetworkModule = ./modules/overlay-network.nix;
            }
          );

          # What the fixture apps generate: engine detection, units, target URLs.
          checks.backup = detach (
            _:
            import ./tests/backup.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              clusterLib = import ./lib { inherit (nixpkgs) lib; };
              clanSystem = self.nixosConfigurations.node1;
            }
          );

          # FreeIPA wiring on the fixture node1: firewall, restarts, image, stops.
          checks.freeipa = detach (
            _:
            import ./tests/freeipa.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              clusterLib = import ./lib { inherit (nixpkgs) lib; };
              topology = fixtureTopology;
              clanSystem = self.nixosConfigurations.node1;
            }
          );

          # Every alert rule fires when it should and stays quiet when it should not.
          checks.alert-rules = detach (
            _:
            import ./tests/alert-rules-test.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
            }
          );

          # The off-cluster dead-man's logic (node --test, no dependencies).
          checks.cluster-watchdog = detach (
            _:
            pkgs.runCommand "cluster-watchdog-tests"
              {
                nativeBuildInputs = [ pkgs.nodejs_22 ];
              }
              ''
                cp -r ${./workers/cluster-watchdog} w && cd w
                node --test test/*.test.js
                touch $out
              ''
          );

          # An alert travels Prometheus → Alertmanager → bridge → (stub) Cloudflare.
          checks.alerting = detach (
            _:
            import ./tests/alerting.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
            }
          );

          # A journal entry from a host unit and from an app's container
          # journal directory reaches Loki with the label contract Grafana
          # and lib/log-alert-rules.nix query by (modules/logging.nix). The REAL
          # Loki module: its store on local disk, no credentials, retention; and
          # no core dump on the host or in a container (modules/coredumps-off.nix).
          checks.logging = detach (
            _:
            import ./tests/logging.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              clusterLib = import ./lib { inherit (nixpkgs) lib; };
            }
          );

          # backup → damage → restore against an S3 server in a VM, with the REAL
          # modules/backup-core.nix and PostgreSQL + MariaDB containers.
          checks.backup-roundtrip = detach (
            _:
            import ./tests/backup-roundtrip.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
            }
          );

          # Installs the real disk layout into a VM, REBOOTS it, and asserts it
          # comes back. Added after a node was bricked by a config that installed
          # cleanly and then panicked with
          #   VFS: Unable to mount root fs on "" or unknown-block(0,0)
          # Every check we had passed, because every check we had was an
          # evaluation check — none of them booted anything.
          checks.install-boot = detach (
            _:
            import ./tests/install-boot.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              diskoSrc = inputs.disko;
            }
          );

          # Guards the clan-core adoption. clan-core is pinned to `main` — their
          # unstable channel — and every node applies its flake from git on a
          # timer, so this check is what makes each clan bump a reviewable diff
          # instead of a remote surprise. Run it on every bump.
          checks.clan-coexist = detach (
            _:
            import ./tests/clan-coexist.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              topology = fixtureTopology;
              clusterLib = import ./lib { inherit (nixpkgs) lib; };
              clanSystem = self.nixosConfigurations.node1;
            }
          );

          # Boots the fixture node1 (its real machine module, fixture secrets, a
          # stand-in internet) twice and requires the whole cold-start chain to
          # converge: network, etcd, JuiceFS on S3, Nomad + ACLs + every app's job,
          # Prometheus/Loki. See tests/lib/cluster-harness.nix.
          checks.cluster-single = detach (
            _:
            import ./tests/cluster-single.nix {
              inherit pkgs lib;
              clan = fixtureCluster;
              harness = fixtureHarness;
            }
          );

          # Three nodes, as a topology is once node2/node3 are real voters: etcd
          # and Nomad quorum, one JuiceFS volume across nodes, and Nomad-run
          # containers (probe apps) with cross-node reachability, pinning and
          # fencing.
          checks.cluster = detach (_: clusterTest { });

          # Nomad's PKI without booting anything: the real generators' certificates, their
          # names, chain, validity, the gossip file, and a minted JWT.
          checks.nomad-pki = detach (
            _:
            import ./tests/nomad-pki.nix {
              inherit
                pkgs
                lib
                fixtureCluster
                fixtureTopology
                ;
            }
          );

          # A machine on the control VLAN with each credential an attacker could hold,
          # against node1's Nomad: what TLS and the gossip key refuse, and the one limit.
          # And against the control mesh: what a machine on the VLANs reaches without a key.
          checks.control-plane-attack = detach (_: controlPlaneAttack { });

          # What the control plane does when its own pieces fail, on node1 and an installed
          # node2: the mesh cut, a key rotated on one side, a node booted without its key,
          # every Nomad certificate expired.
          checks.control-plane-failure = detach (
            _:
            import ./tests/control-plane-failure.nix {
              inherit pkgs lib;
              mkClan = mkFixtureCluster;
              topology = fixtureTopology;
              harnessFor =
                topology:
                import ./tests/lib/cluster-harness.nix {
                  inherit pkgs lib topology;
                };
            }
          );

          # MTU 9000 on the vRack and 8920 on the mesh (D25), on a link that carries it and
          # on one that silently doesn't.
          checks.jumbo-mtu = detach (_: jumboMtu { });

          # Container to host and container to container: default-deny, with the holes an
          # app declares named by its bridge port (design WS9, Appendix E).
          checks.container-isolation = detach (_: containerIsolation { });

          # One Nomad voter to three: the first voter's switch, a worker promoted, a fresh
          # voter, etcd formed once three nodes carry it, and the bootstrap_expect trap
          # (design WS10). Order A; order B is legacyPackages.mutants.voter-growth-order-b.
          checks.voter-growth = detach (_: voterGrowth { });

          # The JuiceFS volume is encrypted; a plaintext one is refused at format and at
          # mount; restore works with the key, only with the key, and from escrow alone
          # (design WS11).
          checks.jfs-encrypted = detach (_: jfsEncrypted { });

          # Per class: plant the canary, scan, found; remove it, scan, not found. Swap plain
          # against dm-crypt, the bucket of a plaintext volume against the encrypted one, a
          # real zstd core that a grep cannot see into.
          checks.canary-scan = detach (_: canaryScan { });

          # The Tang host: Tang only on the private NIC and to its clients, SSH only on the
          # public one; the key guard refuses where stock tangd would mint keys; rotation
          # with a t=2 Clevis client; the verified probe and /rec events reach the real
          # Worker, and a receiver outage delays them without losing one (design WS15).
          checks.tang-server = detach (_: tangServer { });

          # The boot security posture and its one opt-out: what evaluates, what is
          # refused, and that each refusal is for the reason it claims. Eval only.
          checks.security-policy = detach (
            _:
            import ./tests/security-policy.nix {
              inherit
                pkgs
                lib
                mkCluster
                mkOpsIndex
                mkFixtureCluster
                fixtureCluster
                fixtureTopology
                ;
              libraryInputs = {
                inherit (inputs)
                  clan-core
                  lanzaboote
                  disko
                  nixpkgs
                  ;
              };
            }
          );

          # The security-policy subtests that need a whole fixture toplevel per node.
          # Apart because those are about 9 GB of evaluation, and `nix flake check` forces
          # them anyway for nixosConfigurations.
          checks.security-policy-fixture = detach (
            _:
            import ./tests/security-policy-fixture.nix {
              inherit
                pkgs
                lib
                fixtureCluster
                fixtureTopology
                ;
            }
          );

          # What a pull deploy does with a closure that fails, a closure that changes
          # what an unlock depends on, and a frozen PID 1.
          checks.deploy-safety = detach (
            _:
            import ./tests/deploy-safety.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
            }
          );

          # The merge gates' workflows (.github/, the template's .github/) and tools/ci:
          # linted, their structure held, the scripts run against a stub nix.
          checks.ci-workflows = detach (
            _:
            import ./tests/ci-workflows.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
            }
          );

          # The README held to the code: the check table, the commands, the topology, alert
          # and secrets tables, and no private address (design WS16). Reads check names
          # only, so no check is forced.
          checks.docs = detach (
            _:
            import ./tests/docs.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              checkNames = builtins.attrNames self'.checks;
            }
          );

          # The staged rollout: a follower activates a new boot stack only after the canary
          # has booted it cleanly (design D22, modules/pull-deploy-core.nix).
          checks.canary-gate = detach (
            _:
            import ./tests/canary-gate.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
            }
          );

          # The encrypted boot path, installed with the real disko script and booted from
          # those disks, through Lanzaboote with keys made on the node. Nothing is bound
          # yet, so the passphrase is typed. See tests/lib/boot-harness.nix.
          checks.boot-fallback = detach (_: bootTest ./tests/boot-fallback.nix { });
          checks.boot-degraded = detach (_: bootTest ./tests/boot-degraded.nix { });
          checks.boot-install = detach (_: bootTest ./tests/boot-install.nix { });
          checks.boot-attack = detach (_: bootTest ./tests/boot-attack.nix { });

          # What can be proven about a closure without booting it: the ESP budget, and when
          # the boot contract moves.
          checks.boot-closure = detach (
            _:
            import ./tests/boot-closure.nix {
              inherit
                pkgs
                lib
                mkCluster
                ;
            }
          );

          # Named mutants: one control removed, and the assertion that must flip
          # (tests/lib/control.py). Not in `checks`, so they add nothing to `nix flake
          # check`. tests/run-mutants.sh runs them all; a workstream runs its own.
          legacyPackages.mutants = {
            # Nothing holds the import back for a slow human.
            boot-no-gate = detach (
              _:
              bootTest ./tests/boot-fallback.nix {
                mutant = "slow-human-gate";
                extraModule =
                  { lib, ... }:
                  {
                    boot.initrd.systemd.services.rpool-unlock-gate.enable = lib.mkForce false;
                  };
              }
            );
            # The gate's first design: any leg whose device exists is pending. A present disk
            # that can never open then hangs the whole mirror, which was the blocker.
            gate-waits-on-failed-unit = detach (
              _:
              bootTest ./tests/boot-degraded.nix {
                mutant = "disk-luks-header-corrupt";
                extraModule =
                  { config, lib, ... }:
                  {
                    boot.initrd.systemd.services.rpool-unlock-gate.script = lib.mkForce ''
                      deadline=$(($(date +%s) + 30))
                      while :; do
                        pending=0
                        ${lib.concatStrings (
                          lib.mapAttrsToList (name: leg: ''
                            if [ ! -e /dev/mapper/${name} ]; then
                              if [ -e ${leg.device} ] || [ "$(date +%s)" -lt "$deadline" ]; then
                                pending=1
                              fi
                            fi
                          '') config.boot.initrd.luks.devices
                        )}
                        [ "$pending" = 0 ] && break
                        sleep 1
                      done
                    '';
                  };
              }
            );
            # cryptsetup's default of three tries, so mistyping fails the leg.
            boot-tries-default = detach (
              _:
              bootTest ./tests/boot-fallback.nix {
                mutant = "wrong-then-right";
                extraModule =
                  { lib, ... }:
                  let
                    withoutTries = lib.mkForce [
                      "nofail"
                      "x-systemd.device-timeout=30s"
                    ];
                  in
                  {
                    disko.devices.disk.nvme0.content.partitions.luks.content.settings.crypttabExtraOpts = withoutTries;
                    disko.devices.disk.nvme1.content.partitions.luks.content.settings.crypttabExtraOpts = withoutTries;
                  };
              }
            );
            # The check is simply not there, so the forged root's payload runs.
            identity-check-removed = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "forged-identity-mismatch";
                extraModule =
                  { lib, ... }:
                  {
                    boot.initrd.systemd.services.volume-identity-check.enable = lib.mkForce false;
                  };
              }
            );
            # Merely before switch-root, which is what the check used to promise.
            # initrd-nixos-activation runs prepare-root from the root inside the initrd, and that
            # comes first here, so the payload runs. Ordering only before
            # initrd-switch-root.target isn't this: that target comes before activation, and the
            # check still halts in time.
            identity-check-late = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "forged-identity-mismatch";
                extraModule =
                  { lib, ... }:
                  {
                    boot.initrd.systemd.services.volume-identity-check = {
                      after = lib.mkForce [
                        "sysroot.mount"
                        "initrd-nixos-activation.service"
                      ];
                      before = lib.mkForce [ "initrd-switch-root.service" ];
                      requiredBy = lib.mkForce [ "initrd-switch-root.service" ];
                    };
                  };
              }
            );
            # Scans the raw partitions as well, so a plaintext pool there is a candidate.
            # The core's own assertion goes too, or this would never evaluate.
            boot-zfs-any-devnodes = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "plain-pool-not-imported";
                extraModule =
                  { lib, ... }:
                  {
                    assertions = lib.mkForce [ ];
                    boot.zfs.devNodes = lib.mkForce "/dev/disk/by-id";
                  };
              }
            );
            # The keys are made and never enrolled, so nothing is enforcing.
            sb-unenrolled = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "unsigned-loader-refused";
                skipEnroll = true;
              }
            );
            # A dead disk's leg takes cryptsetup.target down with it. It doesn't stop the
            # boot: that's the gate, and what disk-a-dead proves is not this.
            luks-no-nofail = detach (
              _:
              bootTest ./tests/boot-degraded.nix {
                mutant = "disk-a-dead-encrypted-volumes-target-holds";
                extraModule =
                  { lib, ... }:
                  let
                    withoutNofail = lib.mkForce [
                      "tries=0"
                      "x-systemd.device-timeout=30s"
                    ];
                  in
                  {
                    disko.devices.disk.nvme0.content.partitions.luks.content.settings.crypttabExtraOpts = withoutNofail;
                    disko.devices.disk.nvme1.content.partitions.luks.content.settings.crypttabExtraOpts = withoutNofail;
                  };
              }
            );
            # One ESP is installed, and the other stays as disko left it.
            single-esp = detach (
              _:
              bootTest ./tests/boot-degraded.nix {
                mutant = "disk-a-dead";
                extraModule =
                  { lib, ... }:
                  {
                    cluster.boot.espMounts = lib.mkForce [ "/boot" ];
                  };
              }
            );
            # Lanzaboote's own hook, which writes through an unmounted ESP into the root.
            upstream-install-hook = detach (
              _:
              bootTest ./tests/boot-degraded.nix {
                mutant = "esp-unmounted-guard";
                extraModule =
                  {
                    config,
                    lib,
                    pkgs,
                    ...
                  }:
                  let
                    lz = config.boot.lanzaboote;
                  in
                  {
                    boot.loader.external.installHook = lib.mkOverride 10 (
                      pkgs.writeShellScript "lzbt-upstream" ''
                        PATH=${config.systemd.package}/lib/systemd:$PATH
                        for esp in /boot /boot-fallback; do
                          ${lz.installCommand} \
                            --public-key=${toString lz.publicKeyFile} \
                            --private-key=${toString lz.privateKeyFile} \
                            --protected-system=${lz.protectedSystem} \
                            "$esp" /nix/var/nix/profiles/system-*-link
                        done
                      ''
                    );
                  };
              }
            );
            # nixpkgs' random-seed unit as it comes: bootctl writes through /boot whether the
            # ESP is mounted there or not, so with the first disk dead it writes to the root.
            random-seed-any-boot = detach (
              _:
              bootTest ./tests/boot-degraded.nix {
                mutant = "disk-a-dead-unmounted-esp-untouched";
                extraModule =
                  { lib, ... }:
                  {
                    systemd.services.systemd-boot-random-seed = {
                      after = lib.mkForce [ ];
                      unitConfig.ConditionPathIsMountPoint = lib.mkForce "/";
                    };
                  };
              }
            );
            # A mapping called crypt-something passes, whatever it really is.
            audit-name-only = detach (
              _:
              bootTest ./tests/boot-degraded.nix {
                mutant = "no-plain-vdev";
                extraModule =
                  {
                    config,
                    lib,
                    pkgs,
                    ...
                  }:
                  {
                    systemd.services.cluster-boot-audit.serviceConfig.ExecStart = lib.mkForce (
                      pkgs.writeShellScript "cluster-boot-audit" (
                        lib.replaceStrings
                          [
                            ''dmsetup table "$(basename "$v")" | grep -q ' crypt ' || bad=$((bad + 1))''
                          ]
                          [ ":" ]
                          config.system.build.auditText
                      )
                    );
                  };
              }
            );
            # ── Clevis (WS4) ───────────────────────────────────────────────────────
            # nixpkgs' clevis without the reply fix, the fleet's other fixes kept: its
            # askpass hands every recovered key to pkgs.systemd's reply binary, which the
            # initrd doesn't have. The build gate refuses this closure before any boot
            # (boot-closure proves that); it is taken out here so that the boot itself can
            # be shown to fail.
            clevis-stock-package = detach (
              _:
              bootTest ./tests/boot-install.nix {
                mutant = "unattended-both-devices";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.boot.clevisPackage = lib.mkForce (config.system.build.clevisFor { replyFix = false; });
                    system.checks = lib.mkForce [ (config.system.build.espBudgetFor 1024) ];
                  };
              }
            );
            # Clevis that can unlock, without --max-time: stuck forever on a silent Tang.
            clevis-no-maxtime = detach (
              _:
              bootTest ./tests/boot-fallback.nix {
                mutant = "tarpit-max-time-recovers";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.boot.clevisPackage = lib.mkForce (config.system.build.clevisFor { maxTime = false; });
                  };
              }
            );
            # Clevis that recovers a device's key again for every question it asks: a reply
            # that was lost costs another /rec at Tang.
            clevis-askpass-no-memory = detach (
              _:
              bootTest ./tests/boot-install.nix {
                mutant = "askpass-one-recovery-per-device";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.boot.clevisPackage = lib.mkForce (config.system.build.clevisFor { recoverOnce = false; });
                  };
              }
            );
            # Emergency mode with PCR 7 intact: the shell asks Clevis for the key.
            no-pcr-burn = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "emergency-burn-refused";
                extraModule =
                  { lib, ... }:
                  {
                    boot.initrd.systemd.services.emergency-pcr-burn.enable = lib.mkForce false;
                  };
              }
            );
            # The Tang VLAN left up into stage 2.
            no-vlan-teardown = detach (
              _:
              bootTest ./tests/boot-install.nix {
                mutant = "tang-vlan-gone-in-stage2";
                extraModule =
                  { lib, ... }:
                  {
                    boot.initrd.systemd.services.vlan-teardown.enable = lib.mkForce false;
                  };
              }
            );
            # The seal tool without its Secure Boot check. Its own refusal goes; the bind still
            # fails, since Setup Mode logs no authority and need_own_authority_only refuses too.
            seal-no-sb-check = detach (
              _:
              bootTest ./tests/boot-install.nix {
                mutant = "bind-refused-in-setup-mode";
                sealEdit = builtins.replaceStrings [ "need_enforcing\n    need_unburned" ] [ "need_unburned" ];
              }
            );
            # No initrd SSH: nobody without a console can answer the prompt.
            no-initrd-ssh-network = detach (
              _:
              bootTest ./tests/boot-fallback.nix {
                mutant = "drop-ssh";
                extraModule =
                  { lib, ... }:
                  {
                    boot.initrd.network.ssh.enable = lib.mkForce false;
                  };
              }
            );
            # Bound to the TPM with no PCR at all: it unseals whatever the firmware trusts.
            bind-pcr-none = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "sb-toggled-off";
                sealEdit =
                  builtins.replaceStrings
                    [ '',tpm2:[{pcr_bank:"sha256",pcr_ids:"7"}]'' ]
                    [ '',tpm2:[{pcr_bank:"sha256"}]'' ];
              }
            );

            # Bind trusts any PCR 7: a value an earlier-logged authority lets anyone replay.
            bind-any-authority = detach (
              _:
              bootTest ./tests/boot-attack.nix {
                mutant = "foreign-authority-bind-refused";
                sealEdit =
                  builtins.replaceStrings
                    [ "need_unburned\n    need_own_authority_only\n" ]
                    [ "need_unburned\n" ];
              }
            );
            # The advertisement's signature is not checked: only the thumbprints are.
            seal-no-adv-signature-check = detach (
              _:
              bootTest ./tests/boot-install.nix {
                mutant = "bind-refused-forged-signature";
                sealEdit =
                  builtins.replaceStrings
                    [ "if ! printf '%s' \"$sig\" | jose jws ver" ]
                    [ "if false && printf '%s' \"$sig\" | jose jws ver" ];
              }
            );

            # No guard at boot: the timer's first tick re-activates the closure the operator
            # escaped at the console.
            rollback-guard-removed = detach (
              _:
              import ./tests/deploy-safety.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "rollback-refused-at-boot";
                extraModule =
                  { lib, pkgs, ... }:
                  {
                    systemd.services.cluster-upgrade-rollback-guard.serviceConfig.ExecStart =
                      lib.mkForce "${pkgs.coreutils}/bin/true";
                  };
              }
            );
            # nix.gc's own collection: the booted generation's link goes after 14 days.
            gc-deletes-booted = detach (
              _:
              import ./tests/deploy-safety.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "gc-keeps-the-booted-generation";
                generationGc = pkgs.writeShellScriptBin "cluster-generation-gc" ''
                  ${pkgs.nix}/bin/nix-collect-garbage --delete-older-than 14d
                '';
              }
            );

            # ── Nomad (WS5) ────────────────────────────────────────────────────────
            # No gossip key on node1: serf takes anyone, so a machine with no credentials
            # at all is a member (and only TLS keeps it out of raft).
            nomad-no-gossip = detach (
              _:
              controlPlaneAttack {
                mutant = "rogue-server-no-creds";
                extraModule =
                  { lib, ... }:
                  {
                    services.nomad.extraSettingsPaths = lib.mkForce [ ];
                  };
              }
            );
            # Any CA-signed certificate may be a server: a worker's, stolen with the gossip
            # key, joins raft and is promoted.
            nomad-no-verify-hostname = detach (
              _:
              controlPlaneAttack {
                mutant = "rogue-stolen-client-cert";
                extraModule =
                  { lib, ... }:
                  {
                    services.nomad.settings.tls.verify_server_hostname = lib.mkForce false;
                  };
              }
            );

            # ── Nomad scoped tokens (WS6) ──────────────────────────────────────────
            # The fence asks for allocations without naming the apps namespace. Its scoped
            # token is refused there (with a management token it would get `200 []` and
            # stop everything), so it fences nothing: the orphan must survive.
            fence-no-namespace = detach (
              _:
              clusterTest {
                mutant = "fence-stops-orphan";
                extraModule =
                  {
                    config,
                    lib,
                    pkgs,
                    ...
                  }:
                  {
                    systemd.services.nomad-fence.serviceConfig.ExecStart = lib.mkForce (
                      let
                        text = config.system.build.nomadFenceText;
                        edited = builtins.replaceStrings [ "/v1/allocations?namespace=apps&" ] [ "/v1/allocations?" ] text;
                      in
                      # Fails loudly when the query moves, rather than proving nothing.
                      assert edited != text;
                      "${pkgs.writeShellScript "nomad-fence" edited}"
                    );
                  };
              }
            );

            # The fence's fail-safe made unsafe: a 5xx (no leader) reads as an empty list,
            # so the local agent's node ID and "no allocation here" stop every container.
            # fence-failsafe-on-5xx must notice.
            fence-5xx-reads-empty = detach (
              _:
              clusterTest {
                mutant = "fence-failsafe-on-5xx";
                extraModule =
                  {
                    config,
                    lib,
                    pkgs,
                    ...
                  }:
                  {
                    systemd.services.nomad-fence.serviceConfig.ExecStart = lib.mkForce (
                      let
                        text = config.system.build.nomadFenceText;
                        line = ''Nomad not answering; fencing nothing (fail-safe)"'';
                        edited = builtins.replaceStrings [ line ] [ ''${line}; echo '[]' > "$2"; return 0'' ] text;
                      in
                      # Fails loudly when the branch moves, rather than proving nothing.
                      assert edited != text;
                      "${pkgs.writeShellScript "nomad-fence" edited}"
                    );
                  };
              }
            );

            # ── raw_exec lockdown (WS7) ────────────────────────────────────────────
            # No deny list: a task with no user runs as the agent, root.
            raw-exec-no-denied-uids = detach (
              _:
              controlPlaneAttack {
                mutant = "raw-exec-root-denied";
                extraModule =
                  { lib, ... }:
                  {
                    services.nomad.settings.plugin.raw_exec.config = lib.mkForce { enabled = true; };
                  };
              }
            );
            # No output rule: a task as nomad-apps reaches loopback, the VLAN and the
            # internet like anyone else.
            no-skuid-rule = detach (
              _:
              controlPlaneAttack {
                mutant = "task-has-no-network";
                extraModule =
                  { config, lib, ... }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        text = config.system.build.clusterNftablesRuleset;
                        edited = builtins.replaceStrings [ "meta skuid 4096 reject" ] [ "" ] text;
                      in
                      # Fails loudly when the rule moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );
            # /mnt/jfs left as JuiceFS formats it, /state/clients as mkdir makes it.
            state-clients-0755 = detach (
              _:
              controlPlaneAttack {
                mutant = "task-cannot-read-jfs-or-state";
                extraModule =
                  { lib, ... }:
                  {
                    systemd.services.jfs-health.serviceConfig.ExecStartPost = lib.mkForce [ ];
                    systemd.tmpfiles.settings."10-cluster-client-state"."/state/clients".d.mode = lib.mkForce "0755";
                  };
              }
            );

            # ── The control mesh and MTU (WS8) ─────────────────────────────────────
            # No weak-host drop: the kernel answers ping for the mesh address on the
            # control VLAN. Only ping: every mesh accept names wg-ctrl, and br-app is
            # default-deny, so no mesh service answers either way (defence in depth).
            no-weak-host-rule = detach (
              _:
              controlPlaneAttack {
                mutant = "weak-host-route-refused";
                extraModule =
                  { config, lib, ... }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        text = config.system.build.clusterNftablesRuleset;
                        rule = ''iifname != "${clusterLib.net.meshIf}" ip daddr ${fixtureTopology.mesh.subnet} drop'';
                        edited = builtins.replaceStrings [ rule ] [ "" ] text;
                      in
                      # Fails loudly when the rule moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );
            # The control VLAN trusted, as before the mesh, and a mesh service bound on the
            # control IP as well (node_exporter on every address). Either alone shows
            # nothing: the bind is refused by the firewall, and the firewall alone has only
            # sshd to expose. So the mutant is the old posture: both.
            mesh-open-on-vlan = detach (
              _:
              controlPlaneAttack {
                mutant = "vlan-only-nomad-and-wg-open";
                extraModule =
                  { config, lib, ... }:
                  {
                    services.prometheus.exporters.node.listenAddress = lib.mkForce "0.0.0.0";
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        text = config.system.build.clusterNftablesRuleset;
                        ctrlIf = "${fixtureTopology.nodes.node1.vrackInterface}.${toString fixtureTopology.vlans.control.id}";
                        anchor = ''iifname "${ctrlIf}" ip saddr ${fixtureTopology.vlans.control.subnet} udp dport'';
                        edited =
                          builtins.replaceStrings
                            [ anchor ]
                            [
                              ''
                                iifname "${ctrlIf}" accept
                                                ${anchor}''
                            ]
                            text;
                      in
                      assert edited != text;
                      edited
                    );
                  };
              }
            );
            # The trunk at 1500. The design's mutant only left the trunk's MTU unset, and
            # that changes nothing [RAN]: networkd raises a parent to fit a VLAN asking for
            # more. So the trunk is pinned at 1500, which a VLAN can't exceed.
            trunk-mtu-unset = detach (
              _:
              jumboMtu {
                mutant = "vlan-mtus-applied";
                extraModule =
                  { lib, ... }:
                  {
                    systemd.network.networks."15-vrack".linkConfig = lib.mkForce {
                      RequiredForOnline = "no";
                      MTUBytes = "1500";
                    };
                  };
              }
            );
            # No MTU probing: TCP over a VLAN that drops jumbo frames retransmits full-size
            # segments forever.
            no-mtu-probing = detach (
              _:
              jumboMtu {
                mutant = "blackhole-tcp-recovers";
                extraModule =
                  { lib, ... }:
                  {
                    boot.kernel.sysctl."net.ipv4.tcp_mtu_probing" = lib.mkForce 0;
                  };
              }
            );

            # ── Container default-deny (WS9) ───────────────────────────────────────
            # No bridge table: no marks, no port-to-port drop, no address enforcement on
            # the WAN veths. A container that takes a declared app's IP and MAC is then
            # that app, to anything on its bridge.
            no-bridge-guard = detach (
              _:
              containerIsolation {
                mutant = "spoofed-marked-source-refused";
                extraModule =
                  { config, lib, ... }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        text = config.system.build.clusterNftablesRuleset;
                        edited = builtins.replaceStrings [ config.system.build.clusterNftablesBridgeGuard ] [ "" ] text;
                      in
                      # Fails loudly when the table moves, rather than proving nothing.
                      assert edited != text;
                      assert !(lib.hasInfix "table bridge guard {" edited);
                      edited
                    );
                  };
              }
            );
            # br-app trusted again, as before default-deny: every host port a container can
            # route to answers it.
            br-app-accept-all = detach (
              _:
              containerIsolation {
                mutant = "host-ports-denied";
                extraModule =
                  { config, lib, ... }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        text = config.system.build.clusterNftablesRuleset;
                        edited = builtins.replaceStrings [ ''iifname "br-app" drop'' ] [ ''iifname "br-app" accept'' ] text;
                      in
                      assert edited != text;
                      edited
                    );
                  };
              }
            );

            # Two containers' WAN veths may talk: each one's GUA is open to the others on
            # br-wan, with only the guests' own firewalls between them.
            no-vw-isolation = detach (
              _:
              containerIsolation {
                mutant = "wan-segment-l2-denied";
                extraModule =
                  { config, lib, ... }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        text = config.system.build.clusterNftablesRuleset;
                        edited = builtins.replaceStrings [ ''iifname "vw-*" oifname "vw-*" drop'' ] [ "" ] text;
                      in
                      assert edited != text;
                      assert !(lib.hasInfix ''oifname "vw-*"'' edited);
                      edited
                    );
                  };
              }
            );
            # Neighbour adverts judged by their source alone, as before: a container's
            # advert from its own link-local address may claim any target.
            no-nd-guard = detach (
              _:
              containerIsolation {
                mutant = "nd-spoof-refused";
                extraModule =
                  {
                    config,
                    lib,
                    node,
                    ...
                  }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        net = clusterLib.net;
                        text = config.system.build.clusterNftablesRuleset;
                        rules = map (
                          n:
                          ''iifname "${net.appWanPort n}" icmpv6 type nd-neighbor-advert icmpv6 taddr != { ${net.gua6 node n}, ${net.appWanLinkLocal node n} } drop''
                        ) (lib.attrNames config.cluster.appFirewall.apps);
                        edited = builtins.replaceStrings rules (map (_: "") rules) text;
                      in
                      assert edited != text;
                      assert !(lib.hasInfix "icmpv6 taddr" edited);
                      edited
                    );
                  };
              }
            );
            # No MAC rule on the WAN veths: a container that sends as the gateway's MAC
            # moves the gateway onto its own port in br-wan's forwarding table.
            no-wan-mac-pin = detach (
              _:
              containerIsolation {
                mutant = "wan-mac-pinned";
                extraModule =
                  {
                    config,
                    lib,
                    node,
                    ...
                  }:
                  {
                    networking.nftables.ruleset = lib.mkForce (
                      let
                        net = clusterLib.net;
                        text = config.system.build.clusterNftablesRuleset;
                        rules = map (n: ''iifname "${net.appWanPort n}" ether saddr != ${net.appWanMac node n} drop'') (
                          lib.attrNames config.cluster.appFirewall.apps
                        );
                        edited = builtins.replaceStrings rules (map (_: "") rules) text;
                      in
                      assert edited != text;
                      assert !(lib.hasInfix "ether saddr !=" edited);
                      edited
                    );
                  };
              }
            );

            # ── A late control VLAN (review fix after WS10) ────────────────────────
            # The nixpkgs Nomad unit as it was: ordered only after network-online, three
            # starts in 10 s, 2 s apart. A control address that arrives a minute late
            # leaves Nomad failed (start-limit-hit), and nothing restarts it.
            nomad-start-limit-default = detach (
              _:
              import ./tests/control-plane-failure.nix {
                inherit pkgs lib;
                mkClan = mkFixtureCluster;
                topology = fixtureTopology;
                harnessFor =
                  topology:
                  import ./tests/lib/cluster-harness.nix {
                    inherit pkgs lib topology;
                  };
                mutant = "control-vlan-late-nomad-waits";
                extraModule =
                  { lib, ... }:
                  {
                    systemd.services.nomad = {
                      after = lib.mkForce [ "network-online.target" ];
                      wants = lib.mkForce [ "network-online.target" ];
                      unitConfig.StartLimitIntervalSec = lib.mkForce 10;
                      serviceConfig.RestartSec = lib.mkForce 2;
                    };
                  };
              }
            );

            # ── Voter growth (WS10) ────────────────────────────────────────────────
            # The first voter switches to the three-voter commit with the mesh peers it had
            # before: node2 is never added to its netdev, so node2 reaches none of node1's
            # mesh services. A key can't simply be left out (the core refuses a provisioned
            # peer without one), so the peer list is the single-voter site's, literally.
            growth-peers-missing = detach (
              _:
              voterGrowth {
                mutant = "mesh-peers-applied";
                firstVoterModule =
                  { lib, ... }:
                  {
                    systemd.network.netdevs."30-${clusterLib.net.meshIf}".wireguardPeers = lib.mkForce (
                      let
                        n3 = fixtureTopology.nodes.node3;
                      in
                      [
                        {
                          PublicKey = (import ./tests/lib/fixture-wg.nix).node3.public;
                          AllowedIPs = [ "${clusterLib.net.meshIp fixtureTopology n3}/32" ];
                          Endpoint = "${n3.controlIp}:${toString (clusterLib.net.meshPort fixtureTopology)}";
                          PersistentKeepalive = 25;
                        }
                      ]
                    );
                  };
              }
            );
            # The cloud fingerprinters back (an empty denylist denies nothing): every agent
            # start waits 8 s on a metadata service these hosts don't have, so the promoted
            # worker's client is back only after 9.9 s or more, past what the test allows.
            promotion-fingerprint-delay = detach (
              _:
              voterGrowth {
                mutant = "promotion-heartbeat-gap";
                extraModule =
                  { lib, ... }:
                  {
                    services.nomad.settings.client.options."fingerprint.denylist" = lib.mkForce "";
                  };
              }
            );
            # Not a mutant: the other growth order, which needs a fresh cluster of its own.
            # The design runs it as a second build beside the check rather than in it. It is
            # a normal green build when order B works, which is what run-mutants.sh asks of
            # everything here.
            voter-growth-order-b = detach (_: voterGrowth { order = "b"; });

            # ── Encrypted JuiceFS (WS11) ───────────────────────────────────────────
            # Each edits one script's text through `cluster.juicefs.scriptEdit`, and
            # asserts that the edit happened, so a listing that moves fails loudly
            # instead of proving nothing.
            #
            # The gate out of the mount script (a no-op in its place): a plaintext
            # volume mounts, with the passphrase set, as JuiceFS alone allows.
            jfs-no-gate = detach (
              _:
              jfsEncrypted {
                mutant = "refuse-plaintext-mount";
                extraModule =
                  { lib, pkgs, ... }:
                  {
                    cluster.juicefs.scriptEdit = lib.mkForce (
                      name: text:
                      let
                        gate = clusterLib.juicefs.assertEncryptedSh "${pkgs.jq}/bin/jq" "${pkgs.juicefs}/bin/juicefs";
                        edited = builtins.replaceStrings [ gate ] [ ":\n" ] text;
                      in
                      if name != "juicefs-mount" then
                        text
                      else
                        assert edited != text;
                        edited
                    );
                  };
              }
            );
            # The fake fix: the gate judges EncryptAlgo, which a plaintext volume reports
            # as aes256gcm-rsa too. Everywhere the gate runs.
            jfs-gate-on-encryptalgo = detach (
              _:
              jfsEncrypted {
                mutant = "status-field-gate";
                extraModule =
                  { lib, ... }:
                  {
                    cluster.juicefs.scriptEdit = lib.mkForce (
                      name: text:
                      let
                        edited =
                          builtins.replaceStrings
                            [ ''.Setting.EncryptKey == "removed"'' ]
                            [ ''(.Setting.EncryptAlgo // "") | startswith("aes256gcm")'' ]
                            text;
                      in
                      if
                        lib.elem name [
                          "juicefs-mount"
                          "juicefs-format"
                        ]
                      then
                        assert edited != text;
                        edited
                      else
                        text
                    );
                  };
              }
            );
            # The restore path as it was: `juicefs load` without the key reads an
            # encrypted dump as gzip ("gzip: invalid header").
            format-no-key-flags = detach (
              _:
              jfsEncrypted {
                mutant = "restore-from-dump";
                extraModule =
                  { lib, ... }:
                  {
                    cluster.juicefs.scriptEdit = lib.mkForce (
                      name: text:
                      let
                        # Plain strings: an indented one would lose the leading space.
                        flags = " --encrypt-rsa-key \"$PEM\" --encrypt-algo ${clusterLib.juicefs.encryptAlgo}";
                        load = "load \"$META\" \"$tmp/$latest\"";
                        edited = builtins.replaceStrings [ (load + flags) ] [ load ] text;
                      in
                      if name != "juicefs-format" then
                        text
                      else
                        assert edited != text;
                        edited
                    );
                  };
              }
            );

            # The restore takes the newest dump however old it is.
            jfs-restore-any-age = detach (
              _:
              jfsEncrypted {
                mutant = "stale-dump-refused";
                extraModule =
                  { lib, ... }:
                  {
                    cluster.juicefs.scriptEdit = lib.mkForce (
                      name: text:
                      let
                        edited =
                          builtins.replaceStrings [ ''&& [ "$allowed" != "$latest" ]; then'' ] [ "&& false; then" ]
                            text;
                      in
                      if name != "juicefs-format" then
                        text
                      else
                        assert edited != text;
                        edited
                    );
                  };
              }
            );
            # The S3 pair is put back only straight after a load, as before the review: a
            # restore whose config step failed leaves "removed" in the settings for good.
            jfs-s3-not-reapplied = detach (
              _:
              jfsEncrypted {
                mutant = "interrupted-restore-recovers";
                extraModule =
                  { lib, ... }:
                  {
                    cluster.juicefs.scriptEdit = lib.mkForce (
                      name: text:
                      let
                        edited =
                          builtins.replaceStrings
                            [ ''if [ "$secret" = removed ] || [ "$secret" = unreadable ] || [ "$have" != "$want" ]; then'' ]
                            [ "if false; then" ]
                            text;
                      in
                      if name != "juicefs-format" then
                        text
                      else
                        assert edited != text;
                        edited
                    );
                  };
              }
            );
            # The probe writes to /mnt/jfs whatever is (or isn't) mounted there.
            jfs-probe-no-mount-check = detach (
              _:
              jfsEncrypted {
                mutant = "probe-needs-the-mount";
                extraModule =
                  { lib, ... }:
                  {
                    cluster.juicefs.scriptEdit = lib.mkForce (
                      name: text:
                      let
                        edited =
                          builtins.replaceStrings
                            [
                              "mountpoint -q /mnt/jfs"
                              ''[ \"\$(findmnt -n -o FSTYPE -M /mnt/jfs)\" = fuse.juicefs ]''
                            ]
                            [
                              "true"
                              "true"
                            ]
                            text;
                      in
                      if name != "jfs-probe" then
                        text
                      else
                        assert edited != text;
                        assert !(lib.hasInfix "findmnt" edited);
                        edited
                    );
                  };
              }
            );

            # ── Coredumps (WS12) ───────────────────────────────────────────────────
            # The wrong fix in place of modules/coredumps-off.nix: systemd-coredump
            # off, which makes nixpkgs set the pattern to `core`, with the rest of the
            # module kept. A shell that raises its own limit then leaves `core` in its
            # working directory, and `coredump-off` has to see that file.
            coredump-enable-false = detach (
              _:
              import ./tests/logging.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                clusterLib = import ./lib { inherit (nixpkgs) lib; };
                mutant = "coredump-off";
                coredumpsModule = {
                  systemd.coredump.enable = false;
                  boot.kernel.sysctl."fs.suid_dumpable" = 0;
                  systemd.settings.Manager.DefaultLimitCORE = "0";
                };
              }
            );

            # The boot report counts Clevis's attempts, every line clevis-luks-askpass
            # logged, rather than the devices it says "Unlocked ... successfully" for. A boot
            # Tang refused is typed through while Clevis keeps trying, so `report-passphrase`
            # must then see it called a Clevis unlock.
            boot-report-counts-attempts = detach (
              _:
              bootTest ./tests/boot-fallback.nix {
                mutant = "report-passphrase";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.bootReport.script = lib.mkForce (
                      let
                        text = config.system.build.bootReportText;
                        edited = builtins.replaceStrings [ "n = len(clevis_ok)\n" ] [ "n = clevis_lines\n" ] text;
                      in
                      # Fails loudly when the listing moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );

            # ── Canary scan (WS14) ─────────────────────────────────────────────────
            # The journal class greps the journal FILES instead of reading them through
            # journalctl. journald compresses a large field, so the planted entry is not
            # in the files as text, and the class's positive control must come up empty.
            canary-raw-grep-journal = detach (
              _:
              canaryScan {
                mutant = "journal-positive-control";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.canary.script = lib.mkForce (
                      let
                        text = config.system.build.canaryScanText;
                        from = ''if c=$(journal_lines); then n=$((n + c)); else ok=0; cannot journal "journalctl failed on the host's journal"; fi'';
                        to = ''n=$((n + $(grep -rlF -f "$F" /var/log/journal /run/log/journal 2>/dev/null | wc -l)))'';
                        edited = builtins.replaceStrings [ from ] [ to ] text;
                      in
                      # Fails loudly when the listing moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );

            # ── Tang host (WS15) ───────────────────────────────────────────────────
            # No key guard: stock tangd answers an empty directory by minting keys.
            tang-no-guard = detach (
              _:
              tangServer {
                mutant = "guard-empty-no-mint";
                extraModule =
                  { lib, ... }:
                  {
                    systemd.services."tangd@".serviceConfig.ExecStartPre = lib.mkForce [ ];
                  };
              }
            );
            # The guard counts files but never parses them, so 0-byte keys pass it and tangd,
            # skipping them as unreadable, mints new ones.
            tang-guard-existence-only = detach (
              _:
              tangServer {
                mutant = "guard-zero-length";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.tangServer.guardScript = lib.mkForce (
                      let
                        text = config.system.build.tangKeyGuardText;
                        edited = builtins.replaceStrings [ ''if [ "$t.jwk" != "$k" ]; then'' ] [ "if false; then" ] text;
                      in
                      # Fails loudly when the listing moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );

            # The notifier as it was: only a literal `POST /rec/<kid>` line is posted, so a
            # recovery sent as `//rec/<kid>` (which tangd routes and answers) leaves no trace.
            tang-rec-literal-path = detach (
              _:
              tangServer {
                mutant = "rec-odd-paths-reported";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.tangServer.recNotifyScript = lib.mkForce (
                      let
                        text = config.system.build.tangRecNotifyText;
                        edited =
                          builtins.replaceStrings
                            [
                              ''REC = re.compile(r"(?:^|/)rec/+(?P<kid>[0-9A-Za-z_-]+)$")''
                              ''if m["method"] == "GET":''
                            ]
                            [
                              ''REC = re.compile(r"^/rec/(?P<kid>[0-9A-Za-z_-]+)$")''
                              ''if m["method"] != "POST" or not REC.search(m["path"]):''
                            ]
                            text;
                      in
                      # Fails loudly when the listing moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );
            # The Tang port also open on the public NIC's firewall, by a route the module's
            # assertion can't see. Only IPAddressAllow is left in front of tangd, and
            # `surface` must notice once IPAddressAllow lets everyone through.
            tang-public-port-open = detach (
              _:
              tangServer {
                mutant = "surface";
                extraModule =
                  { lib, ... }:
                  {
                    networking.firewall.extraCommands = lib.mkAfter ''
                      iptables -I nixos-fw -i eth1 -p tcp --dport 7654 -j nixos-fw-accept
                      ip6tables -I nixos-fw -i eth1 -p tcp --dport 7654 -j nixos-fw-accept
                    '';
                  };
              }
            );
            # The probe without its signature check: an /adv altered after signing passes.
            tang-probe-no-signature-check = detach (
              _:
              tangServer {
                mutant = "probe-tampered-adv-refused";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.tangServer.probeScript = lib.mkForce (
                      let
                        text = config.system.build.tangProbeText;
                        edited =
                          builtins.replaceStrings
                            [ ''printf '%s' "$sig" | jose jws ver -i <(printf '%s' "$adv") -k- -a'' ]
                            [ ":" ]
                            text;
                      in
                      # Fails loudly when the listing moves, rather than proving nothing.
                      assert edited != text;
                      edited
                    );
                  };
              }
            );

            # The running closure's contract is not compared with the candidate's.
            # The staged rollout's three controls (tests/canary-gate.nix). Each edit fails
            # loudly when its listing moves, rather than proving nothing.
            #
            # A follower that does not wait for the canary.
            canary-gate-off = detach (
              _:
              import ./tests/canary-gate.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "follower-waits-for-the-canary";
                followerModule = {
                  cluster.deploy.mutate =
                    text:
                    let
                      gate = ''if [ "$stack_new" != "$stack_cur" ]; then'';
                      edited = builtins.replaceStrings [ gate ] [ "if false; then" ] text;
                    in
                    assert edited != text;
                    edited;
                };
              }
            );
            # A canary that vouches for what it switched to, not what it booted.
            canary-publishes-what-runs = detach (
              _:
              import ./tests/canary-gate.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "a-switch-is-not-a-reboot";
                canaryModule = {
                  cluster.deploy.canary.mutate =
                    text:
                    let
                      edited =
                        builtins.replaceStrings
                          [ "booted=$(readlink -f /run/booted-system)" ]
                          [ "booted=$(readlink -f /run/current-system)" ]
                          text;
                    in
                    assert edited != text;
                    edited;
                };
              }
            );
            # A canary that vouches for a boot someone had to type the passphrase for.
            canary-publishes-any-unlock = detach (
              _:
              import ./tests/canary-gate.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "passphrase-boot-vouches-for-nothing";
                canaryModule = {
                  cluster.deploy.canary.mutate =
                    text:
                    let
                      check = ''if [ -z "$clean" ]; then'';
                      # `&& false` and not `false`: `clean` stays read, or shellcheck stops the
                      # build before the VM proves anything.
                      edited = builtins.replaceStrings [ check ] [ ''if [ -z "$clean" ] && false; then'' ] text;
                    in
                    assert edited != text;
                    edited;
                };
              }
            );
            # A canary that takes a clean report from an earlier boot as this boot's: a stack
            # whose report failed, booted by hand, would be vouched for by the last one.
            canary-publishes-stale-report = detach (
              _:
              import ./tests/canary-gate.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "stale-report-vouches-for-nothing";
                canaryModule = {
                  cluster.deploy.canary.mutate =
                    text:
                    let
                      check = ''if [ -z "$fresh" ]; then'';
                      # `&& false`, so that `fresh` stays read and shellcheck lets it build.
                      edited = builtins.replaceStrings [ check ] [ ''if [ -z "$fresh" ] && false; then'' ] text;
                    in
                    assert edited != text;
                    edited;
                };
              }
            );
            deploy-safety-no-gate = detach (
              _:
              import ./tests/deploy-safety.nix {
                inherit pkgs;
                lib = nixpkgs.lib;
                mutant = "contract-change-refused-profile-untouched";
                extraModule =
                  { config, lib, ... }:
                  {
                    cluster.deploy.package = lib.mkForce (
                      import ./lib/cluster-upgrade.nix {
                        inherit lib pkgs;
                        inherit (config.cluster.deploy) targetCommand;
                        edit =
                          text:
                          let
                            gate = ''[ "$want" != "$have" ] && '';
                            edited = builtins.replaceStrings [ gate ] [ "false && " ] text;
                          in
                          # Fails loudly when the listing moves, rather than proving nothing.
                          assert edited != text;
                          edited;
                      }
                    );
                  };
              }
            );
          };

          # Every check and mutant above is detached, so `nix flake check` holds one at a time,
          # and detaching changes no .drv (tests/eval-memory.nix). `avc` is not: it is
          # `packages.avc`, which the flake keeps anyway.
          checks.eval-memory = detach (
            _:
            import ./tests/eval-memory.nix {
              inherit pkgs lib detach;
              checks = self'.checks;
              mutants = self'.legacyPackages.mutants;
              exempt = [ "avc" ];
            }
          );

          # mkCluster as a consumer calls it, with a `self` that exports nothing,
          # and the template's own flake outputs.
          checks.mk-cluster = detach (
            _:
            import ./tests/mk-cluster.nix {
              inherit
                pkgs
                lib
                mkCluster
                mkOpsIndex
                ;
            }
          );
        };

      flake = {
        # The consumer interface (mkCluster, mkOpsIndex) and the pure helpers.
        lib = clusterLib // {
          inherit mkCluster mkOpsIndex;
        };
        inherit nixosModules;

        templates.default = {
          path = ./templates/cluster;
          description = "A private cluster flake: topology, apps/, hosts/ and a pinned input";
        };

        # Local clan service registry, for clans that want the service directly.
        # mkCluster does not depend on this output (see lib/mk-cluster.nix).
        clan.modules.cluster-roles = ./modules/cluster-roles.nix;

        # The FIXTURE cluster, not anyone's fleet: what this flake's checks run
        # against. A consumer takes these from its own mkCluster call. Keyed by
        # machine name == topology key == hostName (node1, node2, …).
        inherit (fixtureCluster.config) nixosConfigurations clanInternals;

        opsIndex = mkOpsIndex {
          clan = fixtureCluster;
          topology = fixtureTopology;
        };
      };
    };
}
