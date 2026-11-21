{
  description = "NixOS module library for clusters of systemd-nspawn containers, run by Nomad, on JuiceFS, behind Cloudflare Tunnels";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    disko = {
      url = "github:nix-community/disko";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Secrets: agenix decrypts on the node, agenix-rekey re-encrypts each secret from the
    # operators' master identities to the one host that reads it (modules/secrets.nix).
    # Pinned BY REV like Lanzaboote below: the nodes apply this flake from git on a
    # timer, and what decrypts their secrets at activation must change in one
    # reviewable commit.
    agenix = {
      url = "github:ryantm/agenix/5e5b88a0c8e56f291a108c2fe9934054d9745b2e";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    agenix-rekey = {
      url = "github:oddlama/agenix-rekey/87e5d5f2ca5de294eb5386c2773b94d58ec9773b";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-parts.follows = "flake-parts";
    };

    # Lanzaboote: Secure Boot for encrypted nodes (modules/boot-security-core.nix).
    # Pinned BY REV: nodes auto-apply, so a bump
    # must be one reviewable commit. This rev, not a release, because it is the one
    # carrying `protectedSystem`, and the one the boot tests ran against.
    lanzaboote = {
      url = "github:nix-community/lanzaboote/4b98333073bdaf9b1b5dd7d87c2dab96883b234e";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # The installer (lib/mk-cluster.nix, `installers`): nixos-anywhere with a step
    # between the kexec and the partitioning, where `avc boot install` makes the node's
    # TPM identity and hands over the partitioning secrets. Not part of what a node
    # boots, so not in the boot stack.
    nixos-install-helper = {
      url = "github:Avunu/nixos-install-helper";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.disko.follows = "disko";
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
      ...
    }:
    let
      inherit (nixpkgs) lib;
      clusterLib = import ./lib { inherit lib; };

      # modules/secrets.nix lowers every secret to agenix, so it comes with agenix and
      # agenix-rekey: a test that imports a few modules directly imports this.
      secretsModule = {
        imports = [
          inputs.agenix.nixosModules.default
          inputs.agenix-rekey.nixosModules.default
          ./modules/secrets.nix
        ];
      };

      # Everything mkCluster imports on every machine, and what `nixosModules` exports.
      clusterModuleSet = {
        zfsHost = ./modules/zfs-host.nix;
        bootSecurity = ./modules/boot-security.nix;
        clusterCommon = ./modules/cluster-common.nix;
        overlayNetwork = ./modules/overlay-network.nix;
        # The WireGuard control mesh every service but Nomad listens on.
        meshControl = ./modules/mesh-control.nix;
        storageEtcd = ./modules/storage-etcd.nix;
        storageJuicefs = ./modules/storage-juicefs.nix;
        # Its metadata database (a member on every node) and the volume's format.
        storageJuicefsPg = ./modules/storage-juicefs-pg.nix;
        storageJuicefsFormat = ./modules/storage-juicefs-format.nix;
        monitoring = ./modules/monitoring.nix;
        # Prometheus, Alertmanager and Loki, on every node (it imports the other two).
        monitoringServer = ./modules/monitoring-server.nix;
        logging = ./modules/logging.nix;
        # What the cluster's secrets are (vars), and how one is declared, kept and
        # brought to a node (secrets).
        vars = ./modules/vars.nix;
        secrets = secretsModule;
        pullDeploy = ./modules/pull-deploy.nix;
        appContainer = ./modules/app-container.nix;
        # The app catalogue (apps/, one file per app) and the kinds an
        # app can be (modules/kinds/). Keys order the module list, so
        # `freeipa` and `grafana` keep theirs.
        apps = ./modules/apps.nix;
        freeipa = ./modules/kinds/freeipa.nix;
        grafana = ./modules/kinds/grafana.nix;
        # The cluster's binary cache, and every node's use of it.
        attic = ./modules/kinds/attic.nix;
        odoo = ./modules/kinds/odoo.nix;
        frappe = ./modules/kinds/frappe.nix;
        wordpress = ./modules/kinds/wordpress.nix;
        nomadBootstrap = ./modules/nomad-bootstrap.nix;
        # Job registration, on every Nomad server.
        nomadRegister = ./modules/nomad-register.nix;
        # Namespaces, policies, and every node's scoped-token logins; the ACL bootstrap
        # on the Nomad servers.
        nomadAcl = ./modules/nomad-acl.nix;
        # The off-host audit trail (SSH logins, deploys, Nomad ACL changes) and each
        # boot's report on how it unlocked.
        auditShip = ./modules/audit-ship.nix;
        bootReport = ./modules/boot-report.nix;
        # The weekly look for the canary where client data must not be in plaintext.
        canaryScan = ./modules/canary-scan.nix;
        backup = ./modules/backup.nix;
        # An app's local state as a dataset of its own, replicated to every node, so
        # that Nomad can run the app on any of them.
        appState = ./modules/app-state.nix;
        # Deploys the moment the site's branch moves, and a preview per pull request:
        # the node's half of workers/cluster-ci.
        ciAgent = ./modules/ci-agent.nix;
        # Read access to the site's GitHub repositories: short-lived tokens from that
        # Worker, for Nix and for git.
        githubAccess = ./modules/github-access.nix;
      };
      nixosModules = clusterModuleSet;

      # `lib.mkCluster` (lib/mk-cluster.nix): a consumer's machines, from these modules.
      mkCluster = import ./lib/mk-cluster.nix {
        inherit lib clusterLib;
        libraryInputs = inputs;
        # Lanzaboote's module only acts under `boot.lanzaboote.enable`, so it changes
        # nothing on a node that opts out of boot security.
        # disko: the disk layout (modules/zfs-host.nix) is its `disko.devices`.
        clusterModules = lib.attrValues clusterModuleSet ++ [
          inputs.lanzaboote.nixosModules.lanzaboote
          inputs.disko.nixosModules.default
        ];
      };

      # What the operations tool reads (lib/ops-index.nix): nodes, apps, and
      # which vars generators each app consumes.
      mkOpsIndex =
        { site, topology }:
        import ./lib/ops-index.nix {
          inherit lib topology clusterLib;
          inherit (site) nixosConfigurations;
        };

      # What the site needs from its providers, as an OpenTofu configuration
      # (lib/cloud.nix), and where each thing they hand back goes. `avc cloud` runs it.
      mkCloud =
        { site, topology }:
        import ./lib/cloud.nix {
          inherit lib topology clusterLib;
          inherit (site) nixosConfigurations;
        };

      # The fixture cluster (tests/fixtures): what this flake's checks and its
      # nixosConfigurations are built from. A function of the topology so
      # tests/cluster.nix can build the SAME site over a test topology. Nothing
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
          # Nomad is BSL-licensed (unfree); allow it.
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
                site = fixtureCluster;
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
                mkSite = mkFixtureCluster;
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
                mkSite = mkFixtureCluster;
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
                mkSite = mkFixtureCluster;
                topology = fixtureTopology;
                harnessFor =
                  topology:
                  import ./tests/lib/cluster-harness.nix {
                    inherit pkgs lib topology;
                  };
                inherit secretsModule;
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
                inherit secretsModule;
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
                inherit secretsModule;
              }
              // args
            );
        in
        {
          _module.args.pkgs = pkgs;

          # The operations tool: status, sites, apps, secrets, deploys.
          # `.override { siteProvisioner = …; }` enables `avc site …` (lib/avc.nix).
          packages.avc = pkgs.callPackage ./lib/avc.nix { agenixRekey = self'.packages.agenix; };

          # `nix run .#agenix -- rekey | edit | view`: agenix-rekey's command, which reads
          # the flake it is run in (its `agenix-rekey` output, from mkCluster).
          packages.agenix = inputs.agenix-rekey.packages.${system}.default;
          packages.default = self'.packages.avc;

          # Its tests (policy gate, ship ordering, registry) run in the build.
          checks.avc = self'.packages.avc;

          devShells.default = pkgs.mkShell {
            packages = [
              # Secrets: rekey, edit, view (modules/secrets.nix).
              self'.packages.agenix
              pkgs.age-plugin-yubikey
              pkgs.age-plugin-tpm
              pkgs.nomad
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
              echo "nixos-cluster-orchestration devshell — agenix / nomad / juicefs"
              echo "  avc           → start here: status, sites, apps, secrets, deploys"
              echo "  agenix        → secrets: rekey, edit, view"
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
              inherit secretsModule;
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
              nodeSystem = self.nixosConfigurations.node1;
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
              nodeSystem = self.nixosConfigurations.node1;
            }
          );

          # The wordpress kind's wiring on the fixture node1: the module, the secrets and
          # where they are, the tunnel, the host's nightly copies, a preview slot.
          checks.wordpress = detach (
            _:
            import ./tests/wordpress.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              topology = fixtureTopology;
              nodeSystem = self.nixosConfigurations.node1;
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

          # The pipeline's Worker: what a webhook and a node's report make of each other.
          # TypeScript, with no dependencies: tsc checks the types (the Workers runtime
          # and Node are declared in src/workers.d.ts and test/node.d.ts, for want of
          # npm), and `node --test` runs the sources as they are, removing the types
          # itself, which Node does unasked from 24 on.
          checks.cluster-ci = detach (
            _:
            pkgs.runCommand "cluster-ci-tests"
              {
                nativeBuildInputs = [
                  pkgs.nodejs_24
                  pkgs.typescript
                ];
              }
              ''
                cp -r ${./workers/cluster-ci} w && cd w
                tsc --noEmit -p .
                node --test test/*.test.ts
                touch $out
              ''
          );

          # A node's read access to GitHub (modules/github-access.py), as a process,
          # against a stand-in Worker: what it writes and with which modes, what a
          # failed refresh keeps, and what git's credential helper answers, through
          # git itself.
          checks.github-access = detach (
            _:
            pkgs.runCommand "github-access-tests"
              {
                nativeBuildInputs = [
                  pkgs.python3
                  pkgs.git
                  # The nix a node runs (nix.package's default), for the one case that
                  # asks it to read the fragment.
                  pkgs.nix
                ];
                REQUIRE_NIX = "1";
              }
              ''
                python3 ${./tests/github-access.py} ${./modules/github-access.py}
                touch $out
              ''
          );

          # The pipeline's agent, as a process, against a stand-in Worker and stand-in
          # nix, zfs, juicefs and systemd: what it asks of them, in which order.
          checks.ci-agent = detach (
            _:
            pkgs.runCommand "ci-agent-tests"
              {
                nativeBuildInputs = [ pkgs.python3 ];
              }
              ''
                python3 ${./tests/ci-agent.py} ${./modules/ci-agent.py}
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

          # The fixture's OpenTofu configuration (lib/cloud.nix) against the providers' own
          # schemas, with the OpenTofu and the providers avc runs: every resource type and
          # argument exists, and it says what the fixture's topology and apps call for.
          checks.cloud = detach (
            _:
            let
              cloud = mkCloud {
                site = fixtureCluster;
                topology = fixtureTopology;
              };
              tofu = pkgs.opentofu.withPlugins (ps: [
                ps.ovh_ovh
                ps.cloudflare_cloudflare
                ps.hashicorp_random
              ]);
            in
            pkgs.runCommand "cloud-config-check"
              {
                nativeBuildInputs = [
                  tofu
                  pkgs.jq
                ];
                config = builtins.toJSON cloud.config;
                writeback = builtins.toJSON cloud.writeback;
                passAsFile = [
                  "config"
                  "writeback"
                ];
              }
              ''
                mkdir work && cd work
                cp "$configPath" main.tf.json
                export HOME=$PWD TF_IN_AUTOMATION=1
                tofu init -input=false -backend=false >/dev/null
                tofu validate -no-color
                want() { jq -e "$1" main.tf.json >/dev/null || { echo "missing: $2" >&2; exit 1; }; }
                want '.resource.ovh_cloud_project_storage.juicefs.name == "${fixtureTopology.objectStorage.juicefsBucket}"' "the JuiceFS bucket"
                want '.resource.ovh_cloud_project_storage.juicefs.lifecycle.prevent_destroy' "a bucket that cannot be destroyed by a plan"
                want '.resource.ovh_cloud_project_storage.state_backup.versioning.status == "enabled"' "a versioned state backup bucket"
                want '.resource.ovh_cloud_project_user_s3_policy.state_backup.policy | fromjson | .Statement[0].Action | index("s3:DeleteObjectVersion") | not' "a user that cannot delete a version"
                want '.resource.ovh_cloud_project_user_s3_policy.juicefs.policy | fromjson | .Statement[0].Resource | all(test("fixture-juicefs|${fixtureTopology.objectStorage.juicefsBucket}"))' "a policy for its own bucket only"
                want '.resource.cloudflare_zero_trust_tunnel_cloudflared."demo_odoo".config_src == "local"' "a locally configured tunnel per app"
                want '[.import[].to] | index("cloudflare_zero_trust_tunnel_cloudflared.demo_odoo")' "an import of the tunnel the app already names"
                want '.resource.cloudflare_dns_record | to_entries | all(.value.type == "CNAME" and .value.proxied)' "proxied CNAMEs"
                want '.resource.cloudflare_zero_trust_tunnel_cloudflared_route."demo_idm".network | endswith("/32")' "FreeIPA's private route"
                want '.resource.cloudflare_r2_bucket_lock.audit.rules[0].condition.max_age_seconds == 31536000' "the audit bucket's lock"
                want '.resource.cloudflare_zero_trust_tunnel_cloudflared | has("demo_site") | not' "no tunnel for an app whose tunnel is in another account"
                want '[.import[].to] | index("cloudflare_zero_trust_tunnel_cloudflared.demo_site") | not' "no import of a tunnel in another account"
                want '.resource.ovh_cloud_project_storage.wordpress_media.versioning.status == "enabled"' "a versioned WordPress media mirror"
                want '.resource.ovh_cloud_project_user_s3_policy.wordpress_media.policy | fromjson | .Statement[0].Action | index("s3:DeleteObjectVersion") | not' "a mirror user that cannot delete a version"
                want '.resource.ovh_cloud_project_storage.wordpress_dev_restore.name == "fixture-juicefs-wordpress-dev-restore"' "the WordPress dev-restore bucket"
                jq -e '.vars."s3_juicefs_secret_key" == "ovh-s3/secret-key" and .vars."s3_state_backup_access_key" == "backup-state-target/access-key" and (.tunnels."demo-odoo".known)
                  and .vars."s3_wordpress_media_access_key" == "wordpress-media-mirror/access-key"
                  and (.tunnels | has("demo-site") | not) and (.unmanagedHosts | index("demo-site.example.org"))' "$writebackPath" >/dev/null \
                  || { echo "the write-back map is wrong: $(cat "$writebackPath")" >&2; exit 1; }
                touch $out
              ''
          );

          # tunnel.accountId: what `avc cloud` makes for a tunnel in the cluster's Cloudflare
          # account, and what it leaves to whoever made one in another (tests/cloud-accounts.nix).
          checks.cloud-accounts = detach (
            _:
            import ./tests/cloud-accounts.nix {
              inherit pkgs;
              lib = nixpkgs.lib;
              clusterLib = import ./lib { inherit (nixpkgs) lib; };
            }
          );

          # An app's local state following it between three nodes with real ZFS: a
          # move that loses nothing, a dead holder, its return, and what is refused.
          checks.app-state = detach (
            _:
            import ./tests/app-state.nix {
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

          # What a node is given of the site's secrets and what it is not, where each
          # lands, what the gate holds, and what agenix-rekey says of a node whose
          # secrets were never rekeyed. Evaluation only (tests/secrets.nix).
          checks.secrets = detach (
            _:
            import ./tests/secrets.nix {
              inherit
                pkgs
                lib
                mkCluster
                fixtureCluster
                fixtureTopology
                ;
              mkSecure = import ./tests/fixtures/secure { inherit self mkCluster; };
            }
          );

          # The real path, with a software TPM: a master-encrypted secret, rekeyed by
          # agenix-rekey's own app and by avc's runner to a node's TPM recipient, decrypted
          # at boot by that TPM and by no other, and what a node that could not decrypt
          # looks like (tests/secrets-tpm.nix).
          checks.secrets-tpm = detach (
            _:
            import ./tests/secrets-tpm.nix {
              inherit
                pkgs
                lib
                mkCluster
                fixtureTopology
                ;
              harness = fixtureHarness;
              avc = self'.packages.avc;
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
              site = fixtureCluster;
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

          # The binary cache: placed by Nomad, filled by a push, read back by
          # substitution, read-only from outside, and never needed (tests/attic.nix).
          checks.attic = detach (
            _:
            import ./tests/attic.nix {
              inherit pkgs lib;
              mkSite = mkFixtureCluster;
              topology = fixtureTopology;
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
              mkSite = mkFixtureCluster;
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
                  agenix
                  agenix-rekey
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
          # A node installed through the real installer: nixos-install-helper's deploy,
          # nixos-anywhere's kexec, `avc boot stage` between it and the partitioning, the
          # identity made on the machine's TPM, the recovery key, and a TPM that is not the
          # node's (tests/install-node.nix).
          checks.install-node = detach (
            _:
            bootTest ./tests/install-node.nix {
              inherit secretsModule nixpkgs;
              installHelper = inputs.nixos-install-helper;
              avc = self'.packages.avc;
            }
          );

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

          # What a fixture is made by, when it is a build (tests/fixtures/agenix).
          legacyPackages.fixtures.secrets-tpm-rekeyed =
            (import ./tests/secrets-tpm.nix {
              inherit
                pkgs
                lib
                mkCluster
                fixtureTopology
                ;
              harness = fixtureHarness;
              avc = self'.packages.avc;
            }).rekeyed;
          # The same site rekeyed by avc's runner, which the test then decrypts on the TPM.
          legacyPackages.fixtures.secrets-tpm-avc-rekeyed =
            (import ./tests/secrets-tpm.nix {
              inherit
                pkgs
                lib
                mkCluster
                fixtureTopology
                ;
              harness = fixtureHarness;
              avc = self'.packages.avc;
            }).avcRekeyed;

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
                      "tpm2-device=auto"
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
                      "tpm2-device=auto"
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
            # ── TPM unlock ─────────────────────────────────────────────────────────
            # The initrd without TPM support: the binding is on the disk and nothing in the
            # initrd can open it, so every boot waits at the prompt, the first one after
            # the install included. The build gate that refuses such an initrd is out too,
            # or there would be no closure to boot.
            initrd-no-tpm = detach (
              _:
              bootTest ./tests/boot-install.nix {
                mutant = "first-boot-unattended";
                extraModule =
                  { lib, ... }:
                  {
                    assertions = lib.mkForce [ ];
                    system.checks = lib.mkForce [ ];
                    boot.initrd.systemd.tpm2.enable = lib.mkForce false;
                  };
              }
            );
            # Emergency mode with PCR 7 intact: the shell asks the TPM for the key.
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
                mutant = "refused-ssh";
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
                sealEdit = builtins.replaceStrings [ "--tpm2-pcrs=7 " ] [ "--tpm2-pcrs= " ];
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
                mkSite = mkFixtureCluster;
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

            # The boot report counts the legs that asked the TPM, refused or not, rather than
            # the legs it opened. A boot the TPM refused is typed through after both legs
            # asked, so `report-passphrase` must then see it called a TPM unlock.
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
                        edited = builtins.replaceStrings [ "n = len(tpm_ok)\n" ] [ "n = len(tpm_ok | tpm_refused)\n" ] text;
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

            # ── Staged rollout ─────────────────────────────────────────────────────
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

          # One Bedrock site (tests/fixtures/bedrock-site), built by wordpress-nix and booted
          # by the wordpress kind on the fixture node1: served through its socket, read-only,
          # backed up and restored, and a preview slot (tests/wordpress-site-smoke.nix). The
          # cluster template re-exports it, so a site's merge gate runs it at its own lock.
          checks.wordpress-site-smoke = detach (
            _:
            import ./tests/wordpress-site-smoke.nix {
              inherit pkgs lib;
              mkSite = mkFixtureCluster;
              topology = fixtureTopology;
              wordpressNix = inputs.wordpress-nix;
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
          inherit mkCluster mkOpsIndex mkCloud;
        };
        inherit nixosModules;

        templates.default = {
          path = ./templates/cluster;
          description = "A private cluster flake: topology, apps/, hosts/ and a pinned input";
        };

        # The FIXTURE cluster, not anyone's fleet: what this flake's checks run
        # against. A consumer takes these from its own mkCluster call. Keyed by
        # machine name == topology key == hostName (node1, node2, …).
        inherit (fixtureCluster) nixosConfigurations agenix-rekey;
        clusterSecrets = fixtureCluster.secrets;

        opsIndex = mkOpsIndex {
          site = fixtureCluster;
          topology = fixtureTopology;
        };
        cloud = mkCloud {
          site = fixtureCluster;
          topology = fixtureTopology;
        };
      };
    };
}
