# What a closure can be checked for without booting it: that it fits the ESP, and that the boot
# contract moves when, and only when, what an unlock depends on moves. The contract is what a
# pull deploy compares before activating anything (modules/pull-deploy.nix): a change that
# gets past it leaves the node needing a console and a passphrase at its next reboot, and one
# that trips it for nothing stops the fleet's deploys. So both directions are held here.
#
# Evaluation plus the build gates' own builds: the ESP budget, and initrd-contents, which is
# what makes a closure whose initrd cannot unlock fail to build.
{
  pkgs,
  lib,
  mkCluster,
}:
let
  mkSecure = import ./fixtures/secure {
    inherit mkCluster;
    self = {
      inputs = { };
      outPath = ./fixtures/secure;
    };
  };
  base = import ./fixtures/secure/topology.nix;

  node =
    {
      topology ? base,
      modules ? [ ],
      admins ? null,
    }:
    (mkSecure (
      {
        inherit topology;
        extraModules = modules;
      }
      // lib.optionalAttrs (admins != null) { inherit admins; }
    )).config.nixosConfigurations.node1;

  contractOf = args: builtins.toJSON (node args).config.cluster.deploy.bootContract;
  baseline = contractOf { };

  withNode1 = attrs: {
    topology = base // {
      nodes = base.nodes // {
        node1 = base.nodes.node1 // attrs;
      };
    };
  };

  # Each is the one thing changed, the way a real change arrives: the topology or the admins
  # list, and the vars file a regeneration would rewrite.
  mustDiffer = {
    "the identity hash" = {
      modules = [
        { cluster.boot.identity.hash = lib.mkForce (lib.fixedWidthString 64 "0" ""); }
      ];
    };
    # Library defaults, or a host file's choice: the files themselves were placed at install.
    "the identity path" = {
      modules = [ { cluster.boot.identity.path = lib.mkForce "/var/lib/elsewhere/secret"; } ];
    };
    "the initrd host key path" = {
      modules = [ { cluster.boot.ssh.hostKeyPath = lib.mkForce "/var/lib/elsewhere/initrd-key"; } ];
    };
    "the WAN interface" = withNode1 { wanInterface = "eno2"; };
    "the WAN address" = withNode1 { publicIp4 = "192.0.2.77"; };
    "the WAN gateway" = withNode1 { publicGw4 = "192.0.2.253"; };
    "initrdNicModules" = withNode1 { initrdNicModules = [ "e1000e" ]; };
    # A dataset added to the layout after install: disko never creates it on a running
    # node, and a boot waits for it (review fix; rpool/loki was one).
    "a new required mount" = {
      modules = [
        {
          fileSystems."/var/lib/ci-new" = {
            device = "rpool/ci-new";
            fsType = "zfs";
          };
        }
      ];
    };
    "the authorized keys" = {
      admins = [
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzjhNlT3jB/hrz7YezwFvYss2fpK43h3qX2P2Aj9edM other@example.com"
      ];
    };
  };
  didNotMove = lib.attrNames (lib.filterAttrs (_: args: contractOf args == baseline) mustDiffer);
  # A mount the boot does not wait for is not the contract's business.
  nofailStable =
    contractOf {
      modules = [
        {
          fileSystems."/var/lib/ci-optional" = {
            device = "rpool/ci-optional";
            fsType = "zfs";
            options = [ "nofail" ];
          };
        }
      ];
    } == baseline;

  # The bump the contract exists to let through. The version is compared as well, or this
  # could pass with a kernel that had not changed at all.
  otherKernel = {
    modules = [
      (
        { pkgs, ... }:
        {
          boot.kernelPackages = lib.mkForce pkgs.linuxPackages_6_12;
        }
      )
    ];
  };
  kernelVersion = args: (node args).config.boot.kernelPackages.kernel.version;
  kernelMoved = kernelVersion otherKernel != kernelVersion { };
  kernelStable = contractOf otherKernel == baseline;

  # The contract's own shape: an empty one would be stable across everything.
  contractFields = lib.attrNames (node { }).config.cluster.deploy.bootContract;

  # Building these reads only the kernel and the initrd.
  budgetFor = (node { }).config.system.build.espBudgetFor;
  withinBudget = budgetFor 1024;
  overBudget = pkgs.testers.testBuildFailure (budgetFor 1);

  # initrd-contents: the fixture's own gate, exactly as system.checks has it, passes. A node
  # whose initrd was built without TPM support has no token plugin to open a leg with, and
  # fails it for that reason. Built directly, since the module's assertion refuses its
  # toplevel.
  contentsOf = system: system.config.system.build.initrdContents;
  contentsPass = contentsOf (node { });
  contentsGated = lib.any (d: d.name == "check-initrd-contents") (node { }).config.system.checks;
  withoutTpm = node {
    modules = [
      {
        boot.initrd.systemd.tpm2.enable = lib.mkForce false;
      }
    ];
  };
  contentsWithoutTpm = pkgs.testers.testBuildFailure (contentsOf withoutTpm);

  fail = name: detail: ''
    echo ${lib.escapeShellArg "FAILED: ${name}: ${detail}"} >&2
    bad=1
  '';
in
pkgs.runCommand "boot-closure-checks" { } ''
  bad=0
  ${lib.optionalString (didNotMove != [ ]) (
    fail "boot-contract does not change with" (lib.concatStringsSep ", " didNotMove)
  )}
  ${lib.optionalString (!kernelMoved) (
    fail "boot-contract-kernel" "the stand-in kernel is the same version, so this proves nothing"
  )}
  ${lib.optionalString (!kernelStable) (
    fail "boot-contract-kernel" "the contract changed across a kernel change"
  )}
  ${lib.optionalString (contractFields == [ ]) (fail "boot-contract" "it has no fields")}
  ${lib.optionalString (!nofailStable) (
    fail "boot-contract-nofail" "the contract changed for a nofail mount"
  )}

  # Passing for the fixture, and refusing a limit it can't possibly fit, for that reason.
  test -e ${withinBudget} || { echo "FAILED: esp-budget: no result" >&2; bad=1; }
  if [ "$(cat ${overBudget}/testBuildFailure.exit)" = 0 ] \
    || ! grep -q 'MiB of 1 MiB' ${overBudget}/testBuildFailure.log; then
    echo "FAILED: esp-budget: a limit of 1 MiB did not fail for the budget's reason" >&2
    cat ${overBudget}/testBuildFailure.log >&2
    bad=1
  fi

  # initrd-contents: the fixture passes, and an initrd without TPM support fails on the plugin.
  ${lib.optionalString (!contentsGated) (
    fail "initrd-contents" "it is not in the secure fixture's system.checks"
  )}
  test -e ${contentsPass} || { echo "FAILED: initrd-contents: no result for the fixture" >&2; bad=1; }
  if [ "$(cat ${contentsWithoutTpm}/testBuildFailure.exit)" = 0 ] \
    || ! grep -q 'MISSING /lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so' ${contentsWithoutTpm}/testBuildFailure.log; then
    echo "FAILED: initrd-contents: an initrd without TPM support did not fail for the token plugin" >&2
    cat ${contentsWithoutTpm}/testBuildFailure.log >&2
    bad=1
  fi

  if [ "$bad" != 0 ]; then
    exit 1
  fi
  echo "esp-budget: passes for the fixture: $(grep -o 'peak .*' ${overBudget}/testBuildFailure.log | sed 's/ of 1 MiB//') of 1024 MiB"
  echo "esp-budget: fails for a synthetic limit"
  echo "initrd-contents: passes for the fixture"
  echo "initrd-contents: an initrd without TPM support fails it: $(grep -o 'MISSING .*' ${contentsWithoutTpm}/testBuildFailure.log | head -n 1)"
  echo "boot-contract: stable across kernel ${kernelVersion { }} to ${kernelVersion otherKernel}"
  echo "boot-contract: changes with: ${lib.concatStringsSep ", " (lib.attrNames mustDiffer)}"
  touch $out
''
