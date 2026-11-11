# The subtests of the security policy that have to reach a toplevel on every node of the
# opted-out fixture: about 4.5 GB allocated per node, because each of the fixture's apps
# is a container with a NixOS evaluation of its own, and about 9 GB of heap for the three.
# They are apart so that tests/security-policy.nix, which later workstreams add to and
# evaluate over and over, stays at about 5 GB. See "Memory" there.
#
# nix flake check forces these same evaluations for nixosConfigurations, so this adds
# nothing to it.
{
  pkgs,
  lib,
  fixtureCluster,
  fixtureTopology,
}:
let
  system = name: fixtureCluster.config.nixosConfigurations.${name};
  failedMessages =
    name: map (a: a.message) (lib.filter (a: !a.assertion) (system name).config.assertions);
  evaluates = name: (builtins.tryEval (system name).config.system.build.toplevel.drvPath).success;

  # systemBuilderCommands names the kernel, initrd and etc, so reading it is a toplevel's
  # worth of evaluation too.
  carriesContract =
    name:
    let
      c = (system name).config;
    in
    lib.hasInfix "> $out/boot-contract" c.system.systemBuilderCommands
    && lib.hasInfix (builtins.toJSON c.cluster.deploy.bootContract) c.system.systemBuilderCommands
    # The boot stack too (design D22): what a follower compares and the canary publishes.
    && lib.hasInfix "> $out/boot-stack" c.system.systemBuilderCommands
    && lib.hasInfix (builtins.toJSON c.cluster.deploy.bootStack) c.system.systemBuilderCommands;

  nodes = lib.attrNames fixtureTopology.nodes;
  notEvaluating = lib.filter (name: !evaluates name) nodes;
  noContract = lib.filter (name: !carriesContract name) nodes;
in
pkgs.runCommand "security-policy-fixture-checks" { } (
  if nodes != [ ] && notEvaluating == [ ] && noContract == [ ] then
    ''
      echo "the opted-out fixture evaluates on every node: ${toString nodes}"
      echo "every node's closure carries its boot contract and boot stack, as canonical JSON: ${toString nodes}"
      touch $out
    ''
  else
    ''
      echo "FAILED: the opted-out fixture does not evaluate on: ${toString notEvaluating}" >&2
      ${lib.concatMapStringsSep "\n" (m: "echo ${lib.escapeShellArg "    ${m}"} >&2") (
        lib.concatMap failedMessages notEvaluating
      )}
      echo "FAILED: no boot contract or boot stack in the closure of: ${toString noContract}" >&2
      exit 1
    ''
)
