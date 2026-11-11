# Every check and every named mutant is detached (tests/lib/detached-check.nix), and
# detaching changes nothing but what stays in memory.
#
# What it guards. `nix flake check --no-build` used to grow with every check, to 57 GB,
# because the flake's outputs kept each check's systems reachable until the end.
# Detached, the same checks took 16 to 32 GB. A check added without `detach` would
# quietly keep its whole evaluation to the end again, and nothing
# else would notice: the result is the same derivation, only the memory differs. So
# this check refuses one.
#
# How it knows. A detached check's attribute names are exactly `shapeNames`; any
# derivation built the ordinary way has others (`args`, `builder`, `passthru` names,
# `drvAttrs`, ...). Reading the names forces the shape, never the check behind it, so
# this costs nothing. The positive control: an ordinary derivation must be reported,
# or the comparison proves nothing.
#
# The other guarantees, each with its own case: the .drv path is the original's, the
# interactive driver is still reachable, and a check with several outputs is refused
# loudly rather than losing an output.
# Run: nix build .#checks.<system>.eval-memory
{
  pkgs,
  lib,
  detach,
  # name -> check, as the flake exports them.
  checks,
  mutants,
  # Checks that are packages exported elsewhere, and so kept by the flake anyway.
  exempt,
}:
let
  shapeNames = builtins.attrNames (detach (_: pkgs.emptyFile));

  isDetached = v: builtins.attrNames v == shapeNames;

  notDetached =
    kind: set:
    map (n: "${kind}.${n}") (
      builtins.filter (n: !(lib.elem n exempt) && !(isDetached set.${n})) (builtins.attrNames set)
    );

  # An ordinary derivation, and one with two outputs.
  plain = pkgs.runCommand "eval-memory-plain" { } "touch $out";
  twoOutputs = pkgs.runCommand "eval-memory-two" {
    outputs = [
      "out"
      "doc"
    ];
  } "touch $out $doc";

  cases = [
    {
      name = "every check and mutant is detached";
      ok = notDetached "checks" checks == [ ] && notDetached "mutants" mutants == [ ];
      detail = notDetached "checks" checks ++ notDetached "mutants" mutants;
    }
    {
      # The positive control for the case above.
      name = "an ordinary derivation is reported as not detached";
      ok = notDetached "control" { inherit plain; } == [ "control.plain" ];
      detail = [ (toString (builtins.attrNames plain)) ];
    }
    {
      name = "the exemption names checks that exist";
      ok = lib.all (n: checks ? ${n}) exempt;
      detail = exempt;
    }
    {
      name = "a detached check has the original's .drv path, output path and name";
      ok =
        let
          d = detach (_: plain);
        in
        d.drvPath == plain.drvPath
        && d.outPath == plain.outPath
        && d.name == plain.name
        && d.outputs == [ "out" ]
        && d.type == "derivation";
      detail = [ ];
    }
    {
      # README: nix run .#checks.<system>.cluster.driverInteractive. `alerting` because it
      # is the cheapest VM test to evaluate again.
      name = "a VM test's interactive driver is still reachable";
      ok = lib.hasPrefix "/nix/store/" checks.alerting.driverInteractive.drvPath;
      detail = [ ];
    }
    {
      name = "a check with two outputs is refused, not cut to one";
      ok = !(builtins.tryEval (detach (_: twoOutputs)).drvPath).success;
      detail = [ ];
    }
  ];

  failed = builtins.filter (c: !c.ok) cases;
in
pkgs.runCommand "eval-memory-checks" { } (
  if failed == [ ] then
    ''
      echo "${toString (builtins.length cases)} eval-memory checks passed"
      echo "${toString (builtins.length (builtins.attrNames checks))} checks and ${toString (builtins.length (builtins.attrNames mutants))} mutants detached"
      touch $out
    ''
  else
    ''
      echo "FAILED:" >&2
      ${lib.concatMapStringsSep "\n" (c: ''
        echo ${lib.escapeShellArg "  - ${c.name}"} >&2
        ${lib.concatMapStringsSep "\n" (d: "echo ${lib.escapeShellArg "      ${d}"} >&2") c.detail}
      '') failed}
      exit 1
    ''
)
