# A check as `nix flake check` needs it, and nothing more: a derivation whose only
# contents, once read, are strings. The evaluation behind it (every NixOS system a VM
# test or policy case builds) is then garbage the moment its .drv path is known.
#
# Why. `nix flake check` keeps the flake's outputs alive until it exits, and a
# derivation from `runNixOSTest` or `runCommand` carries thunks into everything its
# evaluation touched (`nodes`, `driver`, the test's config, the strings of its script).
# So every check's evaluation stayed reachable until the last one finished, and the
# peak grew with the number of checks: 57 GB for 31 checks whose largest alone is 9 GB.
# Detached, the peak is what stays shared anyway (the fixture's nixosConfigurations,
# which the flake exports), the check being evaluated, and what the evaluator's
# conservative collector has not yet let go of: see the README for the figures.
# The same goes for tests/run-mutants.sh, which evaluates every mutant at once.
#
# How. `summary` forces the strings in place (deepSeq of the set it returns, so
# its attributes are strings, not thunks that select from the check), and `shape` is a
# separate function whose environment holds only that summary and `mk`. Neither the
# set below nor anything it refers to keeps the check's value. Keep the two functions
# apart: one `let` holding both the check and the set would keep the check alive
# through every attribute not yet read. tests/eval-memory.nix checks that every check
# is detached and that the .drv is the original's; that the memory really goes is
# measured, not tested (no check can see the evaluator's heap).
#
# A test's interactive driver and its nodes are still there: `driverInteractive`,
# `driver` and `nodes` evaluate the check AGAIN when asked for (`mk` is a function, so
# it is applied anew), and are never forced by `nix flake check` or `nix build`.
#   nix run .#checks.x86_64-linux.cluster.driverInteractive
#
# `mk` is `_: <the check>`. A check with more than one output is refused: `outPath`
# below names only `out`.
let
  summary =
    d:
    let
      s = {
        inherit (d)
          drvPath
          outPath
          name
          system
          ;
        outputs = d.outputs or [ "out" ];
      };
    in
    builtins.deepSeq s (
      if s.outputs == [ "out" ] then
        s
      else
        throw "detached-check: ${s.name} has outputs ${toString s.outputs}; only [ \"out\" ] is supported"
    );

  shape =
    mk: s:
    let
      self = {
        type = "derivation";
        inherit (s)
          drvPath
          outPath
          name
          system
          outputs
          ;
        outputName = "out";
        out = self;
        all = [ self ];
        # Evaluated again from scratch, only when asked for.
        driver = (mk null).driver;
        driverInteractive = (mk null).driverInteractive;
        nodes = (mk null).nodes;
      };
    in
    self;
in
mk: shape mk (summary (mk null))
