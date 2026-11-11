# lib/vrl-check.nix — compile and exercise a Vector VRL program at BUILD time.
#
#   checkVrl = import ./lib/vrl-check.nix { inherit pkgs lib; };
#   system.extraDependencies = [
#     (checkVrl "normalize" [ { sample = { … }; expect = [ ''"app": "x"'' ]; } … ] source)
#   ];
#
# A derivation that builds only if `vector vrl` compiles the program and runs it
# over every sample, and each sample's output contained every `expect` string. In
# a system's extraDependencies, a program that fails it fails the system's build.
#
# Why this exists (learned the hard way): the NixOS vector module validates with
# `vector validate --no-environment`, and --no-environment skips topology
# construction -- the only place VRL is compiled. A broken program therefore
# builds clean and fails at switch-to-configuration, where Restart=always and
# StartLimitBurst=5 trip the start limit in under a second and fail the whole
# deploy. Full `validate` cannot run in the sandbox (it probes Loki and the
# journal directories); `vector vrl` needs neither.
#
# The expectations are the other half: they pin the label contract that
# Grafana, the dashboards and the Loki alert rules query by, so a remap that
# still compiles but stops emitting a label fails the build too.
#
# A dependency rather than import-from-derivation, which `nix flake check
# --no-build` cannot evaluate. Nodes build their own closure
# (modules/pull-deploy.nix), so this costs one small local build per change.
{ pkgs, lib }:
name: cases: source:
pkgs.runCommand "vrl-check-${name}"
  {
    nativeBuildInputs = [ pkgs.vector ];
    passAsFile = [ "source" ];
    inherit source;
  }
  (
    lib.concatImapStringsSep "\n" (
      i: c:
      let
        sample = pkgs.writeText "vrl-${name}-sample-${toString i}.json" (builtins.toJSON c.sample);
      in
      ''
        vector vrl --program "$sourcePath" --input ${sample} --print-object > out-${toString i}.json
        ${lib.concatMapStringsSep "\n" (e: ''
          grep -qF ${lib.escapeShellArg e} out-${toString i}.json || {
            echo "VRL check ${name}, sample ${toString i}: expected ${lib.escapeShellArg e} in the output" >&2
            cat out-${toString i}.json >&2
            exit 1
          }
        '') (c.expect or [ ])}
      ''
    ) cases
    + ''
      cp "$sourcePath" "$out"
    ''
  )
