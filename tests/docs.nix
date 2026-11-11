# The README, held to the code (design WS16): the check table against the flake's checks,
# the commands against avc's registry and the two node tools' usage lines, the topology,
# alert and secrets tables against the template, the fixtures, the alert rules and the
# generators, the paths and metrics against the modules, and no address or email outside
# the reserved ranges. tests/docs.py says what each check reads.
#
# Cheap on purpose: the flake's check names are read with attrNames (no check is
# forced), and the topology files are plain data. Nothing here evaluates a system.
{
  pkgs,
  lib,
  checkNames,
}:
let
  # Leaf paths of a topology, with every node's fields under `nodes.<n>`, one level deep:
  # a node field's own structure (`disks = { a; b; }`) is that field's row to explain.
  paths =
    topo:
    let
      walk =
        prefix: v:
        if builtins.isAttrs v && prefix != [ ] && lib.last prefix == "<n>" then
          map (f: prefix ++ [ f ]) (builtins.attrNames v)
        else if builtins.isAttrs v then
          lib.concatMap (k: walk (prefix ++ [ (if prefix == [ "nodes" ] then "<n>" else k) ]) v.${k}) (
            builtins.attrNames v
          )
        else
          [ prefix ];
    in
    map (lib.concatStringsSep ".") (walk [ ] topo);

  facts = {
    readme = ../README.md;
    templateReadme = ../templates/cluster/README.md;
    checks = checkNames;
    topologyPaths = lib.unique (
      lib.concatMap paths [
        (import ../templates/cluster/topology.nix)
        (import ./fixtures/topology.nix)
        (import ./fixtures/secure/topology.nix)
      ]
    );
    avcFlows = ../tools/avc/avc/flows;
    avcCore = ../tools/avc/avc/core;
    bootCore = ../modules/boot-security-core.nix;
    tangServer = ../modules/tang-server.nix;
    alertRules = [
      ../lib/alert-rules.nix
      ../lib/log-alert-rules.nix
    ];
    generatorFiles = [
      ../modules/vars.nix
      ../modules/boot-security.nix
      ../modules/backup.nix
      ../modules/alerting.nix
    ];
    modules = ../modules;
    lib = ../lib;
  };
in
pkgs.runCommand "docs-checks"
  {
    nativeBuildInputs = [ pkgs.python3 ];
    facts = builtins.toJSON facts;
    passAsFile = [ "facts" ];
  }
  ''
    python3 ${./docs.py} "$factsPath"
    touch $out
  ''
