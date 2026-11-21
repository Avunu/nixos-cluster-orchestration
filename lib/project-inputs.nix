# lib/project-inputs.nix — a site's project inputs held to the library's payload flakes.
#
# A project flake (a Bedrock site, a Frappe bench, an Odoo project) is built on the
# nodes with the NixOS module of the library's own wordpress-nix, frappe-nix or
# odoo-nix. It must be built with the same one, and on the same nixpkgs, or the node
# closures carry a PHP, a MariaDB and a nixpkgs per project, and the module and the
# package disagree on their contract:
#
#   site-acme = {
#     url = "git+https://github.com/OWNER/site-acme.git?ref=main";
#     inputs.wordpress-nix.follows = "cluster/wordpress-nix";
#   };
#
# Read from flake.lock, where a follow is a path (["cluster", "wordpress-nix"]) and an
# input of its own is a node's name. A root input that takes one of the payload flakes
# is a project: that input must follow the library's, and nothing beneath the project
# may be a nixpkgs of its own. The template's `checks.project-inputs-follow` builds
# `check`; the site's merge gate runs it.
{ lib }:
rec {
  # The payload flakes the kinds import (modules/kinds/), by their input names.
  payloads = [
    "wordpress-nix"
    "frappe-nix"
    "odoo-nix"
  ];

  # What is wrong with a parsed flake.lock, as sentences; [ ] = nothing.
  problems =
    lock:
    let
      inherit (lock) nodes;
      rootInputs = nodes.${lock.root}.inputs or { };
      inputsOf = key: nodes.${key}.inputs or { };
      isNixpkgs =
        key:
        builtins.match "nixpkgs(_[0-9]+)?" key != null
        || (nodes.${key}.original.repo or "") == "nixpkgs"
        || (nodes.${key}.original.id or "") == "nixpkgs";
      # Every node beneath `key` that is its own, not a follow.
      beneath =
        key:
        let
          go =
            seen: k:
            let
              next = lib.filter (r: builtins.isString r && !(lib.elem r seen)) (lib.attrValues (inputsOf k));
            in
            lib.foldl' go (seen ++ next) next;
        in
        go [ ] key;
      projects = lib.filterAttrs (
        name: ref: builtins.isString ref && name != "cluster" && lib.any (p: (inputsOf ref) ? ${p}) payloads
      ) rootInputs;
    in
    lib.concatLists (
      lib.mapAttrsToList (
        name: ref:
        map
          (
            p:
            "${name}: its ${p} is its own, not the library's. Set inputs.${p}.follows = \"cluster/${p}\" on it in flake.nix."
          )
          (
            lib.filter (
              p:
              (inputsOf ref) ? ${p}
              &&
                (inputsOf ref).${p} != [
                  "cluster"
                  p
                ]
            ) payloads
          )
        ++ map (
          k:
          "${name}: it brings a nixpkgs of its own (flake.lock node ${k}). Make what takes it follow \"nixpkgs\"."
        ) (lib.filter isNixpkgs (beneath ref))
      ) projects
    );

  # A build that fails, naming each problem, when the lock has any. A site without a
  # lock yet has nothing to check.
  check =
    { pkgs, lockFile }:
    let
      found = if builtins.pathExists lockFile then problems (lib.importJSON lockFile) else [ ];
    in
    pkgs.runCommand "project-inputs-follow" { } (
      if found == [ ] then
        "touch $out"
      else
        lib.concatMapStrings (p: "echo ${lib.escapeShellArg p} >&2\n") found + "exit 1\n"
    );
}
