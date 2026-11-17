# lib/github-repos.nix — the GitHub repositories a site fetches outside its flake.lock,
# and the committed file that names them.
#
# The nodes read GitHub with tokens the cluster-ci Worker mints for them, and the Worker
# decides which repositories from the site's repository alone (workers/cluster-ci/
# src/access.ts): the repository itself, every github.com input in flake.lock, and
# `github-repos.json` at its root. The file is for what no lock names: a WordPress
# site's content, fetched at evaluation (lib/mk-wordpress-site.nix), an app's
# `preview.repo`, a private submodule of a project.
#
# The Worker cannot evaluate Nix, so the list has to be a file. It must not drift from
# the configuration either, so it is not written by hand: every module adds what it
# fetches to `cluster.github.repositories` (modules/github-access.nix), `avc ci repos`
# writes the file from that, and the site's merge gate builds `check`, which fails
# unless the committed file says the same. So the list changes only by a merge, with
# the change that needs it, like the lock.
{ lib }:
rec {
  file = "github-repos.json";

  name = "[A-Za-z0-9_.-]+";

  # "OWNER/name" for a github.com URL, over https, ssh or git's own scp form; null for
  # anything else.
  repoOf =
    url:
    let
      m = builtins.match "(git\\+)?(https|ssh|git)://([^@/]+@)?github\\.com/(${name})/(${name})([/?#].*)?" url;
      scp = builtins.match "([^@/]+@)?github\\.com:(${name})/(${name})" url;
      pair =
        if m != null then
          [
            (builtins.elemAt m 3)
            (builtins.elemAt m 4)
          ]
        else if scp != null then
          [
            (builtins.elemAt scp 1)
            (builtins.elemAt scp 2)
          ]
        else
          null;
    in
    if pair == null then
      null
    else
      "${builtins.head pair}/${lib.removeSuffix ".git" (builtins.elemAt pair 1)}";

  # Every node's list as one: the apps are the same on every node, a host file's
  # additions need not be.
  collect =
    nixosConfigurations:
    lib.sort lib.lessThan (
      lib.unique (
        lib.concatMap (s: s.config.cluster.github.repositories) (lib.attrValues nixosConfigurations)
      )
    );

  # The merge gate's check: the committed file names exactly `repos`. No file is an
  # empty list, so a site that fetches nothing outside its lock needs none.
  check =
    {
      pkgs,
      directory,
      repos,
    }:
    let
      path = "${toString directory}/${file}";
      committed = if builtins.pathExists path then builtins.fromJSON (builtins.readFile path) else [ ];
      same = lib.sort lib.lessThan committed == lib.sort lib.lessThan repos;
    in
    pkgs.runCommand "github-repos" { } (
      if same then
        "touch $out"
      else
        ''
          echo ${lib.escapeShellArg "${file} does not name what this site fetches from GitHub outside flake.lock, so the nodes would be given no token for it. Run \`avc ci repos\` and commit the file."} >&2
          echo ${lib.escapeShellArg "  committed: ${builtins.toJSON committed}"} >&2
          echo ${lib.escapeShellArg "  wanted:    ${builtins.toJSON repos}"} >&2
          exit 1
        ''
    );
}
