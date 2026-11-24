# lib/default.nix — cluster helper library. `import ./lib { inherit lib; }`.
{ lib }:
let
  net = import ./net.nix { inherit lib; };
in
net
// {
  net = net;
  juicefs = import ./juicefs.nix { inherit lib; };
  backupTarget = import ./backup-target.nix { inherit lib; };
  mkAppContainer = import ./mk-app-container.nix { inherit lib; };
  nomad = import ./nomad.nix;
  nomadPki = import ./nomad-pki.nix { inherit lib; };
  githubRepos = import ./github-repos.nix { inherit lib; };
  wordpress = import ./wordpress.nix { inherit lib; };
  projectInputs = import ./project-inputs.nix { inherit lib; };
}
