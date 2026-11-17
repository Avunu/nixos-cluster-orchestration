# lib/avc.nix — the operations tool (tools/avc): one guided entrypoint for
# sites, apps, secrets and deploys.
#
#   nix run .#avc            # status overview + menu
#   nix run .#avc -- --help  # every menu entry is also a subcommand
{
  pkgs,
  lib ? pkgs.lib,
  # Optional provisioning tool that `avc site ...` delegates to
  # (tools/avc/avc/flows/sites.py). Not part of this library; without it those
  # commands say so and everything else works.
  siteProvisioner ? null,
}:
let
  python = pkgs.python3;
  cloudTofu = pkgs.opentofu.withPlugins (ps: [
    ps.ovh_ovh
    ps.cloudflare_cloudflare
    ps.hashicorp_random
  ]);
in
python.pkgs.buildPythonApplication {
  pname = "avc";
  version = "0.1.0";
  pyproject = true;
  src = ../tools/avc;

  build-system = [ python.pkgs.setuptools ];
  dependencies = with python.pkgs; [
    questionary
    rich
  ];

  # git: the ship pipeline's tests run against a real clone and a protected remote
  # (tools/avc/tests/test_ship.py).
  nativeCheckInputs = [
    python.pkgs.pytestCheckHook
    pkgs.git
  ];

  # One element per wrapper argument: under __structuredAttrs (the default for
  # Python apps) a "--prefix X : y" string stays a single arg and makeWrapper
  # rejects it.
  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath (
      lib.optional (siteProvisioner != null) siteProvisioner
      # gh: avc opens a pull request for every change and never pushes the deploy
      # branch (tools/avc/avc/core/pr.py). It uses the operator's own `gh auth login`.
      ++ (with pkgs; [
        git
        gh
        openssh
        nix
      ])
      # `avc cloud` (tools/avc/avc/flows/cloud.py): OpenTofu with the providers the
      # generated configuration names (lib/cloud.nix), from the store, so `tofu init`
      # downloads nothing.
      ++ [ cloudTofu ]
    ))
  ];

  meta = {
    description = "Guided day-to-day operations for a nixos-cluster-orchestration cluster";
    mainProgram = "avc";
  };
}
