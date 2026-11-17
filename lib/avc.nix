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
  # agenix-rekey's `agenix` (this flake's packages.agenix): `agenix rekey` after every
  # change to a secret. Without it avc runs the site's own, `nix run .#agenix`.
  agenixRekey ? null,
}:
let
  python = pkgs.python3;
  # The operators' keys are YubiKeys and a node's is its TPM's (modules/secrets.nix): age
  # finds a plugin on PATH, so the two come with the binary.
  age = pkgs.age.withPlugins (ps: [
    ps.age-plugin-yubikey
    ps.age-plugin-tpm
  ]);
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
  # age, bubblewrap: the generator runner's tests run it for real, with a plain age key
  # (tools/avc/tests/test_runner.py).
  nativeCheckInputs = [
    python.pkgs.pytestCheckHook
    pkgs.git
    pkgs.age
    pkgs.bubblewrap
    pkgs.openssh
  ];

  # A site with real ciphertext and what agenix-rekey made of it: the runner's names for
  # a node's rekeyed files are held to those (tools/avc/tests/test_runner.py).
  env.AVC_AGENIX_FIXTURE = "${../tests/fixtures/agenix}";

  # One element per wrapper argument: under __structuredAttrs (the default for
  # Python apps) a "--prefix X : y" string stays a single arg and makeWrapper
  # rejects it.
  makeWrapperArgs = [
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath (
      lib.optional (siteProvisioner != null) siteProvisioner
      ++ lib.optional (agenixRekey != null) agenixRekey
      # gh: avc opens a pull request for every change and never pushes the deploy
      # branch (tools/avc/avc/core/pr.py). It uses the operator's own `gh auth login`.
      ++ (with pkgs; [
        git
        gh
        openssh
        nix
        # A generator runs in a sandbox with no network (tools/avc/avc/core/secretstore.py).
        bubblewrap
        # `avc deploy break-glass`: build here, switch the node over SSH.
        nixos-rebuild
      ])
      ++ [ age ]
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
