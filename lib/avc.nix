# lib/avc.nix — the operations tool (tools/avc): one guided entrypoint for
# sites, apps, secrets and deploys.
#
#   nix run .#avc            # status overview + menu
#   nix run .#avc -- --help  # every menu entry is also a subcommand
#
# Built on clan-cli's own Python so it can import clan_lib (vars status,
# generator graph) directly; tools/avc/avc/core/vars.py is the only module
# that does.
{
  pkgs,
  lib ? pkgs.lib,
  clan-cli,
  # Optional provisioning tool that `avc site ...` delegates to
  # (tools/avc/avc/flows/sites.py). Not part of this library; without it those
  # commands say so and everything else works.
  siteProvisioner ? null,
}:
let
  python = clan-cli.pythonRuntime;
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

  nativeCheckInputs = [ python.pkgs.pytestCheckHook ];
  # clan_lib on the import path for the checks as well as at runtime.
  preCheck = ''
    export PYTHONPATH=${clan-cli}/${python.sitePackages}:$PYTHONPATH
  '';

  # One element per wrapper argument: under __structuredAttrs (the default for
  # Python apps) a "--prefix X : y" string stays a single arg and makeWrapper
  # rejects it.
  makeWrapperArgs = [
    "--prefix"
    "PYTHONPATH"
    ":"
    "${clan-cli}/${python.sitePackages}"
    # clan_lib shells out to what clan-cli bundles; CLAN_PROVIDED_PACKAGES
    # tells it these are on PATH (otherwise it reaches for `nix shell`).
    "--prefix"
    "PATH"
    ":"
    (lib.makeBinPath (
      [ clan-cli ]
      ++ lib.optional (siteProvisioner != null) siteProvisioner
      ++ lib.attrValues clan-cli.runtimeDependenciesMap
      ++ (with pkgs; [
        git
        openssh
        nix
      ])
    ))
    "--set-default"
    "CLAN_PROVIDED_PACKAGES"
    (lib.concatStringsSep ":" (lib.attrNames clan-cli.runtimeDependenciesMap))
  ];

  meta = {
    description = "Guided day-to-day operations for a nixos-cluster-orchestration cluster";
    mainProgram = "avc";
  };
}
