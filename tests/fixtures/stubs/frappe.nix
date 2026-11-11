# Stands in for a project flake's built bench. frappe-nix reads `${pkg}/bench` and
# passthru.{pythonEnv,nodejs,appsPath} (the same stub frappe-nix's own
# tests/logging-fields.nix uses), and no test ever starts it.
{ pkgs }:
pkgs.runCommand "demo-erp-stub"
  {
    passthru = {
      pythonEnv = pkgs.emptyDirectory;
      inherit (pkgs) nodejs;
      appsPath = _: "/stub/apps";
    };
  }
  ''
    mkdir -p $out/bench/apps $out/bench/env $out/bench/sites $out/bench/config
  ''
