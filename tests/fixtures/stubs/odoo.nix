# Stands in for a project flake's built Odoo. The kind and odoo-nix read only
# `bin/odoo`, passthru.addonsPath and passthru.builtOdoo (the same stub odoo-nix's
# own tests/module-eval.nix uses), and no test ever starts it: the wiring under
# test is indifferent to what runs inside.
{ pkgs }:
pkgs.runCommand "demo-odoo-stub"
  {
    passthru = {
      addonsPath = p: "${p}/addons";
      builtOdoo = null;
    };
  }
  ''
    mkdir -p $out/bin $out/addons
    printf '#!/bin/sh\necho "fixture stub: no Odoo here" >&2\nexit 1\n' > $out/bin/odoo
    chmod +x $out/bin/odoo
  ''
