#!/usr/bin/env bash
# Writes one placeholder per secret the fixture catalogue declares, under
# tests/fixtures/secrets/clan-vars/, in the layout clan's age backend uses.
#
# The placeholders are not ciphertext and hold nothing. They exist because
# lib/mk-app-container.nix asserts that every secret an app mounts was generated,
# which it can only do by looking for the file; nothing ever decrypts them. The VM
# tests replace that activation step and write fixture values to the same paths
# (tests/lib/cluster-harness.nix).
#
# Run it from the repository root after adding a secret to a fixture app:
#   tests/fixtures/update-secrets.sh && git add tests/fixtures/secrets
set -euo pipefail

dir=tests/fixtures/secrets/clan-vars
rm -rf "$dir"
for machine in node1 node2 node3; do
  nix eval --raw ".#nixosConfigurations.$machine.config.clan.core.vars.generators" --apply '
    gens: builtins.concatStringsSep "\n" (builtins.concatLists (map (g:
      map (f: "${f.rel_dir}/${f.name}") (builtins.filter (f: f.secret) (builtins.attrValues g.files))
    ) (builtins.attrValues gens))) + "\n"'
done | sort -u | while read -r path; do
  name=${path##*/}
  mkdir -p "$dir/$path"
  echo "fixture placeholder, not ciphertext" > "$dir/$path/$name.age"
done
