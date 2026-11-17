#!/usr/bin/env bash
# Writes one placeholder per secret the fixture catalogue declares, under
# tests/fixtures/secrets/, in the layout of lib/secrets-layout.nix.
#
# The placeholders are not ciphertext and hold nothing. They exist because a secret
# with no file in the repository is not given to a node (modules/secrets.nix), and
# lib/mk-app-container.nix asserts that every secret an app mounts was generated, which
# it can only do by looking for the file; nothing ever decrypts them. No fixture node
# has a recipient, so nothing is rekeyed either. The VM tests replace the activation
# step and write fixture values to the same paths (tests/lib/cluster-harness.nix).
#
# The public files beside them (wg-ctrl/public) are real values, and are kept.
#
# Run it from the repository root after adding a secret to a fixture app:
#   tests/fixtures/update-secrets.sh && git add tests/fixtures/secrets
set -euo pipefail

dir=tests/fixtures
find "$dir/secrets" -name '*.age' -delete
for machine in node1 node2 node3; do
  nix eval --json ".#clusterSecrets.$machine.generators" \
    | jq -r '.[].files[] | select(.secret) | .storedAs'
done | {
  cat
  # Not in the fixture catalogue: the binary cache app tests/attic.nix declares
  # for itself (modules/kinds/attic.nix), whose generators exist only with it.
  printf 'secrets/shared/%s.age\n' cache-token/rs256.pem cache-signing/secret cache-push/token \
    cache-s3/access-key cache-s3/secret-key
} | sort -u | while read -r path; do
  mkdir -p "$dir/$(dirname "$path")"
  echo "fixture placeholder, not ciphertext" > "$dir/$path"
done
find "$dir/secrets" -type d -empty -delete
