# A site whose secrets are real ciphertext, for the one test that decrypts
# (tests/secrets-tpm.nix). Nothing here protects anything: the master key is in this
# directory in the clear, and the TPM is a software one whose whole state is too.
#
#   master-identity.txt, master.pub     the operator's master key (`age-keygen`), which a
#                                       real site keeps on a YubiKey and never in a file
#   tpm/tpm2-00.permall                 a software TPM's state (swtpm), which a test VM
#                                       started on it gets as its TPM
#   tpm/identity.txt                    that TPM's age identity
#                                       (`age-plugin-tpm --generate`, run in a VM on it)
#   secrets/recipients/node1.pub        its recipient (`age-plugin-tpm --convert`)
#   secrets/shared/canary/value.age,
#   secrets/per-machine/node1/wg-ctrl/private.age
#                                       two secrets, each `age -e -r <master.pub>`: the
#                                       value below, and node1's key from
#                                       tests/lib/fixture-wg.nix
#   secrets/per-machine/node1/wg-ctrl/public
#                                       the public half, as in tests/fixtures
#   secrets/rekeyed/node1/              what `agenix rekey` made of the two for node1
#
# After changing a secret or the recipient, rekey and commit the result:
#
#   nix build .#legacyPackages.x86_64-linux.fixtures.secrets-tpm-rekeyed
#   rm -rf tests/fixtures/agenix/secrets/rekeyed/node1
#   cp -rL --no-preserve=mode result tests/fixtures/agenix/secrets/rekeyed/node1
#
# That build runs the same app the test runs, with the master key where
# `masterIdentityAt` says: agenix-rekey takes an identity as a path on the operator's
# machine and copies none into the store, so the path has to be one that exists both
# in a build's sandbox and in a VM.
{
  directory = ./.;
  masterIdentity = ./master-identity.txt;
  masterIdentityAt = "/build/master-identity.txt";
  masterPubkey = builtins.replaceStrings [ "\n" ] [ "" ] (builtins.readFile ./master.pub);
  tpmIdentity = ./tpm/identity.txt;
  tpmState = ./tpm/tpm2-00.permall;
  canaryValue = "CANARY-agenix-fixture";
}
