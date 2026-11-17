# The fixtures' `masterIdentities`: a recipient whose private half was discarded when
# it was generated, and an identity path that names no file. Nothing is encrypted to
# it and nothing can be rekeyed with it; tests/fixtures/agenix has a master key that
# works, for the one test that rekeys (tests/secrets-tpm.nix).
[
  {
    identity = "/var/empty/fixture-master-identity";
    pubkey = "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar";
  }
]
