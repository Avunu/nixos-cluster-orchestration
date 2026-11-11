# The secure fixture: a node1 that does not opt out of boot security, for evaluation
# only (tests/security-policy.nix, tests/boot-closure.nix). Nothing here boots.
#
# Under vars/ are the public values such a node reads, and under secrets/ a
# placeholder per boot secret. The placeholders are not ciphertext and hold nothing;
# nothing ever decrypts them. Every value was made once with the commands in
# modules/boot-security.nix, and the private halves and passwords were discarded, so
# no key, disk or login anywhere corresponds to them.
#
# After a change to those generators, make their files here by hand: `clan vars
# generate` would need a real recipient. tests/fixtures/update-secrets.sh looks only
# at the opted-out fixture, so it does not touch this directory.
{ self, mkCluster }:
{
  topology ? import ./topology.nix,
  extraModules ? [ ],
  admins ? import ../admins.nix,
}:
mkCluster {
  inherit
    self
    topology
    extraModules
    admins
    ;
  # A string, for the reason in ../default.nix.
  directory = toString ./.;
  meta = {
    name = "fixture-secure";
    domain = "example.com";
  };
  # The same throwaway key as the fixture proper: see ../default.nix.
  recipients = [ "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar" ];
}
