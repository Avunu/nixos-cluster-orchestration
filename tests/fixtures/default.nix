# The fixture cluster: a neutral site, built the way a consumer builds theirs.
#
# A function of the topology so tests/cluster.nix can build the same clan over a
# test topology. See topology.nix for what is deliberately fake.
{ self, mkCluster }:
topology:
mkCluster {
  inherit self topology;
  # A string: `nix flake check --no-build` evaluates read-only, where interpolating
  # a path below a flake's root (as clan does) names a store path it never adds. A
  # real site points at its flake's root, which is already in the store; it must
  # stay a path there, so that each secret's ciphertext joins the closure.
  directory = toString ./.;
  meta = {
    name = "fixture";
    domain = "example.com";
  };
  # A throwaway key: the private half was discarded when it was generated, and
  # nothing is encrypted to it. No vars are committed under this directory; the
  # VM tests write fixture values instead (tests/lib/cluster-harness.nix).
  recipients = [ "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar" ];
  admins = import ./admins.nix;
  appsDir = ./apps;
  hostsDir = ./hosts;
}
