# The fixture cluster: a neutral site, built the way a consumer builds theirs.
#
# A function of the topology so tests/cluster.nix can build the same site over a
# test topology. See topology.nix for what is deliberately fake.
{ self, mkCluster }:
topology:
mkCluster {
  inherit self topology;
  # A string: `nix flake check --no-build` evaluates read-only, where interpolating
  # a path below a flake's root names a store path it never adds. A real site points
  # at its flake's root, a path, which is what `agenix rekey` needs to find where the
  # rekeyed files go.
  directory = toString ./.;
  meta = {
    name = "fixture";
    domain = "example.com";
  };
  # Nothing is encrypted to it, and no node here has a recipient: under secrets/ are
  # placeholders (update-secrets.sh), and the VM tests write fixture values instead
  # (tests/lib/cluster-harness.nix).
  masterIdentities = import ./master-identities.nix;
  admins = import ./admins.nix;
  appsDir = ./apps;
  hostsDir = ./hosts;
}
