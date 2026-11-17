# lib/secrets-layout.nix — where a site's repository keeps its secrets, and where a
# node finds them. The one place that knows; modules/secrets.nix and everything that
# hashes a ciphertext or reads a public value go through it.
#
# Under mkCluster's `directory`:
#
#   secrets/shared/<generator>/<file>.age                 one value for the fleet
#   secrets/shared/<generator>/<file>                     its public files, in the clear
#   secrets/per-machine/<node>/<generator>/<file>.age     one value per node
#   secrets/per-machine/<node>/<generator>/<file>         its public files, in the clear
#   secrets/rekeyed/<node>/                               agenix-rekey's localStorageDir
#   secrets/recipients/<node>.pub                         the node's age recipient
#
# A `.age` file is encrypted to the operators' master identities and to nothing else:
# no node can read it. `agenix rekey` re-encrypts what a node reads to that node's
# recipient and writes the result under rekeyed/<node>/, as
# <hash of recipient and source>-<scope>/<generator>/<file>.age; those files are what a
# node's closure carries. A file with `secret = false` is committed as it is, beside
# the ciphertexts, which is why no public file may be named `<something>.age`.
#
# On a node, a file a service reads is at /run/secrets/<scope>/<generator>/<file>, where
# <scope> is `shared` or `per-machine/<node>`. A file read only at install
# (`neededFor = "partitioning"`) is at /run/partitioning-secrets/<scope>/<generator>/<file>,
# put there by whatever installs the node, and is on no running node.
#
# `dir` may be a path or a string (the fixtures pass a string, tests/fixtures/default.nix).
{
  scope =
    {
      share,
      machine,
    }:
    if share then "shared" else "per-machine/${machine}";

  source =
    dir: rel: file:
    dir + "/secrets/${rel}/${file}.age";
  public =
    dir: rel: file:
    dir + "/secrets/${rel}/${file}";
  # Relative to `dir`: what the generator runner writes.
  storedAs =
    {
      rel,
      file,
      secret,
    }:
    "secrets/${rel}/${file}${if secret then ".age" else ""}";

  rekeyed = dir: machine: dir + "/secrets/rekeyed/${machine}";
  recipient = dir: machine: dir + "/secrets/recipients/${machine}.pub";

  runtimeDir = "/run/secrets";
  partitioningDir = "/run/partitioning-secrets";
}
