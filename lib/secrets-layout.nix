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
#   secrets/<scope>/<generator>/.validation-hash          what the files were made from
#   secrets/.master-recipients                            who every `.age` above is encrypted to
#   secrets/rekeyed/<node>/                               agenix-rekey's localStorageDir
#   secrets/recipients/<node>.pub                         the node's age recipient
#   secrets/identities/<node>.age                         the node's age identity file
#
# A `.age` file is encrypted to the operators' master identities and to nothing else:
# no node can read it. `agenix rekey` re-encrypts what a node reads to that node's
# recipient and writes the result under rekeyed/<node>/, as
# <hash of recipient and source>-<scope>/<generator>/<file>.age; those files are what a
# node's closure carries. A file with `secret = false` is committed as it is, beside
# the ciphertexts, which is why no public file may be named `<something>.age`.
#
# A node's identity file is what `age-plugin-tpm --generate` wrote on that node's TPM at
# install: a handle to a key the TPM holds, and useless on any other machine. The node
# keeps it on its encrypted disk (`cluster.secrets.identityPath`). The copy here is
# encrypted to the master identities like every `.age` file, and is what a reinstall on
# the same machine puts back, so that nothing has to be rekeyed. No generator makes it
# and no node is given it.
#
# `.validation-hash` is the generator's `validationHash` (modules/secrets.nix) as it was
# when the generator last ran, one line, in the clear; a generator without `validation`
# has none. The runner (tools/avc/avc/core/secretstore.py) writes it with the files and
# makes them again when the declared hash is no longer the one written here.
# `.master-recipients` is the sorted list of age recipients the `.age` files were last
# encrypted to, one per line: when the flake's master identities and extra recipients
# are no longer that list, `avc secrets fix` re-encrypts every source and rewrites it.
# Both are the runner's; nothing at evaluation reads either.
#
# On a node, a file a service reads is at /run/secrets/<scope>/<generator>/<file>, where
# <scope> is `shared` or `per-machine/<node>`. A file read only at install
# (`neededFor = "partitioning"`) is at /run/partitioning-secrets/<scope>/<generator>/<file>,
# put there by `avc boot install` (decrypted on the operator's machine, sent into the
# installer's memory), and is on no running node.
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

  # Relative to `dir`, like `storedAs`: the runner's two records.
  validationStoredAs = rel: "secrets/${rel}/.validation-hash";
  masterRecipientsStoredAs = "secrets/.master-recipients";
  reserved = [ ".validation-hash" ];

  rekeyed = dir: machine: dir + "/secrets/rekeyed/${machine}";
  recipient = dir: machine: dir + "/secrets/recipients/${machine}.pub";
  # Relative to `dir`: what the install writes.
  recipientStoredAs = machine: "secrets/recipients/${machine}.pub";
  identityStoredAs = machine: "secrets/identities/${machine}.age";

  runtimeDir = "/run/secrets";
  partitioningDir = "/run/partitioning-secrets";
}
