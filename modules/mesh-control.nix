# modules/mesh-control.nix — the control mesh's keys, from the site's secrets.
#
# The mesh itself is modules/mesh-control-core.nix. This supplies what only the
# repository knows: this node's private key (the `wg-ctrl` generator, modules/vars.nix),
# its ciphertext (so a rotation restarts networkd), and every other node's public key.
#
# Public keys are read from the repository, where each node's `wg-ctrl/public` is
# committed in the clear (lib/secrets-layout.nix): no node reads another's secret. A
# peer whose file is missing is a peer whose secrets were never generated: skipped if
# it is a placeholder, refused if it is installed (the core's assertion). Generating a
# placeholder's secrets before it is installed lists it on every node from the start,
# so its arrival changes nothing; if it was skipped, the next switch adds it.
{ config, topology, ... }:
let
  layout = import ../lib/secrets-layout.nix;
  dir = config.cluster.secrets.directory;
  gen = config.cluster.secrets.generators.wg-ctrl;
  pubPath = name: layout.public dir "per-machine/${name}/wg-ctrl" "public";
  key = gen.files.private;
in
{
  imports = [ ./mesh-control-core.nix ];

  cluster.mesh = {
    privateKeyFile = key.path;
    publicKeys = builtins.mapAttrs (
      name: _: if builtins.pathExists (pubPath name) then builtins.readFile (pubPath name) else null
    ) topology.nodes;
    keyCiphertext = if key.exists then key.source else null;
  };
}
