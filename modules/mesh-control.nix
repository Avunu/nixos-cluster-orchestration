# modules/mesh-control.nix — the control mesh's keys, from clan vars.
#
# The mesh itself is modules/mesh-control-core.nix. This supplies what only clan
# knows: this node's private key (the `wg-ctrl` generator, modules/vars.nix), its
# ciphertext (so a rotation restarts networkd), and every other node's public key.
#
# Public keys are read from the repository by clan's own convention,
# <directory>/vars/per-machine/<peer>/wg-ctrl/public/value, the way clan's own
# wireguard service finds them [READ clanServices/wireguard]. A peer whose file is
# missing is a peer whose vars were never generated: skipped if it is a placeholder,
# refused if it is installed (the core's assertion). Generating a placeholder's vars
# before it is installed lists it on every node from the start, so its arrival
# changes nothing; if it was skipped, the next switch adds it.
{ config, topology, ... }:
let
  dir = config.clan.core.settings.directory;
  gen = config.clan.core.vars.generators.wg-ctrl;
  pubPath = name: "${dir}/vars/per-machine/${name}/wg-ctrl/public/value";
  key = gen.files.private;
  cipher = "${dir}/secrets/clan-vars/${key.rel_dir}/${key.name}/${key.name}.age";
in
{
  imports = [ ./mesh-control-core.nix ];

  cluster.mesh = {
    privateKeyFile = key.path;
    publicKeys = builtins.mapAttrs (
      name: _: if builtins.pathExists (pubPath name) then builtins.readFile (pubPath name) else null
    ) topology.nodes;
    keyCiphertext = if builtins.pathExists cipher then cipher else null;
  };
}
