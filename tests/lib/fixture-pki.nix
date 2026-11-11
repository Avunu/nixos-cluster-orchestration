# Nomad's certificates and gossip key for the VM tests, made with the same shell
# functions as the vars generators (lib/nomad-pki.nix), so a test runs against
# certificates shaped exactly like production's.
#
# A function of the topology: which node gets a server certificate follows its
# `nomad-server` tag, as in production, so tests/cluster.nix (three voters) and the
# fixture topology (one) get different sets.
#
#   $out/ca.crt, $out/ca.key          the CA (the key only so a test can issue more)
#   $out/<node>/{agent,cli}.{crt,key} each node's certificates
#   $out/gossip.hcl                   the serf key, as Nomad loads it
#   $out/signing.{key,pub}            the login JWTs' key (the private half only so a
#                                     test can forge with it)
#   $out/<node>/jwt-<role>            each node's login JWTs, for its roles only
#   $out/rsa.pem, $out/rsa-passphrase the JuiceFS volume key (vars `juicefs-rsa`),
#                                     made with the generator's own commands
#
# Throwaway values, made at build time, used by nothing outside the test VMs. Valid for
# 100 years, because a derivation stays cached far past any normal validity.
{
  pkgs,
  lib,
  topology,
}:
let
  pki = import ../../lib/nomad-pki.nix { inherit lib; };
  net = import ../../lib/net.nix { inherit lib; };
  days = "36500";
in
pkgs.runCommand "fixture-nomad-pki"
  {
    nativeBuildInputs = [
      pkgs.openssl
      pkgs.coreutils
    ];
  }
  ''
    set -euo pipefail
    ${pki.functions}
    mkdir -p $out
    make_ca $out/ca.key $out/ca.crt ${days}
    make_jwt_key $out/signing.key $out/signing.pub
    pki_ca_crt=$out/ca.crt
    pki_ca_key=$out/ca.key
    pki_days=${days}
    ${lib.concatStrings (
      lib.mapAttrsToList (
        name: node:
        let
          isServer = net.hasTag "nomad-server" node;
        in
        ''
          mkdir -p $out/${name}
          pki_out=$out/${name}
          issue agent ${pki.agentName isServer} ${
            lib.escapeShellArg (
              pki.agentSans {
                inherit isServer;
                inherit (node) controlIp;
              }
            )
          }
          issue cli ${pki.cliName} ${lib.escapeShellArg pki.cliSans}
          ${lib.concatMapStrings (r: ''
            mint_jwt ${r} ${lib.escapeShellArg node.hostName} ${pki.jwtAudience} $out/signing.key ${days} > $out/${name}/jwt-${r}
          '') (pki.loginRoles node)}
        ''
      ) topology.nodes
    )}
    gossip_hcl $out/gossip.hcl
    # As modules/vars.nix's juicefs-rsa generator does it.
    openssl rand -hex 32 | tr -d '\n' > $out/rsa-passphrase
    openssl genrsa -aes256 -passout file:$out/rsa-passphrase -out $out/rsa.pem 4096
  ''
