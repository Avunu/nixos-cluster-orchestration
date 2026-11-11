# lib/nomad-pki.nix — Nomad's certificates and gossip key, as shell text.
#
# One copy of the commands, used by the vars generators (modules/vars.nix) and by the
# test fixtures (tests/lib/fixture-pki.nix), so a test runs against certificates made
# exactly as production makes them. `checks.nomad-pki` runs the generators themselves.
#
# Certificate facts (Nomad's rules, not ours):
#   - A server's certificate names `server.<region>.nomad`. With
#     `verify_server_hostname` that name is what lets a peer into raft, and a client
#     certificate (`client.<region>.nomad`) is refused there. So the server cert is
#     the one secret a worker must never hold: with the gossip key it makes a voter.
#   - Every agent certificate also carries `IP:<controlIp>`, because HTTP clients
#     (curl, Prometheus, the CLI) reach the API at that address and verify it.
#   - EKU is serverAuth and clientAuth on every certificate: an agent is both.
#   - The CA is P-256 ECDSA. Ed25519 broke a TLS peer elsewhere in the stack.
#   - The region is fixed as `global` (modules/cluster-common.nix). Changing it
#     invalidates every certificate.
#
# And the JWTs that buy each node its scoped tokens (below, and modules/nomad-acl.nix).
{ lib }:
rec {
  region = "global";
  serverName = "server.${region}.nomad";
  clientName = "client.${region}.nomad";
  cliName = "cli.${region}.nomad";

  # A CA outlives every certificate it signs, so a rotation is always a reissue of
  # agents first. clan does not renew on age: `security.nomadTlsRotation` forces it.
  caDays = 3650;
  certDays = 825;

  agentName = isServer: if isServer then serverName else clientName;
  agentSans =
    { isServer, controlIp }:
    lib.concatStringsSep "," (
      (if isServer then [ "DNS:${serverName}" "DNS:${clientName}" ] else [ "DNS:${clientName}" ])
      ++ [
        "DNS:localhost"
        "IP:127.0.0.1"
        "IP:${controlIp}"
      ]
    );
  cliSans = "DNS:${cliName},DNS:localhost";

  # The CLI identity every local consumer of the HTTP API presents, from a node's
  # vars. `verify_https_client` makes a certificate mandatory for every HTTP call,
  # including the anonymous-looking ones (/v1/status/leader, /v1/metrics).
  cliTlsFor =
    generators:
    let
      caCert = generators.nomad-ca.files."ca.crt".path;
      clientCert = generators.nomad-tls.files."cli.crt".path;
      clientKey = generators.nomad-tls.files."cli.key".path;
    in
    {
      inherit caCert clientCert clientKey;
      curlArgs = "--cacert ${caCert} --cert ${clientCert} --key ${clientKey}";
      env = {
        NOMAD_CACERT = caCert;
        NOMAD_CLIENT_CERT = clientCert;
        NOMAD_CLIENT_KEY = clientKey;
      };
    };

  # ── Scoped tokens: JWT login (modules/nomad-acl.nix) ──────────────────────────
  # Nomad discards a SecretID supplied for anything but the bootstrap token, so a
  # scoped token cannot be minted offline. A JWT can: the `nomad-jwt` key signs one
  # per machine per role (the `nomad-login` generator), and the node exchanges it at
  # the `clan` auth method for a short-lived token bound to that role's policy.
  jwtIssuer = "clan-vars";
  jwtAudience = "nomad";
  authMethod = "clan";
  # A JWT is the long-lived half: a stolen one logs in until it expires, and only a
  # new signing key revokes them all. Same lifetime as a certificate, and reissued
  # with them (`security.nomadTlsRotation`).
  jwtDays = certDays;
  # The token a login returns, and how often a node fetches a fresh one. A refresh
  # well inside the TTL rides out hours of failed logins.
  tokenTtl = "24h";
  tokenRefresh = "6h";
  # Where a node keeps its tokens: tmpfs, root only, gone on reboot.
  tokenDir = "/run/nomad-tokens";

  # The roles a node logs in as, from its tags. What a node holds is what a thief
  # gets from it, so a role is minted only where its consumer runs: `registrar`
  # where jobs are registered (nomad-leader), `autoscaler` where the autoscaler runs
  # (metrics). Every node fences, sets its own node meta, and serves avc.
  loginRoles =
    node:
    let
      has = tag: builtins.elem tag (node.tags or [ ]);
    in
    [
      "fence"
      "node-meta"
      "avc"
    ]
    ++ lib.optional (has "nomad-leader") "registrar"
    ++ lib.optional (has "metrics") "autoscaler";

  # Bash. Needs openssl and coreutils on PATH. Each function works in a directory of
  # its own, so it can run in a generator's sandbox, a build, or a VM.
  #
  #   make_ca <ca.key> <ca.crt> <days>
  #   issue <out-basename> <CN> <SANs>      writes $pki_out/<out-basename>.{key,crt},
  #                                         signed by $pki_ca_crt/$pki_ca_key, valid
  #                                         $pki_days days
  #   gossip_hcl <file>                     a fresh serf key, as the HCL Nomad loads
  #   make_jwt_key <signing.key> <signing.pub>       an RSA key pair for the JWTs
  #   mint_jwt <role> <node> <aud> <keyfile> <days>   an RS256 JWT, on stdout
  functions = ''
    make_ca() {
      openssl ecparam -genkey -name prime256v1 -noout -out "$1"
      openssl req -x509 -new -key "$1" -sha256 -days "$3" -subj "/CN=cluster Nomad CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$2"
    }

    issue() {
      local work
      work=$(mktemp -d)
      openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$pki_out/$1.key" -subj "/CN=$2" -out "$work/req.csr"
      printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$3" > "$work/ext"
      # A random serial per certificate: -CAcreateserial with a fresh serial file.
      openssl x509 -req -in "$work/req.csr" -CA "$pki_ca_crt" -CAkey "$pki_ca_key" \
        -CAcreateserial -CAserial "$work/serial" -days "$pki_days" -sha256 \
        -extfile "$work/ext" -out "$pki_out/$1.crt"
      rm -rf "$work"
    }

    # `server { encrypt }`, not a bare key: Nomad reads the file with -config, so the
    # key never enters the world-readable store as part of the agent's settings.
    gossip_hcl() {
      printf 'server { encrypt = "%s" }\n' "$(openssl rand -base64 32 | tr -d '\n')" > "$1"
    }

    # The login JWTs' signing key. RSA, because Nomad's JWT auth method refuses EdDSA.
    make_jwt_key() {
      openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out "$1"
      openssl pkey -in "$1" -pubout -out "$2"
    }

    mint_jwt() {
      local work h p s now exp
      work=$(mktemp -d)
      b64() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
      h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
      now=$(date +%s)
      exp=$((now + $5 * 86400))
      p=$(printf '{"iss":"${jwtIssuer}","aud":"%s","sub":"%s","role":"%s","node":"%s","iat":%s,"exp":%s}' \
        "$3" "$2" "$1" "$2" "$now" "$exp" | b64)
      printf '%s.%s' "$h" "$p" > "$work/jwt.in"
      s=$(openssl dgst -sha256 -sign "$4" "$work/jwt.in" | b64)
      rm -rf "$work"
      printf '%s.%s.%s' "$h" "$p" "$s"
    }
  '';
}
