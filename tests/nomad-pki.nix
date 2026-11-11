# Nomad's PKI, built and checked without booting anything.
#
# The certificates the VM tests use come from tests/lib/fixture-pki.nix, so this check
# runs the GENERATORS themselves: the fixture cluster's real `nomad-ca`, `nomad-tls` and
# `nomad-gossip` scripts (clan's finalScript, with $in and $out as clan sets them), for
# a server (node1) and a worker (node2). What is checked is what Nomad relies on:
#   - every certificate verifies against the CA, and one from another CA does not
#   - names: server.global.nomad only on servers, client.global.nomad, cli.global.nomad,
#     the control IP on agents (HTTP clients verify the address)
#   - EKU serverAuth and clientAuth, P-256 keys, a CA that is a CA
#   - validity: still valid the day before it lapses, expired the day after
#   - the gossip file is the HCL Nomad loads, with a 32-byte key, and only servers
#     declare it
#   - a JWT from mint_jwt verifies with the public key, carries the claims the auth
#     method binds, and a tampered one does not verify
#   - the real `nomad-jwt` and `nomad-login` generators: the signing key stays off
#     nodes, each machine gets a JWT for its own roles only (no registrar, no
#     autoscaler on a worker), each verifies and names its node and role; and the
#     management token (`nomad-acl`) is declared on the nomad-leader node only
#
# Run: nix build .#checks.x86_64-linux.nomad-pki
{
  pkgs,
  lib,
  fixtureCluster,
  fixtureTopology,
}:
let
  pki = import ../lib/nomad-pki.nix { inherit lib; };
  generatorsOf = name: fixtureCluster.config.nixosConfigurations.${name}.config.clan.core.vars.generators;
  server = generatorsOf "node1";
  worker = generatorsOf "node2";
  fixturePki = import ./lib/fixture-pki.nix {
    inherit pkgs lib;
    topology = fixtureTopology;
  };

  # Facts only evaluation can see, handed to the build and checked there, so a
  # failure is a message in the log rather than an evaluation error.
  facts = {
    workerHasGossip = worker ? nomad-gossip;
    serverHasGossip = server ? nomad-gossip;
    tlsShared = server.nomad-tls.share;
    caShared = server.nomad-ca.share;
    caKeyDeployed = server.nomad-ca.files."ca.key".deploy;
    tlsDependencies = server.nomad-tls.dependencies;
    serverHasAcl = server ? nomad-acl;
    workerHasAcl = worker ? nomad-acl;
    jwtKeyDeployed = server.nomad-jwt.files."signing.key".deploy;
    jwtShared = server.nomad-jwt.share;
    loginShared = server.nomad-login.share;
    loginDependencies = server.nomad-login.dependencies;
    serverLogins = lib.attrNames server.nomad-login.files;
    workerLogins = lib.attrNames worker.nomad-login.files;
  };
in
pkgs.runCommand "nomad-pki-check"
  {
    nativeBuildInputs = [
      pkgs.openssl
      pkgs.coreutils
      pkgs.gnugrep
      pkgs.jq
      pkgs.bash
    ];
    passAsFile = [ "facts" ];
    facts = builtins.toJSON facts;
  }
  ''
    set -euo pipefail
    ${pki.functions}
    fail() { echo "FAIL: $*" >&2; exit 1; }
    pass() { echo "ok: $*"; }

    # ── declarations ────────────────────────────────────────────────────────
    f=$factsPath
    [ "$(jq .serverHasGossip $f)" = true ] || fail "the server does not declare nomad-gossip"
    [ "$(jq .workerHasGossip $f)" = false ] || fail "a worker declares nomad-gossip: a stolen worker would carry the key"
    [ "$(jq .tlsShared $f)" = false ] || fail "nomad-tls is shared: every node would hold the server certificate"
    [ "$(jq .caShared $f)" = true ] || fail "nomad-ca is not shared"
    [ "$(jq .caKeyDeployed $f)" = false ] || fail "the CA key is deployed to nodes"
    [ "$(jq -c .tlsDependencies $f)" = '["nomad-ca"]' ] || fail "nomad-tls does not depend on nomad-ca alone"
    pass "declarations: gossip on servers only, nomad-tls per machine, the CA key stays off nodes"
    [ "$(jq .serverHasAcl $f)" = true ] || fail "the nomad-leader node does not declare nomad-acl"
    [ "$(jq .workerHasAcl $f)" = false ] || fail "a worker declares nomad-acl: it would hold the management token"
    [ "$(jq .jwtKeyDeployed $f)" = false ] || fail "the JWT signing key is deployed to nodes"
    [ "$(jq .jwtShared $f)" = true ] || fail "nomad-jwt is not shared"
    [ "$(jq .loginShared $f)" = false ] || fail "nomad-login is shared: every node would hold every role"
    [ "$(jq -c .loginDependencies $f)" = '["nomad-jwt"]' ] || fail "nomad-login does not depend on nomad-jwt alone"
    [ "$(jq -c .serverLogins $f)" = '["jwt-autoscaler","jwt-avc","jwt-fence","jwt-node-meta","jwt-registrar"]' ] \
      || fail "node1 (leader, metrics) logins: $(jq -c .serverLogins $f)"
    [ "$(jq -c .workerLogins $f)" = '["jwt-avc","jwt-fence","jwt-node-meta"]' ] \
      || fail "a worker's logins: $(jq -c .workerLogins $f)"
    pass "declarations: nomad-acl on the leader only, the JWT key stays off nodes, logins per machine and per role"

    # ── run the generators as clan does ─────────────────────────────────────
    gen() { # name script indir outdir
      mkdir -p "$4"
      in=$3 out=$4 prompts=$(mktemp -d) bash "$2" >/dev/null 2>"$4.log" \
        || { cat "$4.log" >&2; fail "generator $1 failed"; }
    }
    gen nomad-ca ${server.nomad-ca.finalScript} /var/empty ca
    mkdir -p in/nomad-ca && cp ca/ca.crt ca/ca.key in/nomad-ca/
    gen nomad-tls ${server.nomad-tls.finalScript} "$PWD/in" server
    gen nomad-tls ${worker.nomad-tls.finalScript} "$PWD/in" worker
    gen nomad-gossip ${server.nomad-gossip.finalScript} /var/empty gossip
    for x in ca/ca.crt ca/ca.key server/agent.{crt,key} server/cli.{crt,key} worker/agent.{crt,key} worker/cli.{crt,key} gossip/gossip.hcl; do
      [ -s "$x" ] || fail "generator output $x missing or empty"
    done
    pass "the generators wrote every declared file"

    # ── the CA ──────────────────────────────────────────────────────────────
    openssl x509 -in ca/ca.crt -noout -text > ca.txt
    grep -q 'CA:TRUE' ca.txt || fail "the CA is not a CA"
    grep -A1 'X509v3 Basic Constraints: critical' ca.txt | grep -q CA:TRUE || fail "CA basicConstraints not critical"
    grep -A1 'X509v3 Key Usage: critical' ca.txt | grep -q 'Certificate Sign' || fail "CA keyUsage lacks keyCertSign"
    grep -q 'ASN1 OID: prime256v1' ca.txt || fail "the CA key is not P-256"
    pass "CA: P-256, CA:TRUE, keyCertSign"

    # ── names, EKU, keys, chain ─────────────────────────────────────────────
    check() { # crt cn sans
      openssl verify -CAfile ca/ca.crt "$1" >/dev/null || fail "$1 does not verify against the CA"
      local subj sans eku
      subj=$(openssl x509 -in "$1" -noout -subject -nameopt multiline | sed -n 's/^ *commonName *= *//p')
      [ "$subj" = "$2" ] || fail "$1: CN '$subj', want '$2'"
      sans=$(openssl x509 -in "$1" -noout -ext subjectAltName | tail -n +2 | tr -d ' ')
      [ "$sans" = "$3" ] || fail "$1: SANs '$sans', want '$3'"
      eku=$(openssl x509 -in "$1" -noout -ext extendedKeyUsage | tail -n +2 | sed 's/^ *//')
      [ "$eku" = "TLS Web Server Authentication, TLS Web Client Authentication" ] || fail "$1: EKU '$eku'"
      openssl x509 -in "$1" -noout -text | grep -q 'ASN1 OID: prime256v1' || fail "$1: key is not P-256"
      pass "$1: CN $2, SANs $3, EKU both, P-256, chains to the CA"
    }
    s1=${fixtureTopology.nodes.node1.controlIp}
    s2=${fixtureTopology.nodes.node2.controlIp}
    check server/agent.crt ${pki.serverName} "DNS:${pki.serverName},DNS:${pki.clientName},DNS:localhost,IPAddress:127.0.0.1,IPAddress:$s1"
    check worker/agent.crt ${pki.clientName} "DNS:${pki.clientName},DNS:localhost,IPAddress:127.0.0.1,IPAddress:$s2"
    check server/cli.crt ${pki.cliName} "DNS:${pki.cliName},DNS:localhost"
    check worker/cli.crt ${pki.cliName} "DNS:${pki.cliName},DNS:localhost"
    # Each key belongs to its certificate.
    for c in server/agent server/cli worker/agent worker/cli; do
      [ "$(openssl x509 -in $c.crt -noout -pubkey)" = "$(openssl pkey -in $c.key -pubout)" ] \
        || fail "$c.key is not the key of $c.crt"
    done
    pass "every key matches its certificate"
    # The worker holds nothing that names a server.
    ! grep -rq "${pki.serverName}" <(openssl x509 -in worker/agent.crt -noout -text) \
      || fail "the worker's certificate names ${pki.serverName}"
    pass "the worker's certificate does not name a server"

    # ── a certificate from another CA ───────────────────────────────────────
    mkdir -p rogue
    (
      make_ca rogue/ca.key rogue/ca.crt 30
      pki_out=rogue pki_ca_crt=rogue/ca.crt pki_ca_key=rogue/ca.key pki_days=30
      issue agent ${pki.serverName} DNS:${pki.serverName}
    ) 2>/dev/null
    ! openssl verify -CAfile ca/ca.crt rogue/agent.crt >/dev/null 2>&1 \
      || fail "a certificate from another CA verified"
    pass "a certificate from another CA, claiming ${pki.serverName}, does not verify"

    # ── validity ────────────────────────────────────────────────────────────
    now=$(date +%s)
    openssl verify -attime $((now + (${toString pki.certDays} - 1) * 86400)) -CAfile ca/ca.crt server/agent.crt >/dev/null \
      || fail "the agent certificate lapses before ${toString pki.certDays} days"
    res=$(openssl verify -attime $((now + (${toString pki.certDays} + 1) * 86400)) -CAfile ca/ca.crt server/agent.crt 2>&1) \
      && fail "the agent certificate is still valid after ${toString pki.certDays} days"
    grep -q 'certificate has expired' <<<"$res" || fail "expired for another reason: $res"
    openssl verify -attime $((now + (${toString pki.caDays} - 1) * 86400)) -CAfile ca/ca.crt ca/ca.crt >/dev/null \
      || fail "the CA lapses before ${toString pki.caDays} days"
    pass "expiry: valid at ${toString pki.certDays} - 1 days, 'certificate has expired' at ${toString pki.certDays} + 1"

    # ── gossip ──────────────────────────────────────────────────────────────
    grep -qxE 'server \{ encrypt = "[A-Za-z0-9+/]{43}=" \}' gossip/gossip.hcl \
      || fail "gossip.hcl is not 'server { encrypt = \"<base64>\" }': $(cat gossip/gossip.hcl)"
    key=$(sed -E 's/.*"(.*)".*/\1/' gossip/gossip.hcl)
    [ "$(printf %s "$key" | base64 -d | wc -c)" = 32 ] || fail "the gossip key is not 32 bytes"
    pass "gossip.hcl: server { encrypt }, 32 bytes"

    # ── JWT ─────────────────────────────────────────────────────────────────
    openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -out signing.key 2>/dev/null
    openssl pkey -in signing.key -pubout -out signing.pub
    jwt=$(mint_jwt fence node1 nomad signing.key 365)
    unb64() { local s; s=$(printf %s "$1" | tr -- '-_' '+/'); while [ $(( ''${#s} % 4 )) != 0 ]; do s="$s="; done; printf %s "$s" | base64 -d; }
    IFS=. read -r h p s <<<"$jwt"
    verify() { # header payload sig
      printf '%s.%s' "$1" "$2" > signed
      unb64 "$3" > sig
      openssl dgst -sha256 -verify signing.pub -signature sig signed >/dev/null 2>&1
    }
    verify "$h" "$p" "$s" || fail "the JWT does not verify with the public key"
    [ "$(unb64 "$h" | jq -r .alg)" = RS256 ] || fail "JWT alg"
    claims=$(unb64 "$p")
    [ "$(jq -r .iss <<<"$claims")" = clan-vars ] || fail "iss: $claims"
    [ "$(jq -r .aud <<<"$claims")" = nomad ] || fail "aud: $claims"
    [ "$(jq -r .role <<<"$claims")" = fence ] || fail "role: $claims"
    [ "$(jq -r .node <<<"$claims")" = node1 ] || fail "node: $claims"
    [ "$(jq -r '.exp - .iat' <<<"$claims")" = $((365 * 86400)) ] || fail "lifetime: $claims"
    forged=$(jq -c '.role = "registrar"' <<<"$claims" | base64 -w0 | tr '+/' '-_' | tr -d '=')
    ! verify "$h" "$forged" "$s" || fail "a JWT with its role changed still verifies"
    pass "JWT: RS256, verifies, claims iss/aud/role/node/exp; a tampered role does not verify"

    # ── the login generators, as clan runs them ─────────────────────────────
    gen nomad-jwt ${server.nomad-jwt.finalScript} /var/empty jwtkey
    mkdir -p in/nomad-jwt && cp jwtkey/signing.key jwtkey/signing.pub in/nomad-jwt/
    gen nomad-login ${server.nomad-login.finalScript} "$PWD/in" login-server
    gen nomad-login ${worker.nomad-login.finalScript} "$PWD/in" login-worker
    cp jwtkey/signing.pub signing.pub
    for x in login-server/jwt-{fence,node-meta,avc,registrar,autoscaler} login-worker/jwt-{fence,node-meta,avc}; do
      [ -s "$x" ] || fail "nomad-login did not write $x"
      IFS=. read -r h p s < "$x" || true  # no trailing newline: read returns 1 at EOF
      verify "$h" "$p" "$s" || fail "$x does not verify with nomad-jwt's signing.pub"
      claims=$(unb64 "$p")
      role=''${x##*/jwt-}
      want_node=$([ "''${x%%/*}" = login-server ] && echo node1 || echo node2)
      [ "$(jq -r .role <<<"$claims")" = "$role" ] || fail "$x: role: $claims"
      [ "$(jq -r .node <<<"$claims")" = "$want_node" ] || fail "$x: node: $claims"
      [ "$(jq -r .iss <<<"$claims")" = ${pki.jwtIssuer} ] || fail "$x: iss: $claims"
      [ "$(jq -r .aud <<<"$claims")" = ${pki.jwtAudience} ] || fail "$x: aud: $claims"
      [ "$(jq -r '.exp - .iat' <<<"$claims")" = $((${toString pki.jwtDays} * 86400)) ] || fail "$x: lifetime: $claims"
    done
    [ ! -e login-worker/jwt-registrar ] && [ ! -e login-worker/jwt-autoscaler ] \
      || fail "the worker's generator wrote a registrar or autoscaler JWT"
    pass "nomad-login: one verified JWT per role, naming its node; the worker gets fence, node-meta, avc only"

    # ── the fixtures the VM tests use ───────────────────────────────────────
    ${lib.concatStrings (
      lib.mapAttrsToList (
        name: node:
        let
          isServer = lib.elem "nomad-server" (node.tags or [ ]);
        in
        ''
          openssl verify -CAfile ${fixturePki}/ca.crt ${fixturePki}/${name}/agent.crt ${fixturePki}/${name}/cli.crt >/dev/null \
            || fail "fixture ${name} does not verify"
          openssl x509 -in ${fixturePki}/${name}/agent.crt -noout -subject | grep -q 'CN *= *${pki.agentName isServer}$' \
            || fail "fixture ${name}: not ${pki.agentName isServer}"
        ''
      ) fixtureTopology.nodes
    )}
    grep -qxE 'server \{ encrypt = "[A-Za-z0-9+/]{43}=" \}' ${fixturePki}/gossip.hcl || fail "fixture gossip.hcl"
    cp ${fixturePki}/signing.pub signing.pub
    ${lib.concatStrings (
      lib.mapAttrsToList (
        name: node:
        lib.concatMapStrings (r: ''
          IFS=. read -r h p s < ${fixturePki}/${name}/jwt-${r} || true
          verify "$h" "$p" "$s" || fail "fixture ${name}/jwt-${r} does not verify"
          [ "$(unb64 "$p" | jq -r .role)" = ${r} ] || fail "fixture ${name}/jwt-${r}: wrong role"
        '') (pki.loginRoles node)
      ) fixtureTopology.nodes
    )}
    pass "fixture PKI: every node verifies, names follow the nomad-server tag, JWTs follow the roles"

    echo "nomad-pki: all checks passed"
    touch $out
  ''
