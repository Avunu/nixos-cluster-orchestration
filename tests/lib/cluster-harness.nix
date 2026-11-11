# Shared pieces of the cluster VM tests (tests/cluster-single.nix, tests/cluster.nix).
#
# Those tests boot the REAL machine modules — what `clan` builds for each node,
# taken from `clanEval.config.nixosModules."clan-machine-<name>"`, the very
# module behind nixosConfigurations.<name> — and change only what a VM cannot
# have. Each change below is the smallest one that lets the production code
# path run unmodified:
#
#   secrets      clan's age backend decrypts every vars file into /run/secrets
#                during activation, with a key no CI machine holds. The test
#                replaces only that activation step, writing FIXTURE values to
#                the same paths with the same owner and mode. Nothing real is
#                decrypted, and every unit still reads /run/secrets/...
#   NICs         the VMs' NICs are NAMED as the topology says (wanInterface, the
#                vRack trunk vrackInterface), so overlay-network.nix's networkd units and
#                VLAN children apply as written, at the real addresses.
#   the internet one VM, `wan`, that owns the nodes' gateway addresses and
#                answers for the topology's object-storage hostnames over TLS (a
#                test CA the nodes trust). JuiceFS, Loki, restic and rclone talk
#                to topology.objectStorage.endpoint exactly as on a real node.
#   disks        the qemu VM module overrides disko's fileSystems/swap; the disk
#                layout is covered by tests/install-boot.nix instead.
#   pull loop    the timer is unhooked: it would fetch github: and fail offline.
#
# A function of the topology: Nomad's server certificates follow the `nomad-server`
# tag (tests/lib/fixture-pki.nix), so tests/cluster.nix, which promotes node2 and
# node3, builds its harness from its own topology.
#
# The VMs have no route to the real internet (the test network is a private
# switch), so no endpoint is ever contacted with these fake credentials.
{
  pkgs,
  lib,
  topology,
  # Nomad's fixture PKI, when a test needs one shared between two topologies
  # (tests/voter-growth.nix: the same CA before and after a worker becomes a voter).
  # null: made here, from this topology.
  fixturePki ? null,
}:
let
  # Where the stand-in internet answers. Not in the topology, because it is no
  # node's address: a documentation address (RFC 5737) the nodes reach through
  # their default route.
  s3Ip = "198.51.100.10";

  hostOf = url: lib.head (lib.splitString "/" (lib.removePrefix "https://" url));
  s3Hosts = lib.unique [
    (hostOf topology.objectStorage.endpoint)
    (hostOf topology.backup.target.endpoint)
  ];

  # The off-host audit trail's receiver (topology.alerting.auditUrl): the real Worker,
  # on the same stand-in internet (tests/lib/audit-stub.mjs). Each node has its own
  # token, as on a real site, so the Worker can refuse one node speaking for another.
  auditUrl = topology.alerting.auditUrl or null;
  auditHostPort = if auditUrl == null then null else lib.splitString ":" (hostOf auditUrl);
  auditHost = if auditUrl == null then null else lib.head auditHostPort;
  auditPort =
    if auditUrl == null || lib.length auditHostPort < 2 then
      443
    else
      lib.toInt (lib.last auditHostPort);
  auditToken = node: "ci-fixture-audit-token-${node}";
  auditOut = "/var/lib/audit-stub";
  auditTokens = lib.listToAttrs (
    lib.mapAttrsToList (name: n: {
      name = auditToken name;
      value = {
        sender = name;
        kinds = [
          "boot"
          "deploy"
          "ssh_login"
          "canary"
        ]
        ++ lib.optional (lib.elem "nomad-leader" (n.tags or [ ])) "nomad_acl";
      };
    }) topology.nodes
  );
  # Every name the stand-in internet answers for over TLS.
  tlsHosts = s3Hosts ++ lib.optional (auditHost != null) auditHost;
  s3Buckets = [
    topology.objectStorage.juicefsBucket
    topology.backup.target.bucket
  ];
  s3AccessKey = "ci-s3-access";
  s3SecretKey = "ci-fixture-s3-secret";

  # Must be a UUID: Nomad validates an operator-supplied bootstrap token.
  # Every fixture is deliberately low-entropy, so it reads as what it is.
  nomadToken = "11111111-1111-4111-8111-111111111111";

  # A CA and one server certificate for every S3 hostname, made at build time.
  tls = pkgs.runCommand "cluster-test-tls" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    mkdir $out && cd $out
    # The extensions a real CA and server certificate carry. Python's default context
    # verifies strictly (VERIFY_X509_STRICT since 3.13), and refuses a CA without a key
    # usage: the audit sender is the first client here written in Python.
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=cluster-test-ca" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" \
      -keyout ca.key -out ca.crt
    openssl req -newkey rsa:2048 -nodes -subj "/CN=${lib.head s3Hosts}" \
      -keyout server.key -out server.csr
    {
      printf 'subjectAltName=%s\n' "${lib.concatMapStringsSep "," (h: "DNS:${h}") tlsHosts},IP:${s3Ip}"
      echo "basicConstraints=critical,CA:FALSE"
      echo "keyUsage=critical,digitalSignature,keyEncipherment"
      echo "extendedKeyUsage=serverAuth"
      echo "subjectKeyIdentifier=hash"
      echo "authorityKeyIdentifier=keyid,issuer"
    } > ext
    openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 \
      -extfile ext -out server.crt
  '';

  # Nomad's CA, every node's certificates, the gossip key and the login JWTs, made by
  # the same functions as the generators. And the JuiceFS volume key: every fixture
  # volume is encrypted, as a real one is.
  pki =
    if fixturePki != null then fixturePki else import ./fixture-pki.nix { inherit pkgs lib topology; };
  # The control mesh's keys: literals, whose public halves are the fixture's public
  # vars (tests/lib/fixture-wg.nix).
  wg = import ./fixture-wg.nix;
  net = import ../../lib/net.nix { inherit lib; };
  meshIps = lib.mapAttrs (_: n: net.meshIp topology n) topology.nodes;
  nomadPki = import ../../lib/nomad-pki.nix { inherit lib; };
  inherit (import ../../lib/nomad.nix) appsNamespace;

  # Values for the vars files whose content something checks. Everything else
  # gets "ci-fixture-<generator>-<file>", which is enough for a password.
  fixtures = {
    "nomad-acl/token" = nomadToken;
    "ovh-s3/access-key" = s3AccessKey;
    "ovh-s3/secret-key" = s3SecretKey;
    "backup-target/access-key" = s3AccessKey;
    "backup-target/secret-key" = s3SecretKey;
    "juicefs-pg/password" = "ci-fixture-juicefs-pg-password";
    # The canary scan's literal (modules/canary-scan.nix). Shaped as the generator makes it,
    # and not a substring of any fixture's store path name, which the journal can show.
    "canary/value" = "CANARY-ci-fixture-value";
    # pull-deploy.nix `!include`s this into nix.conf, so it must parse.
    "github-token/nix.conf" = "# no GitHub token in the VM tests\n";
    "github-token/netrc" = "";
  };
  fixtureFor = gen: file: fixtures."${gen}/${file}" or "ci-fixture-${gen}-${file}";

  # The file a node gets for one vars file: a path, installed as it is. Never read it
  # into a string at evaluation: the PKI is a build output, and reading one is
  # import-from-derivation, which `nix flake check --no-build` refuses.
  fixtureSource =
    {
      gen,
      file,
      node,
    }:
    if gen == "nomad-ca" || gen == "nomad-gossip" || gen == "nomad-jwt" || gen == "juicefs-rsa" then
      "${pki}/${file}"
    else if gen == "nomad-tls" || gen == "nomad-login" then
      "${pki}/${node}/${file}"
    else if gen == "wg-ctrl" then
      pkgs.writeText "fixture-wg-ctrl-${node}" wg.${node}.${file}
    else if gen == "audit" then
      pkgs.writeText "fixture-audit-${node}" (auditToken node)
    else
      pkgs.writeText "fixture-${gen}-${file}" (fixtureFor gen file);

  # Replaces clan's age `setupSecrets` activation snippet (clan-core:
  # nixosModules/clanCore/vars/secret/age.nix) with one that writes fixtures to
  # the paths that snippet would have decrypted to. `keep` picks the generators:
  # every one for a cluster node, only its own for a test that imports a few modules
  # (tests/jfs-encrypted.nix).
  secretsModuleFor =
    keep:
    { config, nodeName, ... }:
    let
      files = lib.concatLists (
        lib.mapAttrsToList (
          gen: g:
          lib.mapAttrsToList (name: f: f // { inherit gen name; }) (
            lib.filterAttrs (_: f: f.secret && f.deploy && f.neededFor == "services") g.files
          )
        ) (lib.filterAttrs (gen: _: keep gen) config.clan.core.vars.generators)
      );
      write = f: ''
        install -D -m ${f.mode} -o ${f.owner} -g ${f.group} \
          ${
            fixtureSource {
              inherit (f) gen;
              file = f.name;
              node = nodeName;
            }
          } ${f.path}
      '';
    in
    {
      # The production backend is still what decides every `.path`; only the
      # decryption is swapped.
      assertions = [
        {
          assertion = config.clan.core.vars.settings.secretStore == "age";
          message = "cluster-harness: expected the age vars backend; the fixture writer mirrors its paths.";
        }
      ];
      system.activationScripts.setupSecrets = lib.mkForce (
        lib.stringAfter [
          "specialfs"
          "users"
          "groups"
        ] (lib.concatMapStrings write files)
      );
    };

  secretsModule = secretsModuleFor (_: true);

  # What every cluster node gets on top of its real machine module.
  nodeModule =
    { memoryMB }:
    { node, ... }:
    {
      imports = [ secretsModule ];

      virtualisation = {
        memorySize = memoryMB;
        cores = 2;
        diskSize = 4096;
        # The real NIC names: WAN on switch 1, the vRack trunk on switch 2.
        vlans = lib.mkForce [ ];
        interfaces.${node.wanInterface} = {
          vlan = 1;
          assignIP = false;
        };
        interfaces.${node.vrackInterface} = {
          vlan = 2;
          assignIP = false;
        };
      };

      networking.hosts.${s3Ip} = tlsHosts;
      security.pki.certificateFiles = [ "${tls}/ca.crt" ];

      # Offline: a tick of the pull loop would only fail on fetching github:.
      # The unit itself stays, so its configuration is still built.
      systemd.timers.cluster-upgrade.wantedBy = lib.mkForce [ ];

      # QEMU reports no CPU frequency on some hosts, which leaves Nomad
      # fingerprinting 0 MHz and every allocation "exhausted" on cpu.
      services.nomad.settings.client.cpu_total_compute = 4000;
    };

  gateways = lib.unique (lib.mapAttrsToList (_: n: n.publicGw4) topology.nodes);

  # The nodes' upstream: their gateways, and the object storage behind them.
  wanNode =
    { pkgs, ... }:
    {
      virtualisation = {
        memorySize = 1024;
        vlans = lib.mkForce [ ];
        interfaces.eth1 = {
          vlan = 1;
          assignIP = false;
        };
      };
      networking.useDHCP = false;
      networking.firewall.enable = false;
      environment.systemPackages = [
        pkgs.netcat
        pkgs.openssh
      ];
      networking.interfaces.eth1.ipv4.addresses =
        # Every node's gateway (topology.nodes.<n>.publicGw4)…
        map (address: {
          inherit address;
          prefixLength = 24;
        }) gateways
        # …and "the internet": the object-storage endpoints.
        ++ [
          {
            address = s3Ip;
            prefixLength = 32;
          }
        ];

      systemd.services.s3 = {
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig.Restart = "on-failure";
        script = ''
          mkdir -p ${lib.concatMapStringsSep " " (b: "/srv/s3/${b}") s3Buckets}
          exec ${pkgs.rclone}/bin/rclone serve s3 --addr 0.0.0.0:443 \
            --cert ${tls}/server.crt --key ${tls}/server.key \
            --auth-key ${s3AccessKey},${s3SecretKey} /srv/s3
        '';
      };

      systemd.services.audit-stub = lib.mkIf (auditUrl != null) {
        description = "The off-host audit receiver: the real Worker, on files";
        wantedBy = [ "multi-user.target" ];
        environment = {
          WORKER = "${../../workers/cluster-watchdog}/src/index.js";
          PORT = toString auditPort;
          TLS_CERT = "${tls}/server.crt";
          TLS_KEY = "${tls}/server.key";
          OUT = auditOut;
          AUDIT_TOKENS = builtins.toJSON auditTokens;
        };
        serviceConfig = {
          ExecStart = "${pkgs.nodejs_22}/bin/node ${./audit-stub.mjs}";
          Restart = "on-failure";
        };
      };
    };

  # Python shared by both test scripts. `n` is a test-driver machine.
  #
  # Nomad wants a client certificate on every HTTP call. TLSCURL names the one a
  # root shell on the node already has: modules/cluster-common.nix puts NOMAD_CACERT,
  # NOMAD_CLIENT_CERT and NOMAD_CLIENT_KEY in the environment from the node's vars, and
  # the test driver's shell reads /etc/profile. So these helpers also prove that the
  # environment an operator gets is right; the `nomad` CLI reads the same variables.
  pythonHelpers = ''
    import json

    # The management token: the test is the operator. Every unit on a node uses a
    # scoped token from TOKENS instead (modules/nomad-acl.nix).
    NOMAD_TOKEN = "${nomadToken}"
    TLSCURL = '--cacert "$NOMAD_CACERT" --cert "$NOMAD_CLIENT_CERT" --key "$NOMAD_CLIENT_KEY"'
    TOKENS = "${nomadPki.tokenDir}"
    # Every node's address on the control mesh, where everything but Nomad listens.
    MESH = ${builtins.toJSON meshIps}
    MESH_IF = "${net.meshIf}"
    NS = "${appsNamespace}"
    UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

    def nomad_url(ip, path):
        return f"https://{ip}:4646{path}"

    def nomad(n, ip, args):
        return n.succeed(f"NOMAD_TOKEN={NOMAD_TOKEN} nomad {args} -address=https://{ip}:4646")

    def nomad_api(n, ip, path):
        return json.loads(n.succeed(
            f"curl -fsS {TLSCURL} -H 'X-Nomad-Token: {NOMAD_TOKEN}' {nomad_url(ip, path)}"
        ))

    def as_token(n, ip, token, path, method="GET", data=None):
        """(HTTP status, body) of one API call with `token`."""
        body = ""
        if data is not None:
            n.succeed(f"cat > /tmp/as-token-body <<'EOF'\n{data}\nEOF")
            body = "--data-binary @/tmp/as-token-body"
        out = n.succeed(
            f"curl -sS {TLSCURL} -o /tmp/as-token-out -w '%{{http_code}}' -X {method} {body}"
            f" -H 'X-Nomad-Token: {token}' '{nomad_url(ip, path)}' || true; echo; cat /tmp/as-token-out"
        )
        code, _, rest = out.partition("\n")
        return int(code or 0), rest

    def role_token(n, role):
        return n.succeed(f"cat {TOKENS}/{role}").strip()

    def units_reading(n, needle):
        """Every service whose unit file, drop-ins, or a store file one of them names (a
        script it runs, a file it is given), mentions `needle`. One level deep."""
        n.succeed("""cat > /tmp/units-reading <<'EOF'
    set +e +o pipefail
    cd /etc/systemd/system
    for u in *.service; do
      files=$(readlink -f "$u"; for d in "$u.d"/*; do [ -e "$d" ] && readlink -f "$d"; done)
      if grep -qs -- "$1" $files; then echo "$u"; continue; fi
      for p in $(grep -ohE '/nix/store/[a-z0-9]{32}-[^ "=;:]+' $files | sort -u); do
        if [ -f "$p" ] && grep -qs -- "$1" "$p"; then echo "$u"; break; fi
      done
    done
    exit 0
    EOF""")
        return n.succeed(f"bash /tmp/units-reading '{needle}'").split()

    def no_failed_units(n, allowed=()):
        failed = n.succeed("systemctl list-units --failed --plain --no-legend | awk '{print $1}'").split()
        unexpected = [u for u in failed if u not in allowed]
        if unexpected:
            for u in unexpected:
                n.execute(f"systemctl status --no-pager -n 40 {u} >&2")
            raise Exception(f"{n.name}: failed units: {unexpected}")

    AUDIT_OUT = "${auditOut}"

    def audit_stored(kind):
        """What the Worker on the wan VM put in its trail, of one kind, oldest first."""
        _, out = wan.execute(f"cat {AUDIT_OUT}/audit.jsonl 2>/dev/null")
        return [o["value"] for o in map(json.loads, out.splitlines()) if o["value"].get("kind") == kind]

    def audit_received():
        """Every request body the receiver got, as sent, and the Worker's answer."""
        _, out = wan.execute(f"cat {AUDIT_OUT}/requests.jsonl 2>/dev/null")
        return [json.loads(l) for l in out.splitlines()]

    def prom_query(n, ip, q):
        """`ip` is the metrics node's mesh address: Prometheus listens nowhere else."""
        import urllib.parse
        r = json.loads(n.succeed(
            f"curl -fsS 'http://{ip}:9090/api/v1/query?query={urllib.parse.quote(q)}'"
        ))
        return r["data"]["result"]
  '';
in
{
  inherit
    nodeModule
    secretsModuleFor
    wanNode
    pythonHelpers
    fixtureFor
    fixtureSource
    pki
    nomadToken
    s3Buckets
    wg
    meshIps
    ;
}
