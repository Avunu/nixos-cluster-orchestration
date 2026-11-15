# The cluster's binary cache (modules/kinds/attic.nix), on the fixture node1: its
# real machine module, with the app catalogue replaced by one `attic` app that Nomad
# places.
#
#   - the container comes up at its fixed address, atticd makes the cache with the
#     site's signing key, and making it again changes nothing
#   - the node reaches it at its own loopback, through HAProxy and the mesh port
#   - cluster-cache-push puts a store path there with the node's token; the path,
#     deleted from the node, comes back by substitution, which needs the signature
#     to be by the key nix.conf trusts
#   - without a token nothing is configured or pushed; with the node's token the
#     cache is not reconfigured either
#   - the public face (nginx on the tunnel's socket) serves reads and refuses the API
#     and every write, token or no token
#   - with the cache away: the loopback port refuses, a build goes ahead without it,
#     a push exits 0 and says it failed, and the probe says the cache is down
#
# Not here: S3. The fixture cache keeps its NARs in a directory (`attic.storage`);
# atticd against a real bucket is unproven by this test. Nor the dataset that carries
# the index from node to node (tests/app-state.nix has the pools).
#
# Run: nix build .#checks.x86_64-linux.attic -L   (needs KVM)
{
  pkgs,
  lib,
  mkClan,
  topology,
}:
let
  clan = mkClan topology;
  machine = clan.config.nixosConfigurations.node1;
  net = import ../lib/net.nix { inherit lib; };
  node = topology.nodes.node1;

  # A fixture, not a secret: the cache's signing key, whose public half the node is
  # told to trust the way a site's `cache-signing/public` var tells it.
  signingSecret = "fixture-cache-1:Z2RJOdDKiMLsgJnypZl7XoQ5QHhyN9qPFXxwU3g4yz8kBpcI0O7buUS+ThRA7k5v43z5Iaia0jTdfV23WWMzGg==";
  signingPublic = "fixture-cache-1:JAaXCNDu27lEvk4UQO5Ob+N8+SGomtI03X1dt1ljMxo=";

  # The token key and a node's token, made as the generators make them.
  tokens =
    pkgs.runCommand "attic-fixture-tokens"
      {
        nativeBuildInputs = [
          pkgs.openssl
          pkgs.coreutils
          pkgs.jq
          pkgs.bash
        ];
      }
      ''
        mkdir -p $out
        openssl genrsa -traditional -out $out/rs256.pem 2048
        b64() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
        now=$(date +%s)
        h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
        p=$(jq -cn --argjson now "$now" \
          '{sub: "cluster-node", iat: $now, exp: ($now + 315360000),
            "https://jwt.attic.rs/v1": {caches: {cluster: {r: 1, w: 1}}}}' | b64)
        printf '%s.%s' "$h" "$p" > jwt.in
        s=$(openssl dgst -sha256 -sign $out/rs256.pem jwt.in | b64)
        printf '%s.%s.%s' "$h" "$p" "$s" > $out/token
      '';

  harness = import ./lib/cluster-harness.nix {
    inherit pkgs lib topology;
    extraFixtureSources = {
      "cache-token/rs256.pem" = "${tokens}/rs256.pem";
      "cache-push/token" = "${tokens}/token";
      "cache-signing/secret" = pkgs.writeText "fixture-cache-signing" signingSecret;
    };
  };

  hostname = "cache.example.net";
  cacheApp =
    { lib, ... }:
    {
      clusterApps = lib.mkForce {
        cache = {
          attic = {
            bucket = "fixture-cache";
            # No S3 here: see the header.
            storage = {
              type = "local";
              path = "/var/lib/atticd/storage";
            };
            public = true;
            inherit hostname;
          };
          module =
            { pkgs, ... }:
            {
              environment.systemPackages = [ pkgs.curl ];
            };
        };
      };
      cluster.cache.publicKey = signingPublic;
    };

  guestIp = "${lib.concatStringsSep "." (lib.take 3 (lib.splitString "." node.appBridgeIp))}.9";
  local = "http://127.0.0.1:${toString net.cachePort}";
in
pkgs.testers.runNixOSTest {
  name = "attic";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machine._module.specialArgs [ "modulesPath" ];

  nodes = {
    wan = harness.wanNode;
    node1 = {
      imports = [
        clan.config.nixosModules."clan-machine-node1"
        (harness.nodeModule { memoryMB = 4096; })
        cacheApp
      ];
    };
  };

  testScript = ''
    ${harness.pythonHelpers}

    import time

    LOCAL = "${local}"
    CACHE = f"{LOCAL}/cluster"
    M1 = MESH["node1"]
    METRICS = "/var/lib/prometheus-node-exporter-text"

    def guest(cmd):
        return node1.succeed(f"nixos-container run cache -- {cmd}")

    def status(cmd):
        return node1.succeed(f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 20 {cmd}").strip()

    wan.start()
    wan.wait_for_unit("s3.service")
    node1.start()
    node1.wait_for_unit("multi-user.target")

    with subtest("Nomad places the cache, at its fixed address on this node's bridge"):
        node1.wait_for_unit("nomad-bootstrap.service")
        # Not wait_for_unit: until Nomad places the job the unit is inactive with
        # nothing queued, which that takes for a failure.
        node1.wait_until_succeeds("systemctl is-active --quiet container@cache.service", timeout=900)
        node1.wait_until_succeeds("nixos-container run cache -- systemctl is-active attic-init.service", timeout=300)
        guest("ip -4 -o addr show eth0 | grep -qF ' ${guestIp}/'")
        said = guest("journalctl -u attic-init -o cat --no-pager")
        assert "cache cluster created" in said, said

    with subtest("the node reaches it at its own loopback, through the mesh port"):
        node1.wait_until_succeeds(f"curl -fsS --max-time 5 {CACHE}/nix-cache-info | grep -q 'StoreDir: /nix/store'", timeout=120)
        node1.succeed(f"curl -fsS --max-time 5 http://{M1}:${toString net.cacheMeshPort}/cluster/nix-cache-info")
        # On the mesh address and the loopback only.
        ports = node1.succeed("ss -Htln 'sport = :${toString net.cachePort} or sport = :${toString net.cacheMeshPort}'")
        bound = sorted(line.split()[3] for line in ports.splitlines() if line.strip())
        assert bound == sorted(["127.0.0.1:${toString net.cachePort}", f"{M1}:${toString net.cacheMeshPort}"]), ports
        conf = node1.succeed("nix config show 2>/dev/null || nix show-config")
        assert CACHE in conf and "${signingPublic}" in conf, conf

    with subtest("the cache signs with the site's key, and making it again keeps it"):
        guest("systemctl restart attic-init.service")
        said = guest("journalctl -u attic-init -o cat --no-pager")
        assert said.count("cache cluster created") == 1 and "the site's key" in said, said

    with subtest("a pushed path comes back by substitution, signed by the key the node trusts"):
        node1.succeed("echo attic-fixture-$(date +%s%N) > /tmp/payload")
        path = node1.succeed("nix-store --add /tmp/payload").strip()
        digest = path.split("/")[-1].split("-")[0]
        assert status(f"{CACHE}/{digest}.narinfo") == "404"
        node1.succeed(f"cluster-cache-push {path}")
        info = node1.succeed(f"curl -fsS {CACHE}/{digest}.narinfo")
        assert "Sig: fixture-cache-1:" in info, info
        stamp = int(node1.succeed(f"awk '/^cluster_cache_push_last_success/ {{print $2}}' {METRICS}/cache_push.prom"))
        assert stamp > 0, stamp
        node1.succeed(f"nix-store --delete {path} && test ! -e {path}")
        node1.succeed(f"nix-store --realise {path}")
        node1.succeed(f"cmp {path} /tmp/payload")

    with subtest("no token configures or pushes; the node's token does not configure"):
        api = f"{LOCAL}/_api/v1/cache-config/cluster"
        body = "-H 'content-type: application/json' -d '{\"is_public\": false}'"
        # Refused, by whichever of Attic's answers (it may not admit the cache exists).
        anonymous = status(f"-X PATCH {body} {api}")
        assert anonymous in ("401", "403", "404"), anonymous
        token = node1.succeed("cat /run/secrets/shared/cache-push/token").strip()
        assert status(f"-X PATCH -H 'Authorization: Bearer {token}' {body} {api}") == "403"
        assert status(f"-X DELETE -H 'Authorization: Bearer {token}' {api}") == "403"
        # And nothing changed: it still answers a reader with no token.
        assert status(f"{CACHE}/nix-cache-info") == "200"

    with subtest("the public face: reads, and nothing else, token or no token"):
        pub = "curl -sS -o /dev/null -w '%{http_code}' --unix-socket /run/nginx/attic.sock -H 'Host: ${hostname}'"
        assert guest(f"{pub} http://x/cluster/nix-cache-info").strip() == "200"
        assert guest(f"{pub} http://x/cluster/{digest}.narinfo").strip() == "200"
        assert guest(f"{pub} -H 'Authorization: Bearer {token}' http://x/_api/v1/cache-config/cluster").strip() == "403"
        assert guest(f"{pub} -X PUT -H 'Authorization: Bearer {token}' http://x/_api/v1/upload-path").strip() == "403"
        assert guest(f"{pub} -X PUT http://x/cluster/{digest}.narinfo").strip() == "403"

    with subtest("the probe says the cache is up"):
        node1.succeed("systemctl start cluster-cache-probe.service")
        node1.succeed(f"grep -qx 'cluster_cache_up 1' {METRICS}/cache_up.prom")

    with subtest("with the cache away, the node builds without it and a push fails nothing"):
        # Not the harness's nomad(): it puts -address after the job's name, where
        # `job stop` takes no flags.
        node1.succeed(f"NOMAD_TOKEN={NOMAD_TOKEN} nomad job stop -address=https://${node.controlIp}:4646 -namespace={NS} app-cache")
        node1.wait_until_fails("systemctl is-active --quiet container@cache.service", timeout=180)
        # Refused, not an HTTP error: Nix gives a substituter that refuses up for a
        # while, and retries one that answers 503.
        # 000 is curl's "no HTTP answer at all".
        node1.wait_until_succeeds(
            f"test \"$(curl -s -o /dev/null -w '%{{http_code}}' --max-time 5 {LOCAL}/)\" = 000", timeout=60)
        expr = ("derivation { name = \"attic-away\"; system = builtins.currentSystem; builder = \"/bin/sh\";"
                " args = [ \"-c\" \"echo built-$stamp > $out\" ]; stamp = \"%d\"; }" % time.time_ns())
        node1.succeed(f"cat > /tmp/away.nix <<'EOF'\n{expr}\nEOF")
        began = time.monotonic()
        built = node1.succeed("nix-build --no-out-link /tmp/away.nix 2>/tmp/away.log").strip()
        took = time.monotonic() - began
        print(f"cache away: built {built} in {took:.0f}s\n" + node1.succeed("cat /tmp/away.log"))
        node1.succeed(f"grep -q built- {built}")
        assert took < 120, f"a build with the cache away took {took:.0f}s"
        before = node1.succeed(f"cat {METRICS}/cache_push.prom")
        said = node1.succeed(f"cluster-cache-push {built} 2>&1")
        assert "the push failed" in said, said
        assert node1.succeed(f"cat {METRICS}/cache_push.prom") == before
        node1.succeed("systemctl start cluster-cache-probe.service")
        node1.succeed(f"grep -qx 'cluster_cache_up 0' {METRICS}/cache_up.prom")
  '';
}
