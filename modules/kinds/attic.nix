# modules/kinds/attic.nix — clusterApps.<name>.attic: the cluster's binary cache.
#
#   attic = { bucket; public; hostname; retentionDays; };
#
# An Attic server (atticd) in one container, on whichever node Nomad picks. What it
# keeps is in two places: the NARs, chunked and deduplicated, in an S3 bucket of its
# own (`bucket`, on topology.objectStorage's endpoint; lib/cloud.nix makes it and its
# key), and its index, a SQLite file in the app's own dataset, which follows the app
# from node to node like any app's local state (modules/app-state.nix).
#
# Every node fills it and every node reads it:
#
#   fills   cluster-cache-push, after every switch and once a day: the closure of the
#           system the node runs, which holds every app container the node was built
#           with. The CI agent pushes each preview it builds. What cache.nixos.org
#           already signed is skipped by Attic itself. A push that fails is a metric
#           and an alert (CachePushStale), never a failed deploy: nothing waits for it.
#   reads   as a substituter, at the node's own loopback (lib/net.nix cachePort).
#           HAProxy there sends the request to whichever node has the container, over
#           the mesh, found by a health check and not by asking anyone where it is.
#           With no cache anywhere the port refuses connections, Nix gives the
#           substituter up for a minute at a time, and builds what it would have
#           fetched: the cache is never something a deploy needs. That is also how the
#           first deploy of a cluster, and of the cache itself, goes.
#
# ── finding a container that moves ──────────────────────────────────────────
# A container's address is a DHCP lease on its node's bridge, which no other node
# knows. This one takes a fixed address instead, the same host number in whichever
# node's app subnet it starts in (`hostOctet`, below the DHCP pool), so each node
# knows where the cache is IF it is here. Each node's HAProxy has two halves:
#
#   <mesh address>:cacheMeshPort   -> that address on this node's bridge. Answers 503
#                                     when the container is elsewhere.
#   127.0.0.1:cachePort            -> every node's first half, health-checked. One of
#                                     them is up.
#
# ── who may do what ─────────────────────────────────────────────────────────
# Reading needs no token: on the mesh every reader is a node, and root on a node
# holds more than the cache does. Writing needs a token (`cache-push/token`, a JWT
# made offline from `cache-token/rs256.pem`, good for pull and push on this one cache
# and nothing else). The cache signs with a key of the site's (`cache-signing`), which
# the server is given, not asked to make, so that its public half is in the
# repository and every node trusts it by declaration.
#
# `public = true` adds the outside: `hostname`, on the app's tunnel, through an nginx
# in the container that passes GET and HEAD and refuses the API, so nothing is pushed
# or configured from there even with a token. See the README, "The binary cache", for
# what a public cache discloses, before turning it on.
#
# ── retention ───────────────────────────────────────────────────────────────
# Attic's own garbage collection: a path nobody has fetched or pushed for
# `retentionDays` is dropped from the index, and chunks no path refers to are deleted
# from the bucket. A node pushes its running system daily, so what is deployed stays.
#
# ── first start ─────────────────────────────────────────────────────────────
#   apps/<name>.nix with `attic.bucket`
#   avc cloud apply                   # the bucket, its key into cache-s3/*
#   generate the secrets              # cache-token, cache-signing, cache-push
#   -> deploy. The first node to switch after the container is up fills it.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  clusterSite,
  node,
  ...
}:
let
  inherit (lib) mkOption types;
  net = clusterLib.net;
  gens = config.cluster.secrets.generators;
  hostApps = config.clusterApps;
  apps = lib.filterAttrs (_: a: a.attic != null) hostApps;
  enabled = apps != { };
  appName = lib.head (lib.attrNames apps);
  a = apps.${appName}.attic;

  dataDir = "/var/lib/atticd";
  socket = "/run/nginx/attic.sock";
  guestPort = net.cacheGuestPort;

  # The cache's address on a node: `hostOctet` in that node's app subnet.
  net24 = ip: lib.concatStringsSep "." (lib.take 3 (lib.splitString "." ip));
  guestIp = n: g: "${net24 n.appBridgeIp}.${toString g.hostOctet}";

  toml = pkgs.formats.toml { };

  atticType = types.submodule (
    { config, ... }:
    {
      options = {
        cache = mkOption {
          type = types.strMatching "[a-z0-9][a-z0-9-]*";
          default = "cluster";
          description = "The cache's name in Attic: the last part of the substituter's URL.";
        };
        bucket = mkOption {
          type = types.str;
          example = "example-cluster-cache";
          description = "The S3 bucket the NARs are kept in, on topology.objectStorage's endpoint. `avc cloud apply` makes it.";
        };
        public = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Serve the cache, read-only and to anyone, at `hostname`. Off, the cache is
            reachable from the nodes alone. On, every store path the nodes build can be
            fetched by anyone who knows or guesses its name: the README says what that
            gives away.
          '';
        };
        hostname = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "cache.example.com";
          description = "Where the public cache is served, on the app's own tunnel. Needed when `public`.";
        };
        retentionDays = mkOption {
          type = types.ints.positive;
          default = 90;
          description = "A path nobody has pushed or fetched for this long is dropped, and its chunks with it.";
        };
        hostOctet = mkOption {
          type = types.ints.between 2 254;
          default = 9;
          description = ''
            The container's host number in the app subnet of the node it runs on. Below
            that node's DHCP pool.
          '';
        };
        storage = mkOption {
          type = toml.type;
          internal = true;
          default = {
            type = "s3";
            inherit (topology.objectStorage) region endpoint;
            inherit (config) bucket;
          };
          description = "atticd's `storage`. The bucket, unless a test has no S3.";
        };
      };
    }
  );

  # ── the container ───────────────────────────────────────────────────────────
  guestModule =
    name: g:
    let
      settings = {
        listen = "0.0.0.0:${toString guestPort}";
        # The nodes ask by address, the tunnel by name.
        allowed-hosts = [ ];
        database.url = "sqlite://${dataDir}/server.db?mode=rwc";
        inherit (g) storage;
        chunking = {
          nar-size-threshold = 65536;
          min-size = 16384;
          avg-size = 65536;
          max-size = 262144;
        };
        compression.type = "zstd";
        garbage-collection = {
          interval = "12 hours";
          default-retention-period = "${toString g.retentionDays} days";
        };
        # No `api-endpoint`: atticd then answers with the address it was asked at. Set
        # to the public name, it sent the nodes' pushes out to the tunnel, which
        # refuses them (tests/attic.nix).
      };
      configFile = toml.generate "atticd.toml" settings;
      creds = "/run/credentials/atticd.service";

      start = pkgs.writeShellScript "atticd-start" ''
        set -euo pipefail
        # The secrets are root's, bind-mounted; atticd runs as its own user and reads
        # them from its environment, which is how it takes them.
        ATTIC_SERVER_TOKEN_RS256_SECRET_BASE64=$(${pkgs.coreutils}/bin/base64 -w0 < ${creds}/token-key)
        AWS_ACCESS_KEY_ID=$(${pkgs.coreutils}/bin/tr -d '\r\n' < ${creds}/s3-access-key)
        AWS_SECRET_ACCESS_KEY=$(${pkgs.coreutils}/bin/tr -d '\r\n' < ${creds}/s3-secret-key)
        export ATTIC_SERVER_TOKEN_RS256_SECRET_BASE64 AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
        exec ${pkgs.attic-server}/bin/atticd -f ${configFile} --mode monolithic
      '';

      # The cache itself is a row in the database, made through the API, with a token
      # this container mints for itself for ten minutes: it has the key. Every start,
      # so that the signing key, the retention and the name are what the site declares
      # and not what a first run once made.
      init = pkgs.writeShellScript "attic-init" ''
        set -euo pipefail
        export PATH=${
          lib.makeBinPath [
            pkgs.coreutils
            pkgs.curl
            pkgs.openssl
            pkgs.jq
          ]
        }
        url=http://127.0.0.1:${toString guestPort}
        work=$(mktemp -d)
        trap 'rm -rf "$work"' EXIT

        for _ in $(seq 1 60); do
          curl -fsS --max-time 5 -o /dev/null "$url/" && break
          sleep 2
        done

        b64() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
        now=$(date +%s)
        h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
        p=$(jq -cn --arg c ${g.cache} --argjson now "$now" \
          '{sub: "attic-init", iat: $now, exp: ($now + 600),
            "https://jwt.attic.rs/v1": {caches: {($c): {r: 1, w: 1, cc: 1, cr: 1, cq: 1}}}}' | b64)
        printf '%s.%s' "$h" "$p" > "$work/in"
        s=$(openssl dgst -sha256 -sign /run/secrets/attic-token-key "$work/in" | b64)
        printf 'Authorization: Bearer %s.%s.%s\n' "$h" "$p" "$s" > "$work/auth"
        chmod 0600 "$work/auth"

        # The key goes in a file, never on a command line.
        jq -n --rawfile key /run/secrets/attic-signing-key \
          '{keypair: {Keypair: ($key | rtrimstr("\n"))}, is_public: true, store_dir: "/nix/store",
            priority: 41, upstream_cache_key_names: ["cache.nixos.org-1"]}' > "$work/create.json"
        jq '{keypair, is_public, retention_period: {Period: ${toString (g.retentionDays * 86400)}}}' \
          "$work/create.json" > "$work/configure.json"

        api() { # METHOD BODY -> the HTTP status
          curl -sS --max-time 30 -o "$work/out" -w '%{http_code}' -X "$1" -H @"$work/auth" \
            -H 'content-type: application/json' --data-binary @"$2" \
            "$url/_api/v1/cache-config/${g.cache}"
        }
        code=$(api POST "$work/create.json")
        case "$code" in
          200) echo "attic-init: cache ${g.cache} created" ;;
          400 | 409) ;; # it exists
          *)
            echo "attic-init: creating ${g.cache}: HTTP $code: $(head -c 300 "$work/out")" >&2
            exit 1
            ;;
        esac
        code=$(api PATCH "$work/configure.json")
        if [ "$code" != 200 ]; then
          echo "attic-init: configuring ${g.cache}: HTTP $code: $(head -c 300 "$work/out")" >&2
          exit 1
        fi
        echo "attic-init: cache ${g.cache}: the site's key, kept ${toString g.retentionDays} days"
      '';
    in
    {
      users.users.atticd = {
        isSystemUser = true;
        group = "atticd";
        home = dataDir;
      };
      users.groups.atticd = { };

      # The state directory is a bind mount the host created as root.
      systemd.tmpfiles.rules = [ "d ${dataDir} 0700 atticd atticd -" ];

      systemd.services.atticd = {
        description = "Attic binary cache server";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = start;
          User = "atticd";
          Group = "atticd";
          LoadCredential = [
            "token-key:/run/secrets/attic-token-key"
            "s3-access-key:/run/secrets/attic-s3-access-key"
            "s3-secret-key:/run/secrets/attic-s3-secret-key"
          ];
          Restart = "on-failure";
          RestartSec = 5;
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          ReadWritePaths = [ dataDir ];
        };
      };

      systemd.services.attic-init = {
        description = "The cache in Attic: its name, the site's signing key, its retention";
        wantedBy = [ "multi-user.target" ];
        after = [ "atticd.service" ];
        requires = [ "atticd.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          ExecStart = init;
          Restart = "on-failure";
          RestartSec = 10;
        };
      };

      # br-app only, as the database kind does: not the bridged WAN interface.
      networking.firewall.interfaces.eth0.allowedTCPPorts = [ guestPort ];

      # A fixed address in this node's app subnet in place of the DHCP lease, and DNS
      # from the bridge gateway since the lease no longer supplies it.
      systemd.network.networks."10-eth0" = {
        networkConfig = {
          DHCP = lib.mkForce "no";
          DNS = [ node.appBridgeIp ];
        };
        address = [ "${guestIp node g}/${lib.last (lib.splitString "/" node.appSubnet)}" ];
        routes = [ { Gateway = node.appBridgeIp; } ];
      };

      # The outside, when there is one: what Nix fetches and nothing else.
      services.nginx = lib.mkIf (g.public && g.hostname != null) {
        enable = true;
        virtualHosts.${g.hostname} = {
          listen = [ { addr = "unix:${socket}"; } ];
          locations."/_api/".return = "403";
          locations."/" = {
            proxyPass = "http://127.0.0.1:${toString guestPort}";
            extraConfig = ''
              limit_except GET HEAD {
                deny all;
              }
              proxy_buffering off;
            '';
          };
        };
      };
    };

  # ── every node ──────────────────────────────────────────────────────────────
  local = "http://127.0.0.1:${toString net.cachePort}";
  substituter = "${local}/${a.cache}";
  textDir = "/var/lib/prometheus-node-exporter-text";
  pushMetric = "${textDir}/cache_push.prom";
  upMetric = "${textDir}/cache_up.prom";
  signingPub = gens.cache-signing.files."public";

  haproxyConfig = ''
    global
      # Capped at warning: "no server available" is HAProxy's alert, and here it is
      # the ordinary state of a cluster whose cache is between two nodes.
      log stdout format short daemon notice warning
      maxconn 512

    defaults
      mode http
      log global
      option dontlognull
      timeout connect 5s
      # A NAR is as long as it is.
      timeout client 30m
      timeout server 30m
      timeout http-request 30s

    # Where Nix on this node asks. With the cache on no node, refuse the connection:
    # an HTTP error would be retried, a refusal turns the substituter off for a while.
    frontend cache_local
      bind 127.0.0.1:${toString net.cachePort}
      tcp-request connection reject if { nbsrv(cache_nodes) eq 0 }
      default_backend cache_nodes

    backend cache_nodes
      option httpchk
      # HTTP/1.1 with a Host: atticd answers a bare HTTP/1.0 request with an error.
      http-check send meth GET uri / ver HTTP/1.1 hdr Host cluster-cache
      http-check expect status 200
      default-server check inter 5s fall 2 rise 1
    ${lib.concatStringsSep "\n" (
      lib.mapAttrsToList (
        n: o: "  server ${n} ${net.meshIp topology o}:${toString net.cacheMeshPort}"
      ) topology.nodes
    )}

    # What this node passes on for the others, and for itself: the cache's address
    # here, where it is when it is one of this node's containers.
    frontend cache_mesh
      bind ${net.meshIp topology node}:${toString net.cacheMeshPort}
      default_backend cache_container

    backend cache_container
      server here ${guestIp node a}:${toString guestPort}
  '';

  push = pkgs.writeShellApplication {
    name = "cluster-cache-push";
    runtimeInputs = [
      pkgs.coreutils
      pkgs.attic-client
    ];
    # With no argument, the system this node runs. Exits 0 whatever happens: who
    # calls it (a deploy, the CI agent) has nothing to wait for and nothing to undo.
    text = ''
      paths=("$@")
      [ "''${#paths[@]}" -gt 0 ] || paths=(/run/current-system)
      if [ ! -e ${pushMetric} ]; then
        mkdir -p ${textDir}
        printf 'cluster_cache_push_last_success_timestamp_seconds 0\n' > ${pushMetric}
      fi
      work=$(mktemp -d)
      trap 'rm -rf "$work"' EXIT
      mkdir -p "$work/attic"
      # The token in a file of root's, never on a command line.
      (
        umask 077
        printf 'default-server = "cluster"\n[servers.cluster]\nendpoint = "%s"\ntoken = "%s"\n' \
          ${local} "$(tr -d '\r\n' < ${gens.cache-push.files.token.path})" > "$work/attic/config.toml"
      ) || { echo "cluster-cache-push: no token: nothing pushed" >&2; exit 0; }
      if XDG_CONFIG_HOME="$work" timeout 3h attic push ${a.cache} "''${paths[@]}"; then
        printf 'cluster_cache_push_last_success_timestamp_seconds %s\n' "$(date +%s)" > ${pushMetric}.tmp
        mv ${pushMetric}.tmp ${pushMetric}
      else
        echo "cluster-cache-push: the push failed; the cache is an optimisation, so nothing else did" >&2
      fi
      exit 0
    '';
  };

  probe = pkgs.writeShellScript "cluster-cache-probe" ''
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.curl
      ]
    }
    up=0
    curl -fsS --max-time 5 -o /dev/null ${substituter}/nix-cache-info && up=1
    mkdir -p ${textDir}
    printf 'cluster_cache_up %s\n' "$up" > ${upMetric}.tmp
    mv ${upMetric}.tmp ${upMetric}
  '';
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          g = config.attic;
          exposed = g.public && g.hostname != null && config.tunnel.id != "";
        in
        {
          options.attic = mkOption {
            type = types.nullOr atticType;
            default = null;
            description = "The cluster's binary cache, an Attic server (modules/kinds/attic.nix).";
          };

          config = lib.mkIf (config.attic != null) {
            tier = lib.mkDefault "monolith";
            resources = {
              cpu = lib.mkDefault 1000;
              memoryMB = lib.mkDefault 1024;
            };
            # The index. The NARs are in the bucket.
            localState.${dataDir} = "/state/clients/${name}/db";
            secrets = {
              attic-token-key = {
                generator = "cache-token";
                file = "rs256.pem";
              };
              attic-signing-key = {
                generator = "cache-signing";
                file = "secret";
              };
              attic-s3-access-key = {
                generator = "cache-s3";
                file = "access-key";
              };
              attic-s3-secret-key = {
                generator = "cache-s3";
                file = "secret-key";
              };
            };
            # Conditions on the leaves, not on `tunnel` (see kinds/odoo.nix).
            tunnel = {
              ingress = lib.mkIf exposed { ${g.hostname} = "unix:${socket}"; };
              socketGroups = lib.mkIf exposed [ "nginx" ];
            };
            backup = {
              # The bucket is the cache, and a cache is rebuilt by building. The index
              # is snapshotted with the app's dataset like any local state.
              engine = "none";
              localSnapshot = true;
              appUnits = [ "atticd.service" ];
              verifyCommand = ''test -s "$ROOT${dataDir}/server.db"'';
            };
            module = guestModule name g;
          };
        }
      )
    );
  };

  options.cluster.cache = {
    publicKey = mkOption {
      type = types.nullOr types.str;
      default = if enabled && signingPub.exists then lib.removeSuffix "\n" signingPub.value else null;
      defaultText = lib.literalMD "the `cache-signing/public` var, once it is generated";
      description = "The key the cache signs with, as Nix trusts it. Null until the var exists: the nodes then do not ask the cache at all.";
    };
    pushCommand = mkOption {
      type = types.nullOr types.path;
      readOnly = true;
      default = if enabled then lib.getExe push else null;
      description = "What pushes store paths to the cache from this node, for whatever else builds (modules/ci-agent.nix). Null with no cache.";
    };
  };

  config = lib.mkIf enabled {
    assertions = [
      {
        assertion = lib.length (lib.attrNames apps) == 1;
        message = "clusterApps: ${lib.concatStringsSep ", " (lib.attrNames apps)} are all `attic`; a cluster has one binary cache.";
      }
      {
        assertion = !a.public || a.hostname != null;
        message = "clusterApps.${appName}: attic.public needs attic.hostname, where the cache is served.";
      }
      {
        assertion = lib.all (n: n.appDhcpPoolOffset > a.hostOctet) (lib.attrValues topology.nodes);
        message = "clusterApps.${appName}: attic.hostOctet ${toString a.hostOctet} is inside a node's DHCP pool (nodes.<n>.appDhcpPoolOffset).";
      }
    ];

    cluster.mesh.extraPorts = [ net.cacheMeshPort ];

    environment.systemPackages = [
      push
      pkgs.attic-client
    ];

    # Asked first only for what it has: `fallback` builds what a substituter promised
    # and then failed to deliver, and a short connect timeout keeps a cache that is
    # away from costing more than a moment.
    nix.settings = lib.mkIf (config.cluster.cache.publicKey != null) {
      extra-substituters = [ substituter ];
      extra-trusted-public-keys = [ config.cluster.cache.publicKey ];
      fallback = true;
      connect-timeout = lib.mkDefault 5;
    };

    services.haproxy = {
      enable = true;
      config = haproxyConfig;
    };
    systemd.services.haproxy = net.meshBoundUnit;

    systemd.services.cluster-cache-push = {
      description = "Push this node's system closure to the cluster's binary cache";
      after = [
        "haproxy.service"
        "nix-daemon.socket"
      ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe push;
        Nice = 10;
        IOSchedulingClass = "idle";
      };
    };
    # A switch moves the system profile; a boot into a generation does not, so the
    # timer covers that, and whatever a failed push left out.
    systemd.paths.cluster-cache-push = {
      wantedBy = [ "paths.target" ];
      pathConfig.PathChanged = "/nix/var/nix/profiles/system";
    };
    systemd.timers.cluster-cache-push = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "15min";
        OnUnitActiveSec = "1d";
        RandomizedDelaySec = "30min";
      };
    };

    systemd.services.cluster-cache-probe = {
      description = "Whether this node reaches the cluster's binary cache";
      after = [ "haproxy.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = probe;
      };
    };
    systemd.timers.cluster-cache-probe = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = "1min";
      };
    };

    cluster.secrets.generators = {
      # What atticd checks every token with. Its tokens are made from it offline
      # (`cache-push` below) and by the container for itself. Every node holds it, as
      # it holds every app's secrets: the app may start on any of them.
      cache-token = {
        share = true;
        files."rs256.pem" = { };
        runtimeInputs = [ pkgs.openssl ];
        script = ''
          openssl genrsa -traditional -out "$out/rs256.pem" 4096
        '';
      };
      # The cache's signing key: the secret half for the server, the public half in
      # the repository, where every node's nix.conf reads it.
      cache-signing = {
        share = true;
        files.secret = { };
        files."public".secret = false;
        runtimeInputs = [ pkgs.nix ];
        script = ''
          nix --extra-experimental-features nix-command key generate-secret \
            --key-name ${lib.escapeShellArg "${clusterSite.name}-cache-1"} > "$out/secret"
          nix --extra-experimental-features nix-command key convert-secret-to-public \
            < "$out/secret" > "$out/public"
        '';
      };
      # Every node's token: pull and push on this cache, nothing else (not creating,
      # configuring or destroying one). Ten years: a cache token that lapsed would be
      # a push that quietly stopped. Regenerating `cache-token` is how all are revoked.
      cache-push = {
        share = true;
        dependencies = [ "cache-token" ];
        files.token = { };
        runtimeInputs = [
          pkgs.coreutils
          pkgs.openssl
          pkgs.jq
        ];
        script = ''
          b64() { base64 -w0 | tr '+/' '-_' | tr -d '='; }
          now=$(date +%s)
          h=$(printf '{"alg":"RS256","typ":"JWT"}' | b64)
          p=$(jq -cn --arg c ${a.cache} --argjson now "$now" \
            '{sub: "cluster-node", iat: $now, exp: ($now + 315360000),
              "https://jwt.attic.rs/v1": {caches: {($c): {r: 1, w: 1}}}}' | b64)
          printf '%s.%s' "$h" "$p" > jwt.in
          s=$(openssl dgst -sha256 -sign "$in/cache-token/rs256.pem" jwt.in | b64)
          printf '%s.%s.%s' "$h" "$p" "$s" > "$out/token"
        '';
      };
      # The bucket's own key pair, which `avc cloud apply` writes (lib/cloud.nix), or
      # the operator types where OpenTofu is not used.
      cache-s3 = {
        share = true;
        prompts."access-key" = {
          description = "The binary cache bucket's S3 access key";
          persist = true;
        };
        prompts."secret-key" = {
          description = "The binary cache bucket's S3 secret key";
          type = "hidden";
          persist = true;
        };
      };
    };
  };
}
