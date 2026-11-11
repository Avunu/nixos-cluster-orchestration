# modules/mesh-control-core.nix — the WireGuard control mesh, without clan.
#
# Every service but Nomad listens on this interface (design D1): etcd, Loki,
# Prometheus, the exporters, Vector and the JuiceFS metadata engine. A machine
# attached to the vRack VLANs, which is all "conventional provider access" needs,
# reaches none of them without a private key some node lists as a peer. That is
# machine authentication, not per-service: any process on a node can use the mesh.
# Nomad stays on the control VLAN under its own mTLS, a separate failure domain.
#
# The clan wiring (modules/mesh-control.nix) supplies the keys from vars; the VM
# tests that need no clan (checks.jumbo-mtu) supply literals. Peers are every other
# node in the topology. Its own address is <mesh.subnet base>.<index>.
#
# The ruleset (modules/overlay-network.nix) is the other half: the kernel answers
# for a mesh address on any interface, so an attacker on the VLAN with a route to it
# read every exporter while the firewall accepted mesh ports without naming the
# interface [RAN, design 1.14]. Today what keeps the services off the VLAN is that
# every mesh accept is scoped to `iifname wg-ctrl`; the weak-host drop on top is
# defence in depth, and without it such an attacker gets ICMP echo and nothing of
# the mesh's services. `weak-host-route-refused` in checks.control-plane-attack
# shows both: no service either way, and the ICMP half is what its mutant flips.
#
# Also here: `vrack-mtu-probe`, which notices a VLAN that stopped carrying the MTU it
# is configured for (D25). Small frames pass and large ones vanish, so every
# handshake looks healthy while transfers hang; only a full-size, don't-fragment
# ping tells. It is a metric, never a failing unit (VrackJumboBroken).
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  ...
}:
let
  inherit (lib) mkOption types;
  net = clusterLib.net;
  cfg = config.cluster.mesh;
  m = topology.mesh or { };
  vl = topology.vlans;
  ifName = net.meshIf;

  hasSubnet = m ? subnet;
  # A /24, on its network address: meshIp takes the first three octets.
  isMeshCidr =
    s:
    builtins.isString s
    &&
      builtins.match "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){2}\\.0/24" s
      != null;
  subnetOk = hasSubnet && isMeshCidr m.subnet;
  port = net.meshPort topology;
  mtu = net.meshMtu topology;

  others = lib.filterAttrs (n: _: n != nodeName) topology.nodes;
  known = lib.filterAttrs (n: _: (cfg.publicKeys.${n} or null) != null) others;
  # A node not yet installed may have no key: it is skipped, and listed once its
  # key is generated. One that is installed must have one, or the mesh between
  # them silently never forms.
  missingProvisioned = lib.attrNames (
    lib.filterAttrs (n: nd: (nd.provisioned or true) && !(known ? ${n})) others
  );
  badIndex = lib.attrNames (
    lib.filterAttrs (
      _: nd: !(builtins.isInt (nd.index or null) && nd.index >= 1 && nd.index <= 254)
    ) topology.nodes
  );
  otherSubnets =
    lib.mapAttrsToList (n: v: {
      name = "vlans.${n}.subnet";
      cidr = v.subnet;
    }) vl
    ++ lib.optional (topology ? privateServices) {
      name = "privateServices";
      cidr = topology.privateServices;
    };
  overlapping = lib.optionals subnetOk (
    map (o: o.name) (lib.filter (o: net.cidrsOverlap m.subnet o.cidr) otherSubnets)
  );

  meshAddr = net.meshIp topology node;

  # ── vrack-mtu-probe ─────────────────────────────────────────────────────────
  # Every installed peer, on each VLAN and on the mesh, at the largest payload the
  # configured MTU allows (MTU - 28: 20 of IPv4 header, 8 of ICMP), with
  # don't-fragment. A peer that does not answer a SMALL ping is unreachable, which
  # is NodeDown's business: it gets no `ok` sample, so the two alerts don't double.
  provisionedPeers = lib.filterAttrs (_: nd: nd.provisioned or true) others;
  probeTargets = lib.concatLists (
    lib.mapAttrsToList (peer: nd: [
      {
        inherit peer;
        vlan = "control";
        addr = nd.controlIp;
        size = vl.control.mtu - 28;
      }
      {
        inherit peer;
        vlan = "app";
        addr = net.appTransitIp nd;
        size = vl.app.mtu - 28;
      }
      {
        inherit peer;
        vlan = "storage";
        addr = nd.storageIp;
        size = vl.storage.mtu - 28;
      }
      {
        inherit peer;
        vlan = "mesh";
        addr = net.meshIp topology nd;
        size = mtu - 28;
      }
    ]) provisionedPeers
  );
  textDir = "/var/lib/prometheus-node-exporter-text";
  probeScript = pkgs.writeShellScript "vrack-mtu-probe" ''
    set -uo pipefail
    out=${textDir}/vrack_mtu.prom
    mkdir -p ${textDir}
    tmp=$(mktemp ${textDir}/.vrack_mtu.XXXXXX)
    trap 'rm -f "$tmp"' EXIT
    {
      echo "# HELP cluster_vrack_mtu_ok 1 if a don't-fragment ping at the configured MTU reaches the peer, 0 if only small ones do."
      echo "# TYPE cluster_vrack_mtu_ok gauge"
      echo "# HELP cluster_vrack_peer_reachable 1 if a small ping reaches the peer on that VLAN."
      echo "# TYPE cluster_vrack_peer_reachable gauge"
    } > "$tmp"
    probe() { # vlan peer addr size
      local reach=0 ok
      if ping -n -q -c 2 -W 2 "$3" >/dev/null 2>&1; then reach=1; fi
      echo "cluster_vrack_peer_reachable{vlan=\"$1\",peer=\"$2\"} $reach" >> "$tmp"
      [ "$reach" = 1 ] || return 0
      # Three tries: one lost probe is not a blackhole.
      ok=0
      if ping -n -q -M do -s "$4" -c 3 -W 2 "$3" >/dev/null 2>&1; then ok=1; fi
      echo "cluster_vrack_mtu_ok{vlan=\"$1\",peer=\"$2\"} $ok" >> "$tmp"
      [ "$ok" = 1 ] || echo "vrack-mtu-probe: $1 to $2 ($3): $4-byte don't-fragment pings lost, small ones answered" >&2
    }
    ${lib.concatMapStrings (t: ''
      probe ${t.vlan} ${t.peer} ${t.addr} ${toString t.size}
    '') probeTargets}
    echo "cluster_vrack_mtu_probe_timestamp_seconds $(date +%s)" >> "$tmp"
    chmod 0644 "$tmp"
    mv "$tmp" "$out"
    trap - EXIT
  '';
in
{
  options.cluster.mesh = {
    privateKeyFile = mkOption {
      type = types.str;
      description = "This node's WireGuard private key, readable by systemd-network.";
    };
    publicKeys = mkOption {
      type = types.attrsOf (types.nullOr types.str);
      default = { };
      description = ''
        Every node's public key by name, null where none exists yet. A peer with a
        null key is left out if it is a placeholder (`provisioned = false`) and refused
        at evaluation if it is not.
      '';
    };
    keyCiphertext = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        The encrypted private key in the repository, if any. Its hash restarts
        systemd-networkd when it changes: `networkctl reload` does not apply a new
        private key, a restart does, and the netdev file itself does not change, so a
        switch would otherwise never apply a rotation [RAN, design 1.14].
      '';
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = hasSubnet;
          message = "topology.mesh.subnet is required: the WireGuard control mesh every service but Nomad runs over, a /24 (a node takes <base>.<index>).";
        }
        {
          assertion = !hasSubnet || subnetOk;
          message = "topology.mesh.subnet must be an IPv4 /24 on its network address, like 10.25.0.0/24, not \"${toString (m.subnet or "")}\".";
        }
        {
          assertion = overlapping == [ ];
          message = "topology.mesh.subnet ${toString (m.subnet or "")} overlaps ${lib.concatStringsSep ", " overlapping}.";
        }
        {
          assertion = badIndex == [ ];
          message = "mesh: ${lib.concatStringsSep ", " badIndex} need an `index` from 1 to 254: it is the last octet of the node's mesh address.";
        }
        {
          assertion = builtins.isInt port && port >= 1 && port <= 65535;
          message = "topology.mesh.port must be a port number, 1 to 65535.";
        }
        {
          # D25: the mesh's packets ride the control VLAN with up to 80 bytes added. One
          # byte over, and every full-size packet on the mesh is dropped, silently.
          assertion = builtins.isInt mtu && mtu + net.meshOverhead <= vl.control.mtu;
          message = "topology.mesh.mtu ${toString mtu} plus WireGuard's ${toString net.meshOverhead} bytes exceeds vlans.control.mtu ${toString vl.control.mtu}. Leave mesh.mtu unset to follow the VLAN.";
        }
        {
          assertion = missingProvisioned == [ ];
          message = "mesh: no ${ifName} public key for ${lib.concatStringsSep ", " missingProvisioned}. Run: clan vars generate";
        }
      ];
    }

    # Nothing below can be rendered without a subnet, and the assertions above say why.
    (lib.mkIf subnetOk {

      systemd.network.netdevs."30-${ifName}" = {
        netdevConfig = {
          Name = ifName;
          Kind = "wireguard";
          MTUBytes = toString mtu;
        };
        wireguardConfig = {
          PrivateKeyFile = cfg.privateKeyFile;
          ListenPort = port;
        };
        wireguardPeers = lib.mapAttrsToList (n: nd: {
          PublicKey = lib.removeSuffix "\n" cfg.publicKeys.${n};
          AllowedIPs = [ "${net.meshIp topology nd}/32" ];
          Endpoint = "${nd.controlIp}:${toString port}";
          PersistentKeepalive = 25;
        }) (lib.getAttrs (lib.attrNames known) others);
      };
      systemd.network.networks."30-${ifName}" = {
        matchConfig.Name = ifName;
        address = [ "${meshAddr}/${toString net.meshPrefix}" ];
        linkConfig.RequiredForOnline = "no";
      };

      systemd.services.systemd-networkd.restartTriggers = lib.optional (cfg.keyCiphertext != null) (
        builtins.hashFile "sha256" cfg.keyCiphertext
      );

      # Ordered before every mesh-bound service (lib/net.nix meshBoundUnit). Never fails:
      # a missing key leaves the interface absent and the node up [RAN], and those
      # services retry until it is repaired.
      systemd.services."${ifName}-ready" = {
        description = "Wait for the control mesh address";
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-networkd.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        path = [
          pkgs.iproute2
          pkgs.gnugrep
          pkgs.coreutils
        ];
        script = ''
          for _ in $(seq 60); do
            ip -4 -o addr show dev ${ifName} 2>/dev/null | grep -qF ' ${meshAddr}/' && exit 0
            sleep 0.5
          done
          echo "${ifName}-ready: no mesh address after 30s; mesh-bound services will retry" >&2
        '';
      };

      systemd.services.vrack-mtu-probe = {
        description = "Don't-fragment pings at the configured MTU to every peer (metrics)";
        after = [
          "network-online.target"
          "${ifName}-ready.service"
        ];
        wants = [ "network-online.target" ];
        path = [
          pkgs.iputils
          pkgs.coreutils
        ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${probeScript}";
        };
      };
      systemd.timers.vrack-mtu-probe = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "2min";
          OnUnitActiveSec = "5min";
        };
      };
    })
  ];
}
