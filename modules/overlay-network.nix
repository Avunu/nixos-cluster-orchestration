# modules/overlay-network.nix — the vRack L2 fabric (Phase 2), generated per
# node from the topology in the nixos-router style.
#
# Containers are DUAL-STACK: a private DHCPv4 address on br-app (masqueraded,
# still needed for IPv4-only destinations) plus a routable IPv6 GUA on br-wan,
# so the bulk of egress leaves without traversing the NAT hook. Nothing needs to
# reach a container inbound — each carries its own outbound Cloudflare Tunnel.
#
# Layout (no VXLAN — the OVH vRack carries tagged VLANs on the trunk NIC):
#   WAN NIC            -> port on br-wan (no addresses of its own)
#   br-wan bridge      -> host public IPv4 (/32, on-link gw) + IPv6 (::1/64),
#                         and the L2 segment containers join for their GUAs
#   vRack trunk NIC    -> carries VLANs: control / app / storage
#     control VLAN     -> node.controlIp/24: Nomad (mTLS), and the WireGuard
#                         control mesh (modules/mesh-control-core.nix) that
#                         every other cluster service listens on
#     storage VLAN     -> node.storageIp/24 (nothing on the host listens there)
#     app VLAN         -> transit 10.20.0.<index>/24 + static routes to every
#                         OTHER node's container /24 (cross-node reachability)
#   br-app bridge      -> node.appBridgeIp/24, built-in networkd DHCP server for
#                         this node's local containers (no central DHCP, no SPOF)
#
# The host runs resolved with a stub listener on br-app so containers get a
# working resolver via DHCP option 6.
#
# MTU (design D25): each VLAN takes `vlans.<v>.mtu` (9000 on a real vRack), and
# the trunk the largest of them, because a VLAN can't exceed its parent. br-wan,
# br-app and the container veths stay at 1500: the internet path is 1500, and a
# container needs no more. The initrd sets no MTU at all (modules/boot-security-core.nix):
# it brings up only the WAN NIC, for someone to type the passphrase over SSH.
#
# A VLAN that doesn't really carry its MTU is a silent blackhole: small packets
# pass, large ones vanish, so every handshake looks healthy while transfers hang.
# PMTU discovery can't help on one L2 segment. Hence tcp_mtu_probing here, and
# vrack-mtu-probe with VrackJumboBroken (modules/mesh-control-core.nix).
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
  net = clusterLib.net;
  vl = topology.vlans;
  vrack = node.vrackInterface;

  ctrlIf = net.vlanChild vrack vl.control.id;
  appIf = net.vlanChild vrack vl.app.id;
  stgIf = net.vlanChild vrack vl.storage.id;

  # app-VLAN transit addressing: node uplink = 10.20.0.<index>/24; each node's
  # containers live on br-app = 10.20.<index>.0/24. Routes below stitch them.
  appTransitIp = net.appTransitIp node;
  appTransitCidr = "${appTransitIp}/24";

  others = lib.filterAttrs (n: _: n != nodeName) topology.nodes;
  containerRoutes = lib.mapAttrsToList (_n: o: {
    Destination = o.appSubnet;
    Gateway = net.appTransitIp o;
  }) others;

  # A VLAN can't exceed its parent, so the trunk carries the largest.
  trunkMtu = lib.foldl' lib.max 0 (lib.mapAttrsToList (_: v: v.mtu) vl);

  meshIf = net.meshIf;
  meshIp = net.meshIp topology node;
  meshSubnet = topology.mesh.subnet;
  meshPorts = lib.concatMapStringsSep ", " toString (net.meshPortsFor node);
  isMetrics = net.hasTag "metrics" node;

  # ── Container default-deny (design WS9, Appendix E) ─────────────────────────
  # What each app declares it may reach (clusterApps.<n>.network, set by
  # modules/app-container.nix). Every node declares every app, so these rules are
  # the same set everywhere but for the node's own addresses.
  apps = config.cluster.appFirewall.apps;
  appNames = lib.attrNames apps;
  portOf = net.appPortFor apps;
  hex = m: "0x${lib.toLower (lib.toHexString m)}";
  markOf = n: hex (net.appMark apps n);
  peerIn = hex net.peerInMark;
  lines = lib.concatStringsSep "\n";

  hostAccessApps = lib.filter (n: apps.${n}.hostAccess != [ ]) appNames;
  peerSources = lib.filter (n: apps.${n}.peerAccess != [ ]) appNames;
  markedApps = lib.unique (hostAccessApps ++ peerSources);
  # (source, target, port), once each.
  peerFlows = lib.unique (
    lib.concatMap (
      s:
      map (p: {
        inherit s;
        t = p.app;
        inherit (p) port;
      }) apps.${s}.peerAccess
    ) peerSources
  );
  peerTargets = lib.unique (map (f: f.t) peerFlows);
  portsTo = t: lib.unique (map (f: toString f.port) (lib.filter (f: f.t == t) peerFlows));
  portsFrom = s: lib.unique (map (f: toString f.port) (lib.filter (f: f.s == s) peerFlows));
  setOf = xs: lib.concatStringsSep ", " xs;

  otherSubnets = lib.mapAttrsToList (_: o: o.appSubnet) others;
  # The internet, for a container: not the fabric, and not this cluster's own public
  # addresses (a container must not reach another node's SSH through the NAT).
  allPublic4 = lib.unique (lib.mapAttrsToList (_: n: n.publicIp4) topology.nodes);
  notInternet4 = [
    "10.0.0.0/8"
    "172.16.0.0/12"
    "192.168.0.0/16"
    "169.254.0.0/16"
    "100.64.0.0/10"
  ]
  ++ allPublic4;

  # Bridge prerouting: the mark that names a declared app's frames.
  marks = lines (map (n: ''iifname "${portOf n}" meta mark set ${markOf n}'') markedApps);
  # Bridge prerouting, per WAN veth: the frame's source is the container's own fixed
  # MAC (lib/net.nix appWanMac), its IPv6 source its own GUA or its fixed link-local
  # address (appWanLinkLocal; the container's networkd sets both), and a neighbour
  # advert it sends speaks only for those two addresses.
  #   - IPv6 source: a container added a spoofed GUA and its egress worked [RAN, 1.15].
  #   - Ethernet source: br-wan learns MACs from what arrives on a port, before the
  #     inet tables see anything, so a frame from a container with the gateway's MAC
  #     would have moved the gateway to the container's port in br-wan's forwarding
  #     table, and the host's own traffic to the gateway (IPv4 included) with it.
  #     Prerouting runs before learning.
  #   - Neighbour adverts: an unsolicited NA (override flag) from the container's own
  #     link-local address, claiming node1's public IPv6 for the container's MAC,
  #     moved the gateway's neighbour entry for the node to the container [RAN, a
  #     review's probe]: inbound IPv6 for the host went to a tenant. The source check
  #     alone can't see that; the target is a field of its own (`icmpv6 taddr`).
  # `nd-spoof-refused` and `wan-mac-pinned` in checks.container-isolation; mutant
  # `no-nd-guard` (flake.nix) removes the NA rules.
  perAppGuaRules = lines (
    lib.concatMap (
      n:
      let
        port = net.appWanPort n;
        own = "{ ${net.gua6 node n}, ${net.appWanLinkLocal node n} }";
      in
      [
        ''iifname "${port}" ether saddr != ${net.appWanMac node n} drop''
        ''iifname "${port}" ip6 saddr != ${own} drop''
        ''iifname "${port}" icmpv6 type nd-neighbor-advert icmpv6 taddr != ${own} drop''
      ]
    ) appNames
  );
  # Bridge forward: a declared same-node flow, port to port. ARP both ways (or
  # neither end finds the other), the declared port one way, and only the replies
  # back: from that port, never a SYN, so the target can't open a connection to its
  # source. Stateless on purpose: the bridge then needs no conntrack of its own.
  samenodePeerAccepts = lines (
    lib.unique (
      lib.concatMap (
        f:
        let
          s = net.appPeerPort f.s;
          t = net.appPeerPort f.t;
          p = toString f.port;
        in
        lib.optionals (f.s != f.t) [
          ''iifname "${s}" oifname "${t}" ether type arp accept''
          ''iifname "${t}" oifname "${s}" ether type arp accept''
          ''iifname "${s}" oifname "${t}" ether type ip tcp dport ${p} accept''
          ''iifname "${t}" oifname "${s}" ether type ip tcp sport ${p} tcp flags & (syn | ack) != syn accept''
        ]
      ) peerFlows
    )
  );
  # Bridge output: a connection routed in from another node to a declared peer port
  # (marked in the inet forward chain below) reaches only an app declared for that
  # port, whatever address it was sent to.
  peerInDelivers = lines (
    map (
      t:
      ''meta mark ${peerIn} oifname "${net.appPeerPort t}" ether type ip tcp dport { ${setOf (portsTo t)} } accept''
    ) peerTargets
  );

  # inet input: a declared app's own ports on this node's mesh address, by mark. On
  # the metrics node only, since that is where Loki and Prometheus are and the only
  # node a container can reach a mesh address from (its own); app-container.nix
  # asserts such an app is pinned to a metrics node.
  markedHostAccepts = lib.optionalString isMetrics (
    lines (
      map (
        n:
        ''iifname "br-app" meta mark ${markOf n} ip daddr ${meshIp} tcp dport { ${
          setOf (map toString (lib.unique apps.${n}.hostAccess))
        } } accept''
      ) hostAccessApps
    )
  );
  # inet forward: cross-node peer flows. Out: by the source's mark, to the other
  # nodes' container subnets (never a transit or host address), on its declared
  # ports. In: from another node's container subnet to this one's, on a declared
  # port, marked for the bridge's output chain, which picks the target.
  crossNodeAccepts = lib.optionalString (otherSubnets != [ ] && peerFlows != [ ]) (
    lines (
      map (
        s:
        ''iifname "br-app" oifname "${appIf}" meta mark ${markOf s} ip daddr { ${setOf otherSubnets} } tcp dport { ${setOf (portsFrom s)} } accept''
      ) peerSources
      ++ [
        ''iifname "${appIf}" oifname "br-app" ip saddr { ${setOf otherSubnets} } ip daddr ${node.appSubnet} tcp dport { ${
          setOf (lib.unique (map (f: toString f.port) peerFlows))
        } } meta mark set ${peerIn} accept''
      ]
    )
  );

  # Identity by bridge port. A container with CAP_NET_ADMIN can change its IP and
  # MAC, but not which veth its frames arrive on. The bridge family sees every
  # frame between two ports, which the inet tables never do (no br_netfilter), and
  # every frame a container sends the host, before the inet tables see the packet.
  bridgeGuard = ''
    table bridge guard {
      chain prerouting {
        type filter hook prerouting priority -300; policy accept;
        # A container's own mark can't cross its veth (the kernel scrubs it), but
        # say so: every frame from br-app's ports starts unmarked.
        meta ibrname "br-app" meta mark set 0x0
    ${marks}
        # No container answers DHCP, or claims the gateway, on br-app.
        meta ibrname "br-app" ether type ip udp sport 67 drop
        meta ibrname "br-app" arp saddr ip ${node.appBridgeIp} drop
        meta ibrname "br-app" ip saddr ${node.appBridgeIp} drop
        # WAN veths: IPv6 only, no IPv4, no ARP. No container is a router: no router
        # adverts, no redirects. Then each its own MAC, addresses and adverts (above).
        iifname "vw-*" ether type { ip, arp } drop
        iifname "vw-*" icmpv6 type { nd-router-advert, nd-redirect } drop
    ${perAppGuaRules}
      }

      chain forward {
        type filter hook forward priority 0; policy accept;
        # Declared same-node flows ride the deterministic vp-<iid> veths, not the
        # nspawn-truncated vb-<name>, so a 22-character app name still matches (D23).
    ${samenodePeerAccepts}
        # Nothing else between two containers: vb-, vp- and any other port of br-app.
        meta ibrname "br-app" drop
        # Nor between two containers' WAN veths: each one's GUA is on br-wan, and
        # without this the only thing between two of them is each guest's own firewall,
        # which a container with CAP_NET_ADMIN can turn off (`wan-segment-l2-denied` in
        # checks.container-isolation, mutant `no-vw-isolation`).
        iifname "vw-*" oifname "vw-*" drop
      }

      chain input {
        type filter hook input priority 0; policy accept;
        # Nothing on the host is for a container's WAN veth: not SSH on the public
        # IPv6 address either. ND for the gateway is multicast and still reaches the
        # uplink through the forward path.
        iifname "vw-*" drop
      }

      chain output {
        type filter hook output priority 0; policy accept;
    ${peerInDelivers}
        meta mark ${peerIn} drop
      }
    }
  '';

  ruleset = ''
    ${bridgeGuard}
    table inet filter {
      chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state { established, related } accept

        # Declared container flows to this node's mesh address, by bridge port (the
        # mark). Before the weak-host drop: Grafana is local to the metrics node.
    ${markedHostAccepts}

        # Weak host model: the kernel answers for an address on ANY interface, so an
        # attacker on the VLAN with a route to a mesh address reached every service on
        # it, key or no key, before the mesh accepts below were scoped to the mesh
        # interface [RAN, design 1.14]. With those scoped, this drop is defence in
        # depth: without it such an attacker gets ICMP echo from the mesh address and
        # the Nomad ports the control VLAN accepts anyway, not the mesh's services.
        # Mesh addresses are reached through the mesh and nowhere else; and it keeps a
        # future accept that forgets `iifname` from opening a mesh service to the VLAN.
        # `weak-host-route-refused` (checks.control-plane-attack) shows the ICMP half
        # (mutant `no-weak-host-rule`).
        iifname != "${meshIf}" ip daddr ${meshSubnet} drop

        # The mesh: what this node's roles serve (lib/net.nix meshPortsFor).
        iifname "${meshIf}" ip saddr ${meshSubnet} tcp dport { ${meshPorts} } accept
        iifname "${meshIf}" icmp type echo-request accept

        # Control VLAN: Nomad under mTLS, and the mesh's own transport. Nothing else:
        # no SSH, no exporter, no database (`vlan-only-nomad-and-wg-open`).
        iifname "${ctrlIf}" ip saddr ${vl.control.subnet} udp dport ${toString (net.meshPort topology)} accept
        iifname "${ctrlIf}" ip saddr ${vl.control.subnet} tcp dport { ${toString net.nomadHttpPort}, ${toString net.nomadServerPort}, 4648 } accept
        iifname "${ctrlIf}" ip saddr ${vl.control.subnet} udp dport 4648 accept
        iifname "${ctrlIf}" icmp type echo-request accept
        # App VLAN is transit, storage VLAN carries nothing to the host: ICMP only.
        # vrack-mtu-probe pings both.
        iifname { ${
          net.nftSet [
            appIf
            stgIf
          ]
        } } icmp type echo-request accept

        # Containers: DHCP, DNS and ping on the gateway. Default deny for the rest,
        # logged at a rate a chatty container can't flood (LLMNR did [RAN]).
        iifname "br-app" udp sport 68 udp dport 67 accept
        iifname "br-app" ip daddr ${node.appBridgeIp} udp dport 53 accept
        iifname "br-app" ip daddr ${node.appBridgeIp} tcp dport 53 accept
        iifname "br-app" ip daddr ${node.appBridgeIp} icmp type echo-request accept
        iifname "br-app" limit rate 5/minute log prefix "container-to-host-drop "
        iifname "br-app" drop

        # Public arrives on br-wan now, NOT on ${node.wanInterface} — that NIC is
        # a bridge port. Nothing but SSH is served: every workload is reached
        # through its own outbound tunnel, so 80/443 are closed.
        iifname "br-wan" tcp dport 22 accept
        # mosh's UDP session range (programs.mosh default), v4 and v6 alike.
        iifname "br-wan" udp dport 60000-61000 accept
        iifname "br-wan" icmp type { echo-request } accept

        # IPv6 needs more than echo: without NDP the segment does not work at
        # all, and without the error types PMTU discovery silently breaks.
        iifname "br-wan" icmpv6 type {
          echo-request,
          nd-neighbor-solicit, nd-neighbor-advert,
          nd-router-solicit, nd-router-advert,
          destination-unreachable, packet-too-big,
          time-exceeded, parameter-problem
        } accept
      }

      chain forward {
        type filter hook forward priority filter; policy drop;
        # Replies, and the ICMP errors of a flow: among them the fragmentation-needed
        # a 9000-byte VLAN sends back to a 1500-byte bridge (D25).
        ct state { established, related } accept
        # Containers -> internet over IPv4 (masqueraded below): the internet only,
        # not the fabric's private ranges and not this cluster's public addresses.
        # Their IPv6 is bridged, so it never reaches this chain: bridged frames
        # bypass the ip/ip6 hooks unless br_netfilter is loaded, which it
        # deliberately is not; `table bridge guard` above polices those frames.
        iifname "br-app" oifname "br-wan" ip daddr != { ${setOf notInternet4} } accept
        # Cross-node container traffic over the app-VLAN transit: declared peerAccess
        # only, to container subnets only.
    ${crossNodeAccepts}
        iifname "br-app" limit rate 5/minute log prefix "container-forward-drop "
      }

      chain output {
        type filter hook output priority 0; policy accept;
        # raw_exec tasks run as nomad-apps and need no network at all: their only
        # job is asking systemd, over D-Bus, to start or stop a container. Every
        # packet that uid sends is refused, loopback and the VLANs included, and
        # root is untouched. A stolen submit-job token can't reach Nomad, the
        # metadata engine or the internet from a task (`task-has-no-network`).
        # By number, not name: the build checks this ruleset in a sandbox, which
        # has no such account.
        meta skuid ${toString clusterLib.nomad.appsUid} reject
      }
    }

    table inet nat {
      chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        # IPv4 only, and only for the private container subnet: IPv6 egress is
        # bridged and unNATted, which is the point of giving containers a GUA.
        # IPv4 stays because it is still needed for v4-only destinations —
        # wordpress.org publishes no AAAA, and this plane owns plugin installs.
        ip saddr ${node.appSubnet} oifname "br-wan" masquerade
      }
    }
  '';
in
{
  # What the host's ruleset lets each container reach. Set from clusterApps by
  # modules/app-container.nix; a test with no containers sets it directly.
  imports = [ ./app-network-option.nix ];

  config = {
    assertions = [
      {
        assertion = lib.all (t: builtins.elem t appNames) peerTargets;
        message =
          "clusterApps: network.peerAccess names "
          + lib.concatStringsSep ", " (lib.filter (t: !(builtins.elem t appNames)) peerTargets)
          + ", which no app is called. A flow to an app that doesn't exist would be a rule"
          + " that never matches, so it is refused instead.";
      }
      {
        # The cross-node delivery mark must be no app's mark.
        assertion = net.appMarkBase + builtins.length appNames < net.peerInMark;
        message = "clusterApps: more apps than the host firewall's marks can name (lib/net.nix appMark).";
      }
    ];

    systemd.network = {
      enable = true;

      netdevs = {
        # br-wan bridges the WAN NIC so containers can sit on the same L2 segment
        # as OVH's gateway and take addresses from the node's routed /64 — the
        # arrangement already proven on this provider under Proxmox/LXC. Plain
        # networkd; nothing here needs Open vSwitch.
        "05-br-wan".netdevConfig = {
          Name = "br-wan";
          Kind = "bridge";
        };
        "10-br-app".netdevConfig = {
          Name = "br-app";
          Kind = "bridge";
        };
        "20-${ctrlIf}" = {
          netdevConfig = {
            Name = ctrlIf;
            Kind = "vlan";
            MTUBytes = toString vl.control.mtu;
          };
          vlanConfig.Id = vl.control.id;
        };
        "20-${appIf}" = {
          netdevConfig = {
            Name = appIf;
            Kind = "vlan";
            MTUBytes = toString vl.app.mtu;
          };
          vlanConfig.Id = vl.app.id;
        };
        "20-${stgIf}" = {
          netdevConfig = {
            Name = stgIf;
            Kind = "vlan";
            MTUBytes = toString vl.storage.mtu;
          };
          vlanConfig.Id = vl.storage.id;
        };
      };

      networks = {
        # WAN NIC — a bridge port only; all addressing lives on br-wan.
        "05-wan-port" = {
          matchConfig.Name = node.wanInterface;
          networkConfig = {
            Bridge = "br-wan";
            LinkLocalAddressing = "no";
          };
          linkConfig.RequiredForOnline = "enslaved";
        };

        # br-wan — the host's public addressing, and the segment containers join.
        # Both OVH gateways are off-subnet, so both default routes are on-link
        # (GatewayOnLink), IPv4 via the /32 pattern OVH requires.
        "10-br-wan" = {
          matchConfig.Name = "br-wan";
          address = [
            "${node.publicIp4}/32"
            "${node.publicIp6}/${toString node.publicPrefix6}"
          ];
          routes = [
            {
              Gateway = node.publicGw4;
              GatewayOnLink = true;
            }
            {
              Gateway = node.publicGw6;
              GatewayOnLink = true;
            }
          ];
          networkConfig = {
            IPv4Forwarding = true;
            IPv6Forwarding = true;
            IPv4ReversePathFilter = "strict";
            # OVH sends no RAs here and container addresses are static, so accepting
            # RAs would only invite surprises.
            IPv6AcceptRA = false;
            # Host resolver for nix / juicefs S3 / etc. (containers use br-app stub).
            DNS = [
              "9.9.9.9"
              "149.112.112.112"
              "2620:fe::fe"
            ];
          };
          linkConfig.RequiredForOnline = "routable";
        };

        # vRack trunk — carries the VLAN children, no IP of its own. At the largest
        # VLAN MTU: the kernel refuses a VLAN larger than its parent.
        "15-vrack" = {
          matchConfig.Name = vrack;
          networkConfig.LinkLocalAddressing = "no";
          vlan = [
            ctrlIf
            appIf
            stgIf
          ];
          linkConfig = {
            RequiredForOnline = "no";
            MTUBytes = toString trunkMtu;
          };
        };

        # Control VLAN — cluster/DB traffic.
        "20-control" = {
          matchConfig.Name = ctrlIf;
          address = [ "${node.controlIp}/24" ];
          networkConfig.IPv4Forwarding = true;
          linkConfig = {
            RequiredForOnline = "no";
            MTUBytes = toString vl.control.mtu;
          };
        };

        # Storage VLAN — JuiceFS<->S3 + DB base-backup/SST.
        "20-storage" = {
          matchConfig.Name = stgIf;
          address = [ "${node.storageIp}/24" ];
          linkConfig = {
            RequiredForOnline = "no";
            MTUBytes = toString vl.storage.mtu;
          };
        };

        # App VLAN — transit /24 + static routes to other nodes' container subnets.
        "20-app" = {
          matchConfig.Name = appIf;
          address = [ appTransitCidr ];
          networkConfig = {
            IPv4Forwarding = true;
            IPv4ReversePathFilter = "no"; # cross-node container traffic is multi-source
          };
          routes = containerRoutes;
          linkConfig = {
            RequiredForOnline = "no";
            MTUBytes = toString vl.app.mtu;
          };
        };

        # br-app — container gateway + BUILT-IN DHCP server for local containers.
        "40-br-app" = {
          matchConfig.Name = "br-app";
          address = [ (net.appBridgeCidr node) ];
          networkConfig = {
            ConfigureWithoutCarrier = true;
            DHCPServer = true;
            IPv4Forwarding = true;
            IPv4ReversePathFilter = "no";
          };
          dhcpServerConfig = {
            PoolOffset = node.appDhcpPoolOffset;
            PoolSize = node.appDhcpPoolSize;
            EmitDNS = true;
            DNS = [ node.appBridgeIp ]; # host resolved stub (below)
            EmitRouter = true;
          };
          linkConfig.RequiredForOnline = "no";
        };

        # nspawn veth host-ends -> enslave to br-app.
        "50-veth" = {
          matchConfig.Name = "ve-*";
          networkConfig.Bridge = "br-app";
          linkConfig.RequiredForOnline = "no";
        };

        # Each container's SECOND veth (lib/mk-app-container.nix extraVeths) ->
        # br-wan, giving it a GUA on the public segment for egress. Named vw-<iid>
        # rather than per-app because the host and container ends share a name and
        # IFNAMSIZ is 16.
        "51-veth-wan" = {
          matchConfig.Name = "vw-*";
          networkConfig = {
            Bridge = "br-wan";
            LinkLocalAddressing = "no";
          };
          linkConfig.RequiredForOnline = "no";
        };

        # The br-app veth of an app in a peerAccess flow, vp-<iid> (lib/net.nix
        # appPeerPort): named by this repo, not by nspawn, so the ruleset can name it.
        # nspawn creates it (lib/mk-app-container.nix) but does not bridge it.
        "52-veth-peer" = {
          matchConfig.Name = "vp-*";
          networkConfig = {
            Bridge = "br-app";
            LinkLocalAddressing = "no";
          };
          linkConfig.RequiredForOnline = "no";
        };
      };
    };

    # Ordered before every unit that binds the control VLAN address (lib/net.nix
    # controlBoundUnit): Nomad. network-online.target means br-wan here
    # (modules/cluster-common.nix), and the control VLAN is RequiredForOnline=no
    # without ConfigureWithoutCarrier, so its address arrives only once the vRack
    # trunk has carrier, which can be seconds after br-wan is routable (the trunk
    # comes up in stage 2, and many NICs reset when their MTU is set).
    # Nomad exits at once on an address it can't bind, and the nixpkgs unit allows 3
    # starts in 10 s, so without this a late VLAN left Nomad failed until someone
    # restarted it. Never fails: a VLAN that is down for longer is a different problem,
    # and the bound units retry (controlBoundUnit has no start limit) until it is back
    # (`control-vlan-late-nomad-waits` in checks.control-plane-failure).
    systemd.services.control-vlan-ready = {
      description = "Wait for the control VLAN address";
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
          ip -4 -o addr show dev ${ctrlIf} 2>/dev/null | grep -qF ' ${node.controlIp}/' && exit 0
          sleep 0.5
        done
        echo "control-vlan-ready: no ${node.controlIp} on ${ctrlIf} after 30s; bound services will retry" >&2
      '';
    };

    # Host resolver reachable by containers on br-app (DHCP hands out node.appBridgeIp).
    # No LLMNR or mDNS: both answered on every internal address, which an attacker on
    # the VLAN enumerated [RAN, design Appendix O], and nothing here resolves names
    # that way.
    services.resolved = {
      enable = true;
      settings.Resolve = {
        DNSStubListenerExtra = node.appBridgeIp;
        LLMNR = "no";
        MulticastDNS = "no";
      };
    };

    boot.kernel.sysctl = {
      "net.ipv4.ip_forward" = 1;
      # A VLAN that drops jumbo frames without saying so (D25): TCP notices the
      # retransmissions and probes down to a size that passes, instead of hanging
      # (`blackhole-tcp-recovers` in checks.jumbo-mtu). 1 = only once a blackhole is
      # suspected, so a healthy 9000-byte path keeps its full segment size.
      "net.ipv4.tcp_mtu_probing" = 1;
    };

    # nftables is authoritative; disable the scripted firewall.
    networking.firewall.enable = false;
    networking.nftables = {
      enable = true;
      inherit ruleset;
    };
    # The same text, for a mutant that must remove one rule from it (flake.nix,
    # `no-skuid-rule`): an option's own value can't be read back to edit it.
    system.build.clusterNftablesRuleset = ruleset;
    # The bridge table alone, which mutant `no-bridge-guard` removes from that text.
    system.build.clusterNftablesBridgeGuard = bridgeGuard;
  };
}
