# VM test: container default-deny (design WS9, Appendix E), on two real nodes: node1
# (every singleton, the metrics node) and node2, an installed worker. Their real
# machine modules, as tests/cluster.nix boots them, with the fixture catalogue and
# four probe apps besides:
#
#   gprobe        network.hostAccess = [ Loki, Prometheus ], pinned to node1 (a
#                 metrics node). Its identity is nspawn's veth vb-gprobe.
#   a-long-named-wordpress-site
#                 27 characters, network.peerAccess to dbprobe on 3306: the shape of a
#                 WordPress plane and its database (D23). Runs on both nodes.
#   dbprobe       the target: serves 3306 (declared) and 3307 (not), on node1.
#   plain         declares nothing. Serves 3306 and 8080, on both nodes.
#
# and the fixture's real `demo-grafana` (modules/kinds/grafana.nix), which must read
# Loki and Prometheus through the mesh address with nothing but its kind's
# declaration. The containers are started by hand (systemctl), not by Nomad: the
# nodes are in node pool `ci-hold` so no catalogue app is placed, and the fence is
# off, because a container Nomad didn't place would otherwise be fenced.
#
#   name-too-long-assertion       (evaluation) hostAccess on a 13+ character name is
#                                 refused; 12 is accepted. With the other refusals:
#                                 hostAccess off a metrics node, and the real kinds'
#                                 own declarations (grafana, wordpress)
#   dhcp-dns-egress-work          after a restart: a DHCP lease from the gateway, DNS
#                                 from its stub, IPv4 egress through the NAT and IPv6
#                                 egress from the container's own GUA
#   same-node-declared-works      the long-named source reaches dbprobe:3306 across
#                                 the bridge, on its vp-<iid> veth
#   spoofed-marked-source-refused plain takes a marked app's IP and MAC: gprobe's (to
#                                 the host's Loki port), and the long-named source's
#                                 (to dbprobe, on the same node and from node2). All
#                                 refused: identity is the bridge port
#   host-ports-denied             every TCP port either node listens on, at every
#                                 address of both, from three apps: only what each
#                                 declared answers (DNS on the gateway for all, and
#                                 Loki and Prometheus for gprobe); a UDP echo on every
#                                 address of node1 answers none of them
#   marked-reaches-only-declared  gprobe reads Loki and Prometheus on node1's mesh
#                                 address; demo-grafana's datasources answer through
#                                 Grafana's own proxy, from its container
#   unmarked-times-out            the same two ports from plain and from the
#                                 long-named source: a timeout (dropped), not a refusal
#   same-node-l2-denied           every other pair on node1, and the declared source on
#                                 a port or a target it did not declare
#   cross-node-declared-only      node2's long-named source reaches dbprobe:3306 on
#                                 node1; not 3307, not plain:3306 on node1 (the target
#                                 is the bridge port, whatever the address), not
#                                 node1's transit, gateway or control addresses; and
#                                 node2's plain reaches nothing there
#   public-v6-ssh-filtered        SSH on the node's public IPv6 address answers the
#                                 internet, and not a container on the node's own WAN
#                                 segment
#   spoofed-gua-egress-blocked    a container's own GUA reaches the internet, an
#                                 address it added (or another app's) does not
#   dhcp-spoof-dropped            a container's DHCP server replies, gateway ARP claims
#                                 and packets from the gateway's address never reach
#                                 br-app; a rogue DHCP server doesn't hand out leases
#   other-node-public-ip-denied   another node's public IPv4 (and this node's) is not
#                                 "the internet" for a container; the internet is
#   wan-segment-l2-denied         plain to gprobe's GUA on br-wan (ping, and TCP to a
#                                 port gprobe opens on its WAN veth), and back: nothing,
#                                 while the internet reaches that port and plain's own
#                                 GUA reaches the internet
#   nd-spoof-refused              plain's unsolicited neighbour adverts (override flag)
#                                 claiming node1's public IPv6 and gprobe's GUA, to all
#                                 nodes and to the gateway, and a router advert: none
#                                 reaches the wire, the gateway's neighbour entries keep
#                                 their owners, the internet still reaches node1's SSH
#                                 over IPv6; plain's advert for its own GUA does arrive
#   wan-mac-pinned                each WAN veth has its fixed MAC and that MAC's
#                                 link-local address; plain sending as the gateway's MAC
#                                 gets nowhere and leaves the gateway on the uplink in
#                                 br-wan's forwarding table, and the host still reaches
#                                 the gateway
#
# Mutants (flake.nix): `no-bridge-guard` (the bridge table removed:
# spoofed-marked-source-refused fails, a stolen IP and MAC reach dbprobe),
# `br-app-accept-all` (the default-deny on br-app accepts: host-ports-denied fails),
# `no-vw-isolation` (the vw-to-vw drop removed: wan-segment-l2-denied fails),
# `no-nd-guard` (the neighbour-advert target rules removed: nd-spoof-refused fails) and
# `no-wan-mac-pin` (the WAN veths' MAC rules removed: wan-mac-pinned fails).
#
# Run: nix build .#checks.x86_64-linux.container-isolation -L   (needs KVM; ~7 GB RAM)
{
  pkgs,
  lib,
  mkClan,
  topology,
  harnessFor,
  clanCoreModule,
  mutant ? "",
  extraModule ? { },
}:
let
  testTopology = lib.recursiveUpdate topology {
    nodes.node2.provisioned = true;
  };
  clan = mkClan testTopology;
  harness = harnessFor testTopology;
  clusterLib = import ../lib { inherit lib; };
  net = clusterLib.net;
  machines = clan.config.nixosConfigurations;
  n1 = testTopology.nodes.node1;
  n2 = testTopology.nodes.node2;

  longApp = "a-long-named-wordpress-site";

  # A probe's container: a TCP server answering "<app> <port> from <peer>" on each
  # port, its guest firewall open for them on eth0 (the br-app link), and the tools
  # the test drives from inside.
  probeModule =
    name: ports:
    { pkgs, ... }:
    let
      serve = pkgs.writeText "ci-serve.py" ''
        import socket, sys, threading
        name = sys.argv[1]
        def serve(port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.listen(16)
            while True:
                c, a = s.accept()
                try:
                    c.sendall(f"{name} {port} from {a[0]}\n".encode())
                finally:
                    c.close()
        for p in sys.argv[2:]:
            threading.Thread(target=serve, args=(int(p),), daemon=True).start()
        threading.Event().wait()
      '';
      # open <first line the server sent> | timeout (dropped) | unreachable (no ARP or
      # ND answer: dropped at the bridge) | refused (an RST or ICMP refusal came back).
      reach = pkgs.writeShellScriptBin "ci-reach" ''
        ip=$1 port=$2 t=''${3:-6}
        err=$(timeout "$t" bash -c "exec 3<>/dev/tcp/$ip/$port" 2>&1)
        rc=$?
        if [ "$rc" = 0 ]; then
          banner=$(timeout 3 bash -c "exec 3<>/dev/tcp/$ip/$port; head -n1 <&3" 2>/dev/null)
          echo "open $banner"
        elif [ "$rc" = 124 ]; then
          echo timeout
        elif echo "$err" | grep -qi 'no route to host'; then
          echo unreachable
        else
          echo "refused ($err)"
        fi
      '';
      # ND messages from inside a container, as a compromised one would send them:
      # `ci-nd IFACE na TARGET MAC DST [N [GAP]]` an unsolicited neighbour advert with
      # the override flag (TARGET is at MAC), `ci-nd IFACE ra - MAC DST [N [GAP]]` a
      # router advert. Hop limit 255, as ND requires; the kernel fills in the checksum.
      nd = pkgs.writeText "ci-nd.py" ''
        import socket, struct, sys, time
        iface, kind, target, mac, dst = sys.argv[1:6]
        n = int(sys.argv[6]) if len(sys.argv) > 6 else 5
        gap = float(sys.argv[7]) if len(sys.argv) > 7 else 0.2
        s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
        lla = bytes.fromhex(mac.replace(":", ""))
        if kind == "na":
            body = (struct.pack("!BBHI", 136, 0, 0, 0x20000000)
                    + socket.inet_pton(socket.AF_INET6, target) + struct.pack("!BB", 2, 1) + lla)
        else:
            body = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0) + struct.pack("!BB", 1, 1) + lla
        for _ in range(n):
            scope = socket.if_nametoindex(iface) if dst.startswith(("ff02", "fe80")) else 0
            s.sendto(body, (dst, 0, 0, scope))
            time.sleep(gap)
      '';
      ndTool = pkgs.writeShellScriptBin "ci-nd" ''exec ${pkgs.python3}/bin/python3 ${nd} "$@"'';
      wanIf = net.appWanPort name;
    in
    {
      networking.firewall.interfaces.eth0.allowedTCPPorts = ports;
      # A port on the WAN veth's GUA, for wan-segment-l2-denied: the internet reaches
      # it (the positive control), another container on the node must not.
      networking.firewall.interfaces.${wanIf}.allowedTCPPorts = [ 8081 ];
      systemd.services.ci-serve6 = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.socat}/bin/socat TCP6-LISTEN:8081,ipv6only=1,fork,reuseaddr SYSTEM:'echo ${name} 8081'";
      };
      environment.systemPackages = [
        reach
        ndTool
        pkgs.nmap
        pkgs.curl
        pkgs.iproute2
        pkgs.iputils
        pkgs.dnsmasq
        pkgs.python3
        pkgs.jq
        pkgs.socat
      ];
      systemd.services.ci-serve = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig.ExecStart = "${pkgs.python3}/bin/python3 ${serve} ${name} ${
          lib.concatMapStringsSep " " toString ports
        }";
      };
    };

  probe =
    name: ports: extra:
    {
      module = probeModule name ports;
      resources = {
        cpu = 100;
        memoryMB = 256;
      };
    }
    // extra;

  ciApps = {
    clusterApps = {
      gprobe = probe "gprobe" [ 8080 ] {
        homeNode = "node1";
        network.hostAccess = [
          net.lokiPort
          net.prometheusPort
        ];
      };
      ${longApp} = probe longApp [ 8080 ] {
        network.peerAccess = [
          {
            app = "dbprobe";
            port = 3306;
          }
        ];
      };
      dbprobe = probe "dbprobe" [
        3306
        3307
      ] { homeNode = "node1"; };
      plain = probe "plain" [
        3306
        8080
      ] { };
    };
  };

  # ── evaluation-level ────────────────────────────────────────────────────────
  # The two modules that make and police containers, on node1, with no catalogue:
  # small enough to evaluate here for each refusal.
  evalNode =
    apps:
    lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      specialArgs = {
        topology = testTopology;
        node = n1;
        nodeName = "node1";
        inherit clusterLib;
      };
      modules = [
        clanCoreModule
        ../modules/app-container.nix
        ../modules/overlay-network.nix
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "/dev/null";
            fsType = "ext4";
          };
          system.stateVersion = testTopology.stateVersion;
          clan.core.enableRecommendedDefaults = false;
          clan.core.settings.machine.name = "node1";
          clan.core.settings.directory = toString ../.;
          clusterApps = apps;
        }
      ];
    };
  failed = sys: map (a: a.message) (lib.filter (a: !a.assertion) sys.config.assertions);
  hostAccessApp = name: homeNode: {
    ${name} = {
      module = { };
      inherit homeNode;
      network.hostAccess = [ net.lokiPort ];
    };
  };
  tooLong = failed (evalNode (hostAccessApp "grafana-thirteen" "node1"));
  twelve = failed (evalNode (hostAccessApp "twelve-chars" "node1"));
  offMetrics = failed (evalNode (hostAccessApp "gr-node2" "node2"));

  # The real kinds, as the fixture catalogue declares them, on this test's node1.
  c1 = machines.node1.config;
  grafanaDs =
    c1.containers.demo-grafana.config.services.grafana.provision.datasources.settings.datasources;
  evalChecks = {
    tooLong = {
      refused = lib.any (m: lib.hasInfix "needs a name of at most 12 characters" m) tooLong;
      messages = tooLong;
    };
    twelve = {
      # Only this module's refusal counts: the bare system may have unrelated ones.
      refused = lib.any (m: lib.hasInfix "network.hostAccess" m) twelve;
      messages = twelve;
    };
    offMetrics = {
      refused = lib.any (m: lib.hasInfix "must be a node tagged `metrics`" m) offMetrics;
      messages = offMetrics;
    };
    kinds = {
      grafanaHostAccess = c1.clusterApps.demo-grafana.network.hostAccess;
      grafanaHome = c1.clusterApps.demo-grafana.homeNode;
      grafanaUrls = map (d: d.url) grafanaDs;
      meshUrls = [
        "http://${net.meshIp testTopology n1}:${toString net.lokiPort}"
        "http://${net.meshIp testTopology n1}:${toString net.prometheusPort}"
      ];
      sitePeers = map (n: c1.clusterApps.${n}.network.peerAccess) [
        "demo-site"
        "demo-site-admin"
      ];
      wpdbPort = c1.clusterApps.demo-wpdb.wpdb.port;
      siteVeth = c1.containers.demo-site.extraFlags;
      siteBridge = c1.containers.demo-site.hostBridge;
      wantVeth = "--network-veth-extra=${net.appPeerPort "demo-site"}:eth0";
    };
  };

  # Every address of both nodes a container might aim at.
  hostIps = node: [
    node.appBridgeIp
    node.controlIp
    node.storageIp
    (net.appTransitIp node)
    (net.meshIp testTopology node)
    node.publicIp4
  ];

  # The stand-in internet, with IPv6 as well: the nodes' v6 gateway, an address to
  # reach, and the nodes' /64s on-link. Echo services say who connected.
  internet6 = "2001:db8:ffff::10";
  wanModule =
    { pkgs, ... }:
    {
      imports = [ harness.wanNode ];
      networking.interfaces.eth1.ipv6 = {
        addresses = [
          {
            address = n1.publicGw6;
            prefixLength = 64;
          }
          {
            address = internet6;
            prefixLength = 128;
          }
        ];
        routes =
          map
            (n: {
              address = "${n.public6Prefix}::";
              prefixLength = 64;
            })
            [
              n1
              n2
            ];
      };
      environment.systemPackages = [ pkgs.socat ];
      systemd.services.ci-echo4 = {
        wantedBy = [ "multi-user.target" ];
        script = "exec ${pkgs.socat}/bin/socat TCP4-LISTEN:7000,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR'";
      };
      systemd.services.ci-echo6 = {
        wantedBy = [ "multi-user.target" ];
        script = "exec ${pkgs.socat}/bin/socat TCP6-LISTEN:7000,ipv6only=1,fork,reuseaddr SYSTEM:'echo $SOCAT_PEERADDR'";
      };
    };

  nodeModule = name: memoryMB: {
    imports = [
      clan.config.nixosModules."clan-machine-${name}"
      (harness.nodeModule { inherit memoryMB; })
      ciApps
      extraModule
    ];
    services.nomad.settings.client.node_pool = "ci-hold";
    # The containers here are started by the test, which the fence would stop as
    # orphans: Nomad placed none of them.
    systemd.timers.nomad-fence.wantedBy = lib.mkForce [ ];
    environment.systemPackages = [
      pkgs.tcpdump
      pkgs.socat
      pkgs.jq
    ];
  };
in
pkgs.testers.runNixOSTest {
  name = "container-isolation";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machines.node1._module.specialArgs [ "modulesPath" ];

  nodes = {
    wan = wanModule;
    node1 = nodeModule "node1" 4096;
    node2 = nodeModule "node2" 2048;
  };

  testScript = ''
    import ipaddress
    import re
    import shlex
    import time

    ${harness.pythonHelpers}

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    EVAL = json.loads(r"""${builtins.toJSON evalChecks}""")
    LONG = "${longApp}"
    M1 = MESH["node1"]
    LOKI, PROM = ${toString net.lokiPort}, ${toString net.prometheusPort}
    GW1, GW2 = "${n1.appBridgeIp}", "${n2.appBridgeIp}"
    TRANSIT1 = "${net.appTransitIp n1}"
    CTRL1 = "${n1.controlIp}"
    PUB4_1, PUB4_2 = "${n1.publicIp4}", "${n2.publicIp4}"
    PUB6_1 = "${n1.publicIp6}"
    S3 = "198.51.100.10"
    NET6 = "${internet6}"
    HOST_IPS = ${builtins.toJSON (hostIps n1 ++ hostIps n2)}
    IID = dict(${
      builtins.toJSON (
        map
          (a: [
            a
            (net.gua6Iid a)
          ])
          [
            "gprobe"
            longApp
            "dbprobe"
            "plain"
          ]
      )
    })
    PREFIX = {"node1": "${n1.public6Prefix}", "node2": "${n2.public6Prefix}"}
    # Each probe's fixed WAN MAC on node1 and that MAC's link-local address (lib/net.nix).
    WAN_MAC = ${
      builtins.toJSON (lib.genAttrs [ "gprobe" longApp "dbprobe" "plain" ] (a: net.appWanMac n1 a))
    }
    WAN_LL = ${
      builtins.toJSON (lib.genAttrs [ "gprobe" longApp "dbprobe" "plain" ] (a: net.appWanLinkLocal n1 a))
    }
    GW4_1 = "${n1.publicGw4}"
    GW6 = "${n1.publicGw6}"
    UPLINK1 = "${n1.wanInterface}"
    # Canonical form, as the kernel and socat print it.
    GUA = {(node, app): str(ipaddress.ip_address(f"{PREFIX[node]}::{iid}")) for node in PREFIX for app, iid in IID.items()}
    WAN_IF = {a: f"vw-{iid}" for a, iid in IID.items()}

    def run(n, app, cmd):
        """`cmd` in a shell INSIDE the container (pipes and `;` included)."""
        return n.succeed(f"nixos-container run {app} -- bash -c {shlex.quote(cmd)}").strip()

    def try_in(n, app, cmd):
        return n.execute(f"nixos-container run {app} -- bash -c {shlex.quote(cmd)}")

    def reach(n, app, ip, port, t=6):
        """open <banner> | timeout | refused, from inside the container."""
        return run(n, app, f"ci-reach {ip} {port} {t}")

    def is_open(r):
        return r.startswith("open")

    def ip4(n, app):
        return run(n, app, "ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -n1")

    def mac(n, app):
        return json.loads(run(n, app, "ip -j link show eth0"))[0]["address"]

    def start(n, app):
        n.succeed(f"systemctl start container@{app}.service")
        n.wait_for_unit(f"container@{app}.service", timeout=300)
        n.wait_until_succeeds(f"nixos-container run {app} -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.'", timeout=120)

    def scan(n, app, ips, ports):
        """nmap SYN scan from inside a container: the (ip, port) pairs that answered."""
        out = run(n, app, f"nmap -n -Pn -sS -T4 --max-retries 1 --host-timeout 240s -p {','.join(map(str, ports))}"
                          f" -oG - {' '.join(ips)}")
        found = set()
        for line in out.splitlines():
            if "Ports:" not in line:
                continue
            ip = line.split()[1]
            for entry in line.split("Ports:", 1)[1].split(","):
                f = entry.strip().split("/")
                if len(f) > 1 and f[1] == "open":
                    found.add((ip, int(f[0])))
        return sorted(found)

    def main():
        with subtest("name-too-long-assertion: hostAccess on a name nspawn would shorten is refused"):
            ev = EVAL["tooLong"]
            print(f"name-too-long-assertion: 16 characters refused={ev['refused']} {ev['messages']};"
                  f" 12 characters: {EVAL['twelve']['messages']}")
            control("name-too-long-assertion", ev["refused"] and EVAL["twelve"]["messages"] == [],
                    f"16 characters: {ev['messages']}; 12 characters: {EVAL['twelve']['messages']}")
            control("hostaccess-off-metrics-refused", EVAL["offMetrics"]["refused"], f"{EVAL['offMetrics']['messages']}")
            k = EVAL["kinds"]
            print(f"real kinds: {k}")
            control("real-kinds-declare-their-flows",
                    k["grafanaHostAccess"] == [LOKI, PROM] and k["grafanaHome"] == "node1"
                    and sorted(k["grafanaUrls"]) == sorted(k["meshUrls"])
                    and k["sitePeers"] == [[{"app": "demo-wpdb", "port": k["wpdbPort"]}]] * 2
                    and k["siteBridge"] is None and k["wantVeth"] in k["siteVeth"],
                    f"{k}")

        wan.start()
        node1.start()
        node2.start()
        wan.wait_for_unit("s3.service")
        wan.wait_for_unit("ci-echo4.service")
        wan.wait_for_unit("ci-echo6.service")
        for n in (node1, node2):
            n.wait_for_unit("multi-user.target")
            n.wait_for_unit(f"{MESH_IF}-ready.service")
            n.wait_for_unit("nftables.service")
        node1.wait_until_succeeds(f"curl -fsS http://{M1}:{LOKI}/ready", timeout=240)
        node1.wait_until_succeeds(f"curl -fsS http://{M1}:{PROM}/-/ready", timeout=240)

        with subtest("the probes and demo-grafana start, each on its own bridge port"):
            for app in ("gprobe", LONG, "dbprobe", "plain"):
                start(node1, app)
            for app in (LONG, "plain"):
                start(node2, app)
            for n, app, port in ((node1, "gprobe", "vb-gprobe"), (node1, LONG, "${net.appPeerPort longApp}"),
                                 (node1, "dbprobe", "${net.appPeerPort "dbprobe"}"), (node1, "plain", "vb-plain"),
                                 (node2, LONG, "${net.appPeerPort longApp}"), (node2, "plain", "vb-plain")):
                n.wait_until_succeeds(f"ip -d link show {port} | grep -q 'master br-app'", timeout=60)
            for app in ("gprobe", LONG, "dbprobe", "plain"):
                node1.wait_until_succeeds(f"nixos-container run {app} -- systemctl is-active ci-serve.service", timeout=120)
            node2.wait_until_succeeds(f"nixos-container run {LONG} -- systemctl is-active ci-serve.service", timeout=120)
            node2.wait_until_succeeds("nixos-container run plain -- systemctl is-active ci-serve.service", timeout=120)
            # Its long name never reaches nspawn's vb-: it has no such veth at all.
            node1.fail("ip -o link | grep -q 'vb-a-long'")
            IP = {(n.name, a): ip4(n, a) for n, a in ((node1, "gprobe"), (node1, LONG), (node1, "dbprobe"),
                                                       (node1, "plain"), (node2, LONG), (node2, "plain"))}
            print(f"container addresses: {IP}")
            node1.succeed("systemctl start container@demo-grafana.service")

        with subtest("dhcp-dns-egress-work: after a restart, a lease, DNS, and both kinds of egress"):
            node1.succeed("systemctl restart container@plain.service")
            node1.wait_for_unit("container@plain.service")
            node1.wait_until_succeeds("nixos-container run plain -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.1.'", timeout=120)
            IP[("node1", "plain")] = ip4(node1, "plain")
            route = run(node1, "plain", "ip -4 route show default")
            dns = try_in(node1, "plain", "getent ahostsv4 s3.example.net")[1].strip()
            v4 = reach(node1, "plain", S3, 443)
            node1.wait_until_succeeds(f"nixos-container run plain -- ping -6 -c1 -W2 {NET6}", timeout=60)
            v6 = try_in(node1, "plain", f"timeout 5 bash -c 'exec 3<>/dev/tcp/{NET6}/7000; head -n1 <&3'")[1].strip()
            v4_from = try_in(node1, "plain", f"timeout 5 bash -c 'exec 3<>/dev/tcp/{S3}/7000; head -n1 <&3'")[1].strip()
            v6_from = v6.strip("[]")
            v6_ok = False
            try:
                v6_ok = ipaddress.ip_address(v6_from) == ipaddress.ip_address(GUA[("node1", "plain")])
            except ValueError:
                pass
            detail = (f"address {IP[('node1', 'plain')]}, {route!r}; DNS s3.example.net: {dns!r}; v4 to {S3}:443: {v4};"
                      f" v4 echo says {v4_from!r} (NAT to {PUB4_1}); v6 echo says {v6!r} (own GUA {GUA[('node1', 'plain')]})")
            print(f"dhcp-dns-egress-work: {detail}")
            control("dhcp-dns-egress-work",
                    IP[("node1", "plain")].startswith("10.20.1.") and f"default via {GW1}" in route
                    and S3 in dns and is_open(v4) and PUB4_1 in v4_from and v6_ok,
                    detail)

        with subtest("same-node-declared-works: a 27-character source reaches its target, on the declared port"):
            db1 = IP[("node1", "dbprobe")]
            r = reach(node1, LONG, db1, 3306)
            print(f"same-node-declared-works: {LONG} -> dbprobe {db1}:3306: {r}")
            control("same-node-declared-works", r.startswith("open dbprobe 3306 from " + IP[("node1", LONG)]), r)

        with subtest("spoofed-marked-source-refused: a stolen IP and MAC is not a stolen identity"):
            # Loki answers node1 itself: a refusal below is the firewall, not a dead Loki.
            node1.succeed(f"curl -fsS http://{M1}:{LOKI}/ready")
            # The same-node flow works for the real owner of the identity being stolen.
            own = reach(node1, LONG, IP[("node1", "dbprobe")], 3306)
            db_mac = mac(node1, "dbprobe")
            def steal(n, victim):
                """plain takes victim's IPv4 address and MAC, the victim's link down so the
                bridge learns the MAC on plain's port alone."""
                v_ip, v_mac = IP[(n.name, victim)], mac(n, victim)
                run(n, victim, "ip link set eth0 down")
                run(n, "plain", "systemctl mask --runtime systemd-networkd.service systemd-networkd.socket >/dev/null;"
                                " systemctl stop systemd-networkd.socket; systemctl stop systemd-networkd.service;"
                                " ! systemctl is-active --quiet systemd-networkd.service")
                run(n, "plain", f"ip link set eth0 down; ip link set eth0 address {v_mac}; ip addr flush dev eth0;"
                                f" ip addr add {v_ip}/24 dev eth0; ip link set eth0 up;"
                                f" ip route replace default via {GW1 if n is node1 else GW2}")
                return v_ip, v_mac
            def give_back(n, victim):
                n.succeed("systemctl restart container@plain.service")
                n.wait_until_succeeds("nixos-container run plain -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.'", timeout=120)
                run(n, victim, "ip link set eth0 up")
                n.wait_until_succeeds(f"nixos-container run {victim} -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.'", timeout=120)
                IP[(n.name, "plain")] = ip4(n, "plain")
                IP[(n.name, victim)] = ip4(n, victim)
            # 1. gprobe's identity, to the two host ports gprobe may use.
            g_ip, g_mac = steal(node1, "gprobe")
            as_gprobe = {p: reach(node1, "plain", M1, p) for p in (LOKI, PROM)}
            give_back(node1, "gprobe")
            # 2. The long-named source's identity, to its target on the same node; the
            #    target's MAC given, so not even ARP is needed.
            l_ip, l_mac = steal(node1, LONG)
            run(node1, "plain", f"ip neigh replace {IP[('node1', 'dbprobe')]} lladdr {db_mac} dev eth0 nud permanent")
            as_long = reach(node1, "plain", IP[("node1", "dbprobe")], 3306)
            give_back(node1, LONG)
            # 3. The same, from node2, across the app VLAN.
            steal(node2, LONG)
            as_long_x = reach(node2, "plain", IP[("node1", "dbprobe")], 3306)
            give_back(node2, LONG)
            detail = (f"the real {LONG}: {own}; as gprobe ({g_ip} {g_mac}) to {M1}: {as_gprobe};"
                      f" as {LONG} ({l_ip} {l_mac}) to dbprobe:3306 on node1: {as_long!r}; and from node2: {as_long_x!r}")
            print(f"spoofed-marked-source-refused: {detail}")
            control("spoofed-marked-source-refused",
                    is_open(own) and not any(is_open(v) for v in as_gprobe.values())
                    and not is_open(as_long) and not is_open(as_long_x),
                    detail)

        # Every TCP port either node listens on, at every address of both.
        port_set: set = set()
        for n in (node1, node2):
            for line in n.succeed("ss -Htln | awk '{print $4}'").split():
                port_set.add(int(line.rsplit(":", 1)[1]))
        ports = sorted(port_set)
        print(f"host TCP ports: {ports}; addresses: {HOST_IPS}")

        with subtest("host-ports-denied: from a container, only what it declared answers"):
            want = {"plain": [(GW1, 53)], LONG: [(GW1, 53)], "gprobe": sorted([(GW1, 53), (M1, LOKI), (M1, PROM)])}
            got = {app: scan(node1, app, HOST_IPS, ports) for app in want}
            # UDP: an echo on every address of node1; it answers node1 and no container.
            # Stopped with SIGKILL: a forked socat child can sit out SIGTERM, and the stop then
            # times out and leaves a failed unit for the last subtest to find.
            node1.succeed("systemd-run --unit=ci-udp-echo -p KillSignal=SIGKILL -p SuccessExitStatus=SIGKILL ${pkgs.socat}/bin/socat UDP4-RECVFROM:5999,fork EXEC:${pkgs.coreutils}/bin/cat")
            node1.wait_until_succeeds("echo local | timeout 3 socat - UDP4:127.0.0.1:5999 | grep -q local", timeout=30)
            udp: dict = {}
            for app in want:
                udp[app] = [ip for ip in HOST_IPS[:6]
                            if try_in(node1, app, f"echo x | timeout 3 socat - UDP4:{ip}:5999 | grep -q x")[0] == 0]
            node1.succeed("systemctl stop ci-udp-echo.service")
            sshd_listens = 22 in ports
            detail = f"open (want {want}): {got}; UDP 5999 answered: {udp}; sshd listening={sshd_listens}"
            print(f"host-ports-denied: {detail}")
            control("host-ports-denied",
                    sshd_listens and all(sorted(got[a]) == sorted(want[a]) for a in want)
                    and not any(udp.values()),
                    detail)

        with subtest("marked-reaches-only-declared: gprobe and the real Grafana read Loki and Prometheus"):
            loki = run(node1, "gprobe", f"curl -fsS --max-time 10 http://{M1}:{LOKI}/ready")
            prom = run(node1, "gprobe", f"curl -fsS --max-time 10 http://{M1}:{PROM}/-/ready")
            others = {p: reach(node1, "gprobe", M1, p) for p in (9100, 9633, 9598, 2379, 5432, 22)}
            # demo-grafana (modules/kinds/grafana.nix, as the fixture declares it): its
            # datasources, health-checked by Grafana itself, from inside its container.
            node1.wait_for_unit("container@demo-grafana.service", timeout=300)
            node1.wait_until_succeeds("nixos-container run demo-grafana -- test -S /run/grafana/grafana.sock", timeout=300)
            def via_grafana(uid, path):
                """Grafana's datasource proxy: Grafana itself, in its container, fetches
                <datasource url><path>, at the URL its kind provisioned. curl is the host
                store's (the container shares it): the guest has none."""
                return try_in(node1, "demo-grafana",
                              "${pkgs.curl}/bin/curl -sS --max-time 30 --unix-socket /run/grafana/grafana.sock"
                              " -u admin:$(cat /run/secrets/grafana-admin-password)"
                              f" 'http://localhost/api/datasources/proxy/uid/{uid}{path}'")[1].strip()
            def ok(body):
                try:
                    return json.loads(body).get("status") == "success"
                except ValueError:
                    return False
            # The kind's own provisioned URLs, from its container, over its own bridge port.
            urls = EVAL["kinds"]["grafanaUrls"]
            direct = {u: try_in(node1, "demo-grafana",
                                f"${pkgs.curl}/bin/curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10 {u}"
                                + ("/ready" if u.endswith(f":{LOKI}") else "/-/ready"))[1].strip()
                      for u in urls}
            hl = hp = ""
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                hl = via_grafana("loki", "/loki/api/v1/labels")
                hp = via_grafana("prometheus", "/api/v1/query?query=up")
                if ok(hl) and ok(hp):
                    break
                time.sleep(5)
            if not (ok(hl) and ok(hp)):
                print("demo-grafana's datasource plugins: "
                      + try_in(node1, "demo-grafana",
                               "${pkgs.curl}/bin/curl -sS --unix-socket /run/grafana/grafana.sock"
                               " -u admin:$(cat /run/secrets/grafana-admin-password)"
                               " 'http://localhost/api/plugins?type=datasource' | ${pkgs.jq}/bin/jq -c '[.[].id]'")[1].strip())
                print("demo-grafana's log on plugins: "
                      + try_in(node1, "demo-grafana",
                               "journalctl -u grafana --no-pager -o cat | grep -iE 'plugin|loki|prometheus' | tail -n 25")[1])
            detail = (f"gprobe: Loki {loki!r}, Prometheus {prom!r}, other mesh and host ports {others};"
                      f" demo-grafana's container to its provisioned URLs: {direct};"
                      f" through Grafana's datasource proxy: loki {hl[:200]}; prometheus {hp[:200]}")
            print(f"marked-reaches-only-declared: {detail}")
            control("marked-reaches-only-declared",
                    loki == "ready" and "Ready" in prom and not any(is_open(v) for v in others.values())
                    and len(direct) == 2 and all(v == "200" for v in direct.values()),
                    detail)
            control("grafana-reads-through-its-datasources", ok(hl) and ok(hp), detail)

        with subtest("unmarked-times-out: the same two ports from apps that did not declare them"):
            res = {app: {p: reach(node1, app, M1, p, 8) for p in (LOKI, PROM)} for app in ("plain", LONG, "dbprobe")}
            print(f"unmarked-times-out: {res}")
            control("unmarked-times-out", all(v == "timeout" for r in res.values() for v in r.values()), f"{res}")

        with subtest("same-node-l2-denied: nothing between two containers but the declared flow"):
            ip = {a: IP[("node1", a)] for a in ("gprobe", LONG, "dbprobe", "plain")}
            tries = {
                "plain->dbprobe:3306": reach(node1, "plain", ip["dbprobe"], 3306),
                "plain->gprobe:8080": reach(node1, "plain", ip["gprobe"], 8080),
                f"plain->{LONG}:8080": reach(node1, "plain", ip[LONG], 8080),
                "gprobe->plain:8080": reach(node1, "gprobe", ip["plain"], 8080),
                "gprobe->dbprobe:3306": reach(node1, "gprobe", ip["dbprobe"], 3306),
                f"{LONG}->dbprobe:3307": reach(node1, LONG, ip["dbprobe"], 3307),
                f"{LONG}->plain:3306": reach(node1, LONG, ip["plain"], 3306),
                f"dbprobe->{LONG}:8080": reach(node1, "dbprobe", ip[LONG], 8080),
            }
            pings = {f"{a}->{b}": try_in(node1, a, f"ping -c1 -W2 {ip[b]}")[0] == 0
                     for a, b in (("plain", "gprobe"), ("gprobe", "plain"), ("plain", "dbprobe"))}
            # The positive control, again: the declared flow still works.
            declared = reach(node1, LONG, ip["dbprobe"], 3306)
            detail = f"{tries}; pings {pings}; declared {LONG}->dbprobe:3306: {declared}"
            print(f"same-node-l2-denied: {detail}")
            control("same-node-l2-denied",
                    is_open(declared) and not any(is_open(v) for v in tries.values()) and not any(pings.values()),
                    detail)

        with subtest("cross-node-declared-only: node2's source reaches its target on node1, and nothing else"):
            db1, plain1 = IP[("node1", "dbprobe")], IP[("node1", "plain")]
            declared = reach(node2, LONG, db1, 3306)
            tries = {
                f"{LONG}->dbprobe:3307": reach(node2, LONG, db1, 3307),
                f"{LONG}->plain:3306 (the declared port, another app)": reach(node2, LONG, plain1, 3306),
                f"{LONG}->transit {TRANSIT1}:22": reach(node2, LONG, TRANSIT1, 22),
                f"{LONG}->gateway {GW1}:22": reach(node2, LONG, GW1, 22),
                f"{LONG}->gateway {GW1}:3306": reach(node2, LONG, GW1, 3306),
                f"{LONG}->control {CTRL1}:4646": reach(node2, LONG, CTRL1, 4646),
                "plain->dbprobe:3306": reach(node2, "plain", db1, 3306),
                "plain->plain:8080": reach(node2, "plain", plain1, 8080),
            }
            detail = f"declared {LONG}@node2->dbprobe@node1:3306: {declared}; {tries}"
            print(f"cross-node-declared-only: {detail}")
            control("cross-node-declared-only",
                    declared.startswith("open dbprobe 3306 from " + IP[("node2", LONG)])
                    and not any(is_open(v) for v in tries.values()),
                    detail)

        with subtest("public-v6-ssh-filtered: the node's public SSH answers the internet, not its own containers"):
            wan.wait_until_succeeds(f"ping -6 -c1 -W2 {PUB6_1}", timeout=60)
            from_wan = wan.execute(f"nc -6 -z -w5 {PUB6_1} 22")[0] == 0
            from_ctr = {a: reach(node1, a, PUB6_1, 22) for a in ("plain", "gprobe")}
            detail = f"from the internet: {from_wan}; from containers on its WAN segment: {from_ctr}"
            print(f"public-v6-ssh-filtered: {detail}")
            control("public-v6-ssh-filtered", from_wan and not any(is_open(v) for v in from_ctr.values()), detail)

        with subtest("spoofed-gua-egress-blocked: only the container's own GUA leaves"):
            vw = WAN_IF["plain"]
            own = GUA[("node1", "plain")]
            node1.wait_until_succeeds(f"nixos-container run plain -- ping -6 -c1 -W2 -I {own} {NET6}", timeout=60)
            made_up = "${n1.public6Prefix}::bad1"
            other = GUA[("node1", "gprobe")]
            res: dict = {}
            for spoof in (made_up, other):
                run(node1, "plain", f"ip -6 addr add {spoof}/64 dev {vw} nodad")
                res[spoof] = try_in(node1, "plain", f"ping -6 -c2 -W2 -I {spoof} {NET6}")[0] == 0
                run(node1, "plain", f"ip -6 addr del {spoof}/64 dev {vw}")
            own_ok = try_in(node1, "plain", f"ping -6 -c2 -W2 -I {own} {NET6}")[0] == 0
            detail = f"own GUA {own}: {own_ok}; spoofed: {res}"
            print(f"spoofed-gua-egress-blocked: {detail}")
            control("spoofed-gua-egress-blocked", own_ok and not any(res.values()), detail)

        with subtest("dhcp-spoof-dropped: no DHCP reply, gateway claim or gateway source from a container"):
            pm, pip = mac(node1, "plain"), IP[("node1", "plain")]
            node1.succeed(f"systemd-run --unit=ci-cap -p SuccessExitStatus=143 ${pkgs.tcpdump}/bin/tcpdump -i br-app -n -e -U -w /tmp/brapp.pcap ether src {pm}")
            time.sleep(2)
            send = ("python3 -c 'import socket,sys; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM);"
                    " s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.bind((\"\", int(sys.argv[1])));"
                    " [s.sendto(b\"ci-dhcp-spoof\", (\"255.255.255.255\", 68)) for _ in range(3)]'")
            run(node1, "plain", f"{send} 67")
            run(node1, "plain", f"{send} 6767")
            # The gateway's address on plain: an unsolicited ARP claiming it, and a ping
            # from it (to gprobe, whose MAC plain is given, so ARP isn't what stops it).
            run(node1, "plain", f"ip addr add {GW1}/32 dev eth0")
            try_in(node1, "plain", f"arping -U -c 2 -I eth0 -s {GW1} {GW1}")
            run(node1, "plain", f"ip neigh replace {IP[('node1', 'gprobe')]} lladdr {mac(node1, 'gprobe')} dev eth0 nud permanent")
            try_in(node1, "plain", f"ping -c 2 -W1 -I {GW1} {IP[('node1', 'gprobe')]}")
            run(node1, "plain", f"ip addr del {GW1}/32 dev eth0; ip neigh del {IP[('node1', 'gprobe')]} dev eth0")
            # The control: an ordinary ARP request, from plain's own address.
            try_in(node1, "plain", f"arping -c 2 -I eth0 {GW1}")
            # A rogue DHCP server, then a victim asking for a lease.
            run(node1, "plain", "systemd-run --unit=ci-rogue-dhcp -p SuccessExitStatus=143 ${pkgs.dnsmasq}/bin/dnsmasq --no-daemon --port=0 --interface=eth0"
                                " --bind-interfaces --dhcp-authoritative --leasefile-ro"
                                " --dhcp-range=10.20.1.240,10.20.1.250,2m --dhcp-option=3,10.20.1.66")
            time.sleep(2)
            run(node1, "gprobe", "networkctl reconfigure eth0")
            node1.wait_until_succeeds("nixos-container run gprobe -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.1.'", timeout=60)
            time.sleep(3)
            v_addr = ip4(node1, "gprobe")
            v_route = run(node1, "gprobe", "ip -4 route show default")
            v_gw_mac = try_in(node1, "gprobe", f"ip neigh show {GW1}")[1].strip()
            run(node1, "plain", "systemctl stop ci-rogue-dhcp.service")
            time.sleep(1)
            node1.succeed("systemctl stop ci-cap.service")
            cap = node1.succeed("tcpdump -r /tmp/brapp.pcap -n -e 2>/dev/null")
            br_mac = json.loads(node1.succeed("ip -j link show br-app"))[0]["address"]
            def count(pattern):
                return sum(1 for l in cap.splitlines() if re.search(pattern, l))
            g, me = re.escape(GW1), re.escape(pip)
            seen = {
                "sport 67": count(r"\.67 > 255\.255\.255\.255\.68"),
                "sport 6767 (control)": count(r"\.6767 > 255\.255\.255\.255\.68"),
                f"ARP from {GW1}": count(rf"ARP.*(tell {g},|Reply {g} is-at)"),
                f"ARP request from {pip} (control)": count(rf"ARP.*tell {me},"),
                f"IPv4 from {GW1}": count(rf" {g} > "),
            }
            detail = (f"on br-app from plain: {seen}; victim after a rogue server: {v_addr}, {v_route!r},"
                      f" gateway neighbour {v_gw_mac!r} (br-app is {br_mac})")
            print(f"dhcp-spoof-dropped: {detail}")
            control("dhcp-spoof-dropped",
                    seen["sport 67"] == 0 and seen["sport 6767 (control)"] > 0 and seen[f"ARP from {GW1}"] == 0
                    and seen[f"ARP request from {pip} (control)"] > 0 and seen[f"IPv4 from {GW1}"] == 0
                    and not v_addr.startswith("10.20.1.24") and not v_addr.startswith("10.20.1.25")
                    and f"default via {GW1}" in v_route and (br_mac in v_gw_mac or v_gw_mac == ""),
                    detail)
            IP[("node1", "gprobe")] = v_addr

        with subtest("other-node-public-ip-denied: the cluster's own public addresses are not the internet"):
            from_wan = wan.execute(f"nc -z -w5 {PUB4_2} 22")[0] == 0
            res = {f"{PUB4_2}:22": reach(node1, "plain", PUB4_2, 22), f"{PUB4_1}:22": reach(node1, "plain", PUB4_1, 22),
                   f"{PUB4_2}:22 from gprobe": reach(node1, "gprobe", PUB4_2, 22)}
            internet = reach(node1, "plain", S3, 443)
            detail = f"from the internet {PUB4_2}:22: {from_wan}; from containers: {res}; the internet {S3}:443: {internet}"
            print(f"other-node-public-ip-denied: {detail}")
            control("other-node-public-ip-denied",
                    from_wan and is_open(internet) and not any(is_open(v) for v in res.values()),
                    detail)

        with subtest("wan-segment-l2-denied: one container's GUA is not reachable from another's on br-wan"):
            g6, p6 = GUA[("node1", "gprobe")], GUA[("node1", "plain")]
            node1.wait_until_succeeds("nixos-container run gprobe -- systemctl is-active ci-serve6.service", timeout=120)
            # Positive controls: the internet reaches gprobe's port on its GUA, and
            # plain's own GUA reaches the internet. So a refusal below is the bridge.
            wan.wait_until_succeeds(f"nc -6 -z -w5 {g6} 8081", timeout=60)
            from_wan = wan.execute(f"nc -6 -z -w5 {g6} 8081")[0] == 0
            plain_out = try_in(node1, "plain", f"ping -6 -c2 -W2 -I {p6} {NET6}")[0] == 0
            tries = {
                "plain->gprobe ping": try_in(node1, "plain", f"ping -6 -c2 -W2 {g6}")[0] == 0,
                "plain->gprobe tcp 8081": is_open(reach(node1, "plain", g6, 8081)),
                "gprobe->plain ping": try_in(node1, "gprobe", f"ping -6 -c2 -W2 {p6}")[0] == 0,
                f"{LONG}->gprobe ping": try_in(node1, LONG, f"ping -6 -c2 -W2 {g6}")[0] == 0,
            }
            detail = f"internet -> gprobe [{g6}]:8081: {from_wan}; plain's own GUA to the internet: {plain_out}; between containers: {tries}"
            print(f"wan-segment-l2-denied: {detail}")
            control("wan-segment-l2-denied", from_wan and plain_out and not any(tries.values()), detail)

        with subtest("nd-spoof-refused: a container's neighbour adverts can't claim the node's or another app's IPv6"):
            g6, p6 = GUA[("node1", "gprobe")], GUA[("node1", "plain")]
            pv = WAN_IF["plain"]
            br_mac = json.loads(node1.succeed("ip -j link show br-wan"))[0]["address"]
            def wan_neigh(ip):
                out = json.loads(wan.succeed(f"ip -6 -j neigh show {ip} dev eth1") or "[]")
                return out[0].get("lladdr", "") if out else ""
            # The gateway (wan) knows both, with their owners' MACs.
            wan.wait_until_succeeds(f"ping -6 -c1 -W2 {PUB6_1}", timeout=60)
            wan.wait_until_succeeds(f"ping -6 -c1 -W2 {g6}", timeout=60)
            before = {PUB6_1: wan_neigh(PUB6_1), g6: wan_neigh(g6)}
            wan.succeed("systemd-run --unit=ci-nd-cap -p SuccessExitStatus=143 ${pkgs.tcpdump}/bin/tcpdump -i eth1 -n -e -U"
                        f" -w /tmp/nd.pcap 'ether src {WAN_MAC['plain']} and icmp6'")
            time.sleep(2)
            for target in (PUB6_1, g6):
                for dst in ("ff02::1", GW6):
                    run(node1, "plain", f"ci-nd {pv} na {target} {WAN_MAC['plain']} {dst} 5")
            run(node1, "plain", f"ci-nd {pv} ra - {WAN_MAC['plain']} ff02::1 3")
            # The positive control: plain's advert for its own GUA does reach the gateway.
            run(node1, "plain", f"ci-nd {pv} na {p6} {WAN_MAC['plain']} ff02::1 3")
            time.sleep(2)
            after = {PUB6_1: wan_neigh(PUB6_1), g6: wan_neigh(g6)}
            ssh = [wan.execute(f"nc -6 -z -w5 {PUB6_1} 22")[0] == 0 for _ in range(3)]
            wan.succeed("systemctl stop ci-nd-cap.service")
            cap = wan.succeed("${pkgs.tcpdump}/bin/tcpdump -r /tmp/nd.pcap -n -v 2>/dev/null")
            def adverts(target):
                return len(re.findall(rf"neighbor advertisement.*\n?.*tgt is {re.escape(target)}\b", cap))
            seen = {"NA for node1": adverts(PUB6_1), "NA for gprobe": adverts(g6),
                    "RA": cap.count("router advertisement"), "NA for itself (control)": adverts(p6)}
            detail = (f"wan's neighbours before {before}, after {after} (node1's br-wan {br_mac}, gprobe {WAN_MAC['gprobe']},"
                      f" plain {WAN_MAC['plain']}); wan -> [{PUB6_1}]:22 after: {ssh}; plain's ICMPv6 on the wire: {seen}")
            print(f"nd-spoof-refused: {detail}")
            control("nd-spoof-refused",
                    before[PUB6_1] == br_mac and before[g6] == WAN_MAC["gprobe"]
                    and after == before and all(ssh)
                    and seen["NA for node1"] == 0 and seen["NA for gprobe"] == 0 and seen["RA"] == 0
                    and seen["NA for itself (control)"] > 0,
                    detail)

        with subtest("wan-mac-pinned: a container's WAN frames carry its own MAC, and can't move the gateway's"):
            have = {a: json.loads(run(node1, a, f"ip -j link show {WAN_IF[a]}"))[0]["address"] for a in ("gprobe", "plain")}
            ll = {a: run(node1, a, f"ip -6 -o addr show dev {WAN_IF[a]} scope link | awk '{{print $4}}' | cut -d/ -f1").split()
                  for a in ("gprobe", "plain")}
            gw_mac = wan.succeed("cat /sys/class/net/eth1/address").strip()
            def fdb_ports(m):
                return sorted({e.get("ifname", "") for e in json.loads(node1.succeed("bridge -j fdb show br br-wan"))
                               if e.get("mac") == m})
            node1.succeed(f"ping -c2 -W2 {GW4_1}")
            fdb_before = fdb_ports(gw_mac)
            # plain sends as the gateway: its WAN veth takes the gateway's MAC.
            pv = WAN_IF["plain"]
            run(node1, "plain", f"ip link set {pv} down; ip link set {pv} address {gw_mac}; ip link set {pv} up")
            spoofed_out = try_in(node1, "plain", f"ping -6 -c3 -W2 -I {GUA[('node1', 'plain')]} {NET6}")[0] == 0
            # A steady stream as the gateway (an advert for its own GUA every 0.1 s for
            # 6 s), and br-wan's table sampled meanwhile: the gateway's own frames are
            # sparse, so a learned entry would sit on plain's port for most of it. One
            # sample after the fact can miss it: the gateway's next frame moves it back.
            node1.succeed(f"nixos-container run plain -- ci-nd {pv} na {GUA[('node1', 'plain')]} {gw_mac} ff02::1 60 0.1"
                          " >/dev/null 2>&1 &")
            samples = []
            t_end = time.monotonic() + 5
            while time.monotonic() < t_end:
                samples.append(tuple(fdb_ports(gw_mac)))
                time.sleep(0.1)
            fdb_during = sorted({p for smp in samples for p in smp})
            host_out = node1.execute(f"ping -c2 -W2 {GW4_1}")[0] == 0
            host_out6 = wan.execute(f"nc -6 -z -w5 {PUB6_1} 22")[0] == 0
            node1.succeed("systemctl restart container@plain.service")
            node1.wait_until_succeeds("nixos-container run plain -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.'", timeout=120)
            node1.wait_until_succeeds(f"nixos-container run plain -- ping -6 -c1 -W2 -I {GUA[('node1', 'plain')]} {NET6}", timeout=60)
            IP[("node1", "plain")] = ip4(node1, "plain")
            detail = (f"WAN MACs {have} (want {WAN_MAC['gprobe']}, {WAN_MAC['plain']}); link-local {ll} (want"
                      f" {WAN_LL['gprobe']}, {WAN_LL['plain']}); gateway {gw_mac} in br-wan's table on {fdb_before} before,"
                      f" {fdb_during} in {len(samples)} samples while plain sent as it; plain's egress as the gateway: {spoofed_out};"
                      f" host to the gateway meanwhile: v4 {host_out}, wan -> node1 v6 ssh {host_out6}")
            print(f"wan-mac-pinned: {detail}")
            control("wan-mac-pinned",
                    have == {a: WAN_MAC[a] for a in have}
                    and all([ipaddress.ip_address(x) for x in ll[a]] == [ipaddress.ip_address(WAN_LL[a])] for a in ll)
                    and fdb_before == [UPLINK1] and fdb_during == [UPLINK1] and len(samples) >= 5
                    and not spoofed_out and host_out and host_out6,
                    detail)

        with subtest("no failed units on either node"):
            for n in (node1, node2):
                no_failed_units(n)

    run_main(main)
  '';
}
