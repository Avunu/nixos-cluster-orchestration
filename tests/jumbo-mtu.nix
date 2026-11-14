# VM test: MTU 9000 on the vRack and 8920 on the control mesh (design D25), with the
# REAL modules/overlay-network.nix and modules/mesh-control-core.nix on small nodes.
#
# Two pairs of machines, because the two things under test need two kinds of link:
#
#   jumbo1, jumbo2   a trunk that really carries 9000-byte frames: a QEMU `dgram`
#                    netdev between the two VMs, over the build's loopback. The
#                    test VDE switch can't be used for this: it silently drops frames
#                    above about 1500 [RAN, design D25].
#   vde1, vde2       both configured for 9000, on that VDE switch. Which makes it an
#                    accurate stand-in for a vRack that does NOT carry jumbo frames:
#                    small packets pass, large ones vanish, nothing says so.
#
#   vlan-mtus-applied            trunk and all three VLANs at 9000, the mesh at 8920,
#                                br-wan, br-app and a container's veth at 1500
#   mesh-8892-passes-8893-fails  a don't-fragment ping of 8892 bytes crosses the mesh,
#                                8893 does not, and 8972 crosses the VLAN under it
#   container-still-1500-cross-node  containers on two nodes, over the 9000 VLAN:
#                                1500-byte pings and a bulk transfer, and the
#                                fragmentation-needed a 1500 bridge sends back reaches
#                                a 9000 sender. The stand-in container is the
#                                declared app `ctr` (peerAccess to itself on 8080,
#                                cluster.appFirewall.apps), on its vp-<iid> port:
#                                container default-deny allows nothing else across
#                                nodes. Its pings are not a declared flow, so this
#                                test, and only this test, adds one accept for ICMP
#                                echo to the two containers (in mkNode below)
#   blackhole-detected           vrack-mtu-probe reports the VDE pair's VLANs and mesh
#                                as broken (0) while reachable, and Prometheus, with
#                                the real rules, holds VrackJumboBroken pending (its
#                                `for` is 10 minutes; checks.alert-rules proves the
#                                firing); on the jumbo pair the same probe says 1
#   blackhole-tcp-recovers       a bulk TCP transfer over the VDE pair's VLAN and over
#                                its mesh completes anyway, through tcp_mtu_probing
#   initrd-sets-no-mtu           a secure node at 9000 sets no MTU in its initrd, where
#                                stage 2 sets them all (evaluation)
#   mesh-mtu-too-big-fails-eval  mesh.mtu + 80 > vlans.control.mtu is refused
#                                (evaluation), with the mesh module's other refusals
#
# Mutants (flake.nix): `trunk-mtu-unset` (the trunk keeps 1500, so no VLAN can be
# 9000: vlan-mtus-applied fails) and `no-mtu-probing` (blackhole-tcp-recovers hangs).
#
# Run: nix build .#checks.x86_64-linux.jumbo-mtu -L   (needs KVM; ~4 GB RAM)
{
  pkgs,
  lib,
  mkCluster,
  mutant ? "",
  extraModule ? { },
}:
let
  clusterLib = import ../lib { inherit lib; };
  net = clusterLib.net;
  wg = import ./lib/fixture-wg.nix;

  vlans = {
    control = {
      id = 10;
      subnet = "10.10.0.0/24";
      mtu = 9000;
    };
    app = {
      id = 20;
      subnet = "10.20.0.0/16";
      mtu = 9000;
    };
    storage = {
      id = 30;
      subnet = "10.30.0.0/24";
      mtu = 9000;
    };
  };

  mkNodeData = index: tags: {
    inherit index tags;
    hostName = "n${toString index}";
    wanInterface = "wan0";
    vrackInterface = "vrack0";
    publicIp4 = "192.0.2.${toString (10 + index)}";
    publicGw4 = "192.0.2.254";
    public6Prefix = "2001:db8:0:${toString index}";
    publicIp6 = "2001:db8:0:${toString index}::1";
    publicPrefix6 = 64;
    publicGw6 = "2001:db8:0:ff::1";
    controlIp = "10.10.0.${toString (10 + index)}";
    storageIp = "10.30.0.${toString (10 + index)}";
    appBridgeIp = "10.20.${toString index}.1";
    appSubnet = "10.20.${toString index}.0/24";
    appDhcpPoolOffset = 10;
    appDhcpPoolSize = 100;
  };
  # mesh.mtu left out: it follows the control VLAN to 8920, as in the template.
  mkTopology = nodes: {
    datacenter = "dc1";
    inherit vlans nodes;
    privateServices = "10.21.0.0/24";
    mesh.subnet = "10.25.0.0/24";
    stateVersion = "25.11";
  };
  # Two separate sites on separate links. vde2 carries `etcd` only so that a mesh port
  # is open on it for the bulk transfer (nothing runs etcd here).
  jumboTopology = mkTopology {
    jumbo1 = mkNodeData 1 [ "worker" ];
    jumbo2 = mkNodeData 2 [ "worker" ];
  };
  vdeTopology = mkTopology {
    vde1 = mkNodeData 1 [ "worker" ];
    vde2 = mkNodeData 2 [ "etcd" ];
  };
  keyOf = {
    jumbo1 = wg.node1;
    jumbo2 = wg.node2;
    vde1 = wg.node1;
    vde2 = wg.node2;
  };

  textDir = "/var/lib/prometheus-node-exporter-text";

  # The real rules, as the metrics node loads them.
  rulesFile = pkgs.writeText "alert-rules.json" (
    builtins.toJSON (import ../lib/alert-rules.nix { inherit lib; })
  );

  # The jumbo pair's trunk: a point-to-point QEMU link over loopback in the build,
  # named as the topology says by the same kind of udev rule the test driver uses.
  dgramPort = {
    jumbo1 = 47001;
    jumbo2 = 47002;
  };
  dgramMac = {
    jumbo1 = "52:54:00:ab:ff:01";
    jumbo2 = "52:54:00:ab:ff:02";
  };
  peerOf = {
    jumbo1 = "jumbo2";
    jumbo2 = "jumbo1";
  };

  # The stand-in container: a declared app, so the real ruleset lets its bulk transfer
  # cross nodes (container default-deny, modules/overlay-network.nix).
  ctrApp = "ctr";
  ctrPort = net.appPeerPort ctrApp;
  ctrAddrs = "10.20.1.50, 10.20.2.50";

  mkNode =
    topology: name:
    { config, pkgs, ... }:
    let
      node = topology.nodes.${name};
      jumbo = topology == jumboTopology;
    in
    {
      cluster.appFirewall.apps.${ctrApp}.peerAccess = [
        {
          app = ctrApp;
          port = 8080;
        }
      ];
      # Test-only: ICMP echo to the stand-in containers, which no declared flow carries
      # (peerAccess is TCP ports). What is under test here is MTU, and a DF ping is how
      # this test reads it. Fails loudly when the anchor moves.
      networking.nftables.ruleset = lib.mkForce (
        let
          text = config.system.build.clusterNftablesRuleset;
          anchor = ''iifname "br-app" limit rate 5/minute log prefix "container-forward-drop "'';
          edited =
            builtins.replaceStrings
              [ anchor ]
              [
                ''
                  icmp type echo-request ip daddr { ${ctrAddrs} } accept
                  ${anchor}''
              ]
              text;
        in
        assert edited != text;
        edited
      );

      imports = [
        ../modules/overlay-network.nix
        ../modules/mesh-control-core.nix
        extraModule
      ];
      _module.args = {
        inherit topology node clusterLib;
        nodeName = name;
      };

      cluster.mesh = {
        privateKeyFile = "/etc/ci-wg/private";
        publicKeys = lib.mapAttrs (n: _: keyOf.${n}.public) topology.nodes;
      };
      environment.etc."ci-wg/private" = {
        text = keyOf.${name}.private;
        mode = "0400";
        user = "systemd-network";
      };

      networking.useNetworkd = true;
      networking.useDHCP = false;
      virtualisation = {
        memorySize = 768;
        vlans = lib.mkForce [ ];
        interfaces = {
          ${node.wanInterface} = {
            vlan = 1;
            assignIP = false;
          };
        }
        // lib.optionalAttrs (!jumbo) {
          ${node.vrackInterface} = {
            vlan = 2;
            assignIP = false;
          };
        };
        qemu.options = lib.optionals jumbo [
          "-netdev dgram,id=vrack,local.type=inet,local.host=127.0.0.1,local.port=${toString dgramPort.${name}},remote.type=inet,remote.host=127.0.0.1,remote.port=${
            toString dgramPort.${peerOf.${name}}
          }"
          "-device virtio-net-pci,netdev=vrack,mac=${dgramMac.${name}}"
        ];
      };
      boot.initrd.services.udev.rules = lib.optionalString jumbo ''
        SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="${dgramMac.${name}}", NAME="${node.vrackInterface}"
      '';

      # What vrack-mtu-probe writes, readable as on a fleet node.
      services.prometheus.exporters.node = {
        enable = true;
        listenAddress = "127.0.0.1";
        enabledCollectors = [ "textfile" ];
        extraFlags = [ "--collector.textfile.directory=${textDir}" ];
      };
      systemd.tmpfiles.rules = [ "d ${textDir} 0755 root root -" ];
      # Probed by hand in the test, not on a timer.
      systemd.timers.vrack-mtu-probe.wantedBy = lib.mkForce [ ];

      environment.systemPackages = [
        pkgs.socat
        pkgs.wireguard-tools
        pkgs.jq
      ];
    };

  # Prometheus on vde1, with the real rules: does VrackJumboBroken see the real metric?
  promModule = {
    services.prometheus = {
      enable = true;
      listenAddress = "127.0.0.1";
      globalConfig = {
        scrape_interval = "5s";
        evaluation_interval = "5s";
      };
      ruleFiles = [ rulesFile ];
      scrapeConfigs = [
        {
          job_name = "nixos-hosts";
          static_configs = [ { targets = [ "127.0.0.1:9100" ]; } ];
        }
      ];
    };
  };

  # ── evaluation-level ────────────────────────────────────────────────────────
  # The mesh module alone, over a topology, for its refusals.
  meshEval =
    {
      topology,
      nodeName ? "jumbo1",
      keys ? lib.mapAttrs (n: _: keyOf.${n}.public or wg.node3.public) topology.nodes,
    }:
    lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        ../modules/mesh-control-core.nix
        {
          _module.args = {
            inherit topology clusterLib nodeName;
            node = topology.nodes.${nodeName};
          };
          cluster.mesh = {
            privateKeyFile = "/dev/null";
            publicKeys = keys;
          };
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "/dev/null";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    };
  failed = sys: map (a: a.message) (lib.filter (a: !a.assertion) sys.config.assertions);
  refusedFor =
    args: needle:
    let
      f = failed (meshEval args);
    in
    {
      ok = lib.any (lib.hasInfix needle) f;
      detail = f;
    };
  accepted =
    args:
    let
      f = failed (meshEval args);
    in
    {
      ok = f == [ ];
      detail = f;
    };
  withMesh = mesh: jumboTopology // { inherit mesh; };
  at1500 = jumboTopology // {
    vlans = lib.mapAttrs (_: v: v // { mtu = 1500; }) vlans;
  };
  evalChecks = {
    "mesh-mtu-too-big-fails-eval" = {
      "8921 over a 9000 VLAN is refused" = refusedFor {
        topology = withMesh {
          subnet = "10.25.0.0/24";
          mtu = 8921;
        };
      } "exceeds vlans.control.mtu";
      "8920 over a 9000 VLAN is accepted" = accepted {
        topology = withMesh {
          subnet = "10.25.0.0/24";
          mtu = 8920;
        };
      };
      "1421 over a 1500 VLAN is refused" = refusedFor {
        topology = at1500 // {
          mesh = {
            subnet = "10.25.0.0/24";
            mtu = 1421;
          };
        };
      } "exceeds vlans.control.mtu";
      "unset follows a 1500 VLAN to 1420" = {
        ok = net.meshMtu at1500 == 1420 && (accepted { topology = at1500; }).ok;
        detail = net.meshMtu at1500;
      };
      "unset follows a 9000 VLAN to 8920" = {
        ok = net.meshMtu jumboTopology == 8920;
        detail = net.meshMtu jumboTopology;
      };
    };
    # Beyond the design's list: the mesh module's other refusals.
    "mesh-topology-refusals" = {
      "no mesh.subnet" = refusedFor {
        topology = builtins.removeAttrs jumboTopology [ "mesh" ];
      } "topology.mesh.subnet is required";
      "a /16 mesh.subnet" = refusedFor {
        topology = withMesh { subnet = "10.25.0.0/16"; };
      } "must be an IPv4 /24";
      "a mesh.subnet off its network address" = refusedFor {
        topology = withMesh { subnet = "10.25.0.1/24"; };
      } "must be an IPv4 /24";
      "a mesh.subnet inside the app VLAN" = refusedFor {
        topology = withMesh { subnet = "10.20.9.0/24"; };
      } "overlaps vlans.app.subnet";
      "an installed peer with no key" = refusedFor {
        topology = jumboTopology;
        keys = {
          jumbo1 = wg.node1.public;
          jumbo2 = null;
        };
      } "no ${net.meshIf} public key for jumbo2";
      "a placeholder peer with no key is skipped" =
        let
          sys = meshEval {
            topology = lib.recursiveUpdate jumboTopology { nodes.jumbo2.provisioned = false; };
            keys = {
              jumbo1 = wg.node1.public;
              jumbo2 = null;
            };
          };
        in
        {
          ok =
            failed sys == [ ] && sys.config.systemd.network.netdevs."30-${net.meshIf}".wireguardPeers == [ ];
          detail = failed sys;
        };
      "a node index outside 1 to 254" = refusedFor {
        topology = lib.recursiveUpdate jumboTopology { nodes.jumbo2.index = 255; };
      } "need an `index` from 1 to 254";
    };
  };

  # A secure node (not opted out) at MTU 9000: every MTU its initrd's networkd sets,
  # against every MTU its stage 2 sets. The initrd must set none (D25).
  secureTopology = import ./fixtures/secure/topology.nix;
  secureNode =
    (import ./fixtures/secure
      {
        inherit mkCluster;
        self = {
          inputs = { };
          outPath = ./fixtures/secure;
        };
      }
      {
        topology = secureTopology // {
          inherit vlans;
          mesh = builtins.removeAttrs secureTopology.mesh [ "mtu" ];
        };
      }
    ).config.nixosConfigurations.node1.config;
  mtusIn =
    nw:
    lib.filter (x: x != null) (
      lib.mapAttrsToList (
        n: d: if d.netdevConfig ? MTUBytes then "netdev ${n}: ${toString d.netdevConfig.MTUBytes}" else null
      ) (nw.netdevs or { })
      ++ lib.mapAttrsToList (
        n: d: if d.linkConfig ? MTUBytes then "network ${n}: ${toString d.linkConfig.MTUBytes}" else null
      ) (nw.networks or { })
      ++ lib.mapAttrsToList (
        n: d: if d.linkConfig ? MTUBytes then "link ${n}: ${toString d.linkConfig.MTUBytes}" else null
      ) (nw.links or { })
    );
  initrdMtus = {
    initrd = mtusIn secureNode.boot.initrd.systemd.network;
    initrdNetworks = lib.attrNames secureNode.boot.initrd.systemd.network.networks;
    stage2 = mtusIn secureNode.systemd.network;
  };
in
pkgs.testers.runNixOSTest {
  name = "jumbo-mtu";

  nodes = {
    jumbo1 = mkNode jumboTopology "jumbo1";
    jumbo2 = mkNode jumboTopology "jumbo2";
    vde1 = {
      imports = [
        (mkNode vdeTopology "vde1")
        promModule
      ];
    };
    vde2 = mkNode vdeTopology "vde2";
  };

  testScript = ''
    import json
    import time

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    MESH_IF = "${net.meshIf}"
    CTR_PORT = "${ctrPort}"
    VRACK = "vrack0"
    IFS = {"control": f"{VRACK}.10", "app": f"{VRACK}.20", "storage": f"{VRACK}.30"}
    MESH = {
        "jumbo1": "${net.meshIp jumboTopology jumboTopology.nodes.jumbo1}",
        "jumbo2": "${net.meshIp jumboTopology jumboTopology.nodes.jumbo2}",
        "vde1": "${net.meshIp vdeTopology vdeTopology.nodes.vde1}",
        "vde2": "${net.meshIp vdeTopology vdeTopology.nodes.vde2}",
    }
    CTRL = {"jumbo1": "10.10.0.11", "jumbo2": "10.10.0.12", "vde1": "10.10.0.11", "vde2": "10.10.0.12"}
    EVAL = json.loads(r"""${builtins.toJSON evalChecks}""")
    INITRD = json.loads(r"""${builtins.toJSON initrdMtus}""")
    TEXT = "${textDir}/vrack_mtu.prom"
    PAIRS = [(jumbo1, jumbo2), (vde1, vde2)]

    def mtus(n):
        return {l["ifname"]: l["mtu"] for l in json.loads(n.succeed("ip -j link show"))}

    def container(n, idx):
        """A stand-in for an nspawn container: a namespace whose veth is named as the
        declared app `ctr`'s is (vp-<iid>), so the real 52-veth-peer network bridges it
        into br-app and the ruleset knows it."""
        n.succeed(
            "ip netns add ctr"
            f" && ip link add {CTR_PORT} type veth peer name eth0 netns ctr"
            f" && ip -n ctr addr add 10.20.{idx}.50/24 dev eth0"
            " && ip -n ctr link set lo up && ip -n ctr link set eth0 up"
            f" && ip -n ctr route add default via 10.20.{idx}.1"
        )
        n.wait_until_succeeds(f"ip -d link show {CTR_PORT} | grep -q 'master br-app'", timeout=60)
        n.wait_until_succeeds(f"ip netns exec ctr ping -c1 -W2 10.20.{idx}.1", timeout=60)

    def df_ping(n, ip, size, ns=None):
        pre = f"ip netns exec {ns} " if ns else ""
        rc, out = n.execute(f"{pre}ping -n -M do -s {size} -c 3 -W 2 {ip} 2>&1")
        return rc == 0, out.strip().splitlines()[-2:] if out.strip() else []

    def blob(n, size_mb=20):
        n.succeed(f"head -c {size_mb}M /dev/urandom > /tmp/blob")
        return n.succeed("sha256sum < /tmp/blob").split()[0]

    def fetch(n, ip, port, seconds=150, ns=None):
        """A bulk TCP transfer to `n` from ip:port. Returns (sha256 or None, seconds)."""
        pre = f"ip netns exec {ns} " if ns else ""
        start = time.monotonic()
        rc, _ = n.execute(f"rm -f /tmp/got; {pre}timeout {seconds} socat -u TCP:{ip}:{port} CREATE:/tmp/got")
        took = round(time.monotonic() - start, 1)
        if rc != 0:
            return None, took
        return n.succeed("sha256sum < /tmp/got").split()[0], took

    def serve(n, unit, ip, port, ns=None):
        pre = f"ip netns exec {ns} " if ns else ""
        n.succeed(f"systemd-run --unit={unit} {pre}$(command -v socat) TCP-LISTEN:{port},bind={ip},reuseaddr,fork OPEN:/tmp/blob,rdonly")
        n.wait_until_succeeds(f"{pre}ss -Htln 'sport = :{port}' | grep -qF '{ip}:{port}'", timeout=30)

    def handshake(a, b):
        """Traffic over the mesh until a and b have shaken hands."""
        b.wait_until_succeeds(f"ping -c1 -W2 {MESH[a.name]}", timeout=90)
        a.wait_until_succeeds(f"ping -c1 -W2 {MESH[b.name]}", timeout=90)

    def probe(n):
        n.succeed("systemctl start vrack-mtu-probe.service")
        out = n.succeed(f"cat {TEXT}")
        print(f"{n.name} {TEXT}:\n{out}")
        return out

    def main():
        start_all()
        for n in (jumbo1, jumbo2, vde1, vde2):
            n.wait_for_unit("multi-user.target")
            n.wait_for_unit(f"{MESH_IF}-ready.service")

        with subtest("vlan-mtus-applied: 9000 on the trunk and every VLAN, 8920 on the mesh, 1500 at the edges"):
            results = {}
            for n, idx in ((jumbo1, 1), (jumbo2, 2)):
                container(n, idx)
                m = mtus(n)
                inner = json.loads(n.succeed("ip -n ctr -j link show eth0"))[0]["mtu"]
                got = {"trunk": m.get(VRACK), **{v: m.get(i) for v, i in IFS.items()}, "mesh": m.get(MESH_IF),
                       "br-wan": m.get("br-wan"), "br-app": m.get("br-app"), "veth": m.get(CTR_PORT), "in-container": inner}
                results[n.name] = got
            want = {"trunk": 9000, "control": 9000, "app": 9000, "storage": 9000, "mesh": 8920,
                    "br-wan": 1500, "br-app": 1500, "veth": 1500, "in-container": 1500}
            probing = {n.name: n.succeed("sysctl -n net.ipv4.tcp_mtu_probing").strip() for n in (jumbo1, jumbo2)}
            print(f"vlan-mtus-applied: {results}; tcp_mtu_probing {probing}")
            control("vlan-mtus-applied", all(r == want for r in results.values()),
                    f"want {want}, got {results}; tcp_mtu_probing {probing}")

        with subtest("mesh-8892-passes-8893-fails: WireGuard at 8920 over a link that carries 9000"):
            handshake(jumbo1, jumbo2)
            under, under_out = df_ping(jumbo1, CTRL["jumbo2"], 8972)
            p92, out92 = df_ping(jumbo1, MESH["jumbo2"], 8892)
            p93, out93 = df_ping(jumbo1, MESH["jumbo2"], 8893)
            detail = f"VLAN DF 8972: {under} {under_out}; mesh DF 8892: {p92} {out92}; mesh DF 8893: {p93} {out93}"
            print(f"mesh-8892-passes-8893-fails: {detail}")
            control("mesh-8892-passes-8893-fails", under and p92 and not p93, detail)

        with subtest("container-still-1500-cross-node: containers stay at 1500 across a 9000 VLAN"):
            c2 = "10.20.2.50"
            p72, out72 = df_ping(jumbo1, c2, 1472, ns="ctr")
            p73, out73 = df_ping(jumbo1, c2, 1473, ns="ctr")
            want_sum = blob(jumbo2)
            serve(jumbo2, "ctr-blob", c2, 8080, ns="ctr")
            got_sum, took = fetch(jumbo1, c2, 8080, ns="ctr")
            jumbo2.succeed("systemctl stop ctr-blob.service")
            # The host, at 9000, sends a full-size don't-fragment packet to the other
            # node's container: jumbo2 can't put it on its 1500 bridge and says so, and
            # that ICMP must reach the sender (otherwise this is the blackhole again).
            rc, frag = jumbo1.execute(f"ping -n -M do -s 8972 -c 2 -W 2 {c2} 2>&1")
            frag_seen = "mtu = 1500" in frag or "Frag needed" in frag or "Message too long, mtu=1500" in frag
            after, _ = df_ping(jumbo1, c2, 1472)
            detail = (f"container DF 1472: {p72} {out72}; DF 1473: {p73} {out73}; bulk 20 MiB: {got_sum == want_sum} in {took}s;"
                      f" host DF 8972 to the far container: rc={rc}, frag-needed came back={frag_seen} {frag.strip().splitlines()[-3:]};"
                      f" then 1472: {after}")
            print(f"container-still-1500-cross-node: {detail}")
            control("container-still-1500-cross-node",
                    p72 and not p73 and got_sum == want_sum and rc != 0 and frag_seen and after,
                    detail)

        with subtest("blackhole-detected: the probe reports a VLAN that drops jumbo frames, and the alert sees it"):
            handshake(vde1, vde2)
            small, _ = df_ping(vde1, CTRL["vde2"], 1472)
            big, _ = df_ping(vde1, CTRL["vde2"], 8972)
            text = probe(vde1)
            good_text = probe(jumbo1)
            def samples(t, metric):
                out = {}
                for line in t.splitlines():
                    if line.startswith(metric + "{"):
                        labels, value = line.rsplit(" ", 1)
                        out[labels[len(metric):]] = value
                return out
            broken = samples(text, "cluster_vrack_mtu_ok")
            reach = samples(text, "cluster_vrack_peer_reachable")
            healthy = samples(good_text, "cluster_vrack_mtu_ok")
            vde1.wait_for_unit("prometheus.service")
            def pending(_):
                r = json.loads(vde1.succeed(
                    "curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=ALERTS%7Balertname%3D%22VrackJumboBroken%22%7D'"
                ))["data"]["result"]
                return len(r) == 4 and all(x["metric"]["alertstate"] == "pending" and x["metric"]["peer"] == "vde2" for x in r)
            retry(pending, timeout_seconds=120)
            alerts = vde1.succeed(
                "curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=ALERTS%7Balertname%3D%22VrackJumboBroken%22%7D'"
                " | jq -c '[.data.result[].metric | {vlan, peer, alertstate}]'"
            ).strip()
            detail = (f"VDE pair: DF 1472 {small}, DF 8972 {big}; probe ok={broken} reachable={reach};"
                      f" Prometheus: {alerts}; jumbo pair probe ok={healthy}")
            print(f"blackhole-detected: {detail}")
            control("blackhole-detected",
                    small and not big and len(broken) == 4 and all(v == "0" for v in broken.values())
                    and len(reach) == 4 and all(v == "1" for v in reach.values())
                    and len(healthy) == 4 and all(v == "1" for v in healthy.values()),
                    detail)

        with subtest("blackhole-tcp-recovers: a bulk transfer completes over the blackholed VLAN and mesh"):
            want_sum = blob(vde2)
            serve(vde2, "blob-vlan", CTRL["vde2"], 4646)
            serve(vde2, "blob-mesh", MESH["vde2"], 2379)
            vlan_sum, vlan_took = fetch(vde1, CTRL["vde2"], 4646)
            mesh_sum, mesh_took = fetch(vde1, MESH["vde2"], 2379)
            probing = vde1.succeed("sysctl -n net.ipv4.tcp_mtu_probing").strip()
            detail = (f"tcp_mtu_probing={probing}; 20 MiB over the VLAN: {vlan_sum == want_sum} in {vlan_took}s;"
                      f" over the mesh: {mesh_sum == want_sum} in {mesh_took}s")
            print(f"blackhole-tcp-recovers: {detail}")
            control("blackhole-tcp-recovers", vlan_sum == want_sum and mesh_sum == want_sum, detail)

        with subtest("initrd-sets-no-mtu: a secure node at 9000 sets none in its initrd"):
            detail = f"initrd networks {INITRD['initrdNetworks']} set {INITRD['initrd']}; stage 2 sets {INITRD['stage2']}"
            print(f"initrd-sets-no-mtu: {detail}")
            # The positive control: the same reading finds stage 2's.
            control("initrd-sets-no-mtu-stage2-has-them", len(INITRD["stage2"]) >= 6, detail)
            # The initrd has networks to read: the WAN NIC, for the passphrase over SSH.
            control("initrd-sets-no-mtu", INITRD["initrd"] == [] and len(INITRD["initrdNetworks"]) >= 1, detail)

        with subtest("mesh-mtu-too-big-fails-eval, and the mesh module's other refusals"):
            for name, cases in EVAL.items():
                for case, r in cases.items():
                    print(f"{name}: {case}: {r['ok']} {r['detail']}")
                control(name, all(r["ok"] for r in cases.values()),
                        json.dumps({c: r for c, r in cases.items() if not r["ok"]}))

    run_main(main)
  '';
}
