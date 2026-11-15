# Eval-level check for the container/tunnel wiring (lib/mk-app-container.nix,
# modules/app-container.nix, modules/overlay-network.nix).
#
# Deliberately NOT a VM test: it asserts what this repo *generates*, and building
# a real app container would drag in a full WordPress/PHP or ERPNext closure for
# no extra confidence. The payload flakes carry the runtime tests; what can
# regress here is the wiring, and every property below was a bug at some point
# during the tunnel refactor.
#
# Run: nix build .#checks.<system>.container-tunnel
{
  pkgs,
  lib,
  topology,
  clusterLib,
  clanCoreModule,
  appContainerModule,
  overlayNetworkModule,
}:
let
  node = topology.nodes.node1;

  # A stand-in payload: the wiring under test is indifferent to what runs inside,
  # and a stub keeps this an evaluation rather than a distro build.
  stubApp = {
    systemd.services.stub.script = "sleep infinity";
  };

  sys = lib.nixosSystem {
    system = pkgs.stdenv.hostPlatform.system;
    specialArgs = {
      inherit topology clusterLib node;
      nodeName = "node1";
    };
    modules = [
      # clanCore supplies clan.core.vars.*, which the secret bind mounts resolve
      # through. Its recommended defaults are off for the same reason as on a
      # real node — see checks.clan-coexist.
      clanCoreModule
      appContainerModule
      overlayNetworkModule
      {
        boot.loader.grub.devices = [ "/dev/null" ];
        fileSystems."/" = {
          device = "/dev/null";
          fsType = "ext4";
        };
        system.stateVersion = topology.stateVersion;
        clan.core.enableRecommendedDefaults = false;
        clan.core.settings.machine.name = "node1";
        # Normally supplied by lib.clan; this fixture builds a bare nixosSystem.
        # A string: see tests/fixtures/default.nix.
        clan.core.settings.directory = toString ../.;

        # A stand-in generator. Nothing is actually generated in a test fixture,
        # so every `.path` here resolves to the "/no-such-path" sentinel — which
        # is exactly why the assertions below check the GUEST side (mount points,
        # credentialsFile) rather than host paths. What can regress in this file
        # is the wiring, and the wiring is guest-side.
        clan.core.vars.generators.probe = {
          files.cloudflared = { };
          files.token = { };
          script = "";
        };

        clusterApps.probe = {
          tier = "monolith";
          module = stubApp;
          secrets.token = {
            generator = "probe";
            file = "token";
          };
          tunnel = {
            id = "00000000-0000-4000-8000-000000000010";
            credentials = {
              generator = "probe";
              file = "cloudflared";
            };
            ingress."probe.example.com" = "unix:/run/probe/app.sock";
            socketGroups = [ "probe" ];
          };
        };
      }
    ];
  };

  c = sys.config;
  inner = c.containers.probe.config;
  iid = clusterLib.net.gua6Iid "probe";
  wanIf = "vw-${iid}";
  # Written out here rather than asked of lib/net.nix: 02:76:77, the node's index, the
  # app's identifier; and that MAC's EUI-64 link-local address.
  wanMac = "02:76:77:0${toString node.index}:${lib.substring 0 2 iid}:${lib.substring 2 2 iid}";
  wanLinkLocal = "fe80::76:77ff:fe0${toString node.index}:${iid}";
  unit = "cloudflared-tunnel-00000000-0000-4000-8000-000000000010";

  ruleset = c.networking.nftables.ruleset;
  hasRule = s: lib.hasInfix s ruleset;
  appIf = "${node.vrackInterface}.${toString topology.vlans.app.id}";

  # The same node with a peerAccess flow added (container default-deny, design WS9):
  # a long-named source and its target. Its ports are 3306 and 3307, so nothing in
  # this ruleset says `dport 80` (the WAN check above reads the probe-only one).
  peerSys = sys.extendModules {
    modules = [
      {
        clusterApps.a-twenty-two-char-site = {
          module = stubApp;
          network.peerAccess = [
            {
              app = "peerdb";
              port = 3306;
            }
          ];
        };
        clusterApps.peerdb = {
          module = stubApp;
          network.peerAccess = [ ];
        };
        clusterApps.plainapp.module = stubApp;
      }
    ];
  };
  pc = peerSys.config;
  peerRuleset = pc.networking.nftables.ruleset;
  hasPeerRule = s: lib.hasInfix s peerRuleset;
  vp = clusterLib.net.appPeerPort;
  srcPort = vp "a-twenty-two-char-site";
  dbPort = vp "peerdb";
  srcMark = "0x${lib.toLower (lib.toHexString (clusterLib.net.appMark pc.cluster.appFirewall.apps "a-twenty-two-char-site"))}";

  checks = [
    # ── the connector lives in the container, against a socket ──────────────
    {
      name = "connector runs inside the container";
      ok = inner.services.cloudflared.enable;
    }
    {
      name = "route is a socket path, not an address";
      ok =
        inner.services.cloudflared.tunnels.${c.clusterApps.probe.tunnel.id}.ingress == {
          "probe.example.com" = "unix:/run/probe/app.sock";
        };
    }
    {
      name = "credentials come from the auto-appended tunnel secret";
      ok =
        inner.services.cloudflared.tunnels.${c.clusterApps.probe.tunnel.id}.credentialsFile
        == "/run/secrets/cloudflared";
    }
    {
      name = "credentials secret is bind-mounted into the container";
      ok = c.containers.probe.bindMounts ? "/run/secrets/cloudflared";
    }
    {
      name = "declared secrets are bind-mounted read-only";
      ok =
        (c.containers.probe.bindMounts ? "/run/secrets/token")
        && c.containers.probe.bindMounts."/run/secrets/token".isReadOnly
        && c.containers.probe.bindMounts."/run/secrets/cloudflared".isReadOnly;
    }
    {
      # The container must never hold a decryption key: sops-nix decrypts on the
      # HOST at activation and only the plaintext is bind-mounted in.
      name = "no secret machinery leaks into the container";
      ok = !(inner ? sops) || inner.sops.secrets == { };
    }
    {
      # cloudflared runs under DynamicUser, so without this it cannot open the
      # app's socket at all.
      name = "connector gets the app's group";
      ok = inner.systemd.services.${unit}.serviceConfig.SupplementaryGroups == [ "probe" ];
    }

    # ── no static addressing survives ───────────────────────────────────────
    {
      name = "container has no static IPv4";
      ok = c.containers.probe.localAddress == null;
    }
    # (The Nomad service can no longer carry an Address: the `address` option
    # does not exist, so there is nothing to assert against.)

    # ── dual-stack ──────────────────────────────────────────────────────────
    {
      name = "second veth is bridged onto the WAN segment";
      ok = c.containers.probe.extraVeths.${wanIf}.hostBridge == "br-wan";
    }
    {
      # And its fixed link-local address beside it, nothing else.
      name = "container takes a derived GUA from the node's /64";
      ok =
        inner.systemd.network.networks."20-${wanIf}".address == [
          "${node.public6Prefix}::${iid}/64"
          "${wanLinkLocal}/64"
        ];
    }
    {
      # The gateway sits outside the /64, so without this there is no route.
      name = "IPv6 gateway is on-link";
      ok = (builtins.head inner.systemd.network.networks."20-${wanIf}".routes).GatewayOnLink;
    }
    {
      name = "derived identifier avoids the reserved ones";
      ok = !(builtins.elem iid clusterLib.net.gua6Reserved);
    }
    {
      # Bridged frames bypass the host's ip/ip6 hooks, so the container must
      # filter for itself or its WAN interface is unprotected.
      name = "container firewalls its own WAN interface";
      ok = inner.networking.firewall.enable;
    }

    # ── host: WAN is a bridge port, and the surface is closed ───────────────
    {
      name = "WAN NIC is a port on br-wan";
      ok = c.systemd.network.networks."05-wan-port".networkConfig.Bridge == "br-wan";
    }
    {
      name = "br-wan is dual-stack";
      ok =
        c.systemd.network.networks."10-br-wan".address == [
          "${node.publicIp4}/32"
          "${node.publicIp6}/64"
        ];
    }
    {
      name = "host address is not the subnet-router anycast address";
      ok = node.publicIp6 != "${node.public6Prefix}::";
    }
    {
      name = "SSH is reachable on br-wan";
      ok = hasRule ''iifname "br-wan" tcp dport 22 accept'';
    }
    {
      name = "no HTTP/HTTPS on the WAN surface";
      ok = !(hasRule "dport 80") && !(hasRule "dport 443") && !(hasRule "dport { 80");
    }
    {
      # Without NDP the segment does not work; without the error types PMTU
      # discovery breaks silently.
      name = "ICMPv6 is permitted";
      ok = hasRule "icmpv6 type" && hasRule "nd-neighbor-solicit" && hasRule "packet-too-big";
    }
    {
      name = "IPv4 egress is still masqueraded";
      ok = hasRule "masquerade";
    }

    # ── container default-deny (design WS9, Appendix E) ─────────────────────
    {
      name = "the bridge guard table is in the ruleset";
      ok = hasRule "table bridge guard {";
    }
    {
      # Container to host: DHCP, DNS and ping on the gateway, then drop.
      name = "br-app is default-deny to the host";
      ok =
        hasRule ''iifname "br-app" ip daddr ${node.appBridgeIp} udp dport 53 accept''
        && hasRule ''iifname "br-app" drop''
        && !(hasRule ''iifname "br-app" accept'');
    }
    {
      name = "no container reaches another over br-app, whatever its port";
      ok = hasRule ''meta ibrname "br-app" drop'';
    }
    {
      name = "no container answers DHCP or claims the gateway";
      ok =
        hasRule ''meta ibrname "br-app" ether type ip udp sport 67 drop''
        && hasRule ''meta ibrname "br-app" arp saddr ip ${node.appBridgeIp} drop'';
    }
    {
      name = "a WAN veth sends only from its own GUA or the link-local address of its fixed MAC";
      ok = hasRule ''iifname "${wanIf}" ip6 saddr != { ${node.public6Prefix}::${iid}, ${wanLinkLocal} } drop'';
    }
    {
      # Before the bridge learns anything from the frame: a container can't move the
      # gateway's MAC onto its own port.
      name = "a WAN veth sends only from its own fixed MAC and link-local address, which the container sets";
      ok =
        hasRule ''iifname "${wanIf}" ether saddr != ${wanMac} drop''
        && inner.systemd.network.networks."20-${wanIf}".linkConfig.MACAddress == wanMac
        && lib.elem "${wanLinkLocal}/64" inner.systemd.network.networks."20-${wanIf}".address
        && inner.systemd.network.networks."20-${wanIf}".networkConfig.LinkLocalAddressing == "no";
    }
    {
      name = "a WAN veth's neighbour adverts speak only for its own two addresses, and it sends no router adverts or redirects";
      ok =
        hasRule ''iifname "${wanIf}" icmpv6 type nd-neighbor-advert icmpv6 taddr != { ${node.public6Prefix}::${iid}, ${wanLinkLocal} } drop''
        && hasRule ''iifname "vw-*" icmpv6 type { nd-router-advert, nd-redirect } drop'';
    }
    {
      name = "nothing on the host answers a container's WAN veth";
      ok = hasRule ''iifname "vw-*" drop'' && hasRule ''iifname "vw-*" ether type { ip, arp } drop'';
    }
    {
      # The only host control between two containers' GUAs on br-wan.
      name = "no frame from one container's WAN veth to another's";
      ok = hasRule ''iifname "vw-*" oifname "vw-*" drop'';
    }
    {
      # It declares nothing, so nothing names it: no mark, no accept.
      name = "an app with no network declaration is unmarked and keeps nspawn's veth";
      ok =
        !(hasRule "meta mark set 0x1")
        && c.containers.probe.hostBridge == "br-app"
        && !(lib.hasInfix "network-veth-extra" (toString c.containers.probe.extraFlags));
    }
    {
      name = "IPv4 egress is the internet only: not the fabric, not the cluster's public addresses";
      ok =
        hasRule ''iifname "br-app" oifname "br-wan" ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10''
        && lib.all (n: hasRule n.publicIp4) (lib.attrValues topology.nodes);
    }
    {
      name = "no blanket container forwarding across the app VLAN";
      ok =
        !(hasRule ''iifname "br-app" oifname "${appIf}" accept'')
        && !(hasRule ''iifname "${appIf}" oifname "br-app" accept'');
    }
    {
      name = "raw_exec's uid still has no network";
      ok = hasRule "meta skuid ${toString clusterLib.nomad.appsUid} reject";
    }
    {
      # Both ends of a flow get the deterministic veth, eth0 inside; the others don't.
      name = "a peerAccess source and target ride vp-<iid>, eth0 inside, not nspawn's vb-<name>";
      ok =
        pc.containers.a-twenty-two-char-site.hostBridge == null
        && pc.containers.peerdb.hostBridge == null
        && builtins.elem "--network-veth-extra=${srcPort}:eth0" pc.containers.a-twenty-two-char-site.extraFlags
        && builtins.elem "--network-veth-extra=${dbPort}:eth0" pc.containers.peerdb.extraFlags
        && pc.containers.plainapp.hostBridge == "br-app"
        && pc.systemd.network.networks."52-veth-peer".networkConfig.Bridge == "br-app";
    }
    {
      name = "same node: the declared port one way, replies only back, ARP both ways";
      ok =
        hasPeerRule ''iifname "${srcPort}" oifname "${dbPort}" ether type ip tcp dport 3306 accept''
        && hasPeerRule ''iifname "${dbPort}" oifname "${srcPort}" ether type ip tcp sport 3306 tcp flags & (syn | ack) != syn accept''
        && hasPeerRule ''iifname "${srcPort}" oifname "${dbPort}" ether type arp accept''
        && hasPeerRule ''iifname "${dbPort}" oifname "${srcPort}" ether type arp accept''
        && !(lib.hasInfix "3307" peerRuleset);
    }
    {
      name = "cross node: by the source's mark out, and only to the declared target in";
      ok =
        hasPeerRule ''iifname "${srcPort}" meta mark set ${srcMark}''
        && hasPeerRule ''iifname "br-app" oifname "${appIf}" meta mark ${srcMark} ip daddr {''
        && hasPeerRule ''meta mark 0x10000 oifname "${dbPort}" ether type ip tcp dport { 3306 } accept''
        && hasPeerRule "meta mark 0x10000 drop";
    }
    {
      name = "a flow to an app that doesn't exist is refused";
      ok =
        let
          bad = sys.extendModules {
            modules = [
              {
                clusterApps.lonely = {
                  module = stubApp;
                  network.peerAccess = [
                    {
                      app = "nobody";
                      port = 3306;
                    }
                  ];
                };
              }
            ];
          };
        in
        lib.any (
          a: !a.assertion && lib.hasInfix "names nobody, which no app is called" a.message
        ) bad.config.assertions;
    }

    # ── one app's failure is not the node's failure ─────────────────────────
    {
      # Upstream's ExecReload propagates the guest switch's exit status, which
      # fails the host's switch-to-configuration for every other app too.
      name = "container reload is ours, not the status-propagating one";
      ok = lib.hasInfix "container-reload-probe" "${c.systemd.services."container@probe".serviceConfig.ExecReload
      }";
    }
    {
      # nixos-containers' 1min default kills a reload -- i.e. a deploy -- whose
      # guest is still migrating a database.
      name = "a deploy may take longer than nixos-containers' 1min default";
      ok = c.systemd.services."container@probe".serviceConfig.TimeoutStartSec == "30min";
    }
    {
      # A unit that fails during a switch fails the host's switch, even one
      # the reload started itself -- so degraded is a metric, not a unit.
      name = "no deploy-health unit for a switch to trip over";
      ok = !(c.systemd.services ? "app-deploy-probe");
    }
  ];

  failed = lib.filter (c': !c'.ok) checks;

  # Two properties of the reload script that only its text can show: it runs
  # the guest switch, and whatever that returns it reports rather than fails.
  reloadAssertions = ''
    reload=${c.systemd.services."container@probe".serviceConfig.ExecReload}
    for want in 'switch-to-configuration test' 'the host deploy is NOT failed by this' 'app-deploy-metric-probe'; do
      grep -q "$want" "$reload" || { echo "FAILED: reload script lacks: $want" >&2; exit 1; }
    done
    ! grep -q 'systemctl" start' "$reload" \
      || { echo "FAILED: reload script starts a unit -- one that fails would fail the host's switch" >&2; exit 1; }
    last=$(awk 'NF { line = $0 } END { print line }' "$reload")
    [ "$last" = "exit 0" ] \
      || { echo "FAILED: reload script ends in '$last', not 'exit 0' — a guest failure would fail the host" >&2; exit 1; }
  '';
in
pkgs.runCommand "container-tunnel-checks" { } (
  reloadAssertions
  + (
    if failed == [ ] then
      ''
        echo "${toString (builtins.length checks)} wiring checks passed"
        touch $out
      ''
    else
      ''
        echo "FAILED:" >&2
        ${lib.concatMapStringsSep "\n" (c': ''echo "  - ${c'.name}" >&2'') failed}
        exit 1
      ''
  )
)
