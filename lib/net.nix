# lib/net.nix — pure networking/topology helper functions (nixos-router style).
#
# These take the topology attrset (mkCluster's `topology`) and/or plain lists
# and return derived values used by the networking, etcd, DB and Nomad modules.
# No `pkgs`; only `lib`.
{ lib }:
let
  inherit (lib)
    concatStringsSep
    concatMapStringsSep
    mapAttrsToList
    attrValues
    attrNames
    ;
in
rec {
  # Render a list of strings as the *body* of an nftables anonymous set, so it
  # can be used as:  iifname { ${nftSet ifs} }   =>   iifname { "br-app", "wg-ctrl" }
  nftSet = items: concatMapStringsSep ", " (i: ''"${i}"'') items;

  # kernel 8021q VLAN sub-interface naming: <parent>.<vid>
  vlanChild = parent: vid: "${parent}.${toString vid}";

  # Node helpers ---------------------------------------------------------------
  nodeNames = topology: attrNames topology.nodes;
  nodeList = topology: attrValues topology.nodes;

  # Map over nodes producing a list: f name node -> x
  mapNodesToList = topology: f: mapAttrsToList f topology.nodes;

  # Control-VLAN IPs of every node (for gossip peers, DB replication, etc.).
  controlIps = topology: map (n: n.controlIp) (nodeList topology);

  # ── Role membership by tag ──────────────────────────────────────────────────
  # Cluster roles live in `topology.nodes.<n>.tags` (see README.md "Topology schema").
  # Everything quorum- or singleton-shaped derives from these, so adding a
  # client-only or storage-only node is a data change rather than a code change.
  #
  # This replaces `head (attrNames topology.nodes)`, which made whichever node
  # sorted first the leader — invisibly, and wrongly the moment a node was
  # renamed or one sorting before it was added.
  taggedNames = topology: tag: lib.filter (n: hasTag tag topology.nodes.${n}) (nodeNames topology);
  taggedNodes = topology: tag: lib.filter (hasTag tag) (nodeList topology);
  hasTag = tag: node: builtins.elem tag (node.tags or [ ]);

  # The single node carrying a singleton role. Throws rather than silently
  # picking one: an ambiguous juicefs-meta means two metadata engines over one
  # bucket, and an absent one means a cluster that never mounts.
  soleTaggedNode =
    topology: tag:
    let
      matches = taggedNodes topology tag;
    in
    if builtins.length matches == 1 then
      builtins.head matches
    else if matches == [ ] then
      throw "topology: no node is tagged \"${tag}\"; exactly one must be."
    else
      throw (
        "topology: ${toString (builtins.length matches)} nodes are tagged \"${tag}\""
        + " (${concatStringsSep ", " (taggedNames topology tag)}); exactly one must be."
      );

  # ── The control mesh (modules/mesh-control-core.nix) ──────────────────────
  # Every service but Nomad listens on a WireGuard interface carried over the
  # control VLAN (design D1): a machine on the VLAN reaches nothing there without
  # a key a node lists. Nomad stays on the VLAN under its own mTLS, so the two are
  # separate failure domains.
  #
  # The interface's name, in one place. Nothing outside this file spells it: the
  # ruleset's weak-host rule, the netdev, the readiness unit and the tests all read
  # it from here, so renaming the interface (say, to `wg0`) is this one line. It
  # has no other effect.
  meshIf = "wg-ctrl";
  meshDefaultPort = 51820;
  # What WireGuard adds to a packet at most: 40 (IPv6 header) + 8 (UDP) + 32. The
  # mesh runs over IPv4 (60), so a mesh MTU of the VLAN's minus this always fits.
  meshOverhead = 80;
  meshPrefix = 24;
  meshPort = topology: topology.mesh.port or meshDefaultPort;
  # The default follows the control VLAN: 8920 at 9000, 1420 at 1500 (D25).
  meshMtu = topology: topology.mesh.mtu or (topology.vlans.control.mtu - meshOverhead);
  # <first three octets of mesh.subnet>.<index>. The subnet is asserted to be a /24
  # (modules/mesh-control-core.nix), and the index 1 to 254.
  meshIp =
    topology: node:
    let
      octets = lib.take 3 (lib.splitString "." (lib.head (lib.splitString "/" topology.mesh.subnet)));
    in
    concatStringsSep "." (octets ++ [ (toString node.index) ]);

  # The TCP ports a node serves on the mesh, by role. Appendix E of the design:
  # every node its exporters, its log shipper and its app state; `metrics` Loki and Prometheus;
  # `etcd` etcd; `juicefs-meta` the metadata engine. The host firewall accepts
  # exactly these on the mesh interface, and nothing of them anywhere else.
  meshPortsFor =
    node:
    [
      nodeExporterPort
      smartctlExporterPort
      vectorMetricsPort
      statePort
    ]
    ++ lib.optionals (hasTag "metrics" node) [
      lokiPort
      prometheusPort
    ]
    ++ lib.optionals (hasTag "etcd" node) [
      etcdClientPort
      etcdPeerPort
    ]
    ++ lib.optional (hasTag "juicefs-meta" node) jfsMetaPort;

  # A unit that binds a mesh address, or talks to one at start: ordered after the
  # address exists, and retrying for as long as it takes. A node whose mesh key is
  # missing boots anyway (wg-ctrl-ready never fails), and these units then retry
  # every few seconds instead of hitting systemd's start limit and staying failed
  # once the key is repaired. Merge it into `systemd.services.<unit>`.
  meshBoundUnit = {
    after = [ "${meshIf}-ready.service" ];
    wants = [ "${meshIf}-ready.service" ];
    # Defaults, so a unit's own (Vector's 5 starts in 10s) still wins: at one start
    # every 5s, that limit is never reached either.
    unitConfig.StartLimitIntervalSec = lib.mkDefault 0;
    serviceConfig.RestartSec = lib.mkDefault 5;
  };

  # A unit that binds the node's control VLAN address (Nomad: bind_addr = controlIp):
  # ordered after the address exists (control-vlan-ready, modules/overlay-network.nix),
  # and retrying for as long as it takes once that gives up. The same shape as
  # meshBoundUnit, at a priority above a plain definition, because the nixpkgs Nomad
  # unit sets StartLimitIntervalSec = 10, StartLimitBurst = 3 and RestartSec = 2 at
  # normal priority: with those, a control address 6 s late left Nomad failed for
  # good. Merge it into `systemd.services.<unit>`.
  controlVlanReady = "control-vlan-ready.service";
  controlBoundUnit = {
    after = [ controlVlanReady ];
    wants = [ controlVlanReady ];
    unitConfig.StartLimitIntervalSec = lib.mkOverride 90 0;
    serviceConfig.RestartSec = lib.mkOverride 90 5;
  };

  # The app VLAN's transit address of a node: its uplink there. Each node's
  # containers live behind it (modules/overlay-network.nix).
  appTransitIp = node: "10.20.0.${toString node.index}";

  # ── JuiceFS metadata ────────────────────────────────────────────────────────
  # Where every node's JuiceFS client finds the metadata engine. One function, so
  # that the day the engine follows a primary (Patroni, with an address that moves),
  # this is the only place that changes: every client reads it from here.
  jfsMetaPort = 5432;
  jfsMetaHost = topology: meshIp topology (soleTaggedNode topology "juicefs-meta");

  # ── etcd ────────────────────────────────────────────────────────────────────
  # http, on the mesh: WireGuard authenticates the machine (D1), and etcd has no
  # per-client authorization worth adding on top. Peers and clients both.
  etcdScheme = "http";
  etcdPeerPort = 2380;
  etcdClientPort = 2379;
  etcdMembers = topology: taggedNames topology "etcd";
  etcdPeerUrl = topology: node: "${etcdScheme}://${meshIp topology node}:${toString etcdPeerPort}";
  etcdClientUrl =
    topology: node: "${etcdScheme}://${meshIp topology node}:${toString etcdClientPort}";
  etcdInitialCluster =
    topology:
    map (name: "${name}=${etcdPeerUrl topology topology.nodes.${name}}") (etcdMembers topology);
  etcdClientUrls =
    topology: map (name: etcdClientUrl topology topology.nodes.${name}) (etcdMembers topology);

  # ── Nomad ───────────────────────────────────────────────────────────────────
  nomadServerPort = 4647; # RPC
  nomadHttpPort = 4646;
  # bootstrap_expect = number of raft voters, i.e. nodes tagged nomad-server.
  serverCount = topology: builtins.length (taggedNames topology "nomad-server");

  # The local agent's API address. NOT 127.0.0.1: modules/cluster-common.nix
  # sets `bind_addr = node.controlIp`, so Nomad listens ONLY on the control
  # VLAN and every loopback client gets "connection refused".
  #
  # That mismatch was silent in three different ways at once — nomad-bootstrap
  # burned its full 5-minute leadership wait then failed, jfs-nomad-meta
  # retried forever, and nomad-fence hit its `|| exit 0` fail-safe and simply
  # stopped fencing. Deriving the address in one place is what stops a fourth.
  #
  # https, by address: every agent certificate carries IP:<controlIp> for exactly
  # this (lib/nomad-pki.nix), and every caller presents a client certificate.
  nomadAddr = node: "https://${node.controlIp}:${toString nomadHttpPort}";

  # ── App state ───────────────────────────────────────────────────────────────
  # Where each node answers its peers about the app state it holds, and sends it
  # (modules/app-state.nix). On the mesh, like everything but Nomad.
  statePort = 8731;

  # ── Observability ───────────────────────────────────────────────────────────
  # Named here rather than in the modules because the exporter port is bound by
  # the per-node half (modules/monitoring.nix) and scraped by the singleton half
  # (modules/monitoring-server.nix); they must not drift apart.
  nodeExporterPort = 9100;
  smartctlExporterPort = 9633;
  prometheusPort = 9090;
  # Loki on the metrics node (modules/logging-server.nix), pushed to by every
  # node's Vector (modules/logging.nix), which exposes its own health here.
  lokiPort = 3100;
  vectorMetricsPort = 9598;

  # ── Galera (per-client MariaDB) ─────────────────────────────────────────────
  # gcomm connection string from a list of member IPs.
  gcomm = memberIps: "gcomm://${concatStringsSep "," memberIps}";

  # ── Convenience: the /24 gateway + CIDR for a node's container bridge. ──────
  appBridgeCidr = node: "${node.appBridgeIp}/24";

  # ── Container IPv6 (GUA from the node's /64) ────────────────────────────────
  # Containers are bridged onto the WAN segment and addressed statically from the
  # node's /64: OVH sends no RAs there, so SLAAC is not an option. The interface
  # identifier is DERIVED from the app name rather than assigned by hand — the
  # address is never referenced by anything (the tunnel route is a socket path),
  # so it only has to be unique on the segment, and deriving it keeps the "no IP
  # registry" property that dropping static IPv4 just won.
  #
  # 16 bits keeps it legible in logs (2001:db8:0:1::a3f1). Uniqueness is
  # asserted at eval time by guaAssertions rather than trusted.
  gua6Iid = name: lib.substring 0 4 (builtins.hashString "sha256" name);
  gua6 = node: name: "${node.public6Prefix}::${gua6Iid name}";

  # ── Container identity on the host's bridges (design 1.12, Appendix E) ─────
  # A container holds CAP_NET_ADMIN in its own namespace, so it can change its IP
  # and MAC at will, but not which host-side veth its frames arrive on. The host's
  # firewall therefore names containers by that veth: the "bridge port".
  #
  # WAN side: vw-<iid>, on br-wan. Host and container ends share the name, hence
  # the 4-hex identifier rather than the app name (IFNAMSIZ is 16).
  appWanPort = name: "vw-${gua6Iid name}";
  # The container's MAC on that veth, fixed: a locally administered unicast address
  # from the node's index and the app's identifier (02:76:77 is "vw"), set by the
  # container's own networkd (lib/mk-app-container.nix). The bridge guard drops every
  # frame from vw-<iid> with another source MAC (modules/overlay-network.nix), so a
  # container that sends as the gateway's MAC can't make br-wan learn that MAC on its
  # port, which would have handed it the host's own traffic to the gateway. Its
  # link-local address is fixed too (below), so neighbour adverts can be held to its
  # own two addresses. Unique per node because the identifiers are
  # (guaAssertions); the index keeps one app's MAC distinct between nodes.
  appWanMac =
    node: name:
    let
      iid = gua6Iid name;
      idx = lib.fixedWidthString 2 "0" (lib.toLower (lib.toHexString node.index));
    in
    "02:76:77:${idx}:${lib.substring 0 2 iid}:${lib.substring 2 2 iid}";
  # Its link-local address: the EUI-64 form of that MAC (the universal/local bit
  # flipped, ff:fe in the middle), set statically by the container, which makes none
  # of its own (lib/mk-app-container.nix says why).
  appWanLinkLocal =
    node: name:
    let
      iid = gua6Iid name;
      idx = lib.fixedWidthString 2 "0" (lib.toLower (lib.toHexString node.index));
    in
    "fe80::76:77ff:fe${idx}:${iid}";
  # br-app, for an app in no peerAccess relation: nspawn's own veth, vb-<name>.
  # nspawn shortens a name that doesn't fit, unpredictably (`probe-longer-name`
  # became `vb-probe-lo_Dxt` [RAN, design 1.12]), so this is the identity only up to
  # 12 characters, which modules/app-container.nix asserts for an app that needs it.
  appBridgePort = name: "vb-${name}";
  # br-app, for an app that is a peerAccess source or target: a veth this repo names,
  # vp-<iid>, always 7 characters, whatever the app's name (design D23). It REPLACES
  # nspawn's vb-<name> for that app: the container's eth0 is its far end
  # (lib/mk-app-container.nix), because a second link on the same segment would never
  # carry the traffic (the kernel routes by destination, and the subnet is eth0's).
  appPeerPort = name: "vp-${gua6Iid name}";
  # The apps whose br-app port is vp-<iid>: every peerAccess source and every app one
  # names. `apps` is <name> -> { peerAccess; ... } (clusterApps.<n>.network).
  peerAppNames =
    apps:
    let
      sources = lib.filter (n: apps.${n}.peerAccess != [ ]) (attrNames apps);
      targets = lib.concatMap (n: map (p: p.app) apps.${n}.peerAccess) (attrNames apps);
    in
    lib.unique (sources ++ targets);
  appPortFor =
    apps: name: if builtins.elem name (peerAppNames apps) then appPeerPort name else appBridgePort name;
  # What the host's bridge stamps on a declared app's frames (meta mark), by its
  # place among ALL the app names, sorted: every node declares every app, so the
  # same app has the same mark everywhere, which is what a cross-node rule needs.
  appMarkBase = 256;
  appMark = apps: name: appMarkBase + lib.lists.findFirstIndex (n: n == name) 0 (attrNames apps);
  # A frame routed in from another node to a declared peer port, on its way to the
  # bridge: the bridge's output chain lets it reach only that port's declared target.
  # Above every app mark (asserted in modules/overlay-network.nix).
  peerInMark = 65536;

  # ::0 is the Subnet-Router anycast address (RFC 4291 2.6.1) and ::1 is the
  # host itself, so neither may be handed to a container.
  gua6Reserved = [
    "0000"
    "0001"
  ];

  # Collision and reserved-address checks over one node's app set.
  guaAssertions =
    appNames:
    let
      iids = map gua6Iid appNames;
      dupes = lib.subtractLists (lib.unique iids) iids;
      clashing = lib.filter (n: builtins.elem (gua6Iid n) gua6Reserved) appNames;
    in
    [
      {
        assertion = dupes == [ ];
        message =
          "clusterApps: derived IPv6 interface identifiers collide (${concatStringsSep ", " dupes})."
          + " Rename one of the apps, or widen gua6Iid in lib/net.nix.";
      }
      {
        assertion = clashing == [ ];
        message =
          "clusterApps: ${concatStringsSep ", " clashing} derive a reserved IPv6 identifier"
          + " (::0 is Subnet-Router anycast, ::1 is the host). Rename the app.";
      }
    ];

  # IPv4 arithmetic ------------------------------------------------------------
  # Enough to check address plans at eval time: an address as an integer, a
  # CIDR as its [first, last] integer range.
  ip4ToInt = ip: lib.foldl' (acc: o: acc * 256 + lib.toInt o) 0 (lib.splitString "." ip);
  cidrPrefix = cidr: lib.toInt (lib.last (lib.splitString "/" cidr));
  cidrRange =
    cidr:
    let
      base = ip4ToInt (lib.head (lib.splitString "/" cidr));
      size = lib.foldl' (acc: _: acc * 2) 1 (lib.range 1 (32 - cidrPrefix cidr));
      first = base - lib.mod base size;
    in
    [
      first
      (first + size - 1)
    ];
  cidrContains =
    cidr: ip:
    let
      r = cidrRange cidr;
      x = ip4ToInt ip;
    in
    x >= lib.head r && x <= lib.last r;
  cidrsOverlap =
    a: b:
    let
      ra = cidrRange a;
      rb = cidrRange b;
    in
    lib.head ra <= lib.last rb && lib.head rb <= lib.last ra;
}
