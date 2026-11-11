# lib/ops-index.nix — what the operations tool (avc, tools/avc) needs to know
# about the cluster, as one JSON-able attrset: `nix eval --json .#opsIndex`.
#
# Derived, never edited: nodes come from the topology and apps from the
# evaluated clusterApps of one node, so the tool cannot drift from what is
# actually deployed. One eval instead of the tool scraping apps/ and topology,
# and the only place that knows which app consumes which vars generator —
# which is how a rotation knows what to restart.
{
  lib,
  topology,
  clusterLib,
  nixosConfigurations,
}:
let
  # The catalogue is identical on every node (modules/apps.nix reads appsDir), so
  # any node's view will do; the nomad leader's is the one that registers jobs.
  leader = lib.findFirst (
    n: lib.elem "nomad-leader" topology.nodes.${n}.tags
  ) (throw "ops-index: no node tagged nomad-leader") (lib.attrNames topology.nodes);
  apps = nixosConfigurations.${leader}.config.clusterApps;

  # The kinds an app can be (modules/kinds/); each is a nullable namespace.
  kinds = [
    "wordpress"
    "wpdb"
    "odoo"
    "frappe"
    "freeipa"
    "grafana"
  ];

  secretRefs =
    a:
    lib.mapAttrsToList (_: s: { inherit (s) generator file; }) a.secrets
    ++ lib.optional (a.tunnel.credentials != null) { inherit (a.tunnel.credentials) generator file; };
in
{
  inherit leader;
  flakeUrl = topology.deploy.flakeUrl;

  nodes = lib.mapAttrs (
    name: node:
    let
      cfg = nixosConfigurations.${name}.config;
    in
    {
      inherit (node) fqdn tags deployHost;
      # Paths on the node: avc runs the CLI there over SSH. The certificate is that
      # node's own CLI one; the API refuses a handshake without one. The token is the
      # node's `avc` login (modules/nomad-acl.nix): status, logs and restarts in the
      # apps namespace, never a submit, and never the management token, which only the
      # nomad-leader node holds.
      nomad =
        let
          tls = clusterLib.nomadPki.cliTlsFor cfg.clan.core.vars.generators;
        in
        {
          addr = clusterLib.net.nomadAddr node;
          inherit (tls) caCert clientCert clientKey;
          namespace = clusterLib.nomad.appsNamespace;
          tokenPath = "${clusterLib.nomadPki.tokenDir}/avc";
        };
      # What `avc boot` needs to reach the initrd (modules/boot-security.nix). The host key
      # is public, and is how `avc boot unlock` knows it is talking to this node's initrd.
      # It is readable on the ESP too, so it stops accidents, not someone who read the disk.
      boot =
        let
          gens = cfg.clan.core.vars.generators;
          pub = if gens ? initrd-ssh then gens.initrd-ssh.files."ssh_host_ed25519_key.pub" else null;
        in
        {
          enabled = cfg.cluster.boot.enable;
          sshPort = cfg.cluster.boot.ssh.port;
          hostKeyPub = if pub != null && pub.exists then pub.value else null;
        };
      # What `avc audit` prints for the watchdog Worker's secrets (modules/audit-ship.nix):
      # whether this node ships at all, whether it ships Nomad's ACL changes too, and the
      # address Tang sees its key recoveries come from.
      audit = {
        enabled = cfg.cluster.audit.enable;
        nomadAcl = cfg.cluster.audit.enable && cfg.cluster.audit.nomadAcl.enable;
        tangIp = node.tangIp or null;
      };
    }
  ) topology.nodes;

  apps = lib.mapAttrs (name: a: {
    kind = lib.findFirst (k: (a.${k} or null) != null) null kinds;
    inherit (a) homeNode;
    job = "app-${name}";
    tunnel = a.tunnel.id;
    hostnames = lib.attrNames a.tunnel.ingress;
    generators = lib.unique (map (s: s.generator) (secretRefs a));
    secrets = secretRefs a;
  }) apps;
}
