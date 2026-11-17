# lib/ops-index.nix — what the operations tool (avc, tools/avc) needs to know
# about the cluster, as one JSON-able attrset: `nix eval --json .#opsIndex`.
#
# Derived, never edited: nodes come from the topology and apps from the
# evaluated clusterApps of one node, so the tool cannot drift from what is
# actually deployed. One eval instead of the tool scraping apps/ and topology,
# and the only place that knows which app consumes which generator —
# which is how a rotation knows what to restart.
{
  lib,
  topology,
  clusterLib,
  nixosConfigurations,
}:
let
  # The catalogue is identical on every node (modules/apps.nix reads appsDir), so
  # any node's view will do.
  reference = clusterLib.net.referenceNode topology;
  # Without the preview slots: they are no Nomad job, and nothing here is theirs to do.
  apps = nixosConfigurations.${reference}.config.cluster.nomadApps;

  # The kinds an app can be (modules/kinds/); each is a nullable namespace.
  kinds = [
    "wordpress"
    "wpdb"
    "odoo"
    "frappe"
    "freeipa"
    "grafana"
    "attic"
  ];

  secretRefs =
    a:
    lib.mapAttrsToList (_: s: { inherit (s) generator file; }) a.secrets
    ++ lib.optional (a.tunnel.credentials != null) { inherit (a.tunnel.credentials) generator file; };
in
{
  # A machine to read and write shared secrets through, and whose evaluation the
  # catalogue above came from. Not a node anything runs on: avc asks whichever
  # node answers.
  inherit reference;
  flakeUrl = topology.deploy.flakeUrl;
  # What github-repos.json must say (lib/github-repos.nix): `avc ci repos` writes it.
  githubRepos = clusterLib.githubRepos.collect nixosConfigurations;

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
      # Nomad servers hold.
      nomad =
        let
          tls = clusterLib.nomadPki.cliTlsFor cfg.cluster.secrets.generators;
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
          gens = cfg.cluster.secrets.generators;
          pub = if gens ? initrd-ssh then gens.initrd-ssh.files."ssh_host_ed25519_key.pub" else null;
        in
        {
          enabled = cfg.cluster.boot.enable;
          sshPort = cfg.cluster.boot.ssh.port;
          hostKeyPub = if pub != null && pub.exists then pub.value else null;
        };
      # What `avc audit` prints for the watchdog Worker's secrets (modules/audit-ship.nix):
      # whether this node ships at all, and whether it ships Nomad's ACL changes too.
      audit = {
        enabled = cfg.cluster.audit.enable;
        nomadAcl = cfg.cluster.audit.enable && cfg.cluster.audit.nomadAcl.enable;
      };
      # Whether this node's agent talks to the cluster-ci Worker (modules/ci-agent.nix),
      # which then needs its `ci/token` in AGENT_TOKENS (`avc ci tokens`).
      ci.enabled = cfg.cluster.ci.enable;
    }
  ) topology.nodes;

  apps = lib.mapAttrs (name: a: {
    kind = lib.findFirst (k: (a.${k} or null) != null) null kinds;
    job = "app-${name}";
    tunnel = a.tunnel.id;
    hostnames = lib.attrNames a.tunnel.ingress;
    generators = lib.unique (map (s: s.generator) (secretRefs a));
    secrets = secretRefs a;
  }) apps;
}
