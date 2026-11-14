# modules/ci-agent.nix — this node's half of the pipeline: deploys the moment the site's
# branch moves, and a preview per pull request of an app's project.
#
# The other half is the cluster-ci Worker (workers/cluster-ci), a GitHub App's endpoint.
# A node accepts nothing inbound, so the agent (modules/ci-agent.py) asks the Worker,
# with a token of this node's own, and the Worker holds the request until it has
# something to say. `topology.ci.url` turns it on, on every node.
#
#   deploy    GitHub tells the Worker of a push to the branch `deploy.flakeUrl` names,
#             the Worker answers every node's held request, and each starts
#             cluster-upgrade.service: the same tick, with every gate it has
#             (modules/pull-deploy.nix), minutes sooner. The timer stays, for a
#             push the Worker never heard of.
#
#   preview   `preview.slots` on an app declares that many more containers,
#             `<app>-pv<k>` (modules/apps.nix), dormant like every container and with
#             everything the host decides about one fixed at evaluation. For a pull
#             request the agent on the app's homeNode builds this site's flake with the
#             app's project input at the pull request's commit, for one slot's guest;
#             gives the slot a ZFS clone of the state dataset and a JuiceFS clone of the
#             app's files; and starts it, whose own units migrate the copy. The Worker
#             made the preview's tunnel and hostname, and writes the result on the pull
#             request.
#
# What a preview is trusted with: the app's own secrets and a copy of its data, like the
# app. It runs a branch of the app's repository, which takes write access to push; the
# Worker gives a fork nothing. Its outgoing mail and scheduled jobs are off
# (modules/kinds/). It is still production's data on a hostname of its own: keep the
# preview zone behind Cloudflare Access if the app's own sign-in is not enough.
#
# Only on the homeNode: the clone is of that node's disks. Not a Nomad job: a slot is
# started by the agent, as root, and the fence and the registrar read
# `cluster.nomadApps`, which leaves slots out.
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
  url = topology.ci.url or null;
  enabled = url != null;
  apps = config.clusterApps;

  previewed = lib.filterAttrs (_: a: a.preview.slots > 0) apps;
  slotsOf = name: lib.filterAttrs (_: a: a.preview.of == name) apps;
  here = lib.filterAttrs (_: a: a.homeNode == nodeName) previewed;

  agentConfig = {
    node = nodeName;
    host = node.hostName;
    url = "${lib.removeSuffix "/" (toString url)}/agent/sync";
    flake = topology.deploy.flakeUrl;
    stateMount = "/state";
    cloneRoot = "/state-preview";
    jfsMount = clusterLib.juicefs.mountPoint;
    apps = lib.mapAttrs (name: a: {
      inherit (a.preview) repo input healthPath;
      inputUrl =
        if a.preview.inputUrl != null then a.preview.inputUrl else "github:${a.preview.repo}/{rev}";
      slots = lib.mapAttrsToList (slot: s: {
        name = slot;
        inherit (s.preview) origin;
      }) (slotsOf name);
    }) here;
  };

  agent = pkgs.writeScript "cluster-ci-agent" (
    "#!${pkgs.python3}/bin/python3\n" + builtins.readFile ./ci-agent.py
  );
in
{
  options.cluster.ci.enable = lib.mkOption {
    type = lib.types.bool;
    readOnly = true;
    default = enabled;
    description = "Whether this node's agent talks to the cluster-ci Worker (topology.ci.url).";
  };

  config = lib.mkMerge [
    {
      assertions = lib.concatLists (
        lib.mapAttrsToList (n: a: [
          {
            assertion = enabled;
            message = "clusterApps.${n}: preview.slots needs topology.ci.url, the cluster-ci Worker that says which pull requests want a preview.";
          }
          {
            assertion = a.preview.input != null && a.preview.repo != null;
            message = "clusterApps.${n}: preview.slots needs preview.input, the site flake's input this app's package comes from, and preview.repo, that input's GitHub repository (\"OWNER/name\").";
          }
          {
            assertion = a.preview.origin != null;
            message = "clusterApps.${n}: this app's kind has no previews. The odoo and frappe kinds do.";
          }
          {
            assertion = a.homeNode != null;
            message = "clusterApps.${n}: preview.slots needs homeNode: a preview's database is a clone of that node's disks.";
          }
        ]) previewed
      );
    }

    (lib.mkIf enabled {
      # Its token is the `ci` generator, with every node's own in modules/vars.nix.
      systemd.tmpfiles.rules = [
        "d /run/cluster-preview 0700 root root -"
        "d ${agentConfig.cloneRoot} 0755 root root -"
      ];

      systemd.services.cluster-ci-agent = {
        description = "Deploys and previews, as the cluster-ci Worker asks";
        wantedBy = [ "multi-user.target" ];
        wants = [ "network-online.target" ];
        after = [
          "network-online.target"
          "nix-daemon.service"
        ];
        path = [
          config.nix.package
          config.systemd.package
          config.boot.zfs.package
          pkgs.nixos-container
          pkgs.juicefs
          pkgs.git
          pkgs.util-linux
          pkgs.coreutils
        ];
        environment = {
          CI_CONFIG = pkgs.writeText "cluster-ci-agent.json" (builtins.toJSON agentConfig);
          STATE_DIR = "/var/lib/cluster-ci";
          RUN_DIR = "/run/cluster-preview";
          METRICS_DIR = "/var/lib/prometheus-node-exporter-text";
        };
        serviceConfig = {
          ExecStart = agent;
          LoadCredential = [ "token:${config.clan.core.vars.generators.ci.files.token.path}" ];
          StateDirectory = "cluster-ci";
          StateDirectoryMode = "0700";
          # The Worker being away is a wait, not a failure; a crash is restarted.
          Restart = "always";
          RestartSec = 10;
        };
        # It starts the switch that may change it (cluster-upgrade, not as a child), and a
        # restart only costs the build it was in the middle of.
        startLimitIntervalSec = 0;
      };
    })
  ];
}
