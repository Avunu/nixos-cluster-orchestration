# modules/app-state.nix — an app's local state follows the app.
#
# Nomad chooses the node an app runs on; no app names one. A database's directory is on
# local disk all the same (README, "Storage has two tiers"), so it has to be on whichever
# node that turns out to be. This module is what puts it there (modules/app-state.py):
#
#   - Each app with `localState` has a ZFS dataset of its own, <state>/apps/<app>, where
#     <state> is the dataset mounted at /state. The node running the app (its holder) has
#     it mounted at /state/clients/<app>; every other node keeps it unmounted and
#     read-only, a replica.
#   - Every `intervalSeconds` the holder snapshots it, if anything was written, and each
#     other node asks every peer what it holds and pulls what it lacks. Incrementally:
#     a snapshot's guid is the same on every node that has it, so the newest one two
#     nodes share is where the stream starts.
#   - container@<app> starts with `cluster-state acquire` and ends with `release`. Acquire
#     stops the app wherever else it is running (Nomad placed it here, so that copy is the
#     one that goes), pulls the newest copy any reachable node has, and mounts it
#     read-write. Release takes a last snapshot, with the database stopped. So a move
#     Nomad makes while both nodes are up, a drain or a restart elsewhere, loses nothing.
#   - A node that died took with it what it wrote since its last snapshot was pulled: at
#     most the interval. The app starts elsewhere from the newest replica. When the node
#     comes back, its copy has history the app's new one does not; it is renamed to
#     <state>/orphans/<app>-<time>, whole, and a new replica is received. Nothing deletes
#     an orphan (`cluster-state orphans`, `drop-orphan`); StateOrphaned says there is one.
#
# Two copies running at once is what must not happen. Nomad starts one allocation of a
# stateful app (count 1, lib/mk-app-container.nix), acquire stops the other copy when it
# can reach it, and when it cannot, the other node may be cut off and still running. Such
# a node stops its own apps `stopOnClientAfterSeconds` after its last heartbeat (Nomad's
# disconnect.stop_on_client_after, set on every stateful job), and acquire waits for that
# to have happened, counted from when this node first found the peer silent, before it
# starts anything. That relies on the cut-off node's Nomad agent running. A node whose
# agent is dead while its containers live, and which no peer can reach, is not fenced by
# anything here.
#
# Starting container@<app> by hand on a node is the same statement as Nomad starting it:
# the app is stopped wherever else it runs. The fence then stops the copy Nomad did not
# place, and Nomad starts its own again, so a stray start costs the app two restarts.
#
# Peers talk on the mesh, to a socket-activated `cluster-state serve`. As with every
# service there (lib/net.nix), WireGuard is what authenticates: a peer can read any
# app's state and ask for an app to be stopped, and every node holds every app's
# secrets already (lib/mk-app-container.nix). Nothing a peer can ask for writes here.
#
# Upgrading a site whose apps had `homeNode`: an app's state is then a plain directory on
# one node. It starts there once more, and that start copies the directory into a
# dataset, keeping the directory. Started anywhere else it refuses, and Nomad tries again.
{
  config,
  lib,
  pkgs,
  topology,
  nodeName,
  clusterLib,
  ...
}:
let
  inherit (lib) mkOption types;
  net = clusterLib.net;
  cfg = config.cluster.state;

  stateMount = "/state";
  mountOf = name: "${stateMount}/clients/${name}";

  # Not a preview slot: its state is a clone the agent makes (modules/ci-agent.nix).
  stateful = lib.filterAttrs (_: a: a.localState != { } && (a.preview.of or null) == null) config.clusterApps;

  stateConfig = {
    node = nodeName;
    port = net.statePort;
    inherit stateMount;
    peers = lib.mapAttrs (_: n: net.meshIp topology n) (removeAttrs topology.nodes [ nodeName ]);
    apps = lib.mapAttrs (name: a: {
      mount = mountOf name;
      # A cut-off node stops the app this long after its last heartbeat, and the stop
      # itself may take the whole kill timeout.
      fence = clusterLib.nomad.stopOnClientAfterSeconds + a.nomad.killTimeoutSeconds + 15;
    }) stateful;
    inherit (cfg) keep;
  };

  tool = pkgs.writeShellScriptBin "cluster-state" ''
    export STATE_CONFIG=${pkgs.writeText "cluster-state.json" (builtins.toJSON stateConfig)}
    export PATH=${
      lib.makeBinPath [
        config.boot.zfs.package
        config.systemd.package
        pkgs.util-linux
        pkgs.coreutils
      ]
    }
    exec ${pkgs.python3}/bin/python3 ${./app-state.py} "$@"
  '';
in
{
  options.cluster.state = {
    enable = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Keep each app's local state in a ZFS dataset of its own, replicated to every
        node, so the app can start on any of them. Off only where /state is not ZFS (a
        test VM): local state is then a directory on whichever node the app starts on,
        and does not follow it.
      '';
    };
    intervalSeconds = mkOption {
      type = types.ints.between 15 3600;
      default = 60;
      description = "How often the holder snapshots and the others pull: what a node's death can lose.";
    };
    keep = {
      recentMinutes = mkOption {
        type = types.ints.positive;
        default = 30;
        description = "Every snapshot is kept this long.";
      };
      hourly = mkOption {
        type = types.ints.unsigned;
        default = 24;
        description = "Then one an hour, for this many hours.";
      };
      daily = mkOption {
        type = types.ints.unsigned;
        default = 7;
        description = "Then one a day, for this many days.";
      };
    };
    package = mkOption {
      type = types.package;
      readOnly = true;
      internal = true;
      default = tool;
    };
  };

  config = lib.mkIf (cfg.enable && stateful != { }) {
    assertions = lib.concatLists (
      lib.mapAttrsToList (
        name: a:
        map (host: {
          assertion = lib.hasPrefix "${mountOf name}/" host;
          message = "clusterApps.${name}: localState \"${host}\" is not under ${mountOf name}/, the app's dataset. Its state would stay on one node while the app moves.";
        }) (lib.attrValues a.localState)
      ) stateful
    );

    environment.systemPackages = [ tool ];

    # Before the directories under it are made (lib/mk-app-container.nix), and after
    # every process that wrote to it has gone.
    systemd.services =
      lib.mapAttrs' (
        name: _:
        lib.nameValuePair "container@${name}" {
          serviceConfig = {
            ExecStartPre = lib.mkBefore [ "${tool}/bin/cluster-state acquire ${name}" ];
            ExecStopPost = [ "${tool}/bin/cluster-state release ${name}" ];
          };
        }
      ) stateful
      // {
        "cluster-state@" = {
          description = "A peer's request for app state";
          serviceConfig = {
            ExecStart = "${tool}/bin/cluster-state serve";
            StandardInput = "socket";
            StandardOutput = "socket";
            StandardError = "journal";
          };
        };
        cluster-state-replicate = {
          description = "Snapshot the app state this node holds, and pull what it does not";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${tool}/bin/cluster-state replicate";
            # A whole copy of a large database, the first time.
            TimeoutStartSec = "6h";
          };
        };
      };

    systemd.sockets.cluster-state = {
      description = "App state, to the other nodes";
      wantedBy = [ "sockets.target" ];
      # The mesh address and no other; bound before the mesh is up.
      listenStreams = [ "${net.meshIp topology topology.nodes.${nodeName}}:${toString net.statePort}" ];
      socketConfig = {
        Accept = true;
        FreeBind = true;
        MaxConnections = 64;
      };
    };

    systemd.timers.cluster-state-replicate = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitInactiveSec = "${toString cfg.intervalSeconds}s";
        AccuracySec = "1s";
      };
    };
  };
}
