# lib/mk-app-container.nix — the per-client stack generator.
#
# Given one `clusterApps.<name>` entry plus module context, produce a NixOS
# config fragment with BOTH halves of the design:
#   (a) a DORMANT systemd-nspawn container (autoStart=false) deployed to every
#       node, pre-compiled but off until Nomad starts it; and
#   (b) a rendered Nomad jobspec (a raw_exec wrapper, run as nomad-apps, that
#       starts and stops container@<name>) collected into
#       system.build.nomadJobs.<name>.
#
# Tier semantics (per plan):
#   monolith/split -> pinned to app.homeNode (its localState lives there), count=1.
#   replica/scale  -> DB tier layered by db-* modules; app spreads via Nomad.
{ lib }:
let
  inherit (lib)
    mapAttrs'
    nameValuePair
    listToAttrs
    optionalAttrs
    optional
    optionals
    ;
  net = import ./net.nix { inherit lib; };
  inherit (import ./nomad.nix) maxKillTimeoutSeconds appsNamespace appsUser;
in
{
  app, # one clusterApps.<name> submodule value
  config, # host config (for clan vars file paths)
  pkgs,
  topology,
  node, # THIS host's topology node — the container's IPv6 GUA comes from the
  # node it actually runs on, not from app.homeNode.
  # Whether this app is in a peerAccess flow (modules/app-container.nix): then its
  # br-app veth is vp-<iid>, which the host firewall names, not nspawn's vb-<name>.
  peerPort ? false,
}:
let
  n = app.name;

  usesJfs = app.juicefsPaths != { };
  pinned = app.homeNode != null;
  home = if pinned then topology.nodes.${app.homeNode} else null;

  # Per-site tunnel, run inside the container against a unix socket. Because the
  # route is a socket PATH rather than an address, it stays correct wherever the
  # container is scheduled — which is what lets static container IPs go away.
  tun = app.tunnel;
  hasTunnel = tun.id != "";

  # The credentials secret rides the existing secrets bind-mount mechanism, so
  # the connector needs no special handling — it is just another guest secret.
  #
  # Deliberately NOT gated on "can this app run here". Every node builds an
  # identical container for every app — that is the core of the design (dormant
  # everywhere, Nomad decides when, not whether it exists). Mounting secrets
  # only on an app's homeNode would make the container definition differ per
  # node, so escalating a monolith to a replica tier, or removing a pin, would
  # start it somewhere with no credentials and fail silently. App secrets are
  # `share = true` for the same reason.
  credsGuestName = "cloudflared";

  # Written when a guest switch fails, removed when one succeeds, and
  # mirrored as cluster_app_deploy_degraded{app} for Prometheus. See the
  # container@ overrides below.
  degradedMarker = "/run/cluster-app-deploy-failed/${n}";

  # node_exporter textfile collector: write-then-rename so a scrape never
  # reads half a file.
  deployMetric = pkgs.writeShellScript "app-deploy-metric-${n}" ''
    d=/var/lib/prometheus-node-exporter-text
    ${pkgs.coreutils}/bin/mkdir -p "$d"
    echo "cluster_app_deploy_degraded{app=\"${n}\"} $1" > "$d/cluster_app_deploy_${n}.prom.tmp"
    ${pkgs.coreutils}/bin/mv "$d/cluster_app_deploy_${n}.prom.tmp" "$d/cluster_app_deploy_${n}.prom"
  '';

  # Replaces nixos-containers' ExecReload. Same work — run the new closure's
  # switch-to-configuration inside the container, reading SYSTEM_PATH from the
  # unit's EnvironmentFile exactly as upstream does, so the reload applies the
  # closure this deploy just wrote — but a guest failure becomes a report
  # rather than a failed host unit.
  reloadScript = pkgs.writeShellScript "container-reload-${n}" ''
    set -uo pipefail
    systemctl=${config.systemd.package}/bin/systemctl
    # The package's defaults (/etc/nixos-containers, /var/lib/nixos-containers)
    # are the names the module itself uses for stateVersion >= 22.05, which is
    # what this cluster is on — the reload triggers above read the same conf.
    nixosContainer=${pkgs.nixos-container}/bin/nixos-container

    # switch-to-configuration only reloads ACTIVE units, but a container is
    # owned by Nomad and can stop between the decision and this script.
    if ! "$systemctl" is-active --quiet container@${n}.service; then
      exit 0
    fi

    rc=0
    "$nixosContainer" run ${n} -- \
      bash --login -c "''${SYSTEM_PATH:-/nix/var/nix/profiles/system}/bin/switch-to-configuration test" || rc=$?

    if [ "$rc" -eq 0 ]; then
      ${pkgs.coreutils}/bin/rm -f ${degradedMarker}
      ${deployMetric} 0
      exit 0
    fi

    {
      echo "app ${n}: the new closure did NOT fully apply inside the container (guest switch-to-configuration exited $rc)."
      echo "app ${n}: failed units inside the container:"
      "$nixosContainer" run ${n} -- systemctl --failed --no-legend --no-pager 2>&1 \
        | ${pkgs.gnused}/bin/sed 's/^/  /'
      echo "app ${n}: the host deploy is NOT failed by this; the app is marked degraded (cluster_app_deploy_degraded)."
    } >&2

    ${pkgs.coreutils}/bin/mkdir -p ${builtins.dirOf degradedMarker}
    {
      echo "app ${n}: deploy of $(${pkgs.coreutils}/bin/date -Is) did not apply inside the container"
      echo "  guest switch-to-configuration exited $rc"
    } > ${degradedMarker}
    # A metric, not a unit that fails: switch-to-configuration fails the
    # host's switch (status 4) for ANY unit that is failed once systemd has
    # settled after it, including one this reload started -- which is how a
    # failing app-deploy-<name>.service used to fail every deploy after all.
    ${deployMetric} 1
    exit 0
  '';
  appSecrets =
    app.secrets
    // optionalAttrs (hasTunnel && tun.credentials != null) {
      ${credsGuestName} = tun.credentials;
    };

  tunnelModule = {
    services.cloudflared = {
      enable = true;
      tunnels.${tun.id} = {
        credentialsFile = "${secretsGuestDir}/${credsGuestName}";
        ingress = tun.ingress;
        default = tun.default;
      };
    };
    # cloudflared runs under DynamicUser, so reaching the app's socket needs the
    # group that owns its directory.
    systemd.services."cloudflared-tunnel-${tun.id}".serviceConfig = {
      SupplementaryGroups = tun.socketGroups;
      # The journal field contract (modules/logging.nix): `service="tunnel"`
      # rather than one label value per tunnel UUID.
      LogExtraFields = [ "APP_SERVICE=tunnel" ];
    };
  };

  # Where a secret appears INSIDE the container. The host-side path is wherever
  # the age vars backend decrypted it to (/run/secrets/...); the guest path is
  # stable and short so the payload flakes' *File options stay readable.
  secretsGuestDir = "/run/secrets";

  # Resolve guest name -> host path through clan vars.
  secretHostPath = s: config.clan.core.vars.generators.${s.generator}.files.${s.file}.path;

  # Whether a declared secret has actually been generated. Unlike the sops
  # backend (whose `.path` fell back to a "/no-such-path" sentinel for a
  # missing secret), the age backend's fileModule
  # (clan-core: nixosModules/clanCore/vars/secret/age.nix) always returns a
  # real-looking /run/secrets/... path regardless of whether the ciphertext
  # exists — so an ungenerated secret would otherwise be cheerfully
  # bind-mounted from a path that just isn't there at runtime. Check the
  # repo directly instead, mirroring clan-core's own on-disk convention
  # (nixosModules/clanCore/vars/secret/age-source-path.nix):
  #   {directory}/secrets/clan-vars/{rel_dir}/{name}/{name}.age
  # The agenix setup this replaced could not express "declared but
  # ungenerated" at all (it derived its declarations FROM the files on
  # disk), so this is a genuinely new failure mode and is asserted below
  # rather than discovered at runtime.
  secretCiphertextPath =
    s:
    let
      f = config.clan.core.vars.generators.${s.generator}.files.${s.file};
    in
    config.clan.core.settings.directory + "/secrets/clan-vars/${f.rel_dir}/${f.name}/${f.name}.age";

  ungenerated = lib.filterAttrs (_g: s: !(builtins.pathExists (secretCiphertextPath s))) appSecrets;

  secretMounts = mapAttrs' (
    guest: s:
    nameValuePair "${secretsGuestDir}/${guest}" {
      hostPath = secretHostPath s;
      isReadOnly = true;
    }
  ) appSecrets;

  # JuiceFS paths: guestPath -> /mnt/jfs/<sub>  (read-write, shared)
  jfsMounts = mapAttrs' (
    guest: sub:
    nameValuePair guest {
      hostPath = "/mnt/jfs/${sub}";
      isReadOnly = false;
    }
  ) app.juicefsPaths;

  # Local state: guestPath -> host path (DB data etc., never JuiceFS)
  localMounts = mapAttrs' (
    guest: host:
    nameValuePair guest {
      hostPath = host;
      isReadOnly = false;
    }
  ) app.localState;

  bindMounts = secretMounts // jfsMounts // localMounts // app.extraBindMounts;

  # Bind-mount sources must exist before nspawn starts. tmpfiles can't order
  # after the JuiceFS service mount, so create them in ExecStartPre instead.
  bindSources =
    (map (sub: "/mnt/jfs/${sub}") (builtins.attrValues app.juicefsPaths))
    ++ builtins.attrValues app.localState;

  # The raw_exec wrapper: task-alive == container running; SIGTERM stops it
  # cleanly within kill_timeout. The node-local fencing reconciler (Phase 7)
  # handles SIGKILL/crash orphans.
  #
  # It runs as nomad-apps, not root (`User` below), so it asks systemd over D-Bus,
  # and polkit allows that account exactly `start` and `stop` of the declared
  # container@ units (modules/app-container.nix). Not `nixos-container start`: as
  # anyone but root it fails on `mkdir /var/lib/nixos-containers` [RAN, the
  # design's spike], and it is only `systemctl start` underneath. `systemctl stop`
  # waits for the stop, as before, so the stops still nest (tests/freeipa.nix).
  wrapper = pkgs.writeShellScript "run-${n}" ''
    set -euo pipefail
    systemctl=${config.systemd.package}/bin/systemctl
    cleanup() { "$systemctl" stop container@${n}.service || true; }
    trap cleanup TERM INT
    "$systemctl" start container@${n}.service
    # Block while the unit is active; exit non-zero if it fails => reschedule.
    while "$systemctl" is-active --quiet container@${n}.service; do sleep 2; done
    exit 1
  '';

  constraints =
    app.nomad.constraints
    ++ optional pinned {
      LTarget = "\${node.unique.name}";
      Operand = "=";
      RTarget = home.hostName;
    }
    ++ optional usesJfs {
      LTarget = "\${meta.jfs_ready}";
      Operand = "=";
      RTarget = "true";
    }
    ++ optional app.nomad.distinctHosts {
      Operand = "distinct_hosts";
      RTarget = "true";
    };

  count = if pinned then 1 else app.nomad.count;

  # Nomad jobspec (JSON) — submitted by nomad-bootstrap.service (Phase 7).
  job = {
    Job = {
      ID = "app-${n}";
      # The only namespace that may run raw_exec, and the only one any scoped token
      # can see (modules/nomad-acl.nix). The fence queries it by name: a job outside
      # it would be invisible to the fence, and its container fenced as an orphan.
      Namespace = appsNamespace;
      Datacenters = [ topology.datacenter ];
      Type = "service";
      TaskGroups = [
        (
          {
            Name = n;
            Count = count;
            Constraints = constraints;
            Tasks = [
              {
                Name = "activate";
                Driver = "raw_exec";
                # The one account raw_exec does not refuse (modules/cluster-common.nix).
                # Without it the task would run as the agent, root, and be refused.
                User = appsUser;
                Config.command = "${wrapper}";
                KillSignal = "SIGTERM";
                # Nomad's JSON job API takes durations in NANOSECONDS.
                KillTimeout = app.nomad.killTimeoutSeconds * 1000000000;
                Resources = {
                  CPU = app.resources.cpu;
                  MemoryMB = app.resources.memoryMB;
                };
              }
            ];
          }
          // optionalAttrs (app.service != null) {
            # Lifecycle/observability only. Nothing routes through Nomad's
            # registry any more, so no Address is registered — each container
            # carries its own connector and is reached over a unix socket.
            Services = [
              {
                Name = app.service.name;
                Provider = "nomad";
                PortLabel = toString app.service.port;
                Tags = app.service.tags;
              }
            ];
          }
          // optionalAttrs (app.nomad.max > app.nomad.min && !pinned) {
            Scaling = {
              Min = app.nomad.min;
              Max = app.nomad.max;
              Enabled = true;
            };
          }
        )
      ];
    };
  };

  # Inner networking. Uniformly dual-stack now that nothing reaches a container
  # inbound: DHCPv4 on br-app for IPv4-only destinations, plus a derived IPv6
  # GUA on the WAN segment so the bulk of egress skips the NAT hook. There is no
  # static-IPv4 variant any more — the tunnel routes to a socket path, so no
  # address has to be stable or recorded anywhere.
  wanIf = net.appWanPort n;
  # The br-app veth of an app in a peerAccess flow (design 1.12, D23). nspawn names
  # its own veth vb-<name> and shortens a long name unpredictably (`probe-longer-name`
  # became `vb-probe-lo_Dxt` [RAN]), and the host firewall must name the port a
  # declared flow arrives on. So such an app gets no nspawn bridge veth at all: an
  # extra veth instead, vp-<iid> on the host (7 characters, whatever the name) and
  # eth0 in the container, which is where the rest of this file and the kinds expect
  # the container's br-app link. In place of vb-<name>, not beside it: two links on
  # one segment, and the kernel would route the peer's traffic out of eth0 anyway.
  # modules/overlay-network.nix's 52-veth-peer, and ExecStartPost below, bridge it.
  peerIf = net.appPeerPort n;

  # The link-local address the host's bridge guard expects is the only one on the WAN
  # veth. networkd adds it and stops the kernel making its own (LinkLocalAddressing =
  # "no" below), but the veth was up in here before networkd saw it, and the kernel's
  # address from nspawn's random MAC was already there and stayed [RAN,
  # checks.container-isolation `wan-mac-pinned`]. Its packets would only be dropped at
  # the host (modules/overlay-network.nix); this removes it once networkd has
  # configured the link, so the container never sources anything from it.
  wanLinkLocal = net.appWanLinkLocal node n;
  wanLinkLocalOnly =
    { pkgs, ... }:
    {
      systemd.services.wan-link-local = {
        description = "Keep only the fixed link-local address on ${wanIf}";
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-networkd.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        path = [
          pkgs.iproute2
          pkgs.gnugrep
          pkgs.gawk
          pkgs.coreutils
        ];
        script = ''
          for _ in $(seq 120); do
            ip -6 -o addr show dev ${wanIf} scope link | grep -qF ' ${wanLinkLocal}/' && break
            sleep 0.5
          done
          for a in $(ip -6 -o addr show dev ${wanIf} scope link | awk '{print $4}'); do
            [ "$a" = "${wanLinkLocal}/64" ] || ip -6 addr del "$a" dev ${wanIf}
          done
        '';
      };
    };

  innerNetworking = {
    networking = {
      useNetworkd = true;
      useDHCP = false;
      useHostResolvConf = false;

      # The host's inet tables govern br-app, but nothing filters what reaches the
      # container on its WAN interface: that one is bridged onto the public
      # segment, and the host's bridge table (modules/overlay-network.nix) only
      # polices what the container SENDS there (its own GUA, no IPv4, not the
      # host). So the container must filter its inbound for itself. Nothing
      # inbound is wanted — cloudflared dials out — and in socket mode the app
      # binds no port at all, so this is defence in depth over a bare surface.
      firewall = {
        enable = true;
        interfaces.${wanIf} = {
          allowedTCPPorts = [ ];
          allowedUDPPorts = [ ];
        };
      };
    };

    systemd.network.enable = true;
    systemd.network.networks = {
      "10-eth0" = {
        matchConfig.Name = "eth0"; # container init renames host0 -> eth0
        networkConfig.DHCP = "ipv4";
        dhcpV4Config = {
          UseDNS = true;
          UseRoutes = true;
        };
      };
      # WAN side: static GUA, and the OVH gateway reached on-link because it sits
      # outside the /64 (the networkd equivalent of the explicit link-scope /128
      # route Debian's ifupdown needs).
      "20-${wanIf}" = {
        matchConfig.Name = wanIf;
        # The link-local address is static too, the one the host's bridge guard expects
        # (lib/net.nix appWanLinkLocal), and the kernel makes none of its own. An EUI-64
        # address from the MAC below does not work: the kernel had already made one
        # from nspawn's random MAC when networkd set this one, and kept it [RAN,
        # checks.container-isolation, `wan-mac-pinned`].
        address = [
          "${net.gua6 node n}/${toString node.publicPrefix6}"
          "${wanLinkLocal}/64"
        ];
        routes = [
          {
            Gateway = node.publicGw6;
            GatewayOnLink = true;
          }
        ];
        networkConfig = {
          DHCP = "no";
          IPv6AcceptRA = false;
          LinkLocalAddressing = "no";
        };
        # Fixed, and the only source MAC the host's bridge guard lets through from this
        # veth (lib/net.nix appWanMac). Not the host's to set: nspawn creates the veth
        # with a MAC of its own, and the container end is in here.
        linkConfig.MACAddress = net.appWanMac node n;
      };
    };
    services.resolved.enable = true;
  };

  # The guest's journal is what modules/logging.nix ships (read from the host's
  # side of the container root), so it only has to hold the last stretch: Loki
  # is the long-term store. Bounded because it lives on the host's disk, and
  # nothing else would bound it -- demo-odoo's had reached 1.4G. The burst limit
  # is raised because journald's default (10000 per 30s) drops a busy app's
  # access log exactly when it is most interesting.
  guestLogging = {
    services.journald.settings.Journal = {
      SystemMaxUse = lib.mkDefault "512M";
      RateLimitBurst = lib.mkDefault 50000;
    };
  };
in
assert lib.assertMsg (
  (app.tier == "monolith" || app.tier == "split") -> pinned
) "clusterApps.${n}: tier \"${app.tier}\" requires homeNode (its local state lives there)";
assert lib.assertMsg (app.nomad.killTimeoutSeconds >= app.stopTimeoutSeconds)
  "clusterApps.${n}: nomad.killTimeoutSeconds (${toString app.nomad.killTimeoutSeconds}) is shorter than stopTimeoutSeconds (${toString app.stopTimeoutSeconds}) — Nomad would SIGKILL the wrapper while the container is still stopping cleanly.";
assert lib.assertMsg (app.nomad.killTimeoutSeconds <= maxKillTimeoutSeconds)
  "clusterApps.${n}: nomad.killTimeoutSeconds (${toString app.nomad.killTimeoutSeconds}) exceeds the Nomad client's max_kill_timeout (${toString maxKillTimeoutSeconds}s), which would silently cap it.";
assert lib.assertMsg (app.tunnel.ingress != { } -> hasTunnel)
  "clusterApps.${n}: tunnel.ingress requires tunnel.id — a hostname declared without a tunnel would be silently unroutable (the failure mode the old host-level module shipped with).";
assert lib.assertMsg (hasTunnel -> app.tunnel.credentials != null)
  "clusterApps.${n}: tunnel.id is set but tunnel.credentials is null — the connector cannot authenticate, so the tunnel would come up dead.";
{
  # A NixOS assertion rather than a bare `assert`, deliberately: a bare assert
  # here fires whenever ANY attribute of this fragment is forced, including
  # during the evaluation `clan vars generate` performs to discover which
  # generators exist — which would deadlock (cannot generate without evaluating,
  # cannot evaluate until generated). As an assertion it blocks building the
  # system, which is the thing that actually must not happen, and leaves
  # evaluation free.
  assertions = [
    {
      assertion = ungenerated == { };
      message =
        "clusterApps.${n}: secret(s) ${lib.concatStringsSep ", " (lib.attrNames ungenerated)}"
        + " have no generated value (no ciphertext under secrets/clan-vars/), so they would be"
        + " bind-mounted from a path that does not exist and the app would start with an empty"
        + " credential."
        + " Run: clan vars generate ${node.hostName}";
    }
  ];

  # (a) dormant container on every node
  containers.${n} = {
    autoStart = false;
    # Bounds a deploy's reload as well as a start: see the option.
    timeoutStartSec = app.startTimeout;
    privateNetwork = true;
    # Private IPv4 side (DHCP from this node's br-app, masqueraded): nspawn's own
    # veth, vb-<name>, or for an app in a peerAccess flow, vp-<iid> (peerIf above).
    hostBridge = if peerPort then null else "br-app";
    # Public IPv6 side: a second veth bridged onto the WAN segment, where the
    # container takes a derived GUA so egress skips the NAT hook. Host and
    # container ends share this name, hence vw-<iid> rather than vw-<app> —
    # IFNAMSIZ is 16.
    extraVeths.${wanIf}.hostBridge = "br-wan";
    additionalCapabilities = app.additionalCapabilities;
    inherit bindMounts;
    extraFlags = [
      "--resolv-conf=off"
    ]
    # host end vp-<iid>, container end eth0. Not `extraVeths`, which names both ends
    # the same.
    ++ optional peerPort "--network-veth-extra=${peerIf}:eth0";
    config =
      { ... }:
      {
        imports = [
          app.module
          innerNetworking
          wanLinkLocalOnly
          guestLogging
          # A guest has its own nixpkgs: the host's overlays do not reach it, so
          # a pin made on the host would be ignored here.
          ../modules/nixpkgs-overlays.nix
        ]
        ++ optional hasTunnel tunnelModule;
        system.stateVersion = topology.stateVersion;
      };
  };

  # container@<name> overrides: never bounce on rebuild; gate on JuiceFS when
  # used (the jfs mount is an ExecStart service, NOT a .mount unit, so
  # RequiresMountsFor cannot gate it — explicit ordering required, R3);
  # create bind sources; enforce real resource limits on the host (R8).
  #
  # A deploy still has to REACH a running container. The containers are not
  # autoStart, so nixos-containers registers no triggers for them at all, and
  # a pull-deploy that changed an app's closure only rewrote the declared
  # SYSTEM_PATH in /etc/nixos-containers/<name>.conf: the container Nomad had
  # started kept running the closure it was started with, forever (demo-odoo's
  # tunnel unit "did not exist" after the deploy that added it). The closure
  # and the conf are reload triggers: when either changes, switch-to-
  # configuration RELOADS an active container@ — nixos-containers' ExecReload
  # runs the new closure's switch-to-configuration inside it, so only the
  # units that changed restart and the container, its network and its tunnel
  # stay up — and leaves a dormant one alone (it only compares active units).
  #
  # Not reloadIfChanged: that keys on the unit FILE, which a closure change
  # never touches (hence upstream's explicit restartTriggers for autoStart),
  # and combined with reloadTriggers it degrades them to restart triggers.
  #
  # What a reload cannot apply: bind mounts, network interfaces, capabilities
  # and host-side resource limits are fixed at nspawn start. Those need
  #   nomad job restart app-<name>
  # which is the clean stop/start through the owner of the lifecycle.
  # ...and a guest that fails to converge must not fail the NODE. Upstream's
  # ExecReload propagates the guest switch-to-configuration's exit status, so
  # one app whose guest unit fails to start fails the host's
  # switch-to-configuration too (status 4), and with it the whole pull-deploy —
  # for every other app on the node, on every ten-minute tick, behind a
  # host-level message that names nothing but the container:
  #
  #     Failed to reload container@demo-erp.service
  #     switching to system configuration … failed (status 4)
  #
  # (That was a Frappe site whose database had not been restored after a
  # reinstall: `bench migrate` cannot run against an empty database, so its
  # activation failed, forever.) A multi-tenant node cannot have one tenant's
  # application state gating every other tenant's config.
  #
  # So the reload REPORTS the guest's failure instead of inheriting it: the
  # host journal gets the guest's own failed units by name — the detail the
  # host-level message lacks — and the app is marked degraded: the marker in
  # /run, and cluster_app_deploy_degraded{app} = 1 through node_exporter's
  # textfile collector, which AppDeployDegraded alerts on. Deliberately not a
  # failing unit: switch-to-configuration counts every unit that is failed
  # when systemd settles after the switch, so one the reload started failed
  # the host after all (demo-idm, 2026-09-29). The host switch stays green,
  # because the host is fine.
  #
  # A (re)start runs the current closure, so it clears both; that is also
  # what a reboot does, through Nomad.
  #
  # Still synchronous: the reload waits for the guest switch, so a deploy
  # converges the node's apps in order and never overlaps itself.
  systemd.services."container@${n}" = {
    restartIfChanged = false;
    reloadTriggers = [
      config.containers.${n}.path
      config.environment.etc."nixos-containers/${n}.conf".source
    ];
    after = optionals usesJfs [ "jfs-health.service" ];
    requires = optionals usesJfs [ "jfs-health.service" ];
    serviceConfig = {
      ExecStartPre = [
        "${pkgs.coreutils}/bin/rm -f ${degradedMarker}"
        "${deployMetric} 0"
      ]
      ++ optional (
        bindSources != [ ]
      ) "${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArgs bindSources}";
      # nixos-containers bridges only the veths it declares. networkd's 52-veth-peer
      # bridges this one as soon as nspawn creates it; this is the backstop, as
      # nixos-containers' own postStart is for vw-<iid>, should networkd have missed it.
      ExecStartPost = optional peerPort "${pkgs.iproute2}/bin/ip link set dev ${peerIf} master br-app up";
      ExecReload = lib.mkForce reloadScript;
      TimeoutStopSec = app.stopTimeoutSeconds;
      MemoryMax = "${toString app.resources.memoryMB}M";
      CPUWeight = 100; # relative fairness; hard CPU quotas revisited in Phase 10
    };
  };

  # (b) rendered Nomad job for the bootstrap oneshot to register.
  system.build.nomadJobs.${n} = pkgs.writeText "nomad-${n}.json" (builtins.toJSON job);
}
