# modules/cluster-common.nix — base identity + SSH access + Nomad on every node.
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  clusterSite,
  ...
}:
let
  net = clusterLib.net;
  pki = clusterLib.nomadPki;
  vars = config.clan.core.vars.generators;
  cliTls = pki.cliTlsFor vars;

  # A vars file's ciphertext in the site's repository, by clan's age layout
  # (clan-core nixosModules/clanCore/vars/secret/age-source-path.nix). Its hash changes
  # when the file is regenerated, and nothing else about the unit does.
  ciphertextHash =
    gen: file:
    let
      f = vars.${gen}.files.${file};
      p = config.clan.core.settings.directory + "/secrets/clan-vars/${f.rel_dir}/${f.name}/${f.name}.age";
    in
    lib.optional (builtins.pathExists p) (builtins.hashFile "sha256" p);

  # Human operators' SSH keys (mkCluster's `admins`). Deploys land as root, so
  # root MUST carry these or every `nixos-rebuild switch` locks you out.
  adminKeys = clusterSite.admins;

  isServer = net.hasTag "nomad-server" node;
  serverIps = map (n: n.controlIp) (net.taggedNodes topology "nomad-server");

  inherit (clusterLib.nomad) appsUser appsUid rawExecDeniedUids;
in
{
  # Every node, host and containers alike: no core dump is ever written.
  imports = [ ./coredumps-off.nix ];

  networking.hostName = node.hostName;

  systemd.settings.Manager = import ../lib/watchdog-settings.nix;

  # Refuse to build a login-less (lockout) system.
  assertions = [
    {
      assertion = adminKeys != [ ];
      message =
        "cluster-common: mkCluster's `admins` is empty — deploying would lock you "
        + "out of every node. Add your SSH public key there.";
    }
    # The bootstrap_expect trap (design Appendix G, `trap-two-expect-1-diverge` in
    # tests/voter-growth.nix): a fresh server whose expect is lower than the voters it
    # can see elects itself and accepts a second `acl bootstrap`, which is two clusters
    # on one gossip key, each with its own management token. bootstrap_expect comes
    # from the topology's voter count, the same on every node, so one topology cannot
    # produce that; this keeps a host file from producing it either. Raising a voter
    # count later is safe: a server with raft state ignores expect.
    {
      assertion =
        let
          s = config.services.nomad.settings.server or { };
        in
        (s.enabled or false) == isServer
        && (isServer -> (s.bootstrap_expect or null) == net.serverCount topology);
      message =
        let
          s = config.services.nomad.settings.server or { };
        in
        "cluster-common: ${nodeName}'s Nomad server block must be the topology's: a server "
        + "exactly when tagged nomad-server, with bootstrap_expect = the voter count "
        + "(${toString (net.serverCount topology)}). It has enabled = ${
          builtins.toJSON (s.enabled or false)
        }, bootstrap_expect = ${builtins.toJSON (s.bootstrap_expect or null)}. "
        + "A new server expecting fewer voters than exist elects itself: two clusters.";
    }
  ];

  users.users = {
    root.openssh.authorizedKeys.keys = adminKeys;
    admin = {
      isNormalUser = true;
      extraGroups = [ "wheel" ];
      openssh.authorizedKeys.keys = adminKeys;
    };
  };
  security.sudo.wheelNeedsPassword = false;

  # ── What a raw_exec task is ─────────────────────────────────────────────────
  # Every app's task runs as this account (lib/mk-app-container.nix), and raw_exec
  # refuses every other uid up to 65535 (denied_host_uids below). So a stolen
  # submit-job token runs code as uid 4096 on every node, and that is all it gets:
  #   - no network: the ruleset's output chain rejects this uid outright, loopback
  #     included (modules/overlay-network.nix);
  #   - no root: polkit lets it start and stop declared container@ units and nothing
  #     else (modules/app-container.nix);
  #   - no data: the directories below, and /mnt/jfs (modules/storage-juicefs.nix).
  # A system account, no shell, no home. modules/boot-security.nix refuses any other
  # account at this uid, and any at all above 65535.
  users.users.${appsUser} = {
    isSystemUser = true;
    uid = appsUid;
    group = appsUser;
    description = "raw_exec tasks (start and stop declared containers, nothing else)";
  };
  users.groups.${appsUser}.gid = appsUid;

  # Client state stays out of the task's reach. Nomad runs its tasks with
  # supplementary gid 0 as well as their own (a Nomad bug: `groups=4096(nomad-apps),
  # 0(root)` [RAN, the design's spike]), so a root-group-readable mode would not be
  # enough: the "other" and "group" bits both have to exclude it.
  #
  # Group systemd-journal, mode 0750, for both: Vector (a DynamicUser holding
  # systemd-journal, modules/logging.nix) must still traverse them to the journals
  # it ships: every container's under /var/lib/nixos-containers/<app>/var/log/journal,
  # and an app's declared journalDirs, which FreeIPA keeps under /state/clients
  # (modules/kinds/freeipa.nix). 0700 root on /state/clients would have silenced
  # FreeIPA's logs. Neither group includes nomad-apps or root's group.
  #
  # Containers are unaffected: nspawn binds each source in as root, and inside the
  # container the bound directory is reached through its own mount, not these.
  # Settings, not rules, so a mutant (state-clients-0755) can change one mode.
  systemd.tmpfiles.settings."10-cluster-client-state" = {
    "/state/clients".d = {
      mode = "0750";
      user = "root";
      group = "systemd-journal";
    };
    "/var/lib/nixos-containers".d = {
      mode = "0750";
      user = "root";
      group = "systemd-journal";
    };
  };

  system.stateVersion = topology.stateVersion;

  nix.settings.experimental-features = [
    "nix-command"
    "flakes"
  ];

  # Nomad + nomad-autoscaler are BSL-licensed (unfree).
  nixpkgs.config.allowUnfree = true;

  # REQUIRED, not convenience: nix shells out to `git` to fetch `git+https://`
  # flake inputs, and app files can pull a project flake (a Frappe bench, an Odoo
  # project) that way (with submodules). Without it every evaluation on the node dies with
  #   error: executing "git": No such file or directory
  # which fails the pull loop and therefore every deploy.
  #
  # It used to arrive via clan's `enableRecommendedDefaults` bundle, which is
  # off here because the same bundle injects networkd units this host cannot
  # tolerate (see flake.nix). Re-added explicitly so the dependency is visible
  # rather than inherited.
  environment.systemPackages = with pkgs; [
    git
    # The rest of what enableRecommendedDefaults used to provide: basic
    # reachability debugging on a box whose only inbound port is SSH.
    dnsutils
    curl
    jq
  ];

  networking.useNetworkd = true;
  networking.useDHCP = false;

  # systemd-networkd-wait-online waits for EVERY managed link to be online, and
  # on this host two of them never will be:
  #   br-app  — no carrier until a container attaches, which is the normal
  #             resting state of a node with nothing scheduled on it
  #   the OVH BMC/USB NIC — degraded, permanently "configuring"
  # so it burned its full 120s timeout and then failed activation, which is what
  # made `switch-to-configuration` exit non-zero even though the switch worked.
  #
  # Scoped rather than disabled: "online" here means the WAN bridge is up, which
  # is what units ordered after network-online.target actually need. Disabling it
  # outright (what clan's recommended defaults do) would make
  # network-online.target fire immediately and let the pull loop race the network.
  systemd.network.wait-online = {
    enable = true;
    extraArgs = [ "--interface=br-wan" ];
  };

  # So `nomad ...` works from a root shell. Without it every interactive command
  # tries 127.0.0.1:4646 and gets "connection refused", which is exactly the
  # confusion that hid the bind-address bug for so long. The certificate variables
  # are what lets it through `verify_https_client`; the key is root's only.
  #
  # NOMAD_NAMESPACE: every app's job is in `apps` (modules/nomad-acl.nix), and
  # `default` runs nothing, so a bare `nomad job status` should look there. The
  # operator brings a token (avc reads the `avc` role's, /run/nomad-tokens/avc).
  environment.variables = {
    NOMAD_ADDR = net.nomadAddr node;
    NOMAD_NAMESPACE = clusterLib.nomad.appsNamespace;
  }
  // cliTls.env;

  # nixos-container tooling is in /run/current-system/sw/bin on every node.
  boot.enableContainers = true;

  # mosh: roams across IP changes and survives dropped links. It bootstraps
  # over SSH, then talks UDP 60000-61000 (rule in modules/overlay-network.nix).
  programs.mosh.enable = true;

  services.openssh = {
    enable = true;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "prohibit-password"; # key-based root (deploys land as root)
    };
  };

  # ── Nomad: converged server + client on all nodes ───────────────────────────
  # SIGHUP makes Nomad reload its certificate and key [RAN, the design's spike;
  # `sighup-rotates-cert` in tests/control-plane-attack.nix], and the nixpkgs unit's
  # ExecReload sends it. The unit file doesn't change when only a vars file does,
  # so without these a reissued certificate would wait for the next restart.
  #
  # And it binds the control VLAN address alone (bind_addr below), which can arrive
  # after network-online.target: lib/net.nix controlBoundUnit waits for it and takes
  # away the start limit, so a late VLAN delays Nomad instead of leaving it failed.
  systemd.services.nomad = net.controlBoundUnit // {
    reloadTriggers =
      ciphertextHash "nomad-tls" "agent.crt"
      ++ ciphertextHash "nomad-tls" "agent.key"
      ++ ciphertextHash "nomad-ca" "ca.crt";
  };

  services.nomad = {
    enable = true;
    # Serf's encryption key, servers only (modules/vars.nix declares it nowhere
    # else). A file Nomad reads at start, so the key stays out of /etc/nomad.json,
    # which is in the world-readable store. Clients don't gossip.
    extraSettingsPaths = lib.optional isServer vars.nomad-gossip.files."gossip.hcl".path;
    # The agent stays root: it creates task directories, switches each task to its
    # account, and renders templates. The task itself is nomad-apps (below).
    dropPrivileges = false;
    enableDocker = false;

    settings = {
      datacenter = topology.datacenter;
      # Named in every certificate (lib/nomad-pki.nix): changing it reissues them all.
      region = pki.region;
      # Bind cluster traffic to the control VLAN.
      bind_addr = node.controlIp;
      advertise = {
        http = "${node.controlIp}:${toString net.nomadHttpPort}";
        rpc = "${node.controlIp}:${toString net.nomadServerPort}";
        serf = "${node.controlIp}:4648";
      };

      # A server only where topology says so. This used to be `true` on every
      # node, with bootstrap_expect = <voter count>, so a worker-only node
      # (node2/node3 as tagged today) would have elected ITSELF leader of a
      # one-server cluster the moment it booted, and never joined the real one.
      server = lib.optionalAttrs isServer {
        enabled = true;
        bootstrap_expect = net.serverCount topology;
        # Spread, not Nomad's default of packing the fullest node first: the nodes are
        # a fixed fleet that is paid for whether used or not, so an app goes to the
        # emptiest one that can run it. Read when the cluster is first bootstrapped
        # only; on one that exists, `nomad operator scheduler set-config
        # -scheduler-algorithm=spread` (README, "Upgrading a running cluster").
        default_scheduler_config.scheduler_algorithm = "spread";
        # Without a join list the voters never find each other: each waits
        # for bootstrap_expect peers forever ("No cluster leader"). Invisible
        # with one voter, which bootstraps alone; tests/cluster.nix boots
        # three. Serf's port (4648) is the default here.
        server_join.retry_join = serverIps;
      };

      client = {
        enabled = true;
        # The client's half: RPC (4647, the default) on every server, so a
        # worker-only node finds the cluster too.
        server_join.retry_join = serverIps;
        # Placement metadata (jfs_ready flipped to "true" by jfs-health, Phase 4).
        meta = {
          role = node.roleTag;
          jfs_ready = "false";
        };
        # Nomad caps every task's kill_timeout at this, silently; its default
        # of 30s cut short the stop of every app (lib/nomad.nix).
        max_kill_timeout = "${toString clusterLib.nomad.maxKillTimeoutSeconds}s";

        # raw_exec only. Namespace capabilities refuse other drivers at submit
        # (modules/nomad-acl.nix); this keeps them from being loaded at all, so a
        # namespace edited by a management token still cannot reach exec or docker.
        options."driver.allowlist" = "raw_exec";

        # The cloud fingerprinters ask a metadata service at 169.254.169.254 that
        # these hosts don't have, one after another with a 2 s timeout each, so
        # every agent start sat 8 s in them before its client came up [RAN: 8.0 to
        # 8.5 s on every start in tests/voter-growth.nix]. That is 8 s without a
        # heartbeat on every Nomad restart, where the servers mark a node down as
        # little as 10 s after its last heartbeat was due (heartbeat_grace). A
        # worker promoted to a voter spends it on top of its new server's join, and
        # the leader marked it down and moved its allocation (`worker-promoted-to-
        # voter`, voter-growth order B). Nothing places on `platform.*` attributes.
        options."fingerprint.denylist" = lib.concatStringsSep "," [
          "env_aws"
          "env_azure"
          "env_digitalocean"
          "env_gce"
        ];

        # Nomad's defaults, stated because the lockdown depends on them: templates are
        # rendered by the agent, as root, so they must not read outside the task's
        # directory (`template-outside-sandbox`), and must not run commands.
        template = {
          disable_file_sandbox = false;
          function_denylist = [
            "plugin"
            "writeToFile"
          ];
        };
      };

      # ACLs on from day one. Nomad accepts an OPERATOR-SUPPLIED bootstrap
      # token, so `nomad-acl` in modules/vars.nix mints one up front and
      # nomad-acl-init (modules/nomad-acl.nix) hands it to the raft — rather than
      # the reverse, which would mean nothing could be provisioned until a
      # human had already stood the cluster up by hand.
      acl.enabled = true;

      # raw_exec driver (NOT exec — exec's chroot/cgroup isolation breaks
      # nixos-container start). Locked down by the apps namespace and scoped tokens
      # (modules/nomad-acl.nix), and here by account: every uid up to 65535 is
      # refused except nomad-apps', so a task with no `user` (root, the agent's own),
      # `root`, an admin or `nobody` is refused before it starts (`raw-exec-*-denied`
      # in tests/control-plane-attack.nix). The gap above 65535: see lib/nomad.nix.
      #
      # NEVER set denied_host_gids: any list containing 0 denies every user, because
      # Nomad builds the task's group list with make([]T, n) and then appends, so it
      # always holds zeros [RAN, the design's spike; READ validators_unix.go].
      plugin.raw_exec.config = {
        enabled = true;
        denied_host_uids = rawExecDeniedUids;
      };

      # /v1/metrics in Prometheus form, on EVERY node: the metrics node's Prometheus
      # scrapes them all (modules/monitoring-server.nix). This used to be set only
      # there, so every other node answered the scrape with an error and its
      # `up{job="nomad"}` was 0, unnoticed until tests/cluster.nix asked.
      telemetry = {
        prometheus_metrics = true;
        publish_allocation_metrics = true;
        publish_node_metrics = true;
      };

      # mTLS on HTTP and RPC. The agent serves and presents its own machine's
      # certificate, and checks the peer's against the cluster CA.
      #
      #   verify_server_hostname  a peer on the server RPC must hold
      #                           server.global.nomad, which only servers' vars carry.
      #                           Without it any CA-signed certificate, a stolen
      #                           worker's included, could join raft as a voter
      #                           (mutant nomad-no-verify-hostname).
      #   verify_https_client     the HTTP API wants a certificate too, before any
      #                           token is looked at. So an attacker on the VLAN gets
      #                           a failed handshake, not an anonymous policy.
      #
      # The gossip key is the other half (extraSettingsPaths above): without it, a
      # machine on the VLAN with no credentials at all is still let into serf.
      tls = {
        http = true;
        rpc = true;
        ca_file = vars.nomad-ca.files."ca.crt".path;
        cert_file = vars.nomad-tls.files."agent.crt".path;
        key_file = vars.nomad-tls.files."agent.key".path;
        verify_server_hostname = true;
        verify_https_client = true;
      };
    };
  };
}
