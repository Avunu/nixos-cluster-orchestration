# modules/app-container.nix — declares the `clusterApps.<name>` option schema
# and fans each entry out into a dormant container + Nomad job via the
# lib/mk-app-container.nix generator. Populated from apps/ (modules/apps.nix),
# with the per-kind namespaces of modules/kinds/.
{
  config,
  lib,
  pkgs,
  topology,
  clusterLib,
  node,
  ...
}:
let
  inherit (lib)
    mkOption
    types
    mkMerge
    mapAttrsToList
    ;

  serviceType = types.submodule (
    { name, ... }:
    {
      options = {
        port = mkOption {
          type = types.port;
          description = "Port the app listens on inside the container.";
        };
        name = mkOption {
          type = types.str;
          default = name;
          description = "Nomad service name (lifecycle/observability only).";
        };
        check = mkOption {
          type = types.nullOr types.attrs;
          default = null;
          description = "Nomad service health check block.";
        };
        tags = mkOption {
          type = types.listOf types.str;
          default = [ ];
        };
      };
    }
  );

  nomadType = types.submodule {
    options = {
      count = mkOption {
        type = types.int;
        default = 1;
      };
      min = mkOption {
        type = types.int;
        default = 1;
      };
      max = mkOption {
        type = types.int;
        default = 1;
      };
      distinctHosts = mkOption {
        type = types.bool;
        default = false;
      };
      spread = mkOption {
        type = types.nullOr types.str;
        default = null;
      };
      constraints = mkOption {
        type = types.listOf types.attrs;
        default = [ ];
      };
      killTimeoutSeconds = mkOption {
        type = types.int;
        default = 90;
        description = ''
          Grace period for the SIGTERM->clean container stop path. At least
          stopTimeoutSeconds, and at most the Nomad client's max_kill_timeout
          (modules/cluster-common.nix), which silently caps it.
        '';
      };
      scalingChecks = mkOption {
        type = types.listOf types.attrs;
        default = [ ];
      };
    };
  };

  resourcesType = types.submodule {
    options = {
      cpu = mkOption {
        type = types.int;
        default = 500;
        description = "Nomad CPU shares (MHz) — mirror the container's real reservation (R8).";
      };
      memoryMB = mkOption {
        type = types.int;
        default = 512;
        description = "Memory ceiling (MiB) — also enforced as container@X MemoryMax (R8).";
      };
    };
  };

  # A reference to one file of one clan vars generator. Secrets are named by
  # (generator, file) rather than by a flat name because that is how clan
  # addresses them, and it keeps a client's whole secret set in one generator
  # that can be regenerated or deleted as a unit.
  secretRefType = types.submodule {
    options = {
      generator = mkOption {
        type = types.str;
        description = "clan.core.vars.generators.<name>";
      };
      file = mkOption {
        type = types.str;
        description = "…files.<name> within that generator.";
      };
    };
  };

  # Per-app Cloudflare Tunnel, run INSIDE the container next to the app and
  # reaching it over a unix socket. The unit of tunnel identity is the site, not
  # the container: Cloudflare requires every connector on a tunnel to serve
  # identical routes and steers to the closest one, so two different sites
  # sharing a tunnel would silently serve each other's traffic. Two containers
  # of the SAME app may share one — that is the replica model working correctly.
  tunnelType = types.submodule {
    options = {
      id = mkOption {
        type = types.str;
        default = "";
        example = "00000000-0000-4000-8000-000000000010";
        description = ''
          Tunnel UUID (`cloudflared tunnel create <site>`). Empty = no tunnel
          for this app. Each hostname needs its own CNAME to
          `<id>.cfargotunnel.com`; a wildcard cannot work with per-site tunnels.
        '';
      };
      credentials = mkOption {
        type = types.nullOr secretRefType;
        default = null;
        example = {
          generator = "wp-acme";
          file = "cloudflared";
        };
        description = ''
          clan vars file holding the tunnel credentials JSON; defaults to
          <name>-cf/cloudflared once `id` is set. Added to the
          app's `secrets` automatically as `cloudflared`, so it is
          bind-mounted read-only at /run/secrets/cloudflared inside the
          container. systemd reads it via LoadCredential as root before
          dropping to the unit's DynamicUser, so the default root:root 0400
          is correct.

          Required whenever `ingress` is non-empty — a connector cannot
          authenticate without it.
        '';
      };
      ingress = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          "acme.example.com" = "unix:/run/wordpress/wp.sock";
        };
        description = ''
          hostname -> cloudflared service. Prefer `unix:<path>` so the app
          needs no listening port and therefore no inbound reachability; a
          path is correct on every node under any scheduling decision.
        '';
      };
      accessProtected = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "acme-admin.example.com" ];
        description = ''
          Hostnames of `ingress` that sit behind Cloudflare Access. The edge
          answers for them with a redirect to the Access login, so an
          anonymous probe from outside proves only that Cloudflare is up;
          alerting (modules/alerting.nix) leaves them out of its app probes.
        '';
      };
      default = mkOption {
        type = types.str;
        default = "http_status:404";
        description = "Catch-all for hostnames not matched above.";
      };
      socketGroups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "wordpress" ];
        description = ''
          Supplementary groups for the connector unit. cloudflared runs under
          DynamicUser, so it needs the group owning the app's socket directory
          (the directory is the access gate — the socket file itself is
          permissive by design in every server we front).
        '';
      };
    };
  };

  appType = types.submodule (
    { name, config, ... }:
    {
      # A tunnel's credentials are <name>-cf/cloudflared unless the app names
      # its own; modules/apps.nix declares that prompted generator.
      config.tunnel.credentials = lib.mkIf (config.tunnel.id != "") (
        lib.mkDefault {
          generator = "${name}-cf";
          file = "cloudflared";
        }
      );

      options = {
        name = mkOption {
          type = types.str;
          default = name;
        };
        tunnel = mkOption {
          type = tunnelType;
          default = { };
          description = "Per-site Cloudflare Tunnel run inside this container.";
        };
        module = mkOption {
          type = types.deferredModule;
          description = "Inner NixOS module (from the user's wordpress-nix/frappe-nix/odoo-nix flake).";
        };
        secrets = mkOption {
          type = types.attrsOf secretRefType;
          default = { };
          example = {
            db-password = {
              generator = "demo-erp";
              file = "db-password";
            };
          };
          description = ''
            Secrets this container needs: guest name -> clan vars file. Each is
            bind-mounted read-only at /run/secrets/<guest name> inside the
            container, decrypted on the HOST by clan's age vars backend at
            activation.

            The container itself never holds a key and never runs clan.
          '';
        };
        juicefsPaths = mkOption {
          type = types.attrsOf types.str;
          default = { };
          description = "guestPath -> subpath under /mnt/jfs.";
        };
        localState = mkOption {
          type = types.attrsOf types.str;
          default = { };
          description = ''
            guestPath -> host path on LOCAL disk (DB data, never JuiceFS).
            Ties the stack to its homeNode; dirs are created before start.
          '';
        };
        homeNode = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = ''
            Topology node key (e.g. "node1") this stack is pinned to. Required
            for monolith/split tiers (their localState lives on that node).
            Renders a Nomad constraint on the node's hostname.
          '';
        };
        # `address` is gone: with the connector inside the container reaching the
        # app over a unix socket, nothing needs to reach a container inbound, so
        # no address has to be stable or recorded. IPv4 comes from br-app's DHCP
        # server and IPv6 is derived from the node's /64 (lib/net.nix gua6).
        extraBindMounts = mkOption {
          type = types.attrsOf types.anything;
          default = { };
        };
        additionalCapabilities = mkOption {
          type = types.listOf types.str;
          default = [ ];
        };
        startTimeout = mkOption {
          type = types.str;
          default = "30min";
          example = "1h";
          description = ''
            How long container@<name> may take to converge: both a cold start
            (nspawn waits for the guest's systemd to report ready, which is after
            the guest's services started) and a deploy's reload (the guest's
            switch-to-configuration). systemd times ExecReload with
            TimeoutStartSec too.

            nixos-containers' default is 1min, which an application that migrates
            its database on start cannot meet: demo-odoo's first migration after
            onboarding updates ~200 Odoo modules in about a minute and a half,
            and a killed reload is a failed deploy.
          '';
        };
        stopTimeoutSeconds = mkOption {
          type = types.ints.positive;
          default = 90;
          example = 300;
          description = ''
            How long container@<name> may take to stop cleanly before systemd
            kills what is left (TimeoutStopSec). Raise it for an app whose
            database needs longer than 90 s to shut down: a directory server
            killed mid-shutdown replays its logs on the next start, at best.

            nomad.killTimeoutSeconds must be at least this long -- Nomad's
            SIGTERM starts the stop, and its SIGKILL must not overtake it.
          '';
        };
        service = mkOption {
          type = types.nullOr serviceType;
          default = null;
        };
        nomad = mkOption {
          type = nomadType;
          default = { };
        };
        resources = mkOption {
          type = resourcesType;
          default = { };
        };
        tier = mkOption {
          type = types.enum [
            "monolith"
            "split"
            "replica"
            "scale"
          ];
          default = "replica";
          description = "Per-client escalation tier (see plan). Default = replica (Tier 2).";
        };
        ha = mkOption {
          type = types.bool;
          default = true;
          description = "Provision a streaming replica + auto-failover for this client's DB.";
        };
        logging = {
          journalDirs = mkOption {
            type = types.listOf types.str;
            default = [ ];
            example = [ "/state/clients/idm/ipa/var/log/journal" ];
            description = ''
              HOST paths of journals this app writes besides its container's
              own, shipped to Loki as this app's (modules/logging.nix). For a
              process with its own journald -- systemd inside a podman image.
              The container's journal is always shipped; do not list it.
            '';
          };
          journalGroups = mkOption {
            type = types.listOf types.str;
            default = [ ];
            example = [ "190" ];
            description = ''
              Groups (names or numeric GIDs) that own those journals, added
              to the log shipper's. A foreign journald writes its files 0640 to
              ITS systemd-journal group, which need not be ours.
            '';
          };
        };
        backup = mkOption {
          type = import ../lib/app-backup-type.nix { inherit lib; };
          default = { };
          description = "How modules/backup.nix backs this app up. Detected; override when detection is wrong.";
        };
        preview = {
          slots = mkOption {
            type = types.ints.unsigned;
            default = 0;
            example = 2;
            description = ''
              How many branches of this app's project can have a preview at once
              (modules/ci-agent.nix). Each slot is a container of its own,
              `<name>-pv<k>`, declared like any other and dormant until a pull
              request takes it: the same kind, mounts, limits and firewall, on a copy
              of this app's database and files. 0 = no previews.
            '';
          };
          input = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "my-odoo-project";
            description = "The site flake's input this app's package comes from: what a preview builds at the pull request's commit.";
          };
          repo = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "OWNER/my-odoo-project";
            description = "That input's GitHub repository, whose pull requests get previews.";
          };
          inputUrl = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "git+https://github.com/OWNER/my-odoo-project.git?ref={ref}&rev={rev}&submodules=1";
            description = ''
              The flake reference a preview overrides `input` with, where `{rev}` is the
              commit and `{ref}` the branch. null = `github:<repo>/{rev}`. Set it when
              the input is not a plain `github:` one (submodules, say), in the same
              form as in flake.nix.
            '';
          };
          healthPath = mkOption {
            type = types.str;
            default = "/";
            description = "What is asked of a preview through its hostname before it is called live. Anything but a 5xx passes.";
          };
          of = mkOption {
            type = types.nullOr types.str;
            default = null;
            internal = true;
            description = "On a slot: the app it previews. Set by modules/apps.nix, never by hand.";
          };
          origin = mkOption {
            type = types.nullOr types.str;
            default = null;
            internal = true;
            description = "Where the app answers inside its container, as a cloudflared service. Set by the kind; a kind that sets none cannot be previewed.";
          };
          socketGroups = mkOption {
            type = types.listOf types.str;
            default = [ ];
            internal = true;
            description = "Groups a slot's connector needs to reach `origin`. Set by the kind.";
          };
          # What a kind names its data by. A slot's is the app's own name, because the
          # copy holds the app's database, under its own directory on its own volume.
          base = mkOption {
            type = types.str;
            readOnly = true;
            internal = true;
            default = if config.preview.of != null then config.preview.of else name;
          };
          stateRoot = mkOption {
            type = types.str;
            readOnly = true;
            internal = true;
            default = if config.preview.of != null then "/state-preview/${name}" else "/state";
          };
          jfsRoot = mkOption {
            type = types.str;
            readOnly = true;
            internal = true;
            default = if config.preview.of != null then "previews/${name}" else "clients/${name}";
          };
        };
        network = mkOption {
          type = import ../lib/app-network-type.nix { inherit lib; };
          default = { };
          description = ''
            What this container may reach besides the internet and its node's DHCP
            and DNS. Container to host and container to container are default-deny
            (modules/overlay-network.nix); see lib/app-network-type.nix.
          '';
        };
      };
    }
  );

  net = clusterLib.net;
  # Each app's `network`, which is all the host firewall reads.
  appNetworks = lib.mapAttrs (_: a: a.network) config.clusterApps;
  peerApps = net.peerAppNames appNetworks;
  hostAccessApps = lib.filterAttrs (_: a: a.network.hostAccess != [ ]) config.clusterApps;
in
{
  imports = [ ./app-network-option.nix ];

  options.clusterApps = mkOption {
    type = types.attrsOf appType;
    default = { };
    description = "Per-client application stacks; each generates a dormant container + Nomad job.";
  };

  # The apps Nomad runs: every one but the preview slots, which the pipeline's agent
  # starts and stops (modules/ci-agent.nix). A slot is a job nowhere, so whatever
  # registers jobs, fences containers without an allocation, backs up or probes reads
  # this and not clusterApps.
  options.cluster.nomadApps = mkOption {
    type = types.attrsOf types.raw;
    readOnly = true;
    internal = true;
    default = lib.filterAttrs (_: a: a.preview.of == null) config.clusterApps;
  };

  # Keep `config`'s TOP-LEVEL keys static (containers / systemd / system) so the
  # module system can resolve "does this module define clusterApps?" WITHOUT
  # forcing config.clusterApps — otherwise the unmatched-definitions / freeform
  # check recurses (attr-names depending on the very option being merged).
  config =
    let
      frags = mapAttrsToList (
        _n: app:
        clusterLib.mkAppContainer {
          inherit
            app
            config
            pkgs
            topology
            node
            ;
          # Its br-app veth is vp-<iid>, named here, rather than nspawn's vb-<name>.
          peerPort = builtins.elem app.name peerApps;
        }
      ) config.clusterApps;
    in
    {
      # Derived container GUAs must not collide or land on a reserved identifier;
      # checked at eval time rather than trusted to a 16-bit hash. Plus each
      # app's own assertions (currently: every referenced secret is generated).
      assertions =
        clusterLib.net.guaAssertions (lib.attrNames config.clusterApps)
        ++ lib.concatMap (f: f.assertions or [ ]) frags
        # hostAccess (design 1.12): the identity is nspawn's vb-<name>, exact only up
        # to 12 characters; and only the metrics node's own containers have a path to
        # its mesh address, so the app must be pinned there.
        ++ lib.concatLists (
          lib.mapAttrsToList (n: a: [
            {
              assertion = lib.stringLength n <= 12;
              message =
                "clusterApps.${n}: network.hostAccess needs a name of at most 12 characters"
                + " (this one has ${toString (lib.stringLength n)}). The host firewall names the"
                + " container by its veth, vb-<name>, and nspawn shortens a longer one"
                + " unpredictably, so the rule would never match. Rename the app.";
            }
            {
              assertion = a.homeNode != null && net.hasTag "metrics" (topology.nodes.${a.homeNode} or { });
              message =
                "clusterApps.${n}: network.hostAccess reaches the metrics node's mesh address,"
                + " which only a container on that node can route to. Pin it there: homeNode"
                + " must be a node tagged `metrics` (it is ${
                   if a.homeNode == null then "unset" else "\"${a.homeNode}\""
                 }).";
            }
          ]) hostAccessApps
        );

      # The host firewall (modules/overlay-network.nix) reads this, and nothing else
      # of the apps.
      cluster.appFirewall.apps = appNetworks;

      containers = mkMerge (map (f: f.containers or { }) frags);
      systemd.services = mkMerge (map (f: f.systemd.services or { }) frags);
      # `system.build` is a lazyAttrsOf raw, so `nomadJobs` is an opaque leaf:
      # mkMerge of per-app { <name> = drv; } attrsets would push down as multiple
      # conflicting definitions rather than deep-merge (unlike containers /
      # systemd.services, which are attrsOf). Union them into ONE definition.
      system.build.nomadJobs = lib.foldl' (acc: f: acc // (f.system.build.nomadJobs or { })) { } frags;

      # What a raw_exec task (nomad-apps, lib/mk-app-container.nix) may ask of
      # systemd: start and stop a container@ unit this host declares, and nothing
      # else. Not restart or reload (a restart is a stop and a start, which is what
      # `nomad job restart` does through the wrapper), not another unit, not an
      # undeclared container@ instance (`container@evil` would load from the
      # template). No other rule names this account, so everything else it asks is
      # polkit's default: refused, since no agent can ever answer for it.
      # `polkit-scope` in tests/control-plane-attack.nix.
      security.polkit = {
        enable = true;
        extraConfig = ''
          // nomad-apps: start and stop of declared containers only (modules/app-container.nix).
          polkit.addRule(function(action, subject) {
            if (action.id == "org.freedesktop.systemd1.manage-units"
                && subject.user == ${builtins.toJSON clusterLib.nomad.appsUser}) {
              var units = ${
                builtins.toJSON (map (n: "container@${n}.service") (lib.attrNames config.cluster.nomadApps))
              };
              var unit = action.lookup("unit");
              var verb = action.lookup("verb");
              if (units.indexOf(unit) >= 0 && (verb == "start" || verb == "stop")) {
                return polkit.Result.YES;
              }
            }
          });
        '';
      };
    };
}
