# modules/kinds/freeipa.nix — clusterApps.<name>.freeipa: a FreeIPA server.
#
#   freeipa = { hostname; domain; realm; privateIp4; image; authelia; };
#
# With the generic tunnel.id and resources beside it, as any app. The app is one
# container, on whichever node Nomad picks, with its state following it
# (modules/app-state.nix). It runs the
# upstream FreeIPA server image under podman -- NixOS has an IPA client module
# but no server. The design follows an earlier standalone deployment, which
# proved it works inside nspawn, minus what went wrong there:
#
#   - The image TRACKS its tag (quay.io/freeipa/freeipa-server:almalinux-10 by
#     default): no hash to recompute, nothing baked into the closure. Set
#     image.digest and image.hash to pin one build instead (baked in, pull =
#     "never") if tracking ever proves a problem.
#   - podman-freeipa is never restarted by a deploy (restartIfChanged =
#     false). Restarting the image IS the upgrade -- ipa-server-upgrade runs on
#     start -- and conmon reports the unit ready before that finishes, so a
#     deploy would neither wait for it nor notice it fail. Upgrades go through
#     `cluster-freeipa-upgrade <app>` instead: pull, hold, export, ZFS
#     snapshot, keep the running image as :previous, restart, wait for a clean
#     healthcheck. A timer runs it nightly with --if-needed (image.autoUpgrade),
#     which does nothing unless a newer build was published or a deploy changed
#     the unit (cluster_freeipa_restart_pending = 1).
#   - Stops are long enough for 389-ds to shut down cleanly: podman 180s
#     inside a unit allowing 200s, inside a container@ allowing 300s, inside a
#     Nomad kill timeout of 330s.
#   - The directory modes dbus-broker (uid 81) and dirsrv need to traverse
#     /data are enforced on every start, not just created once.
#   - Backups are ipa-backup --data --online (an LDIF export, taken live) plus
#     the whole state directory from a ZFS snapshot (backup.localSnapshot), so
#     a restore has the CA and Kerberos master keys too. The weekly rehearsal
#     checks the restored tree.
#   - No Let's Encrypt certificate: httpd keeps IPA's own, which every
#     enrolled client trusts. The web UI is published through the app's tunnel
#     (noTLSVerify towards 127.0.0.1), where browsers see Cloudflare's edge
#     certificate; mounting an LE certificate into httpd is what broke the
#     `ipa` CLI and the web UI in the reference.
#
# ── how clients reach Kerberos and LDAP ─────────────────────────────────────
# Not over the internet: nothing reaches a container inbound (README
# "Ingress"). The server's address is a private one, privateIp4 from
# topology.privateServices, on a dummy interface inside the container.
# Cloudflare routes it to the app's tunnel (WARP private network):
#   cloudflared tunnel route ip add <privateIp4>/32 <tunnel id>
# cloudflared then connects to it from inside the container -- over lo -- so
# the container's firewall opens nothing. WARP clients resolve the hostname to
# privateIp4 through a Gateway DNS override; everyone else resolves the public
# tunnel CNAME and gets the web UI only.
#
# ── first start ─────────────────────────────────────────────────────────────
# ipa-server-install runs unattended from the install options below and takes
# about five minutes; the image then exits 123 and the unit restarts it into
# the installed server. Watch it with
#   nixos-container run <app> -- journalctl -fu podman-freeipa
# The admin password is <app>/password (clan vars get <node> <app>/password);
# it is read at install only, so a password changed in IPA afterwards is not
# reflected there.
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

  hostApps = config.clusterApps;

  # Every FreeIPA app, seen as the flat instance the functions below take:
  # its freeipa namespace plus the generic fields they need, and its
  # Authelia's clients -- its own plus every app that signs in through it
  # (clusterApps.<app>.oidc.idp = <this app>), whose client id is that app's
  # name.
  instances = lib.mapAttrs instanceOf (lib.filterAttrs (_: a: a.freeipa != null) hostApps);
  instanceOf =
    name: a:
    a.freeipa
    // {
      tunnelId = a.tunnel.id;
      authelia = a.freeipa.authelia // {
        oidcClients = a.freeipa.authelia.oidcClients // clientsFrom name;
      };
    };
  clientsFrom =
    idp:
    lib.mapAttrs (_: a: a.oidc // { public = false; }) (
      lib.filterAttrs (_: a: a.oidc != null && a.oidc.idp == idp) hostApps
    );

  # clusterApps.<app>.oidc: this app signs its users in through <idp>'s
  # Authelia. Its client secret is <idp>-oidc-<app>/secret, for the app to
  # mount; Authelia gets the digest.
  oidcType = types.submodule {
    options = {
      idp = mkOption {
        type = types.str;
        description = "The FreeIPA app (with authelia.enable) that signs this app's users in.";
      };
      name = mkOption {
        type = types.nullOr types.str;
        default = null;
      };
      redirectUris = mkOption { type = types.listOf types.str; };
      scopes = mkOption {
        type = types.listOf types.str;
        default = [
          "openid"
          "profile"
          "email"
          "groups"
        ];
      };
      policy = mkOption {
        type = types.enum [
          "one_factor"
          "two_factor"
        ];
        default = "two_factor";
      };
    };
  };

  dataDir = "/var/lib/freeipa-data";
  metricsDir = "/var/lib/prometheus-node-exporter-text";
  holdDir = "/run/cluster-upgrade.hold.d";

  instanceType = types.submodule (
    { name, ... }:
    {
      options = {
        hostname = mkOption {
          type = types.str;
          example = "idm.example.com";
          description = "The server's FQDN. Fixed at install.";
        };
        domain = mkOption {
          type = types.str;
          example = "example.com";
          description = "The IPA DNS domain. Fixed at install.";
        };
        realm = mkOption {
          type = types.str;
          example = "EXAMPLE.COM";
          description = "The Kerberos realm. Fixed at install.";
        };
        privateIp4 = mkOption {
          type = types.str;
          example = "10.21.0.10";
          description = ''
            The server's address, from topology.privateServices: on a dummy
            interface inside the container, routed to WARP clients through
            the app's tunnel.
          '';
        };
        image = {
          name = mkOption {
            type = types.str;
            default = "quay.io/freeipa/freeipa-server";
          };
          tag = mkOption {
            type = types.str;
            default = "almalinux-10";
          };
          digest = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = ''
              null = track the tag: the newest build is pulled at runtime and
              applied by the nightly upgrade. Set it (with `hash`) to pin ONE
              build instead, baked into the closure -- nix-prefetch-docker
              --image-name … --image-tag … prints both.
            '';
          };
          hash = mkOption {
            type = types.nullOr types.str;
            default = null;
            description = "Hash of the pinned image (nix-prefetch-docker prints it); null with digest.";
          };
          autoUpgrade = {
            enable = mkOption {
              type = types.bool;
              default = true;
              description = ''
                Apply updates by themselves: a nightly `cluster-freeipa-upgrade
                <app> --if-needed` (pull the tag, and when a newer build or a
                deployed unit change is waiting: export, snapshot, restart,
                healthcheck). With a pinned image it only applies a deployed
                change, e.g. a bumped pin.
              '';
            };
            schedule = mkOption {
              type = types.str;
              default = "*-*-* 05:30:00";
              description = "systemd calendar, UTC, with up to 20 minutes of jitter. Clear of the nightly backups (topology.backup.schedule), which the upgrade also waits for.";
            };
          };
        };
        authelia = {
          enable = lib.mkEnableOption "Authelia, an OpenID Connect provider for apps over this directory, in the same container";
          hostname = mkOption {
            type = types.str;
            example = "auth.example.com";
            description = "Where Authelia is served, on the app's tunnel. Not behind Cloudflare Access: apps call it back.";
          };
          smtpSender = mkOption {
            type = types.nullOr types.str;
            default = null;
            example = "Example Sign-in <auth@example.com>";
            description = ''
              Sender for one-time codes (2FA enrollment), through Cloudflare's
              SMTP with the <app>-smtp/token var; its domain must be onboarded
              to Email Sending. null = written to a file in Authelia's state
              directory instead -- enough to bootstrap an admin, not for staff.
              Set the var first, then this.
            '';
          };
          oidcClients = mkOption {
            default = { };
            description = ''
              OpenID Connect clients. A confidential one gets an
              <app>-oidc-<id> var: `secret` for the app, `digest` for Authelia.
            '';
            type = types.attrsOf (
              types.submodule {
                options = {
                  name = mkOption {
                    type = types.nullOr types.str;
                    default = null;
                  };
                  redirectUris = mkOption { type = types.listOf types.str; };
                  scopes = mkOption {
                    type = types.listOf types.str;
                    default = [
                      "openid"
                      "profile"
                      "email"
                      "groups"
                    ];
                  };
                  policy = mkOption {
                    type = types.enum [
                      "one_factor"
                      "two_factor"
                    ];
                    default = "two_factor";
                  };
                  public = mkOption {
                    type = types.bool;
                    default = false;
                    description = "A public client (PKCE, no secret), e.g. a single-page app or a CLI.";
                  };
                };
              }
            );
          };
        };
      };
    }
  );

  # ── the container's side ───────────────────────────────────────────────────
  installOptions =
    inst:
    pkgs.writeText "ipa-server-install-options" (
      lib.concatMapStrings (o: o + "\n") [
        "--unattended"
        "--realm=${inst.realm}"
        "--domain=${inst.domain}"
        "--hostname=${inst.hostname}"
        "--ip-address=${inst.privateIp4}"
        # Chrony belongs to the host; the container shares its clock.
        "--no-ntp"
        # The hostname resolves publicly to the tunnel, not to this server.
        "--no-host-dns"
        "--skip-mem-check"
      ]
    );

  image =
    inst:
    pkgs.dockerTools.pullImage {
      imageName = inst.image.name;
      imageDigest = inst.image.digest;
      inherit (inst.image) hash;
      finalImageName = inst.image.name;
      finalImageTag = inst.image.tag;
    };

  # dbus-broker drops to uid 81 and dirsrv to uid 389 early, and both must
  # traverse these to reach /etc/machine-id and their own state: at 0750 every
  # IPA service blocks behind dbus and the web UI answers Bad Gateway. The
  # reference created them 0755 once and lost that to a later refactor, so it
  # is enforced on every start -- on what exists, so a first install still
  # starts from an empty directory. private/ (keytabs, keys) is left as the
  # image makes it, 0700.
  fixModes = pkgs.writeShellScript "freeipa-modes" ''
    set -eu
    d=${dataDir}
    for x in "" etc var var/lib var/lib/ipa var/lib/ipa/certs; do
      [ -d "$d/$x" ] && ${pkgs.coreutils}/bin/chmod 0755 "$d/$x"
    done
    exit 0
  '';

  prefixLen = net.cidrPrefix topology.privateServices;

  guestModule = name: inst: {
    # The server's address: a dummy link, so it exists whatever eth0 does and
    # can never be reached from the segments the container's real links are on.
    systemd.network.netdevs."30-ipa0".netdevConfig = {
      Name = "ipa0";
      Kind = "dummy";
    };
    systemd.network.networks."30-ipa0" = {
      matchConfig.Name = "ipa0";
      # The pool's prefix, not /32: ipa-server-install refuses an address
      # that is its own network's address.
      address = [ "${inst.privateIp4}/${toString prefixLen}" ];
      linkConfig.RequiredForOnline = "no";
    };
    networking.hosts.${inst.privateIp4} = [ inst.hostname ];

    virtualisation.podman.enable = true;
    # podman's events to a file, not the journal: every `podman exec` (the
    # health check, freeipa-bootstrap, backups) is otherwise a multi-kilobyte
    # "container exec" record in this container's journal -- which Vector
    # ships to Loki.
    virtualisation.containers.containersConf.settings.engine.events_logger = "file";
    # FreeIPA runs with --network=host, so there is no podman bridge and no
    # aardvark-dns to reach. nixpkgs would otherwise open 53/tcp+udp on
    # podman+ in this container's firewall, which must open nothing.
    virtualisation.podman.dns.openFirewall = false;
    virtualisation.oci-containers = {
      backend = "podman";
      containers.freeipa = {
        image = "${inst.image.name}:${inst.image.tag}";
        # Tracking: the tag is pulled when it is missing (a node that never had
        # it) and by the upgrade; a restart never pulls. Pinned: loaded from
        # the closure, never from a registry.
        imageFile = if inst.image.digest != null then image inst else null;
        pull = if inst.image.digest != null then "never" else "missing";
        hostname = inst.hostname;
        networks = [ "host" ];
        environment.IPA_SERVER_IP = inst.privateIp4;
        # PASSWORD=… : the admin and Directory Manager password, at install.
        environmentFiles = [ "/run/secrets/ipa-password-env" ];
        volumes = [
          "${dataDir}:/data"
          "${installOptions inst}:/data/ipa-server-install-options:ro"
        ];
        capabilities = {
          SYS_ADMIN = true;
          NET_ADMIN = true;
          # dbus-broker-launch opens a NETLINK_AUDIT socket unconditionally
          # and dies without this; with dbus down, every IPA service blocks.
          AUDIT_WRITE = true;
        };
        extraOptions = [
          # --network=host shares the UTS namespace too, and the installer
          # checks that the hostname it is given is the machine's.
          "--uts=private"
          "--add-host=${inst.hostname}:${inst.privateIp4}"
          # Five seccomp filters are already stacked by nspawn and systemd;
          # podman's own on top breaks the image's systemd.
          "--security-opt=seccomp=unconfined"
          "--read-only=false"
          "--stop-timeout=180"
        ];
      };
    };

    systemd.services.podman-freeipa = {
      # See the header: a restart is an upgrade, and upgrades are deliberate.
      restartIfChanged = false;
      serviceConfig = {
        ExecStartPre = lib.mkBefore [ "${fixModes}" ];
        # Which unit definition this run started from, for the health check's
        # restart_pending: a deploy rewrites the unit but, by design, leaves
        # the server running on the old one.
        ExecStartPost = [
          (pkgs.writeShellScript "freeipa-started" ''
            ${pkgs.coreutils}/bin/readlink -f /etc/systemd/system/podman-freeipa.service > /run/podman-freeipa.started
          '')
        ];
        TimeoutStopSec = lib.mkForce 200;
        # The image exits 123 after its first install, to be started again.
        Restart = lib.mkForce "always";
        RestartSec = 10;
      };
    };

    services.cloudflared.tunnels = lib.mkIf (inst.tunnelId != "") {
      ${inst.tunnelId}.originRequest = {
        # httpd's certificate is IPA's own, issued for the hostname.
        noTLSVerify = true;
        originServerName = inst.hostname;
      };
    };
  };

  # ── Authelia, in the same container ────────────────────────────────────────
  # An OpenID Connect provider over this directory: apps log staff in with
  # their IPA accounts, second factor included. It binds to IPA as a system
  # account (cn=sysaccounts) that freeipa-bootstrap creates, over ldaps to
  # the server's own address, trusting IPA's CA.
  #
  # Deliberately not in the boot transaction: until IPA has installed there
  # is no CA to trust and no account to bind as, and Authelia refuses to
  # start without both. freeipa-bootstrap (a timer) ensures the account and
  # then starts it; a deploy restarts it only if it is running.
  #
  # Password reset and change are off: a password set by anyone but the user
  # comes out of IPA already expired, which would trap people in a loop.
  # Passwords are changed in IPA's own web UI.
  baseDn = inst: "dc=" + lib.concatStringsSep ",dc=" (lib.splitString "." inst.domain);
  ldapi = inst: "ldapi://%2Frun%2Fslapd-${lib.replaceStrings [ "." ] [ "-" ] inst.realm}.socket";
  autheliaDn = inst: "uid=authelia,cn=sysaccounts,cn=etc,${baseDn inst}";
  autheliaPort = 9091;
  confidential = inst: lib.filterAttrs (_: c: !c.public) inst.authelia.oidcClients;

  # Authelia merges its config files, but a list is replaced rather than
  # merged, so the clients live in this one file -- templated, so a client's
  # secret is read at start from the unit's credentials, never written into
  # the store. Authelia refuses an OIDC provider without clients.
  oidcClientsFile =
    name: inst:
    let
      list = xs: "[ ${lib.concatMapStringsSep ", " (x: "'${x}'") xs} ]";
      client =
        id: c:
        [
          "- client_id: '${id}'"
          "  client_name: '${if c.name != null then c.name else id}'"
          "  authorization_policy: '${c.policy}'"
          "  redirect_uris: ${list c.redirectUris}"
          "  scopes: ${list c.scopes}"
          "  require_pkce: true"
          "  pkce_challenge_method: 'S256'"
        ]
        ++ (
          if c.public then
            [
              "  public: true"
              "  token_endpoint_auth_method: 'none'"
            ]
          else
            [
              # Indented like its siblings: at the list item's own column it
              # is not a key of this client, and the file does not parse. The
              # spaces go outside the '' string, which strips leading
              # indentation -- a single-line one loses all of it.
              (
                "  "
                + ''client_secret: {{ mustEnv "CREDENTIALS_DIRECTORY" | printf "%s/oidc-${id}" | secret | msquote }}''
              )
            ]
        );
      text = pkgs.writeText "authelia-${name}-clients-unchecked.yml" (
        lib.concatStringsSep "\n" (
          [
            "identity_providers:"
            "  oidc:"
            "    clients:"
          ]
          ++ map (l: "      " + l) (lib.concatLists (lib.mapAttrsToList client inst.authelia.oidcClients))
        )
        + "\n"
      );
    in
    # Parsed at build time: hand-assembled YAML shipped once with a
    # confidential client's secret at the wrong indent, which only a real
    # confidential client exposed -- and Authelia refuses to start on it.
    # Every client must come out with its id and either a secret or `public`.
    pkgs.runCommand "authelia-${name}-clients.yml" { nativeBuildInputs = [ pkgs.yq-go ]; } ''
      n=$(yq '.identity_providers.oidc.clients | length' ${text})
      test "$n" -eq ${toString (lib.length (lib.attrNames inst.authelia.oidcClients))}
      bad=$(yq '[.identity_providers.oidc.clients[] | select(.client_id == null or (has("client_secret") == false and .public != true))] | length' ${text})
      test "$bad" -eq 0 || { echo "authelia clients: a client lacks client_id or client_secret/public" >&2; cat ${text} >&2; exit 1; }
      cp ${text} $out
    '';

  autheliaFiles = [
    "jwt-secret"
    "session-secret"
    "storage-key"
    "hmac-secret"
    "issuer-key"
    "ldap-password"
  ];

  autheliaModule =
    name: inst:
    let
      a = inst.authelia;
      unit = "authelia-${name}";
      caDir = "/run/${unit}-ca";
      copyCa = pkgs.writeShellScript "${unit}-ca" ''
        ${pkgs.coreutils}/bin/install -D -m 0644 ${dataDir}/etc/ipa/ca.crt ${caDir}/ipa-ca.crt
      '';
      smtp = a.smtpSender != null;
    in
    {
      services.authelia.instances.${name} = {
        enable = true;
        secrets = {
          jwtSecretFile = "/run/secrets/authelia-jwt-secret";
          sessionSecretFile = "/run/secrets/authelia-session-secret";
          storageEncryptionKeyFile = "/run/secrets/authelia-storage-key";
          oidcHmacSecretFile = "/run/secrets/authelia-hmac-secret";
          oidcIssuerPrivateKeyFile = "/run/secrets/authelia-issuer-key";
        };
        environmentVariables = {
          AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE = "%d/ldap-password";
          X_AUTHELIA_CONFIG_FILTERS = "template";
        }
        // lib.optionalAttrs smtp { AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE = "%d/smtp-token"; };
        settingsFiles = [ (oidcClientsFile name inst) ];
        settings = {
          theme = "auto";
          server.address = "tcp://127.0.0.1:${toString autheliaPort}/";
          log.level = "info";
          certificates_directory = caDir;
          totp.issuer = inst.domain;
          webauthn.display_name = inst.domain;
          authentication_backend = {
            password_reset.disable = true;
            password_change.disable = true;
            refresh_interval = "5m";
            ldap = {
              implementation = "freeipa";
              address = "ldaps://${inst.hostname}:636";
              base_dn = baseDn inst;
              user = autheliaDn inst;
              tls.server_name = inst.hostname;
            };
          };
          access_control.default_policy = "two_factor";
          session.cookies = [
            {
              domain = a.hostname;
              authelia_url = "https://${a.hostname}";
            }
          ];
          storage.local.path = "/var/lib/${unit}/db.sqlite3";
          notifier =
            if smtp then
              {
                # Its startup check would keep Authelia down over a mail
                # hiccup. (A notifier-level key in 4.39, not an smtp one.)
                disable_startup_check = true;
                # Implicit TLS on 465; Cloudflare takes no STARTTLS.
                smtp = {
                  address = "submissions://smtp.mx.cloudflare.net:465";
                  username = "api_token";
                  sender = a.smtpSender;
                };
              }
            else
              { filesystem.filename = "/var/lib/${unit}/notifications.txt"; };
        };
      };

      systemd.services.${unit} = {
        wantedBy = lib.mkForce [ ];
        unitConfig.ConditionPathExists = "${dataDir}/etc/ipa/ca.crt";
        serviceConfig = {
          # Root, before the sandboxed validate-config: IPA's CA, alone in a
          # directory of its own (certificates_directory loads every file).
          ExecStartPre = lib.mkBefore [ "+${copyCa}" ];
          LoadCredential = [
            "ldap-password:/run/secrets/authelia-ldap-password"
          ]
          ++ lib.optional smtp "smtp-token:/run/secrets/authelia-smtp-token"
          ++ lib.mapAttrsToList (id: _: "oidc-${id}:/run/secrets/authelia-oidc-${id}") (confidential inst);
        };
      };

      # Ensures what Authelia needs from IPA, then starts it. Idempotent, and
      # a no-op until IPA is up; on a timer rather than in the boot
      # transaction, so a container start never waits on an IPA install.
      systemd.services.freeipa-bootstrap = {
        description = "Ensure ${name}'s service accounts in IPA, then start Authelia";
        after = [ "podman-freeipa.service" ];
        serviceConfig.Type = "oneshot";
        path = [ pkgs.coreutils ];
        script = ''
          set -euo pipefail
          p=/run/current-system/sw/bin/podman
          # New secrets are bind mounts, which arrive with a container restart
          # (nomad job restart app-${name}), not with the deploy that added them.
          if [ ! -r /run/secrets/authelia-ldap-password ]; then
            echo "Authelia's secrets are not mounted yet; restart the container: nomad job restart app-${name}"
            exit 0
          fi
          if ! $p exec freeipa ipactl status >/dev/null 2>&1; then
            echo "FreeIPA is not up yet; trying again later"
            exit 0
          fi
          sock=${lib.escapeShellArg (ldapi inst)}
          dn=${lib.escapeShellArg (autheliaDn inst)}
          pw=$(cat /run/secrets/authelia-ldap-password)
          # Can it bind with the password it has? The password goes over stdin,
          # never onto a command line.
          if printf '%s' "$pw" | $p exec -i freeipa sh -c \
            'f=$(mktemp); cat > "$f"; ldapwhoami -x -H "$1" -D "$2" -y "$f" >/dev/null 2>&1; r=$?; rm -f "$f"; exit $r' \
            _ "$sock" "$dn"; then
            echo "authelia's system account is in place"
          else
            rc=0
            $p exec freeipa ldapsearch -Q -Y EXTERNAL -H "$sock" -b "$dn" -s base dn >/dev/null 2>&1 || rc=$?
            if [ "$rc" = 32 ]; then
              echo "creating authelia's system account"
              printf 'dn: %s\nobjectclass: account\nobjectclass: simplesecurityobject\nuid: authelia\nuserPassword: %s\npasswordExpirationTime: 20380119031407Z\nnsIdleTimeout: 0\n' "$dn" "$pw" \
                | $p exec -i freeipa ldapadd -Q -Y EXTERNAL -H "$sock" >/dev/null
            elif [ "$rc" = 0 ]; then
              echo "resetting authelia's system account password (it did not match the var)"
              printf 'dn: %s\nchangetype: modify\nreplace: userPassword\nuserPassword: %s\n' "$dn" "$pw" \
                | $p exec -i freeipa ldapmodify -Q -Y EXTERNAL -H "$sock" >/dev/null
            else
              echo "ldapsearch for $dn failed ($rc)" >&2
              exit 1
            fi
          fi
          systemctl start --no-block ${unit}.service
        '';
      };
      systemd.timers.freeipa-bootstrap = {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnBootSec = "2min";
          OnUnitActiveSec = "5min";
        };
      };
    };

  # ── the host's side ────────────────────────────────────────────────────────
  preCommand = ''
    podman exec freeipa ipa-backup --data --online
    # Keep only the newest export: each is complete, and restic keeps history.
    podman exec freeipa sh -c 'ls -1dt /var/lib/ipa/backup/ipa-data-* | tail -n +2 | xargs -r rm -rf'
  '';

  appFor = name: inst: {
    tier = "monolith";
    # podman runs systemd inside the image, in its own namespaces.
    additionalCapabilities = [ "all" ];
    stopTimeoutSeconds = 300;
    nomad.killTimeoutSeconds = 330;
    resources = {
      cpu = lib.mkDefault 2000;
      memoryMB = lib.mkDefault 4096;
    };
    localState = {
      ${dataDir} = "/state/clients/${name}/ipa";
    }
    // lib.optionalAttrs inst.authelia.enable {
      "/var/lib/authelia-${name}" = "/state/clients/${name}/authelia";
    };
    # The server's own logs (dirsrv, krb5kdc, httpd, ipa-*) go to the image's
    # systemd journal under /data, not the container's -- ship that too
    # (modules/logging.nix). AlmaLinux's systemd-journal group is GID 190 and
    # its journald writes 0640, so the shipper needs that GID; ours is 62.
    logging = {
      journalDirs = [ "/state/clients/${name}/ipa/var/log/journal" ];
      journalGroups = [ "190" ];
    };
    secrets = {
      ipa-password-env = {
        generator = name;
        file = "password-env";
      };
    }
    // lib.optionalAttrs inst.authelia.enable (
      lib.listToAttrs (
        map (
          f:
          lib.nameValuePair "authelia-${f}" {
            generator = "${name}-authelia";
            file = f;
          }
        ) autheliaFiles
      )
      // lib.optionalAttrs (inst.authelia.smtpSender != null) {
        authelia-smtp-token = {
          generator = "${name}-smtp";
          file = "token";
        };
      }
      // lib.mapAttrs' (
        id: _:
        lib.nameValuePair "authelia-oidc-${id}" {
          generator = "${name}-oidc-${id}";
          file = "digest";
        }
      ) (confidential inst)
    );
    # The id and its <name>-cf credentials are the generic ones. The
    # condition is on the leaf, not on `tunnel`: on the whole option it would
    # need tunnel.id to decide tunnel.id.
    tunnel.ingress = lib.mkIf (inst.tunnelId != "") (
      {
        ${inst.hostname} = "https://127.0.0.1:443";
      }
      // lib.optionalAttrs inst.authelia.enable {
        ${inst.authelia.hostname} = "http://127.0.0.1:${toString autheliaPort}";
      }
    );
    backup = {
      engine = "none";
      localSnapshot = true;
      appUnits = [
        "podman-freeipa.service"
      ]
      ++ lib.optional inst.authelia.enable "authelia-${name}.service";
      exclude = [ "*/var/log/journal" ];
      inherit preCommand;
      verifyCommand = ''
        d="$ROOT${dataDir}"
        test -s "$d/etc/ipa/ca.crt"
        test -s "$d/etc/ipa/default.conf"
        ls "$d"/etc/dirsrv/slapd-*/dse.ldif >/dev/null
        b=$(ls -1d "$d"/var/lib/ipa/backup/ipa-data-* | tail -1)
        test -s "$b/header"
      '';
    };
    module = {
      imports = [
        (guestModule name inst)
      ]
      ++ lib.optional inst.authelia.enable (autheliaModule name inst);
    };
  };

  # Every node has the health check and the upgrade, and each acts on the servers
  # whose container runs there. A node that does not run one still reports it, as
  # not up: lib/alert-rules.nix takes the best any node says of an app.
  local = instances;
  autoUpgraded = lib.filterAttrs (_: i: i.image.autoUpgrade.enable) local;

  # Reports through metrics only (lib/alert-rules.nix FreeIPA*): a failing
  # unit as well would page twice for one outage.
  healthScript = pkgs.writeShellScript "cluster-freeipa-health" ''
    set -uo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.jq
        pkgs.systemd
      ]
    }:/run/current-system/sw/bin
    for APP in "$@"; do
      up=0 errors=-1 warnings=-1 pending=0
      # A unit of the guest's systemd: see in_guest_unit in backup-core.nix.
      g() {
        local c=$1; shift
        # systemd resolves a unit's command on its own fixed search path, not
        # on the PATH given to the unit: 203/EXEC for a bare "podman".
        [[ "$c" == /* ]] || c=/run/current-system/sw/bin/$c
        systemd-run -M "$APP" --pipe --wait --quiet --collect -p RuntimeMaxSec=600 \
          -E PATH=/run/wrappers/bin:/run/current-system/sw/bin -- "$c" "$@"
      }
      if systemctl is-active --quiet "container@$APP"; then
        g podman exec freeipa ipactl status >/dev/null 2>&1 && up=1
        if [ "$up" = 1 ]; then
          # Exits non-zero whenever it has findings; the JSON is what counts.
          out=$(g podman exec freeipa ipa-healthcheck --failures-only --output-type json 2>/dev/null || true)
          if jq -e 'type == "array"' <<<"$out" >/dev/null 2>&1; then
            errors=$(jq '[.[] | select(.result == "ERROR" or .result == "CRITICAL")] | length' <<<"$out")
            warnings=$(jq '[.[] | select(.result == "WARNING")] | length' <<<"$out")
            [ "$errors" = 0 ] || jq -c '.[] | select(.result != "WARNING") | {source, check, result, kw: .kw.msg}' <<<"$out" >&2
          fi
        fi
        started=$(g cat /run/podman-freeipa.started 2>/dev/null | tr -d '\r')
        current=$(g readlink -f /etc/systemd/system/podman-freeipa.service 2>/dev/null | tr -d '\r')
        [ -n "$started" ] && [ "$started" != "$current" ] && pending=1
      fi
      here=0; systemctl is-active --quiet "container@$APP" && here=1
      [ "$up" = 1 ] || [ "$here" = 0 ] || echo "$APP: FreeIPA is not running" >&2
      mkdir -p ${metricsDir}
      f=${metricsDir}/cluster_freeipa_$APP.prom
      {
        echo "cluster_freeipa_up{app=\"$APP\"} $up"
        echo "cluster_freeipa_healthcheck_errors{app=\"$APP\"} $errors"
        echo "cluster_freeipa_healthcheck_warnings{app=\"$APP\"} $warnings"
        echo "cluster_freeipa_restart_pending{app=\"$APP\"} $pending"
        echo "cluster_freeipa_health_last_run_timestamp_seconds{app=\"$APP\"} $(date +%s)"
      } > "$f.tmp" && mv "$f.tmp" "$f"
      [ "$here" = 0 ] || echo "$APP: up=$up errors=$errors warnings=$warnings restart_pending=$pending"
    done
  '';

  # cluster-freeipa-upgrade <app> [--if-needed]
  #
  # Applies what is waiting: for a tracked image, the newest build of its tag;
  # for any, a unit change a deploy left unapplied. --if-needed (the nightly
  # timer's mode) does nothing when nothing is waiting, and leaves a server
  # that is not up to the alerts. Without it, restarts regardless.
  upgradeScript = pkgs.writeShellScriptBin "cluster-freeipa-upgrade" ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.util-linux
        pkgs.systemd
        config.boot.zfs.package
      ]
    }:/run/current-system/sw/bin
    usage() { echo "usage: cluster-freeipa-upgrade <${lib.concatStringsSep "|" (lib.attrNames local)}> [--if-needed]" >&2; exit 2; }
    case "''${1:-}" in
      ${lib.concatStringsSep "|" (lib.attrNames local)}) APP=$1; shift ;;
      *) usage ;;
    esac
    ifneeded=0
    for a in "$@"; do
      case "$a" in
        --if-needed) ifneeded=1 ;;
        *) usage ;;
      esac
    done
    declare -A PRE=(${
      lib.concatStringsSep " " (
        lib.mapAttrsToList (
          n: _:
          "[${n}]=${pkgs.writeShellScript "freeipa-export-${n}" ''
            set -euo pipefail
            ${preCommand}
          ''}"
        ) local
      )
    })
    declare -A REF=(${
      lib.concatStringsSep " " (
        lib.mapAttrsToList (n: i: "[${n}]=${lib.escapeShellArg "${i.image.name}:${i.image.tag}"}") local
      )
    })
    declare -A TRACKED=(${
      lib.concatStringsSep " " (
        lib.mapAttrsToList (n: i: "[${n}]=${if i.image.digest == null then "1" else "0"}") local
      )
    })
    ref=''${REF[$APP]}
    if ! systemctl is-active --quiet "container@$APP"; then
      [ "$ifneeded" = 1 ] && exit 0
      echo "$APP is not running on this node ($(hostname)); \`cluster-state status\` says where it is" >&2
      exit 1
    fi
    # A unit of the guest's systemd: see in_guest_unit in backup-core.nix.
    g() {
      local c=$1; shift
      # systemd resolves a unit's command on its own fixed search path, not
      # on the PATH given to the unit: 203/EXEC for a bare "podman".
      [[ "$c" == /* ]] || c=/run/current-system/sw/bin/$c
      systemd-run -M "$APP" --pipe --wait --quiet --collect \
        -E PATH=/run/wrappers/bin:/run/current-system/sw/bin -- "$c" "$@"
    }
    # The image the running container was made from, and what its tag is now.
    running_id() { g podman inspect --format '{{.Image}}' freeipa 2>/dev/null | tr -d '\r\n' || true; }
    tag_id() { g podman image inspect --format '{{.Id}}' "$ref" 2>/dev/null | tr -d '\r\n' || true; }
    # A deploy rewrites the unit but, by design, leaves the server on the old one.
    restart_pending() {
      local started current
      started=$(g cat /run/podman-freeipa.started 2>/dev/null | tr -d '\r') || true
      current=$(g readlink -f /etc/systemd/system/podman-freeipa.service 2>/dev/null | tr -d '\r') || true
      [ -n "$started" ] && [ "$started" != "$current" ]
    }

    if [ "$ifneeded" = 1 ] && ! g podman exec freeipa ipactl status >/dev/null 2>&1; then
      echo "$APP: FreeIPA is not up; not upgrading what is not running (FreeIPADown covers it)"
      exit 0
    fi
    # The backup reads the state this restarts.
    for i in $(seq 1 240); do
      systemctl is-active --quiet "cluster-backup-$APP.service" || break
      [ "$i" = 1 ] && echo "waiting for the running backup"
      sleep 30
    done

    if [ "''${TRACKED[$APP]}" = 1 ]; then
      echo "== pulling $ref"
      for i in 1 2 3; do
        g podman pull --quiet "$ref" >/dev/null && break
        [ "$i" = 3 ] && { echo "pulling $ref failed three times; the image is not being tracked" >&2; exit 1; }
        sleep $((i * 60))
      done
    fi
    cur=$(running_id)
    new=$(tag_id)
    reason=""
    if [ "''${TRACKED[$APP]}" = 1 ] && [ -n "$new" ] && [ "$new" != "$cur" ]; then
      reason="a newer image of $ref"
    fi
    if restart_pending; then
      reason="''${reason:+$reason, and }a deployed unit change"
    fi
    if [ "$ifneeded" = 1 ] && [ -z "$reason" ]; then
      echo "$APP: up to date"
      exit 0
    fi
    echo "== upgrading $APP: ''${reason:-restart requested}"

    mkdir -p ${holdDir}; touch ${holdDir}/freeipa-upgrade-"$APP"
    trap 'rm -f ${holdDir}/freeipa-upgrade-"$APP"' EXIT
    while systemctl is-active --quiet cluster-upgrade.service; do echo "waiting for the running deploy"; sleep 10; done

    echo "== exporting (ipa-backup --data --online)"
    g "''${PRE[$APP]}"
    ds=$(findmnt -n -o SOURCE -T /state/clients/"$APP")
    snap="$ds@pre-upgrade-$APP-$(date +%Y%m%d-%H%M%S)"
    zfs snapshot "$snap"
    echo "== safety snapshot $snap (copy out of it; rolling back would undo what the server wrote since)"
    if [ "''${TRACKED[$APP]}" = 1 ] && [ -n "$cur" ] && [ "$cur" != "$new" ]; then
      # What was running stays reachable: with the snapshot, the way back.
      g podman tag "$cur" "''${ref%:*}:previous"
      echo "== the running image is kept as ''${ref%:*}:previous"
    fi

    echo "== restarting podman-freeipa"
    g systemctl restart podman-freeipa.service
    for i in $(seq 1 180); do
      if g podman exec freeipa ipactl status >/dev/null 2>&1; then break; fi
      [ "$i" = 180 ] && { echo "FreeIPA did not come back within 30 minutes; see: nixos-container run $APP -- journalctl -u podman-freeipa" >&2; exit 1; }
      sleep 10
    done
    echo "== healthcheck"
    if g podman exec freeipa ipa-healthcheck --failures-only; then
      echo "upgrade of $APP complete"
    else
      echo "FreeIPA is up but ipa-healthcheck has findings (above). The export, $snap and the :previous image are the way back." >&2
      exit 1
    fi
    # Superseded layers; :previous is tagged, so it stays.
    g podman image prune --force >/dev/null || true
    systemctl start cluster-freeipa-health.service || true
  '';
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        {
          options.freeipa = mkOption {
            type = types.nullOr instanceType;
            default = null;
            description = "A FreeIPA server, optionally with Authelia (modules/kinds/freeipa.nix).";
          };
          options.oidc = mkOption {
            type = types.nullOr oidcType;
            default = null;
            description = "Sign this app's users in through a FreeIPA app's Authelia (OpenID Connect).";
          };
          config = lib.mkIf (config.freeipa != null) (appFor name (instanceOf name config));
        }
      )
    );
  };

  config = lib.mkIf (instances != { }) {
    assertions =
      lib.concatLists (
        lib.mapAttrsToList (name: inst: [
          {
            assertion = net.cidrContains topology.privateServices inst.privateIp4;
            message = "clusterApps.${name}.freeipa: privateIp4 ${inst.privateIp4} is outside topology.privateServices (${topology.privateServices}).";
          }
          {
            assertion =
              lib.length (lib.filter (i: i.privateIp4 == inst.privateIp4) (lib.attrValues instances)) == 1;
            message = "clusterApps.${name}.freeipa: privateIp4 ${inst.privateIp4} is used twice.";
          }
          {
            assertion = (inst.image.digest == null) == (inst.image.hash == null);
            message = "clusterApps.${name}.freeipa.image: digest and hash go together -- set both to pin a build, neither to track the tag.";
          }
          {
            assertion = inst.authelia.enable -> inst.authelia.oidcClients != { };
            message = "clusterApps.${name}.freeipa.authelia: Authelia refuses an OpenID Connect provider with no clients; declare one in oidcClients.";
          }
          {
            assertion = inst.authelia.enable -> inst.tunnelId != "";
            message = "clusterApps.${name}.freeipa.authelia: needs tunnel.id -- it is served on the app's tunnel.";
          }
        ]) instances
      )
      ++ [
        {
          # The pool is routed to WARP clients; it must not shadow a network
          # the cluster itself uses.
          assertion = lib.all (s: !(net.cidrsOverlap topology.privateServices s)) (
            lib.mapAttrsToList (_: v: v.subnet) topology.vlans
            ++ lib.mapAttrsToList (_: n: n.appSubnet) topology.nodes
          );
          message = "topology.privateServices (${topology.privateServices}) overlaps a VLAN or an app subnet.";
        }
      ];

    clan.core.vars.generators = lib.mkMerge (
      lib.mapAttrsToList (
        name: inst:
        {
          # The admin (and Directory Manager) password, read by the installer
          # once. Generated so it exists before the first start, kept so a
          # rebuilt node reinstalls with the same one.
          ${name} = {
            share = true;
            files.password = { };
            files.password-env = { };
            runtimeInputs = [
              pkgs.coreutils
              pkgs.openssl
            ];
            script = ''
              openssl rand -base64 30 | tr -d '\n=/+' > "$out/password"
              printf 'PASSWORD=%s\n' "$(cat "$out/password")" > "$out/password-env"
            '';
          };
          # Issued by Cloudflare, so prompted, and apart from the generated
          # one (filling it must not re-run that script). Declared whether
          # or not tunnel.id is set yet: the credentials have to be stored
          # BEFORE the tunnel is wired in, or the build fails on a secret
          # with no value.
          #   cloudflared tunnel create <name>
          #   cloudflared tunnel route dns <name> <hostname>
          #   clan vars set <node> <name>-cf/cloudflared < ~/.cloudflared/<id>.json
          "${name}-cf" = {
            share = true;
            prompts.cloudflared = {
              description = "${name}: tunnel credentials JSON (cloudflared tunnel create)";
              type = "multiline-hidden";
              persist = true;
            };
          };
        }
        // lib.optionalAttrs inst.authelia.enable (
          {
            # Authelia's own secrets, apart from the admin password's generator:
            # adding a file to that one would regenerate it, and the password it
            # holds must keep matching what IPA was installed with.
            "${name}-authelia" = {
              share = true;
              files = lib.genAttrs autheliaFiles (_: { });
              runtimeInputs = [
                pkgs.coreutils
                pkgs.openssl
              ];
              script = ''
                for f in jwt-secret session-secret storage-key hmac-secret; do
                  openssl rand -hex 64 | tr -d '\n' > "$out/$f"
                done
                # Used over stdin in an LDIF, so kept to [A-Za-z0-9].
                openssl rand -base64 48 | tr -d '\n=/+' > "$out/ldap-password"
                openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$out/issuer-key" 2>/dev/null
              '';
            };
            # Cloudflare-issued, so prompted; declared before it is used (set it,
            # then set authelia.smtpSender):
            #   clan vars set <node> <name>-smtp/token   (a token with Email Sending: Edit)
            "${name}-smtp" = {
              share = true;
              prompts.token = {
                description = "${name}: Cloudflare API token with Email Sending: Edit, for Authelia's SMTP";
                type = "hidden";
                persist = true;
              };
            };
          }
          // lib.mapAttrs' (
            id: _:
            # `secret` goes to the app that is the client (its own
            # clusterApps.<app>.secrets), `digest` to Authelia.
            lib.nameValuePair "${name}-oidc-${id}" {
              share = true;
              files.secret = { };
              files.digest = { };
              runtimeInputs = [
                pkgs.coreutils
                pkgs.gnused
                pkgs.authelia
              ];
              script = ''
                out_=$(authelia crypto hash generate pbkdf2 --variant sha512 --random --random.length 72 --random.charset rfc3986)
                printf '%s' "$(sed -n 's/^Random Password: //p' <<<"$out_")" > "$out/secret"
                printf '%s' "$(sed -n 's/^Digest: //p' <<<"$out_")" > "$out/digest"
                test -s "$out/secret" && test -s "$out/digest"
              '';
            }
          ) (confidential inst)
        )
      ) instances
    );

    # Health and upgrades run where the server does, which each finds out when it runs.
    systemd.services =
      lib.optionalAttrs (local != { }) {
        cluster-freeipa-health = {
          description = "FreeIPA health (ipactl, ipa-healthcheck) for ${lib.concatStringsSep " " (lib.attrNames local)}";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = "${healthScript} ${lib.concatStringsSep " " (lib.attrNames local)}";
          };
        };
      }
      # Nightly: pull the tag and apply what is waiting (see upgradeScript).
      // lib.mapAttrs' (
        n: _:
        lib.nameValuePair "cluster-freeipa-autoupgrade-${n}" {
          description = "Apply waiting FreeIPA updates to ${n}";
          serviceConfig = {
            Type = "oneshot";
            # A pull, a restart, ipa-server-upgrade and a healthcheck.
            TimeoutStartSec = "3h";
            ExecStart = "${upgradeScript}/bin/cluster-freeipa-upgrade ${n} --if-needed";
          };
        }
      ) autoUpgraded;
    systemd.timers =
      lib.optionalAttrs (local != { }) {
        cluster-freeipa-health = {
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnBootSec = "5min";
            OnUnitActiveSec = "15min";
          };
        };
      }
      // lib.mapAttrs' (
        n: i:
        lib.nameValuePair "cluster-freeipa-autoupgrade-${n}" {
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnCalendar = i.image.autoUpgrade.schedule;
            RandomizedDelaySec = "20m";
            Persistent = true;
          };
        }
      ) autoUpgraded;
    environment.systemPackages = lib.optional (local != { }) upgradeScript;
  };
}
