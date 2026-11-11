# lib/mk-wordpress-site.nix — expand one site parameter set (the `wordpress`
# section of apps/<slug>.json) into BOTH halves of a split-plane WordPress site,
# plus the secrets and the database entry they share.
#
#   { generators; database; plane; }
#
# `plane` is the clusterApps entry for the role this call was given. The
# catalogue (modules/apps.nix) calls the builder twice per site, once per role,
# so one file in apps/ produces two containers:
#
#   <slug>        the PUBLIC face, on the site's real hostname. An immutable
#                 store docroot composed from the site repo at a pinned rev; no
#                 administration surface, no file modifications, no wp-cron.
#                 Visitors still write — checkout, donations, comments, forms.
#   <slug>-admin  the ADMIN face, on a private hostname behind Cloudflare Access.
#                 Mutable wp-content on JuiceFS, seeded from the site repo, with
#                 gitium pushing changes back. Owns wp-cron and plugin installs.
#
# They share: one database in the cluster's MariaDB (modules/kinds/wpdb.nix), one
# set of session salts, one uploads directory, and one media bucket. Content
# changes are therefore live on both faces at once; CODE changes reach the public
# face only when its pinned rev is bumped and the cluster next upgrades, which is
# the gate between editing and publishing.
{
  inputs,
  lib,
  pkgs,
}:
params:
let
  slug = params.slug;
  role = params.role;
  isPublic = role == "public";
  isAdmin = role == "admin";

  gen = "wp-${slug}";
  genGit = "wp-${slug}-git";
  # Credentials issued BY Cloudflare for this site's own resources. Distinct from
  # the per-app `<name>-cf` generators that modules/apps.nix declares for tunnel
  # credentials -- a site has two of those, one per plane.
  genApi = "wp-${slug}-api";

  # Inside the container every secret appears at /run/secrets/<guest name>.
  secretPath = name: "/run/secrets/${name}";

  # Own directory, not /run itself: Caddy runs unprivileged and /run is 0755
  # root:root. wordpress-nix creates this 0750 owned by its service user, and the
  # tunnel connector reaches the socket through the `wordpress` group.
  socketPath = "/run/wordpress/wp.sock";

  quote = s: "'${lib.replaceStrings [ "'" "\\" ] [ "\\'" "\\\\" ] s}'";
  readSecret = name: "trim((string) @file_get_contents(${quote (secretPath name)}))";

  publicHost = lib.removePrefix "https://" (lib.removePrefix "http://" params.publicUrl);

  # Extra hostnames routed to the public plane. A migration verifies the public
  # face on a staging hostname before any live DNS moves, and after cutover that
  # hostname stays routed so bookmarks and the admin plane's "view site" link
  # keep working. They only reach the same site; WP_HOME still names publicUrl,
  # so a request to an alias is canonicalized to the real domain.
  publicAliases = params.publicAliases or [ ];
  adminUrl = "https://${params.adminHost}";

  # MySQL identifiers: a slug is a hostname-ish label, so fold the characters
  # that are awkward unquoted and keep the user inside MySQL's 32-char limit.
  ident = s: lib.replaceStrings [ "-" "." ] [ "_" "_" ] s;
  dbName = params.dbName or (ident slug);
  dbUser = params.dbUser or (ident slug);

  # Both planes run the service as the SAME uid, because they share the uploads
  # directory on JuiceFS. `isSystemUser` without an explicit uid allocates per
  # container, so the two would differ -- and the module's tmpfiles rule chowns
  # the uploads directory on every start, so each plane would take ownership away
  # from the other on restart, forever.
  wpUid = params.uid or 980;

  # Owner of the secrets the service user reads ITSELF: the salts and the
  # deploy key from wordpress-init, the API keys from PHP on every request.
  # They are bind-mounted from the host as-is, and a root 0400 file is
  # unreadable to `wordpress` -- which is how both planes of a site once
  # failed wordpress-init from 2026-10-08. Numeric, because the user
  # exists only inside the containers; containers share the host's uids, and
  # wpUid is pinned. db-password is not here: wordpress-nix takes it through
  # LoadCredential, which systemd reads as root.
  wpOwned = {
    owner = toString wpUid;
    group = toString wpUid;
  };

  # ── the content the public face serves ─────────────────────────────────────
  # Fetched at EVAL time from the pinned rev, so the public face is a store path
  # that cannot drift and can be rolled back by reverting one JSON field. A full
  # rev makes builtins.fetchGit pure; a private repo resolves through root's
  # ~/.netrc, which the pull-deploy already relies on for its own flake inputs.
  # `content.url` should be an HTTPS url, NOT the ssh `repoUrl`. This fetch runs
  # at eval time on every node, and what the nodes hold for GitHub is a netrc —
  # an ssh url here makes the whole flake fail to evaluate, for every app.
  contentTree =
    if params ? content then
      builtins.fetchGit {
        url = params.content.url or params.repoUrl;
        rev = params.content.rev;
        ref = params.content.branch or params.branch or "main";
      }
    else
      null;

  # Core + the site's wp-content + the platform mu-plugins, composed at build
  # time. Without a pinned rev yet (a site provisioned but never pushed) this is
  # core and the platform's own mu-plugins, which serves rather than failing.
  docroot = inputs.wordpress-nix.lib.mkSiteDocroot {
    inherit pkgs;
    name = "wordpress-docroot-${slug}";
    wpContent = if contentTree != null then "${contentTree}/wp-content" else null;
  };

  # ── wp-config fragments ────────────────────────────────────────────────────
  # Cloudflare Access, validated in-app by wordpress-jwt-auth in proxy mode.
  # Admin plane only: on the public plane this plugin would refuse every password
  # login, including the visitor accounts that plane exists to serve, which is why
  # plane.excludePlugins drops it there.
  jwtDefines = lib.optionalString isAdmin ''
    define('JWT_AUTH_JWKS_URI', ${quote "https://${params.cloudflareTeam}.cloudflareaccess.com/cdn-cgi/access/certs"});
    define('JWT_AUTH_ISSUER', ${quote "https://${params.cloudflareTeam}.cloudflareaccess.com"});
    define('JWT_AUTH_AUD', ${quote params.accessAud});
    define('JWT_AUTH_TOKEN_COOKIE', 'CF_Authorization');
    define('JWT_AUTH_TOKEN_HEADER', 'Cf-Access-Jwt-Assertion');
    define('JWT_AUTH_LOGOUT_URL', '/cdn-cgi/access/logout');
  '';

  # Media offload (wp-cloud-files). BOTH planes, with the same public URL, so a
  # URL in the shared database resolves identically whichever face served it.
  # The public plane gets the credentials too: the plugin's credential-less mode
  # is gated on a non-production environment type and would otherwise no-op.
  r2Defines = lib.optionalString (params ? r2) ''
    // No S3_UPLOAD_ACL: R2 and public buckets reject ACLs.
    define('S3_KEY', ${readSecret "r2-media-key"});
    define('S3_SECRET', ${readSecret "r2-media-secret"});
    define('S3_BUCKET', ${quote params.r2.bucket});
    define('S3_ENDPOINT', ${quote params.r2.endpoint});
    define('S3_PUBLIC_URL', ${quote params.r2.publicUrl});
  '';

  # Mail (wordpress-cloudflare-email). BOTH planes: a donation receipt or a form
  # notification is sent by whichever face took the request, and Action Scheduler
  # sends the rest from the admin plane.
  emailDefines = lib.optionalString (params ? email) ''
    define('CLOUDFLARE_EMAIL_ACCOUNT_ID', ${quote params.email.accountId});
    define('CLOUDFLARE_EMAIL_API_TOKEN', ${readSecret "cf-email-token"});
    define('CLOUDFLARE_EMAIL_FROM', ${quote params.email.from});
    define('CLOUDFLARE_EMAIL_FROM_NAME', ${quote params.email.fromName});
  '';

  # ── secrets ────────────────────────────────────────────────────────────────
  commonSecrets = {
    "wp-salts" = {
      generator = gen;
      file = "wp-salts";
    };
    "db-password" = {
      generator = gen;
      file = "db-password";
    };
  }
  // lib.optionalAttrs (params ? r2) {
    "r2-media-key" = {
      generator = genApi;
      file = "r2-media-key";
    };
    "r2-media-secret" = {
      generator = genApi;
      file = "r2-media-secret";
    };
  }
  // lib.optionalAttrs (params ? email) {
    "cf-email-token" = {
      generator = genApi;
      file = "cf-email-token";
    };
  };

  # Only the admin plane pushes to git.
  adminSecrets = {
    "git-deploy-key" = {
      generator = genGit;
      file = "deploy-key";
    };
  };

  apiPrompts =
    lib.optionalAttrs (params ? r2) {
      "r2-media-key" = {
        description = "${slug}: R2 access key id";
        persist = true;
      };
      "r2-media-secret" = {
        description = "${slug}: R2 secret access key";
        type = "hidden";
        persist = true;
      };
    }
    // lib.optionalAttrs (params ? email) {
      "cf-email-token" = {
        description = "${slug}: Cloudflare Email Sending API token";
        type = "hidden";
        persist = true;
      };
    };
in
{
  # ── the site's secrets ─────────────────────────────────────────────────────
  # share = true throughout: one value per SITE for the whole fleet. Both planes
  # read the same salts (so neither invalidates the other's sessions) and the same
  # database password; a per-machine value would mint a new one the first time a
  # plane moved node.
  generators = {
    # Pure random, ours to choose. Separate from the deploy key so rotating these
    # does not mean re-registering with GitHub.
    ${gen} = {
      share = true;
      files.wp-salts = wpOwned;
      files.db-password = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      script = ''
        for k in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY \
                 AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
          printf "define('%s', '%s');\n" "$k" "$(openssl rand -base64 48 | tr -d '\n')"
        done > "$out/wp-salts"
        openssl rand -hex 24 | tr -d '\n' > "$out/db-password"
      '';
    };

    ${genGit} = {
      share = true;
      files."deploy-key" = wpOwned;
      # The public half is readable at EVAL time (clanLib.getPublicValue), so
      # tooling can register the deploy key with GitHub without decrypting.
      files."deploy-key.pub".secret = false;
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssh
      ];
      script = ''
        ssh-keygen -t ed25519 -N "" -C ${lib.escapeShellArg "${slug}-deploy"} -f "$out/deploy-key"
      '';
    };
  }
  // lib.optionalAttrs (apiPrompts != { }) {
    # Issued at Cloudflare, so it cannot be generated: vars scripts run in an
    # offline sandbox. Prompts, fed non-interactively by the provisioning tool.
    ${genApi} = {
      share = true;
      prompts = apiPrompts;
      files = lib.mapAttrs (_: _: wpOwned) apiPrompts;
    };
  };

  # ── the database the two planes share ──────────────────────────────────────
  database = {
    database = dbName;
    user = dbUser;
    secret = {
      generator = gen;
      file = "db-password";
    };
  };

  # ── this plane's container ─────────────────────────────────────────────────
  plane = {
    # Pinned: the shared uploads directory and the admin plane's git working tree
    # make a site node-bound today, and the database is on one node's local disk.
    tier = lib.mkDefault "monolith";

    module = {
      imports = [ inputs.wordpress-nix.nixosModules.default ];

      # The shared uploads directory means both planes must agree on the uid.
      users.users.wordpress.uid = wpUid;
      users.groups.wordpress.gid = wpUid;

      services.wordpress-nix = {
        enable = true;
        php = params.php or pkgs.php84;

        # Unix socket only: nothing in the container listens on the network. TLS
        # terminates at the Cloudflare edge, and `domain` would enable ACME.
        domain = "";
        inherit socketPath;
        openFirewall = false;

        plane = {
          inherit role;
          publicUrl = params.publicUrl;
          adminUrl = adminUrl;
          # Visitor logins on the public face. Needed by membership, social
          # login and WooCommerce "my account"; privileged users are refused
          # regardless, by platform-public-plane.php.
          allowLogin = params.allowLogin or false;
        };

        source =
          if isPublic then
            {
              # An immutable store docroot: core, the site repo at its pinned
              # rev, and the platform mu-plugins, composed at build time.
              type = "git";
              path = docroot;
            }
          else
            {
              # Mutable wp-content, seeded once from the site repo; gitium
              # commits wp-admin's changes and pushes them back.
              type = "managed";
              siteRepo = {
                url = params.repoUrl;
                branch = params.branch or "main";
                deployKeyFile = secretPath "git-deploy-key";
              };
            };

        saltsFile = secretPath "wp-salts";

        database = {
          type = "mysql";
          createLocally = false;
          host = params.dbHost;
          port = params.dbPort or 3306;
          name = dbName;
          user = dbUser;
          passwordFile = secretPath "db-password";
        };

        # Distinguishable in Loki: APP_SITE is the plane, not just the site.
        logging.site = if isPublic then slug else "${slug}-admin";

        configExtra = ''
          ${jwtDefines}
          ${r2Defines}
          ${emailDefines}
          ${params.configExtra or ""}
        '';
      };

      # NB: no `networking.firewall.enable = false`. The container is bridged
      # onto br-wan and bridged frames bypass the host's ip/ip6 hooks, so host
      # nftables does NOT govern that interface — the container firewalls itself.
    };

    juicefsPaths =
      if isAdmin then
        {
          # The whole WP root: the docroot, the mutable wp-content and its .git.
          "/var/lib/wordpress" = "clients/${slug}/wordpress";
        }
      else
        {
          # The public face's docroot is disposable — a symlink farm into the
          # store, rebuilt on every start. Only uploads is shared state, mounted
          # from the admin plane's tree so both faces see one media directory.
          # It stays writable: form-plugin attachments, generated PDFs and
          # builder CSS are all written by the public face.
          "/var/lib/wordpress/www/wp-content/uploads" = "clients/${slug}/wordpress/www/wp-content/uploads";
        };

    secrets = commonSecrets // lib.optionalAttrs isAdmin adminSecrets;

    # One tunnel per hostname, each run inside its own container. Cloudflare
    # steers to the closest connector without route awareness, so two hostnames
    # sharing a tunnel would serve each other's traffic. Credentials come from
    # the per-app `<name>-cf` generator modules/apps.nix declares by default.
    # The hostname is stated plainly here; modules/kinds/wordpress.nix is what
    # makes it conditional on the tunnel id existing, because a site is declared
    # (and its vars generated) before its tunnel is created, and a hostname
    # without an id is an eval error.
    tunnel = {
      ingress =
        if isPublic then
          lib.genAttrs ([ publicHost ] ++ publicAliases) (_: "unix:${socketPath}")
        else
          { ${params.adminHost} = "unix:${socketPath}"; };
      # The admin face is gated by Access at the edge (jwtDefines below).
      accessProtected = lib.optional isAdmin params.adminHost;
      socketGroups = [ "wordpress" ];
    };

    service = {
      name = if isPublic then slug else "${slug}-admin";
      port = 80;
    };

    resources = {
      # The public face serves cached-ish reads from one PHP pool; the admin face
      # runs cron, Action Scheduler and plugin installs.
      cpu = lib.mkDefault 1000;
      memoryMB = lib.mkDefault (if isPublic then 1024 else 2048);
    };
  };
}
