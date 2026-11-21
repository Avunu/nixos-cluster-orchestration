# modules/kinds/wordpress.nix — clusterApps.<name>.wordpress: a Bedrock WordPress site.
#
#   wordpress = { package; domain; extraDomains; stagingDomain; settings; profile;
#                 access.adminPaths; applicationPasswords; media; devRestore; };
#
# A Tier-0 monolith, the frappe kind's shape: wordpress-nix's FrankenPHP serving the
# site's Composer-built Bedrock tree over a unix socket, with a local MariaDB, in one
# container on whichever node Nomad picks. The code is the package, an immutable store
# path (Bedrock's DISALLOW_FILE_MODS): a plugin or core change is a commit to the site's
# repository, which reaches here as a bump of its flake input. MariaDB's data is on the
# node's local ZFS (unix_socket auth, so no password), and the one writable directory
# the web serves, uploads, is on JuiceFS and follows the app: what a plugin writes there
# that is not an attachment (builder CSS, fonts, form uploads, private downloads).
# Attachments go to the site's own R2 bucket through wp-cloud-files.
#
# The package comes from the site's flake input, which follows the cluster's
# wordpress-nix (`inputs.wordpress-nix.follows = "cluster/wordpress-nix"`), so the
# module here and the build there are one version.
#
# Its tunnel is in the account of the site's own zone, made by `wordpress-nix edge
# provision`, which sets tunnel.id and tunnel.accountId in apps/<name>.json: `avc cloud`
# leaves it and its DNS alone (lib/cloud.nix). Every hostname is routed from the first
# deploy; DNS decides which one gets traffic, so a cutover is a DNS change.
#
# The site is not created here: `wordpress-nix site import` loads the converted
# database after the first start. Deploys then migrate it (`wp core update-db`).
{
  inputs,
  lib,
  pkgs,
  config,
  topology,
  clusterLib,
  ...
}:
let
  inherit (lib) mkOption types;
  wp = clusterLib.wordpress;
  os = topology.objectStorage;

  # Sized so the worst case fits (memory_limit × threads + InnoDB pool + 384 MiB),
  # with wordpress-nix's `profile` choosing the threads, limits and pool to match.
  memoryMB = {
    brochure = 1280;
    woocommerce = 2560;
  };

  # The service user, pinned: the secrets the service reads itself are bind-mounted
  # from the host as they are, so they are made the user's by number (the user exists
  # only inside the container, and containers share the host's uids). A root 0400 file
  # is unreadable to `wordpress`, which is how a site once failed wordpress-init.
  wpUid = 980;
  wpOwned = {
    owner = toString wpUid;
    group = toString wpUid;
  };

  mediaType = types.submodule {
    options = {
      bucket = mkOption {
        type = types.str;
        example = "wp-acme-media";
        description = "The site's R2 bucket (`wordpress-nix media provision`).";
      };
      endpoint = mkOption {
        type = types.str;
        example = "https://<account id>.r2.cloudflarestorage.com";
        description = "Its S3 endpoint.";
      };
      publicUrl = mkOption {
        type = types.str;
        example = "https://media.acme.example";
        description = "Where the bucket is served: what attachment URLs start with.";
      };
      backup = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Copy the bucket nightly into the cluster's media mirror
          (lib/wordpress.nix), with the read-only key in `<name>-media-ro`,
          on the host that backs the site up. R2 keeps no object versions: this
          copy is what brings back a file the site deleted.
        '';
      };
    };
  };

  wordpressType = types.submodule {
    options = {
      package = mkOption {
        type = types.package;
        description = "The site: wordpress-nix's Bedrock build, inputs.site-<name>.packages.x86_64-linux.default.";
      };
      domain = mkOption {
        type = types.str;
        example = "acme.example";
        description = "The site's hostname: WP_HOME is https://<domain>.";
      };
      extraDomains = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "www.acme.example" ];
        description = "More hostnames routed to the site, which WordPress redirects to `domain`.";
      };
      stagingDomain = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "staging.acme.example";
        description = ''
          A hostname the site answers on before its domain's DNS moves here: where
          a conversion is verified. Routed like the others.
        '';
      };
      profile = mkOption {
        type = types.enum [
          "brochure"
          "woocommerce"
        ];
        default = "brochure";
        description = ''
          wordpress-nix's sizing: PHP threads, memory_limit, WP_MAX_MEMORY_LIMIT and
          the InnoDB buffer pool. It also sets the app's resources.memoryMB
          (brochure 1280, woocommerce 2560), so the worst case fits its reservation.
        '';
      };
      settings = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = {
          WP_DEBUG_LOG = "false";
        };
        description = ''
          Non-secret variables for Bedrock's environment, over the kind's own (WP_HOME,
          WP_ENV, the S3_* names of `media`). Secrets go in the `<name>-cloud-files`
          secret, never here: this is a Nix value and lands in the store.
        '';
      };
      access.adminPaths = mkOption {
        type = types.bool;
        default = false;
        description = ''
          wp-admin and wp-login.php are behind a path-scoped Cloudflare Access
          application, which `wordpress-nix edge provision` makes in the zone's
          account. Passed to the site as WORDPRESS_NIX_ACCESS_ADMIN_PATHS, so it can
          refuse an admin request without Access's assertion. For sites without
          public logins (no shop, no members).
        '';
      };
      applicationPasswords = mkOption {
        type = types.bool;
        default = false;
        description = "Allow WordPress application passwords (WORDPRESS_NIX_APPLICATION_PASSWORDS). Off: a stolen one is a login that skips two-factor.";
      };
      media = mkOption {
        type = types.nullOr mediaType;
        default = null;
        description = "The site's media bucket, for wp-cloud-files; null = attachments stay in uploads on JuiceFS.";
      };
      devRestore = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Upload each night's database dump, gzipped, to the cluster's dev-restore
          bucket (lib/wordpress.nix), from the host that backs the site up: what a
          developer's `wp restore` fetches. Kept 30 days.
        '';
      };
    };
  };

  # Not the preview slots: a slot reads the secrets of the app it copies.
  apps = lib.filterAttrs (_: a: a.wordpress != null && a.preview.of == null) config.clusterApps;
  mirrored = wp.mirroredApps apps;

  secretPath = g: f: config.cluster.secrets.generators.${g}.files.${f}.path;

  # An S3 key pair issued by the provider: prompted, on every node, in no container.
  s3Prompts = what: {
    share = true;
    prompts.access-key = {
      description = "S3 access key id for ${what}";
      persist = true;
    };
    prompts.secret-key = {
      description = "Its secret";
      type = "hidden";
      persist = true;
    };
  };
in
{
  options.clusterApps = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        let
          w = config.wordpress;
          # Own directory, not /run itself: FrankenPHP runs unprivileged. The connector
          # reaches the socket through the `wordpress` group.
          socket = "/run/wordpress/wp.sock";
          # On a preview slot these name the app it copies (modules/app-container.nix).
          pv = config.preview;
          isPreview = pv.of != null;
          home = "https://${w.domain}";
          hostnames = [
            w.domain
          ]
          ++ w.extraDomains
          ++ lib.optional (w.stagingDomain != null) w.stagingDomain;

          # What Bedrock reads from its environment (wordpress-nix assembles it from
          # these and the secrets' env files). The rest of Bedrock's -- DB_*,
          # DISABLE_WP_CRON, WP_TEMP_DIR -- is wordpress-nix's own.
          kindSettings = {
            WP_ENV = if isPreview then "staging" else "production";
            WORDPRESS_NIX_APPLICATION_PASSWORDS = lib.boolToString w.applicationPasswords;
            WORDPRESS_NIX_ACCESS_ADMIN_PATHS = lib.boolToString w.access.adminPaths;
          }
          # A slot answers under whatever hostname its preview was given, which is
          # known only when the preview is made: WordPress takes its home from the
          # request there, and only there (staging).
          // (
            if isPreview then
              { WORDPRESS_NIX_HOME_FROM_REQUEST = "true"; }
            else
              {
                WP_HOME = home;
                WP_SITEURL = "${home}/wp";
              }
          )
          # Where attachments are. A slot gets these and no key: wp-cloud-files'
          # read-only mode, so a preview serves production's media and cannot change it.
          // lib.optionalAttrs (w.media != null) {
            S3_BUCKET = w.media.bucket;
            S3_ENDPOINT = w.media.endpoint;
            S3_PUBLIC_URL = w.media.publicUrl;
          };

          # ── the host's nightly copies (backup.hostPostCommand) ───────────────
          # On the node that backed the site up, after its snapshot: the media bucket
          # into the mirror, and the dump into the dev-restore bucket. rclone is
          # configured from the environment, and the keys are the host's: no container
          # holds them.
          rclone = "${pkgs.rclone}/bin/rclone";
          s3Remote = remote: provider: endpoint: region: keyGen: ''
            export RCLONE_CONFIG_${remote}_TYPE=s3 RCLONE_CONFIG_${remote}_PROVIDER=${provider}
            export RCLONE_CONFIG_${remote}_ENDPOINT=${lib.escapeShellArg endpoint} RCLONE_CONFIG_${remote}_REGION=${lib.escapeShellArg region}
            RCLONE_CONFIG_${remote}_ACCESS_KEY_ID=$(cat ${secretPath keyGen "access-key"})
            RCLONE_CONFIG_${remote}_SECRET_ACCESS_KEY=$(cat ${secretPath keyGen "secret-key"})
            export RCLONE_CONFIG_${remote}_ACCESS_KEY_ID RCLONE_CONFIG_${remote}_SECRET_ACCESS_KEY
          '';
          # Not on a preview slot, which is never backed up and has no keys of its own.
          mirrorMedia = !isPreview && w.media != null && w.media.backup;
          hostPost =
            lib.optionalString mirrorMedia ''
              ${s3Remote "MEDIA" "Cloudflare" w.media.endpoint "auto" "${name}-media-ro"}
              ${s3Remote "MIRROR" "Other" os.endpoint os.region wp.mediaMirrorGenerator}
              # copy, never sync: a file deleted in R2 stays here, its older versions too.
              ${rclone} copy --checksum media:${lib.escapeShellArg w.media.bucket} \
                mirror:${lib.escapeShellArg "${wp.mediaMirrorBucket os}/${name}"}
              echo "$APP: media copied to the mirror"
            ''
            + lib.optionalString (!isPreview && w.devRestore) ''
              ${s3Remote "DEVRESTORE" "Other" os.endpoint os.region wp.devRestoreGenerator}
              dest=devrestore:${lib.escapeShellArg "${wp.devRestoreBucket os}/wordpress/${name}"}
              db=$(head -n 1 "$BACKUP_STAGING/databases")
              ${pkgs.gzip}/bin/gzip -c "$BACKUP_STAGING/$db.sql" \
                | ${rclone} rcat "$dest/$(date -u +%Y%m%dT%H%M%SZ).sql.gz"
              ${rclone} delete --min-age 30d "$dest"
              echo "$APP: dump uploaded for dev restores"
            '';
        in
        {
          options.wordpress = mkOption {
            type = types.nullOr wordpressType;
            default = null;
            description = "A Bedrock WordPress site (modules/kinds/wordpress.nix).";
          };

          config = lib.mkIf (config.wordpress != null) {
            tier = lib.mkDefault "monolith";

            module = {
              imports = [ inputs.wordpress-nix.nixosModules.default ];
              services.wordpress-nix = {
                enable = true;
                inherit (w) package profile;
                socketPath = socket;
                database.createLocally = true;
                # The salts; and, outside a preview, the S3 key and mail token. A slot's
                # database is production's, a moment ago: with no key it cannot change
                # production's bucket, and its mail and cron stay off (WP_ENV=staging).
                environmentFiles = [ "/run/secrets/env" ] ++ lib.optional (!isPreview) "/run/secrets/cloud-files";
                settings = kindSettings // w.settings;
                cron.enable = !isPreview;
                migrate.enable = true;
                logging.site = pv.base;
              };
              users.users.wordpress.uid = wpUid;
              users.groups.wordpress.gid = wpUid;
              # DB-on-ZFS: recordsize=16k = InnoDB page, and ZFS record writes
              # are atomic, so the doublewrite buffer is pure overhead.
              services.mysql.settings.mysqld.innodb_doublewrite = 0;
            };

            # What PHP writes outside attachments -- shared, follows the app, served by
            # file_server only, never PHP.
            juicefsPaths."/var/lib/wordpress/uploads" = "${pv.jfsRoot}/uploads";
            # MariaDB data -- local disk, in the app's own dataset, never JuiceFS.
            localState."/var/lib/mysql" = "${pv.stateRoot}/clients/${pv.base}/mysql";

            secrets = {
              env = {
                generator = pv.base;
                file = "env";
              };
            }
            // lib.optionalAttrs (!isPreview) {
              cloud-files = {
                generator = "${name}-cloud-files";
                file = "cloud-files";
              };
            };

            backup = {
              # The rehearsal's database came back as WordPress's: an options table.
              verifyQuery = lib.mkDefault "select count(*) from information_schema.tables where table_schema = database() and table_name like '%options'";
              hostPostCommand = lib.mkIf (hostPost != "") hostPost;
            };

            resources = {
              cpu = lib.mkDefault 1000;
              memoryMB = lib.mkDefault memoryMB.${w.profile};
            };

            preview.origin = "unix:${socket}";
            preview.socketGroups = [ "wordpress" ];
            preview.healthPath = lib.mkDefault "/wp-json/";

            # Conditions on the leaves, not on `tunnel` (see kinds/odoo.nix). Every
            # hostname from the first deploy: DNS decides which one is live.
            tunnel = {
              ingress = lib.mkIf (config.tunnel.id != "") (lib.genAttrs hostnames (_: "unix:${socket}"));
              socketGroups = lib.mkIf (config.tunnel.id != "") [ "wordpress" ];
              probePath = lib.mkDefault "/wp-json/";
            };

            service = {
              inherit name;
              port = 80;
            };
          };
        }
      )
    );
  };

  config = lib.mkMerge [
    {
      # share = true: one value for the fleet, so the site keeps its sessions and its
      # keys wherever it runs.
      cluster.secrets.generators = lib.concatMapAttrs (
        name: a:
        {
          # Bedrock's eight salts, as an env file. Ours to choose, so generated.
          ${name} = {
            share = true;
            files.env = wpOwned;
            runtimeInputs = [
              pkgs.coreutils
              pkgs.openssl
            ];
            script = ''
              for k in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY \
                       AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
                printf "%s='%s'\n" "$k" "$(openssl rand -base64 48 | tr -d '\n')"
              done > "$out/env"
            '';
          };
          # Issued elsewhere, so prompted: an env file with wp-cloud-files' S3_KEY and
          # S3_SECRET (the site's bucket-scoped R2 key) and the CLOUDFLARE_EMAIL_*
          # of its mail. Set it before the first deploy that references it:
          #   avc secrets set <name>-cloud-files/cloud-files
          "${name}-cloud-files" = {
            share = true;
            prompts.cloud-files = {
              description = "${name}: env file, S3_KEY/S3_SECRET (the site's R2 key) and CLOUDFLARE_EMAIL_*";
              type = "multiline-hidden";
              persist = true;
            };
            files.cloud-files = wpOwned;
          };
        }
        // lib.optionalAttrs (a.wordpress.media != null && a.wordpress.media.backup) {
          # A read-only key to the site's bucket, for the nightly mirror. The host's
          # only: no container is given it (backup.hostPostCommand above).
          "${name}-media-ro" = {
            share = true;
            prompts.access-key = {
              description = "${name}: read-only R2 access key id for ${a.wordpress.media.bucket}";
              persist = true;
            };
            prompts.secret-key = {
              description = "${name}: its secret";
              type = "hidden";
              persist = true;
            };
          };
        }
      ) apps;

      assertions = lib.mapAttrsToList (n: a: {
        # The ingress is keyed by hostname: two would silently be one.
        assertion = lib.allUnique (
          [ a.wordpress.domain ]
          ++ a.wordpress.extraDomains
          ++ lib.optional (a.wordpress.stagingDomain != null) a.wordpress.stagingDomain
        );
        message = "clusterApps.${n}: wordpress.domain, extraDomains and stagingDomain name one hostname twice.";
      }) apps;
    }
    {
      # The mirror's and the dev-restore bucket's pairs, one each for the fleet, named as
      # lib/wordpress.nix names them (checks.wordpress holds the two to each other).
      # `avc cloud apply` writes them where the topology has cloud.ovh; else make the
      # buckets and keys by hand.
      cluster.secrets.generators.wordpress-media-mirror = lib.mkIf (mirrored != { }) (
        s3Prompts "the WordPress media mirror (${wp.mediaMirrorBucket os})"
      );
      cluster.secrets.generators.wordpress-dev-restore = lib.mkIf (wp.devRestoreApps apps != { }) (
        s3Prompts "the WordPress dev-restore bucket (${wp.devRestoreBucket os})"
      );
    }
  ];
}
