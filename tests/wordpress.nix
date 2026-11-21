# Eval-level checks for modules/kinds/wordpress.nix, against the fixture node1
# configuration (the demo-site instance, over a stub Bedrock tree). What the site does
# at run time is wordpress-nix's to prove, and checks.wordpress-site-smoke boots one;
# what can regress here unnoticed is the wiring.
#
# Run: nix build .#checks.<system>.wordpress
{
  pkgs,
  lib,
  topology,
  nodeSystem,
}:
let
  c = nodeSystem.config;
  app = c.clusterApps.demo-site;
  container = c.containers.demo-site;
  guest = container.config;
  wp = guest.services.wordpress-nix;
  gens = c.cluster.secrets.generators;
  wordpressLib = (import ../lib { inherit lib; }).wordpress;
  os = topology.objectStorage;

  # The same site as a preview slot (modules/apps.nix makes these from preview.slots,
  # which needs the cluster-ci Worker the fixture has not got), and as a shop.
  extended = nodeSystem.extendModules {
    modules = [
      (
        { lib, ... }:
        {
          clusterApps.demo-site-pv1 = {
            inherit (app) wordpress;
            preview.of = "demo-site";
            backup.enable = false;
          };
          clusterApps.demo-site.wordpress.profile = lib.mkForce "woocommerce";
        }
      )
    ];
  };
  ec = extended.config;
  slot = ec.clusterApps.demo-site-pv1;
  slotWp = ec.containers.demo-site-pv1.config.services.wordpress-nix;

  post = app.backup.hostPostCommand;
  probes = map (p: p.url) (lib.filter (p: p.app == "demo-site") c.cluster.alerting.appProbes);

  checks = [
    {
      name = "one container per site: no admin face, no shared database";
      ok =
        !(c.clusterApps ? demo-site-admin)
        && !(c.clusterApps ? demo-wpdb)
        && app.network.peerAccess == [ ]
        && app.tier == "monolith";
    }
    {
      name = "wordpress-nix serves the site's package over the socket, with its own MariaDB";
      ok =
        wp.enable
        && wp.package == app.wordpress.package
        && wp.socketPath == "/run/wordpress/wp.sock"
        && wp.database.createLocally
        && wp.cron.enable
        && wp.migrate.enable
        && wp.profile == "brochure"
        && guest.services.mysql.settings.mysqld.innodb_doublewrite == 0;
    }
    {
      name = "Bedrock's environment: the salts and the S3 and mail secret as files, the rest as settings";
      ok =
        wp.environmentFiles == [
          "/run/secrets/env"
          "/run/secrets/cloud-files"
        ]
        && wp.settings.WP_ENV == "production"
        && wp.settings.WP_HOME == "https://demo-site.example.org"
        && wp.settings.WP_SITEURL == "https://demo-site.example.org/wp"
        && wp.settings.S3_BUCKET == "wp-demo-site-media"
        && wp.settings.S3_PUBLIC_URL == "https://media.demo-site.example.org"
        && wp.settings.WORDPRESS_NIX_APPLICATION_PASSWORDS == "false"
        && !(wp.settings ? S3_KEY)
        && !(wp.settings ? S3_SECRET)
        && !(wp.settings ? WORDPRESS_NIX_HOME_FROM_REQUEST);
    }
    {
      # The salts and the S3 key are read by the service user itself.
      name = "the env and cloud-files secrets are generated and prompted, shared, and the service user's";
      ok =
        gens.demo-site.share
        && gens.demo-site.files.env.owner == "980"
        && gens.demo-site.files.env.group == "980"
        && guest.users.users.wordpress.uid == 980
        && gens.demo-site-cloud-files.share
        && gens.demo-site-cloud-files.prompts.cloud-files.type == "multiline-hidden"
        && gens.demo-site-cloud-files.files.cloud-files.owner == "980"
        && app.secrets.env.generator == "demo-site"
        && app.secrets.cloud-files.generator == "demo-site-cloud-files";
    }
    {
      # The backup's keys are the host's: nothing in the container could reach the
      # mirror, or the bucket's read-only copy.
      name = "the mirror's keys are on the host and in no container";
      ok =
        gens ? demo-site-media-ro
        && gens ? ${wordpressLib.mediaMirrorGenerator}
        && gens ? ${wordpressLib.devRestoreGenerator}
        &&
          lib.attrNames app.secrets == [
            "cloud-files"
            "env"
          ]
        && !(lib.hasInfix "media-ro" (builtins.toJSON container.bindMounts))
        && !(lib.hasInfix "wordpress-media-mirror" (builtins.toJSON container.bindMounts))
        && !(lib.hasInfix "wordpress-dev-restore" (builtins.toJSON container.bindMounts));
    }
    {
      name = "uploads follow the app on JuiceFS; MariaDB is in the app's dataset";
      ok =
        app.juicefsPaths == {
          "/var/lib/wordpress/uploads" = "data/uploads";
        }
        && app.localState == { "/var/lib/mysql" = "/state/clients/demo-site/mysql"; };
    }
    {
      name = "every hostname is routed from the first deploy, through the socket, to a tunnel in the site's own account";
      ok =
        app.tunnel.ingress == {
          "demo-site.example.org" = "unix:/run/wordpress/wp.sock";
          "www.demo-site.example.org" = "unix:/run/wordpress/wp.sock";
          "staging.demo-site.example.org" = "unix:/run/wordpress/wp.sock";
        }
        && app.tunnel.socketGroups == [ "wordpress" ]
        && app.tunnel.accountId == "11111111111111111111111111111111"
        &&
          app.tunnel.credentials == {
            generator = "demo-site-cf";
            file = "cloudflared";
          };
    }
    {
      name = "alerting probes each hostname at /wp-json/, past the page cache";
      ok =
        lib.sort lib.lessThan probes == [
          "https://demo-site.example.org/wp-json/"
          "https://staging.demo-site.example.org/wp-json/"
          "https://www.demo-site.example.org/wp-json/"
        ];
    }
    {
      name = "the profile sizes the reservation: brochure 1280 MiB, woocommerce 2560";
      ok =
        app.resources.memoryMB == 1280
        && ec.clusterApps.demo-site.resources.memoryMB == 2560
        && ec.containers.demo-site.config.services.wordpress-nix.profile == "woocommerce";
    }
    {
      name = "the nightly backup is MariaDB's dump, rehearsed against an options table";
      ok =
        app.backup.enable
        && app.backup.engine == null
        && guest.services.mysql.enable
        && lib.hasInfix "options" app.backup.verifyQuery;
    }
    {
      # copy, never sync; the mirror and dev-restore buckets are the fleet's, under the
      # site's prefix; the keys are read from the host's secret paths.
      name = "the host copies media into the mirror and the dump into the dev-restore bucket";
      ok =
        post != null
        && lib.hasInfix "rclone copy --checksum media:wp-demo-site-media" post
        && lib.hasInfix "mirror:${wordpressLib.mediaMirrorBucket os}/demo-site" post
        && !(lib.hasInfix " sync " post)
        && lib.hasInfix gens.demo-site-media-ro.files.access-key.path post
        && lib.hasInfix gens.${wordpressLib.mediaMirrorGenerator}.files.secret-key.path post
        && lib.hasInfix "${wordpressLib.devRestoreBucket os}/wordpress/demo-site" post
        && lib.hasInfix ''"$BACKUP_STAGING/$db.sql"'' post
        && lib.hasInfix "delete --min-age 30d" post
        # The keys open objects in one bucket and cannot create one: rclone must not try.
        && lib.hasInfix "RCLONE_CONFIG_MIRROR_NO_CHECK_BUCKET=true" post
        && lib.hasInfix "RCLONE_CONFIG_DEVRESTORE_NO_CHECK_BUCKET=true" post
        && lib.hasInfix "RCLONE_CONFIG_MEDIA_NO_CHECK_BUCKET=true" post;
    }
    {
      # A cutover's staging verification sets only WP_HOME: wp-login and wp-admin must
      # follow it, not stay on the domain that still points at the old host.
      name = "WP_SITEURL follows a site's own WP_HOME, and a site's own WP_SITEURL wins";
      ok =
        let
          with' =
            settings:
            (nodeSystem.extendModules {
              modules = [ { clusterApps.demo-site.wordpress = { inherit settings; }; } ];
            }).config.containers.demo-site.config.services.wordpress-nix.settings;
          staging = with' { WP_HOME = "https://staging.demo-site.example.org"; };
          both = with' {
            WP_HOME = "https://staging.demo-site.example.org";
            WP_SITEURL = "https://core.example.org/wp";
          };
        in
        staging.WP_HOME == "https://staging.demo-site.example.org"
        && staging.WP_SITEURL == "https://staging.demo-site.example.org/wp"
        && both.WP_SITEURL == "https://core.example.org/wp";
    }
    {
      # Both are <prefix>-<name>: one bucket, two owners.
      name = "a JuiceFS volume named like a fleet bucket is refused";
      ok =
        let
          clash =
            v:
            (nodeSystem.extendModules {
              modules = [ { clusterApps.demo-site.juicefsVolume = lib.mkForce v; } ];
            }).config.assertions;
          refused =
            v: lib.any (a: !a.assertion && lib.hasInfix "JuiceFS volume named ${v}" a.message) (clash v);
        in
        refused wordpressLib.mediaMirrorName
        && refused wordpressLib.devRestoreName
        &&
          wordpressLib.mediaMirrorBucket os
          == "${os.appBucketPrefix or os.juicefsBucket}-${wordpressLib.mediaMirrorName}"
        && !(lib.any (a: !a.assertion && lib.hasInfix "JuiceFS volume named" a.message) c.assertions);
    }
    {
      name = "with neither copy wanted, the backup runs no host command and declares no key";
      ok =
        let
          bare =
            (nodeSystem.extendModules {
              modules = [
                {
                  clusterApps.demo-site.wordpress = {
                    media = lib.mkForce null;
                    devRestore = false;
                  };
                }
              ];
            }).config;
        in
        bare.clusterApps.demo-site.backup.hostPostCommand == null
        && !(bare.cluster.secrets.generators ? demo-site-media-ro)
        && !(bare.cluster.secrets.generators ? ${wordpressLib.mediaMirrorGenerator})
        && !(bare.cluster.secrets.generators ? ${wordpressLib.devRestoreGenerator});
    }
    {
      # A slot's database is production's, a moment ago: no key to the bucket (read
      # only), no cron, no mail (WP_ENV=staging), and its home from the request.
      name = "a preview slot: production's salts, no S3 key, staging, cron off, home from the request over a home Bedrock accepts";
      ok =
        slotWp.environmentFiles == [ "/run/secrets/env" ]
        && slot.secrets.env.generator == "demo-site"
        && !(slot.secrets ? cloud-files)
        && slotWp.settings.WP_ENV == "staging"
        && slotWp.settings.WORDPRESS_NIX_HOME_FROM_REQUEST == "true"
        # Bedrock requires both; the request's host replaces them at run time.
        && slotWp.settings.WP_HOME == "https://demo-site.example.org"
        && slotWp.settings.WP_SITEURL == "https://demo-site.example.org/wp"
        && slotWp.settings.S3_BUCKET == "wp-demo-site-media"
        && !slotWp.cron.enable
        && slot.localState == { "/var/lib/mysql" = "/state-preview/demo-site-pv1/clients/demo-site/mysql"; }
        && slot.juicefsPaths == { "/var/lib/wordpress/uploads" = "previews/demo-site-pv1/uploads"; }
        && slot.preview.origin == "unix:/run/wordpress/wp.sock"
        && slot.preview.healthPath == "/wp-json/"
        && slot.backup.hostPostCommand == null
        && !(ec.cluster.secrets.generators ? demo-site-pv1)
        && !(ec.cluster.secrets.generators ? demo-site-pv1-cloud-files);
    }
    {
      name = "a hostname named twice is refused";
      ok =
        let
          twice =
            (nodeSystem.extendModules {
              modules = [ { clusterApps.demo-site.wordpress.extraDomains = [ "demo-site.example.org" ]; } ];
            }).config.assertions;
        in
        lib.any (a: !a.assertion && lib.hasInfix "name one hostname twice" a.message) twice;
    }
  ];

  failed = lib.filter (x: !x.ok) checks;
in
pkgs.runCommand "wordpress-checks" { } (
  if failed == [ ] then
    ''
      echo "${toString (builtins.length checks)} wordpress kind checks passed"
      touch $out
    ''
  else
    ''
      echo "FAILED:" >&2
      ${lib.concatMapStringsSep "\n" (x: ''echo "  - ${x.name}" >&2'') failed}
      exit 1
    ''
)
