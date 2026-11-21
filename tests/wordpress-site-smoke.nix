# One Bedrock site (tests/fixtures/bedrock-site), built by wordpress-nix and served by
# the wordpress kind (modules/kinds/wordpress.nix) on the fixture node1: its real
# machine module, with the app catalogue replaced by the site and one preview slot of it.
#
#   - Nomad places the site; MariaDB, the migrate unit and FrankenPHP come up, and the
#     site answers through its socket, the way the tunnel reaches it
#   - installed, it serves its home page, the REST API and the login page; the
#     classic /wp-admin path redirects into Bedrock's /wp; nothing under uploads runs
#     as PHP; the code tree cannot be written, not even by PHP, and a plugin cannot
#     be installed from a file
#   - its journal has no permission error from FrankenPHP, PHP or wp-cli
#   - backed up, damaged and restored with `cluster-restore --db-only`, the database
#     is the one backed up
#   - a preview slot, started by hand (the pipeline's agent starts them on a real
#     site): staging, no cron, no S3 key, mail short-circuited, and its home and its
#     content, plugin and theme URLs taken from whatever hostname the request named
#
# What it needs from wordpress-nix: v3's lib.mkBedrockSite and NixOS module. The site's
# vendor tree is a fixed-output derivation fetched from Composer's registries, so a
# build without a substituter needs the network (the sandbox allows that to an FOD).
#
# Run: nix build .#checks.x86_64-linux.wordpress-site-smoke -L   (needs KVM)
{
  pkgs,
  lib,
  mkSite,
  topology,
  wordpressNix,
}:
let
  site = mkSite topology;
  machine = site.nixosConfigurations.node1;

  # The fixture's salts and S3 secret, as env files Bedrock parses: the placeholders
  # the harness writes by default are not.
  salts = pkgs.writeText "fixture-wordpress-env" (
    lib.concatMapStrings (k: "${k}='fixture-${lib.toLower k}-0123456789abcdef'\n") [
      "AUTH_KEY"
      "SECURE_AUTH_KEY"
      "LOGGED_IN_KEY"
      "NONCE_KEY"
      "AUTH_SALT"
      "SECURE_AUTH_SALT"
      "LOGGED_IN_SALT"
      "NONCE_SALT"
    ]
  );
  cloudFiles = pkgs.writeText "fixture-wordpress-cloud-files" ''
    S3_KEY='fixture-key'
    S3_SECRET='fixture-secret'
  '';

  harness = import ./lib/cluster-harness.nix {
    inherit pkgs lib topology;
    extraFixtureSources = {
      "demo-site/env" = salts;
      "demo-site-cloud-files/cloud-files" = cloudFiles;
    };
  };

  package = wordpressNix.lib.mkBedrockSite {
    inherit pkgs;
    name = "fixture-site";
    src = ./fixtures/bedrock-site;
  };

  # A plugin to install from a file: the VM has no route to wordpress.org, so an install
  # by slug would fail on the download, read-only tree or not.
  helloZip = pkgs.runCommand "hello-plugin.zip" { nativeBuildInputs = [ pkgs.zip ]; } ''
    mkdir hello
    printf '<?php\n/* Plugin Name: Hello */\n' > hello/hello.php
    zip -qr $out hello
  '';

  domain = "demo-site.example.org";
  previewHost = "pr-1-demo-site.preview.example.net";
  wordpress = {
    inherit package domain;
    # Named, so the settings are what a real site's are; nothing here reaches it.
    media = {
      bucket = "fixture-media";
      endpoint = "https://s3.example.net";
      publicUrl = "https://media.example.org";
      # The host's copies need the mirror's keys and buckets: tests/backup-roundtrip.nix
      # proves hostPostCommand, and checks.wordpress what this kind puts in it.
      backup = false;
    };
    devRestore = false;
  };

  siteApps =
    { lib, ... }:
    {
      clusterApps = lib.mkForce {
        # The fixture's demo-site, whose secrets the fixture has (tests/fixtures/secrets).
        demo-site = {
          inherit wordpress;
          module =
            { pkgs, ... }:
            {
              environment.systemPackages = [ pkgs.curl ];
              environment.etc."wordpress-smoke/hello.zip".source = helloZip;
            };
        };
        # A preview slot, as modules/apps.nix makes one from preview.slots = 1 (which
        # needs the cluster-ci Worker and ZFS, neither of which this VM has).
        demo-site-pv1 = {
          inherit wordpress;
          preview.of = "demo-site";
          backup.enable = false;
          module =
            { pkgs, ... }:
            {
              environment.systemPackages = [ pkgs.curl ];
            };
        };
      };
    };
in
pkgs.testers.runNixOSTest {
  name = "wordpress-site-smoke";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machine._module.specialArgs [ "modulesPath" ];

  nodes = {
    wan = harness.wanNode;
    node1 = {
      imports = [
        site.machineModules.node1
        (harness.nodeModule { memoryMB = 6144; })
        siteApps
      ];
    };
  };

  testScript =
    { nodes, ... }:
    ''
      ${harness.pythonHelpers}

      import shlex

      DOMAIN = "${domain}"
      PREVIEW = "${previewHost}"

      def guest(app, cmd):
          return node1.succeed(f"nixos-container run {app} -- {cmd}")

      def wp(app, args):
          return guest(app, f"runuser -u wordpress -- wp {args}").strip()

      # Through the socket, as the tunnel's connector asks it.
      def get(app, path, host=DOMAIN, fmt="%{http_code}"):
          return guest(app, f"curl -sS -o /dev/null -w {shlex.quote(fmt)} --max-time 30"
                            f" --unix-socket /run/wordpress/wp.sock -H 'Host: {host}'"
                            f" -H 'X-Forwarded-Proto: https' http://localhost{path}").strip()

      def body(app, path, host=DOMAIN):
          return guest(app, f"curl -sS --max-time 30 --unix-socket /run/wordpress/wp.sock"
                            f" -H 'Host: {host}' -H 'X-Forwarded-Proto: https' http://localhost{path}")

      def up(app):
          for unit in ("mysql", "wordpress-migrate", "frankenphp"):
              node1.wait_until_succeeds(
                  f"nixos-container run {app} -- systemctl is-active {unit}.service"
                  f" || nixos-container run {app} -- systemctl show -p Result {unit}.service | grep -qx Result=success",
                  timeout=300)

      def install(app, url):
          wp(app, f"core install --url={url} --title=Fixture --admin_user=admin"
                  " --admin_password=fixture-password --admin_email=admin@example.org --skip-email")
          # Pretty permalinks, as a converted site has: with plain ones /wp-json/ is the
          # home page, with a 200. (Not `wp rewrite structure`, which runs a second wp-cli
          # through proc_open.)
          wp(app, "option update permalink_structure /%postname%/")
          wp(app, "rewrite flush")

      wan.start()
      wan.wait_for_unit("s3.service")
      node1.start()
      node1.wait_for_unit("multi-user.target")

      with subtest("Nomad places the site, and it answers through its socket"):
          node1.wait_for_unit("nomad-bootstrap.service")
          node1.wait_until_succeeds("systemctl is-active --quiet container@demo-site.service", timeout=900)
          up("demo-site")
          # Not installed yet: the migrate unit had nothing to migrate and said so.
          guest("demo-site", "test -S /run/wordpress/wp.sock")

      with subtest("installed, the site serves; old admin paths move into /wp"):
          install("demo-site", f"https://{DOMAIN}")
          assert get("demo-site", "/") == "200"
          assert get("demo-site", "/wp-json/") == "200"
          assert get("demo-site", "/wp/wp-login.php") == "200"
          assert get("demo-site", "/wp-admin/") == "301"
          assert get("demo-site", "/wp-admin/", fmt="%{redirect_url}").endswith("/wp/wp-admin/")
          home = json.loads(body("demo-site", "/wp-json/"))["home"]
          assert home == f"https://{DOMAIN}", home
          assets = wp("demo-site", "eval 'echo parse_url(content_url(), PHP_URL_HOST);'")
          assert assets == DOMAIN, assets

      with subtest("nothing under uploads runs as PHP; private prefixes are refused"):
          guest("demo-site", "install -D -o wordpress -g wordpress /dev/null /var/lib/wordpress/uploads/2024/01/x.php")
          guest("demo-site", "sh -c 'echo \"<?php echo 1;\" > /var/lib/wordpress/uploads/2024/01/x.php'")
          assert get("demo-site", "/app/uploads/2024/01/x.php") == "403"
          guest("demo-site", "install -D -o wordpress -g wordpress /dev/null /var/lib/wordpress/uploads/woocommerce_uploads/a.zip")
          assert get("demo-site", "/app/uploads/woocommerce_uploads/a.zip") == "403"

      with subtest("the code tree is read-only, to PHP too"):
          said = wp("demo-site", "eval 'echo @file_put_contents(ABSPATH . \"probe.txt\", \"x\") === false ? \"ro\" : \"rw\";'")
          assert said == "ro", said
          # From a local file the service user owns, so nothing but the tree can refuse it.
          guest("demo-site", "install -o wordpress -g wordpress -m 0644 /etc/wordpress-smoke/hello.zip /var/lib/wordpress/hello.zip")
          out = node1.fail("nixos-container run demo-site -- runuser -u wordpress -- wp plugin install /var/lib/wordpress/hello.zip 2>&1")
          assert "Could not create directory" in out, out
          node1.fail("nixos-container run demo-site -- runuser -u wordpress -- wp plugin is-installed hello")

      with subtest("no permission errors in the site's journal"):
          log = guest("demo-site", "journalctl -o cat --no-pager -u frankenphp -u wordpress-migrate -u wordpress-cron")
          for bad in ("Permission denied", "Read-only file system", "EACCES", "EROFS"):
              assert bad not in log, f"{bad} in the journal:\n{log}"

      with subtest("backed up, damaged, restored with --db-only"):
          node1.succeed("cluster-backup demo-site")
          wp("demo-site", "option update blogname Damaged")
          node1.succeed("cluster-restore demo-site --db-only --yes")
          up("demo-site")
          assert wp("demo-site", "option get blogname") == "Fixture"

      with subtest("a preview slot: staging, no cron, no S3 key, no mail, home from the request"):
          # What the agent does: clone production's dataset (here an empty one, installed
          # below) and point the slot's profile at the guest it built.
          node1.succeed("mkdir -p /state-preview/demo-site-pv1/clients/demo-site/mysql")
          node1.succeed("mkdir -p /nix/var/nix/profiles/per-container/demo-site-pv1"
                        " && ln -sfn ${nodes.node1.containers.demo-site-pv1.config.system.build.toplevel}"
                        " /nix/var/nix/profiles/per-container/demo-site-pv1/system")
          node1.succeed("systemctl start container@demo-site-pv1.service")
          up("demo-site-pv1")
          install("demo-site-pv1", f"https://{DOMAIN}")
          guest("demo-site-pv1", "test ! -e /run/secrets/cloud-files")
          guest("demo-site-pv1", "test -e /run/secrets/env")
          node1.fail("nixos-container run demo-site-pv1 -- systemctl is-active wordpress-cron.timer")
          assert wp("demo-site-pv1", "eval 'echo WP_ENV;'") == "staging"
          assert wp("demo-site-pv1", "eval 'echo defined(\"S3_KEY\") || getenv(\"S3_KEY\") ? \"key\" : \"none\";'") == "none"
          assert wp("demo-site-pv1", "eval 'echo has_filter(\"pre_wp_mail\") ? \"off\" : \"on\";'") == "off"
          assert get("demo-site-pv1", "/wp-json/", host=PREVIEW) == "200"
          home = json.loads(body("demo-site-pv1", "/wp-json/", host=PREVIEW))["home"]
          assert home == f"https://{PREVIEW}", home
          # Its theme's and plugins' assets are its own, not production's: Bedrock makes
          # WP_CONTENT_URL from WP_HOME, which is production's on a slot too.
          for fn in ("content_url()", "plugins_url()", "get_theme_root_uri()"):
              host = wp("demo-site-pv1", f"--url=https://{PREVIEW} eval 'echo parse_url({fn}, PHP_URL_HOST);'")
              assert host == PREVIEW, f"{fn}: {host}"
          # Production is untouched by all of it.
          assert get("demo-site", "/wp-json/") == "200"
    '';
}
