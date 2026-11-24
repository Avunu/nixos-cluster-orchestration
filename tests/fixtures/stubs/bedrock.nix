# Stands in for a site flake's built Bedrock tree (wordpress-nix's lib.mkBedrockSite):
# the layout the module serves from and the passthru it reads, with mkBedrockSite's
# defaults. No test here starts it; checks.wordpress-site-smoke builds a real one
# (tests/fixtures/bedrock-site).
{ pkgs }:
let
  uploadsDir = "/var/lib/wordpress/uploads";
  envFile = "/run/wordpress/bedrock.env";
in
pkgs.runCommand "demo-site-stub"
  {
    passthru.wordpressNix = {
      inherit uploadsDir envFile;
      php = pkgs.php84;
      wordpressVersion = "0.0.0";
      vendor = pkgs.emptyDirectory;
      productionOnlyPlugins = [ ];
      developmentOnlyPlugins = [ ];
      activeTheme = null;
    };
  }
  ''
    mkdir -p $out/config $out/vendor $out/web/wp/wp-includes $out/web/app/mu-plugins
    touch $out/config/application.php $out/vendor/autoload.php $out/web/index.php \
      $out/web/wp-config.php $out/web/wp/wp-includes/version.php
    ln -s ${uploadsDir} $out/web/app/uploads
    ln -s ${envFile} $out/.env
  ''
