# bedrock-site: the fixture of `checks.wordpress-site-smoke`

A stock [Roots Bedrock](https://github.com/roots/bedrock) 1.31.9 tree (MIT, see
`LICENSE.md`), as a converted site would be: `config/` and `web/` untouched, and the
moonshot v3 delta in `composer.json` (the `only` guard on WP Packages,
`config.platform.php`, stable only, no dev tooling). Its only package beyond Bedrock's
own is the default theme. No premium code, no secrets: the salts come from the fixture
secrets (`tests/wordpress-site-smoke.nix`).

wordpress-nix's `lib.mkBedrockSite` builds it; `nix/vendor-hash` is the hash of its
Composer vendor tree, which only wordpress-nix's own recipe can compute. Refresh it the
way a site does, after changing `composer.lock` or moving to a wordpress-nix whose
vendor recipe changed: build the check, and copy the `got:` hash Nix reports into
`nix/vendor-hash` (wordpress-nix's `relock` does the same for a site).

The committed hash was computed with wordpress-nix's `feat/v3-bedrock` branch at
56c35ae, before its v3.0.0 release: rebuild and refresh it if the release's vendor
recipe differs.
