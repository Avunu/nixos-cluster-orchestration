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

The hash committed with this fixture is Nix's placeholder (`lib.fakeHash`) until that
first build: wordpress-nix v3 did not exist when the fixture was made.
