# demo-site — the wordpress kind, over a stub Bedrock tree. Its tunnel is in the
# site's own Cloudflare account (tunnel.accountId), as `wordpress-nix edge provision`
# makes it, so `avc cloud` makes nothing for it; its hostnames are in no zone of the
# fixture topology's cloudflare.zones.
{ pkgs, ... }:
{
  wordpress = {
    package = import ../stubs/bedrock.nix { inherit pkgs; };
    domain = "demo-site.example.org";
    extraDomains = [ "www.demo-site.example.org" ];
    stagingDomain = "staging.demo-site.example.org";
    media = {
      bucket = "wp-demo-site-media";
      endpoint = "https://r2.example.net";
      publicUrl = "https://media.demo-site.example.org";
    };
  };
  tunnel = {
    id = "00000000-0000-4000-8000-000000000004";
    accountId = "11111111111111111111111111111111";
  };
}
