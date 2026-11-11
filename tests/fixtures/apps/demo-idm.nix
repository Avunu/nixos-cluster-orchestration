# demo-idm — the freeipa kind, with Authelia in front of it.
{ ... }:
{
  homeNode = "node1";
  freeipa = {
    hostname = "idm.example.com";
    domain = "example.com";
    realm = "EXAMPLE.COM";
    privateIp4 = "10.21.0.10";
    authelia = {
      enable = true;
      hostname = "auth.example.com";
      smtpSender = "Sign-in <auth@example.com>";
      oidcClients.oidc-smoke = {
        name = "OIDC smoke test";
        public = true;
        redirectUris = [ "https://oidc.example.net/debug" ];
      };
    };
  };
  tunnel.id = "00000000-0000-4000-8000-000000000003";
}
