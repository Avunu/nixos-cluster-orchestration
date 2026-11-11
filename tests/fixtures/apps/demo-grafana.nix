# demo-grafana — the grafana kind, signing in through demo-idm's Authelia.
{ ... }:
{
  grafana.hostname = "grafana.example.com";
  oidc.idp = "demo-idm";
  tunnel.id = "00000000-0000-4000-8000-000000000006";
}
