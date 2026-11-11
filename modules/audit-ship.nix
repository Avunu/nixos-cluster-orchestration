# modules/audit-ship.nix — the audit trail's wiring: topology and clan vars into
# modules/audit-ship-core.nix (which says what is sent and how).
#
#   topology.alerting.auditUrl   the watchdog Worker's /event URL. Null turns the trail
#                                off, which only a node that opted out of boot security
#                                may do (modules/boot-security.nix refuses it otherwise).
#   `audit/token`                per machine (modules/vars.nix). The Worker knows each by
#                                its AUDIT_TOKENS secret, which `avc audit tokens` prints.
#
# The nomad-leader node also ships Nomad's ACL changes, with the management token it
# already holds for nomad-acl-init. No other node has that token, and no other unit
# reads it (tests/cluster-single.nix checks the list).
#
# Opted-out nodes ship too when a URL is set: SSH logins and deploys are worth a trail
# whatever the disks are, and the fixture cluster, which opts out, is how this is
# tested (tests/cluster-single.nix). Only the boot event is left out on them.
{
  config,
  lib,
  topology,
  node,
  nodeName,
  clusterLib,
  ...
}:
let
  url = topology.alerting.auditUrl or null;
  gens = config.clan.core.vars.generators;
  isLeader = clusterLib.net.hasTag "nomad-leader" node;
  tls = clusterLib.nomadPki.cliTlsFor gens;
in
{
  imports = [ ./audit-ship-core.nix ];

  config = lib.mkIf (url != null) {
    cluster.audit = {
      enable = true;
      inherit url;
      node = nodeName;
      tokenFile = gens.audit.files.token.path;
      nomadAcl = lib.mkIf isLeader {
        enable = true;
        address = clusterLib.net.nomadAddr node;
        tokenFile = gens.nomad-acl.files.token.path;
        inherit (tls) caCert clientCert clientKey;
      };
    };
  };
}
