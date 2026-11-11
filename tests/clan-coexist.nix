# Eval-level check that clan-core coexists with this repo's opinionated host
# config instead of quietly overriding it.
#
# This is the regression detector for the clan adoption, and it exists because
# `clan-core` is pinned to `main` — clan's UNSTABLE channel — while every node
# pulls and applies this flake from git on a 10-minute timer. There is no
# deprecation policy upstream to lean on, so the guarantees we depend on are
# asserted here and re-checked on every bump. Each property below is either
# something clanCore actively tries to set, or something whose loss would break
# a node remotely with no console to recover from.
#
# These are ABSOLUTE assertions, not a diff against a parallel non-clan build:
# during the migration the check compared the two, but clan is now the only way
# machines are built, so "what must be true" is the only meaningful instrument.
#
# Run: nix build .#checks.<system>.clan-coexist
{
  pkgs,
  lib,
  topology,
  clusterLib,
  clanSystem, # nixosConfiguration built through clan-core.lib.clan
  nodeName ? "node1",
}:
let
  node = topology.nodes.${nodeName};
  c = clanSystem.config;

  netNames = lib.attrNames c.systemd.network.networks;

  # Every networkd unit this repo hand-writes in modules/overlay-network.nix and
  # modules/mesh-control-core.nix.
  # If one disappears the node loses an interface; the WAN ones would strand it.
  requiredNets = [
    "05-wan-port"
    "10-br-wan"
    "15-vrack"
    "20-app"
    "20-control"
    "20-storage"
    # modules/mesh-control-core.nix: the control mesh every service but Nomad uses.
    "30-${clusterLib.net.meshIf}"
    "40-br-app"
    "50-veth"
    "51-veth-wan"
    # A peerAccess app's br-app veth, vp-<iid> (container default-deny): without it
    # nothing bridges that container, and it has no network at all.
    "52-veth-peer"
  ];
  missingNets = lib.subtractLists netNames requiredNets;

  # clanCore's recommended defaults inject `99-ethernet-default-dhcp` and
  # `99-wireless-client-dhcp`. Matching the whole 99- prefix rather than those
  # two names catches any future sibling upstream adds.
  strayNets = lib.filter (n: lib.hasPrefix "99-" n) netNames;

  # Exactly one machine may hold each singleton role. clusterLib.soleTaggedNode
  # throws on 0 or >1, so forcing it here turns "two juicefs-meta nodes" into a
  # failed check rather than two metadata engines over one S3 bucket.
  singletonTags = [
    "juicefs-meta"
    "nomad-leader"
    "metrics"
  ];
  singletonsResolve = builtins.all (
    t: (clusterLib.net.soleTaggedNode topology t) ? controlIp
  ) singletonTags;

  checks = [
    # ── secrets: what the PULL loop actually requires ───────────────────────
    #
    # The original agenix setup used the node's SSH host key as the decryption
    # identity, so nothing had to be distributed. That is not achievable for a
    # machine that does not exist yet: you cannot encrypt to a host key before
    # the host has one, and activation fails on a secret it cannot decrypt —
    # so a brand-new node could never complete its first switch.
    #
    # clan resolves it the same way under the age vars backend (modules/vars.nix):
    # it generates a per-machine age keypair in the repo and delivers the
    # private half ONCE, at provisioning time, via `clan machines install`
    # (nixos-anywhere --extra-files -> clan.core.vars.age.secretLocation ->
    # key.txt). It then persists, so the pull loop never uploads anything.
    #
    # The invariant worth guarding is therefore NOT "no key file" but "nothing
    # has to be delivered per-deploy", which is what the two checks below say.
    {
      name = "secret store is the age backend, at the expected key location";
      ok =
        c.clan.core.vars.settings.secretStore == "age"
        && c.clan.core.vars.age.secretLocation == "/etc/secret-vars";
    }
    {
      # THE pull-loop invariant. neededFor = "partitioning" or "activation" puts
      # a secret OUTSIDE sops-nix's normal path: clan uploads those out of band
      # during install/update. The pull loop does no uploading, so such a secret
      # would work on a pushed node and silently break on a pulled one — which
      # is every node here. "services" (the default) is decrypted from the
      # closure at activation and needs nothing.
      name = "every secret is neededFor=services — nothing requires a per-deploy upload";
      ok =
        let
          bad = lib.concatMap (
            g:
            lib.mapAttrsToList (fn: f: "${g.name}/${fn}") (
              lib.filterAttrs (_fn: f: f.secret && f.deploy && f.neededFor != "services") g.files
            )
          ) (lib.attrValues c.clan.core.vars.generators);
        in
        bad == [ ];
    }

    # ── networking: clanCore's recommended defaults must stay out ────────────
    {
      name = "no clan-injected 99-* networkd units";
      ok = strayNets == [ ];
    }
    {
      name = "every hand-written networkd unit survives";
      ok = missingNets == [ ];
    }
    {
      name = "recommended defaults are off";
      ok = !c.clan.core.enableRecommendedDefaults;
    }
    {
      name = "nftables is still authoritative";
      ok = c.networking.firewall.enable == false;
    }
    {
      name = "networkd still owns the network";
      ok = c.networking.useNetworkd && !c.networking.useDHCP;
    }

    # ── ZFS / boot: a wrong hostId or disk layout is an unbootable node ──────
    {
      # clanCore/zfs.nix sets networking.hostId = mkDefault "8425e349". The
      # per-node value from topology is a plain definition and must win, or the
      # pool needs a force-import to mount.
      name = "hostId comes from topology, not clan's default";
      ok = c.networking.hostId == node.hostId;
    }
    {
      name = "state version stays fleet-wide topology data";
      ok = c.system.stateVersion == topology.stateVersion;
    }
    {
      # The second NVMe is only bootable because of the ESP rsync in zfs-host.nix.
      name = "dual-ESP bootloader hook survives";
      ok = c.boot.loader.systemd-boot.extraInstallCommands != "";
    }

    # ── role assignment ─────────────────────────────────────────────────────
    {
      name = "each singleton role resolves to exactly one machine";
      ok = singletonsResolve;
    }
    {
      # The whole point of the tag refactor: nothing may reintroduce a guard
      # that depends on where a node sorts in topology.nodes.
      name = "this machine carries the tags topology gave it";
      ok = c.clan.core.settings.machine.name == nodeName;
    }
  ];

  failed = lib.filter (c': !c'.ok) checks;

  # Name the offending units — "clan added a networkd unit" is not actionable
  # on its own, and this check runs unattended on every clan bump.
  detail = lib.optionalString (strayNets != [ ] || missingNets != [ ]) ''
    echo "  networkd stray:   ${toString strayNets}" >&2
    echo "  networkd missing: ${toString missingNets}" >&2
  '';
in
pkgs.runCommand "clan-coexist-checks" { } (
  if failed == [ ] then
    ''
      echo "${toString (builtins.length checks)} clan coexistence checks passed"
      touch $out
    ''
  else
    ''
      echo "FAILED — clan-core is overriding host config it must not touch:" >&2
      ${lib.concatMapStringsSep "\n" (c': ''echo "  - ${c'.name}" >&2'') failed}
      ${detail}
      exit 1
    ''
)
