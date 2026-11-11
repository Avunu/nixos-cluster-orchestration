# Eval-level checks for modules/kinds/freeipa.nix, against the fixture node1
# configuration (the demo-idm instance). The container's runtime -- an IPA
# install under podman under nspawn -- is proven on the node; what can
# regress unnoticed is the wiring these check.
#
# Run: nix build .#checks.<system>.freeipa
{
  pkgs,
  lib,
  clusterLib,
  topology,
  clanSystem,
}:
let
  c = clanSystem.config;
  app = c.clusterApps.demo-idm;
  guest = c.containers.demo-idm.config;
  ipa = guest.virtualisation.oci-containers.containers.freeipa;
  unit = guest.systemd.services.podman-freeipa;
  fw = guest.networking.firewall;
  authelia = guest.systemd.services.authelia-demo-idm;
  pinnedIpa =
    (clanSystem.extendModules {
      modules = [
        {
          clusterApps.demo-idm.freeipa.image = {
            digest = "sha256:${lib.fixedWidthString 64 "0" ""}";
            hash = lib.fakeHash;
          };
        }
      ];
    }).config.containers.demo-idm.config.virtualisation.oci-containers.containers.freeipa;
  autheliaCfg = guest.services.authelia.instances.demo-idm.settings;

  checks = [
    {
      # The public IPv6 side is bridged past the host's firewall
      # (lib/mk-app-container.nix), so a global allow would publish 88/389
      # to the internet. WARP traffic arrives over lo and needs nothing.
      name = "the container's firewall is on and opens no ports";
      ok =
        fw.enable
        && fw.allowedTCPPorts == [ ]
        && fw.allowedUDPPorts == [ ]
        && fw.allowedTCPPortRanges == [ ]
        && fw.allowedUDPPortRanges == [ ]
        && lib.all (i: i.allowedTCPPorts or [ ] == [ ] && i.allowedUDPPorts or [ ] == [ ]) (
          lib.attrValues fw.interfaces
        );
    }
    {
      name = "a deploy never restarts the server (a restart is an upgrade)";
      ok = unit.restartIfChanged == false;
    }
    {
      # Tracking is the default: no hash to recompute, and a restart never
      # pulls -- only the upgrade does, behind an export and a snapshot.
      name = "the image tracks its tag: nothing baked in, pulled only when missing";
      ok = ipa.pull == "missing" && ipa.imageFile == null && app.freeipa.image.digest == null;
    }
    {
      # The way back, if tracking ever proves a problem.
      name = "a pinned image is baked into the closure and never pulled";
      ok = pinnedIpa.pull == "never" && pinnedIpa.imageFile != null;
    }
    {
      name = "updates are applied nightly, only if needed";
      ok =
        c.systemd.timers.cluster-freeipa-autoupgrade-demo-idm.timerConfig.OnCalendar == "*-*-* 05:30:00"
        && lib.hasSuffix "demo-idm --if-needed" c.systemd.services.cluster-freeipa-autoupgrade-demo-idm.serviceConfig.ExecStart
        # clear of the nightly backups, which the upgrade also waits for
        && !(lib.hasInfix "05:" topology.backup.schedule);
    }
    {
      name = "stops nest: podman < unit < container@ <= Nomad";
      ok =
        lib.elem "--stop-timeout=180" ipa.extraOptions
        && unit.serviceConfig.TimeoutStopSec == 200
        && c.systemd.services."container@demo-idm".serviceConfig.TimeoutStopSec == 300
        && app.nomad.killTimeoutSeconds >= 300;
    }
    {
      name = "podman gets the capabilities the image's systemd needs";
      ok =
        lib.elem "all" app.additionalCapabilities
        && ipa.capabilities.AUDIT_WRITE or false
        && lib.elem "--uts=private" ipa.extraOptions;
    }
    {
      name = "directory modes are enforced before every start";
      ok = lib.any (lib.hasInfix "freeipa-modes") unit.serviceConfig.ExecStartPre;
    }
    {
      name = "the private address is on a dummy link, inside the pool";
      ok =
        guest.systemd.network.netdevs."30-ipa0".netdevConfig.Kind == "dummy"
        && clusterLib.net.cidrContains topology.privateServices "10.21.0.10";
    }
    {
      name = "backed up from a ZFS snapshot, with a live export and a rehearsal check";
      ok =
        app.backup.localSnapshot
        && lib.hasInfix "ipa-backup --data --online" app.backup.preCommand
        && app.backup.verifyCommand != null
        && lib.elem "podman-freeipa.service" app.backup.appUnits
        && c.systemd.services ? cluster-backup-demo-idm;
    }
    {
      name = "health is reported on the home node";
      ok = c.systemd.timers ? cluster-freeipa-health;
    }

    # ── Authelia ────────────────────────────────────────────────────────────
    {
      # It runs as its own user with PrivateUsers; the bind-mounted secrets
      # are root-only, so each must arrive as a credential.
      name = "Authelia gets every secret through LoadCredential";
      ok =
        let
          creds = authelia.serviceConfig.LoadCredential;
          has = n: lib.any (lib.hasPrefix "${n}:") creds;
        in
        lib.all has [
          "ldap-password"
          "oidcIssuerPrivateKeyFile"
          "oidcHmacSecretFile"
          "jwtSecretFile"
          "sessionSecretFile"
          "storageEncryptionKeyFile"
        ]
        && lib.all (cr: lib.hasInfix ":/run/secrets/" cr) creds;
    }
    {
      # Until IPA has installed there is no CA and no account: a boot that
      # waited for Authelia would wait for an install.
      name = "Authelia is started by freeipa-bootstrap, not by the boot";
      ok =
        authelia.wantedBy == [ ]
        && guest.systemd.timers ? freeipa-bootstrap
        && lib.hasInfix "systemctl start --no-block authelia-demo-idm" guest.systemd.services.freeipa-bootstrap.script;
    }
    {
      # A password set by anyone but its owner comes out of IPA expired.
      name = "Authelia never sets passwords";
      ok =
        autheliaCfg.authentication_backend.password_reset.disable
        && autheliaCfg.authentication_backend.password_change.disable;
    }
    {
      name = "Authelia binds to IPA over ldaps with the freeipa schema";
      ok =
        autheliaCfg.authentication_backend.ldap.implementation == "freeipa"
        && lib.hasPrefix "ldaps://idm.example.com" autheliaCfg.authentication_backend.ldap.address;
    }
    {
      name = "both hostnames are on the app's tunnel, and backed up with it";
      ok =
        app.tunnel.ingress ? "auth.example.com"
        && app.localState ? "/var/lib/authelia-demo-idm"
        && lib.elem "authelia-demo-idm.service" app.backup.appUnits;
    }
  ];

  failed = lib.filter (x: !x.ok) checks;

  # Authelia's own `validate-config`, over the exact files the unit starts
  # with, with dummy credentials: the only thing that knows its schema. (It
  # caught notifier.smtp.disable_startup_check, a key 4.39 moved to
  # notifier.disable_startup_check -- Authelia would not have started.)
  # The CA directory is IPA's at runtime; a throwaway one stands in.
  autheliaStart = authelia.serviceConfig.ExecStart;
  validateAuthelia = ''
    start=${lib.escapeShellArg autheliaStart}
    bin=''${start%% *}
    configs=$(sed 's/.*--config \([^ ]*\).*/\1/' <<<"$start")
    d=$(mktemp -d)
    mkdir -p "$d/cred" "$d/ca"
    ${pkgs.openssl}/bin/openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$d/cred/oidcIssuerPrivateKeyFile" 2>/dev/null
    ${pkgs.openssl}/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out "$d/ca/ipa-ca.crt" -subj /CN=ca -days 1 2>/dev/null
    for f in oidcHmacSecretFile jwtSecretFile sessionSecretFile storageEncryptionKeyFile ldap-password smtp-token; do
      ${pkgs.openssl}/bin/openssl rand -hex 48 > "$d/cred/$f"
    done
    # A confidential client's digest, as its generator makes them.
    ${lib.concatMapStrings (
      cred:
      let
        name = lib.head (lib.splitString ":" cred);
      in
      ''
        printf '%s' '$pbkdf2-sha512$310000$c8p78n7pUMln0jzvd4aK4Q$JNRBzwAo0ek5qKn50cFzzvE9RXV88h1wJn5KGiHrD0YKtZaR/nCb2ITPRGsmQCa6yiSkd/uDkQ5fQO/RAXSzRA' > "$d/cred/${name}"
      ''
    ) (lib.filter (lib.hasPrefix "oidc-") authelia.serviceConfig.LoadCredential)}
    main=''${configs%%,*}
    sed "s#/run/authelia-demo-idm-ca#$d/ca#" "$main" > "$d/config.yml"
    configs="$d/config.yml,''${configs#*,}"
    export CREDENTIALS_DIRECTORY="$d/cred" X_AUTHELIA_CONFIG_FILTERS=template
    ${lib.concatStringsSep "\n    " (
      lib.mapAttrsToList (k: v: "export ${k}=${lib.replaceStrings [ "%d" ] [ "$d/cred" ] v}") (
        lib.filterAttrs (k: _: lib.hasSuffix "_FILE" k) authelia.environment
      )
    )}
    result=$("$bin" --config "$configs" validate-config 2>&1) || true
    echo "$result"
    grep -q "loaded with errors" <<<"$result" && { echo "FAILED: Authelia rejects its generated config" >&2; exit 1; }
    grep -q "Configuration parsed and loaded" <<<"$result" || { echo "FAILED: authelia validate-config did not run" >&2; exit 1; }
  '';

  # The last link of "stops nest": the stop Nomad waits on, within killTimeoutSeconds,
  # is the wrapper's, and it has to wait for the container. Since WS7 the wrapper runs as
  # nomad-apps and stops through polkit, with `systemctl stop`, which blocks until the
  # unit has stopped (its TimeoutStopSec, 300 s, which is inside Nomad's). A
  # `--no-block` stop, or one as an account polkit refuses, would let Nomad think it was
  # done while FreeIPA was still stopping. Read from the job JSON at build time: reading
  # it at evaluation would be import-from-derivation.
  stopsNestJob = ''
    job=${c.system.build.nomadJobs.demo-idm}
    task() { ${pkgs.jq}/bin/jq -r ".Job.TaskGroups[0].Tasks[0].$1" "$job"; }
    user=$(task User)
    wrapper=$(task Config.command)
    [ "$user" = nomad-apps ] || { echo "FAILED: stops nest: the task runs as '$user', not nomad-apps" >&2; exit 1; }
    grep -q 'stop container@demo-idm.service' "$wrapper" \
      || { echo "FAILED: stops nest: the wrapper does not stop container@demo-idm.service" >&2; exit 1; }
    ! grep -q -- '--no-block' "$wrapper" \
      || { echo "FAILED: stops nest: the wrapper's stop does not wait" >&2; exit 1; }
    echo "stops nest: the task runs as $user, and its stop is a blocking systemctl stop"
  '';
in
pkgs.runCommand "freeipa-checks" { } (
  if failed == [ ] then
    stopsNestJob
    + validateAuthelia
    + ''
      echo "${toString (builtins.length checks)} FreeIPA checks passed, and Authelia accepts its config"
      touch $out
    ''
  else
    ''
      echo "FAILED:" >&2
      ${lib.concatMapStringsSep "\n" (x: ''echo "  - ${x.name}" >&2'') failed}
      exit 1
    ''
)
