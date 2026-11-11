# modules/tang-server.nix — a Tang-only host: the network half of every node's unlock.
#
# Exported as `nixosModules.tangServer` and NOT in the cluster module set: no clan, no
# topology, no cluster arguments. A separate private repo (the Tang host's own) imports
# this on a small VPS and sets the options. The cluster only ever learns this host's URL
# and its pinned signing thumbprints (`security.tang` in the site's topology).
#
# What makes a Tang host safe to leave alone, each one RAN in the design's prototype and
# in tests/tang-server.nix, where the `stock` VM shows each hazard on `services.tang`:
#
#   - tangd mints a fresh key pair whenever it finds no visible key it can read: an empty
#     directory, every key hidden, or only 0-byte files (a crash in the journal commit
#     window leaves those). `/adv` then answers 200, signed by keys no node is bound to,
#     and every node's next boot needs its passphrase. So a guard runs before tangd, per
#     connection, and refuses instead (`tang-key-guard`).
#   - stock `tangd-rotate-keys`, run as root, leaves root-owned keys in the dynamic
#     user's directory. systemd fixes a StateDirectory's ownership only when the TOP
#     directory's owner differs, so tangd can't read them, skips them, and mints more.
#     `tang-keys` writes keys owned like the directory, and never leaves a moment with
#     zero visible keys.
#   - a 200 from `/adv` proves nothing (an empty directory answers 200 too), so the
#     self-probe verifies the signature and the signing key's thumbprint before it
#     reports a heartbeat (design D5: nothing outside can reach the Tang port).
#   - the port answers only on the private interface, and only to `allowedClients`;
#     SSH answers only on the public one. Both are checked from outside in the test.
#
# Rotation (tang-keys): `rotate-begin`; pin the new thumbprint here and in the site's
# `security.tang.thumbprints` and deploy both; rebind every node from a delivered
# advertisement (`cluster-boot-seal bind --adv FILE --replace`); unpin the old
# thumbprint here and deploy; `rotate-finish`. rotate-finish refuses while an old
# thumbprint is still pinned, because the guard would then refuse every connection.
# Hiding a key does not revoke it: hidden keys still answer /rec.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.cluster.tangServer;
  stateDir = "/var/lib/private/tang";
  jose = "${pkgs.jose}/bin/jose";
  pinned = lib.escapeShellArgs cfg.pinnedThumbprints;

  # Runs INSIDE tangd@'s sandbox before tangd, per connection. tangd itself generates a
  # fresh key pair whenever it finds no visible key, so a wiped or all-hidden directory
  # would otherwise answer /adv happily with keys no JWE was bound to. Only stderr:
  # stdout is the client's socket. The text is `guardScript` (below), which only a mutant
  # changes.
  guardText = ''
    set -u
    cd "$STATE_DIRECTORY" || { echo "tang-key-guard: no state dir" >&2; exit 1; }
    visible=0
    for k in *.jwk; do
      [ -e "$k" ] || continue
      # Existence is not enough. RAN: a crash inside the journal commit window leaves
      # 0-byte .jwk files; tangd skips those as unparsable, counts zero keys, and mints
      # new ones. A key must parse to its own filename.
      t=$(${jose} jwk thp -i "$k" -a S256 2>/dev/null) || t=""
      if [ "$t.jwk" != "$k" ]; then
        echo "tang-key-guard: refusing: $k is unreadable or corrupt" >&2
        exit 1
      fi
      visible=$((visible + 1))
    done
    if [ "$visible" -lt 2 ]; then
      echo "tang-key-guard: refusing: $visible visible key(s); tangd would mint new ones" >&2
      exit 1
    fi
    for t in ${pinned}; do
      if [ ! -e "$t.jwk" ] && [ ! -e ".$t.jwk" ]; then
        echo "tang-key-guard: refusing: pinned key $t is absent" >&2
        exit 1
      fi
    done
  '';
  guard = pkgs.writeShellScript "tang-key-guard" cfg.guardScript;

  # Root tool. Files must end up owned like the directory: systemd only fixes
  # StateDirectory ownership when the TOP directory's owner differs, so a root-owned key
  # in a correctly owned directory stays unreadable, tangd skips it with "Cannot load
  # JSON file", and if no other key is visible mints new ones. (RAN: that is what stock
  # tangd-rotate-keys does here.)
  admin = pkgs.writeShellApplication {
    name = "tang-keys";
    runtimeInputs = [
      pkgs.jose
      pkgs.coreutils
      pkgs.jq
      config.systemd.package
    ];
    text = ''
      d=${stateDir}
      pinned=(${pinned})
      newpair() {
        umask 0337
        for alg in ES512 ECMR; do
          jwk=$(jose jwk gen --input "{\"alg\":\"$alg\"}")
          thp=$(printf '%s' "$jwk" | jose jwk thp --input=- -a S256)
          printf '%s\n' "$jwk" > "$d/.tmp-$thp"
          chown --reference="$d" "$d/.tmp-$thp"
          sync "$d/.tmp-$thp"
          mv "$d/.tmp-$thp" "$d/$thp.jwk"
          if [ "$alg" = ES512 ]; then echo "$thp"; fi
        done
      }
      case "''${1:-}" in
        init)
          systemctl start tang-state-dir.service
          for k in "$d"/*.jwk "$d"/.*.jwk; do
            if [ -e "$k" ]; then echo "keys already exist; refusing" >&2; exit 1; fi
          done
          newpair
          sync "$d" ;;
        # New keys go visible FIRST, then old ones are hidden: there is never a moment
        # with zero visible keys for tangd to answer by minting its own.
        rotate-begin)
          old=()
          for k in "$d"/*.jwk; do
            if [ -e "$k" ]; then old+=("$k"); fi
          done
          if [ "''${#old[@]}" -eq 0 ]; then
            echo "no visible keys to rotate; refusing (a new host runs init)" >&2
            exit 1
          fi
          new=$(newpair)
          sync "$d"
          for k in "''${old[@]}"; do mv -- "$k" "$d/.$(basename "$k")"; done
          sync "$d"
          echo "$new" ;;
        # Deleting a hidden key that is still pinned would make the guard refuse every
        # connection, so unpin it (and deploy) first. All or nothing: nothing is deleted
        # if any one is pinned.
        rotate-finish)
          for k in "$d"/.*.jwk; do
            [ -e "$k" ] || continue
            t=$(basename "$k" .jwk)
            t=''${t#.}
            for p in "''${pinned[@]}"; do
              if [ "$p" = "$t" ]; then
                echo "refusing: $t is still in pinnedThumbprints; unpin it and deploy first" >&2
                exit 1
              fi
            done
          done
          for k in "$d"/.*.jwk; do if [ -e "$k" ]; then rm -f -- "$k"; echo "deleted $(basename "$k")"; fi; done
          sync "$d" ;;
        list)
          ls -la "$d" ;;
        *) echo "usage: tang-keys init|rotate-begin|rotate-finish|list" >&2; exit 2 ;;
      esac
    '';
  };

  # Verified /adv: signature checks out, and the signing key is one we pinned. A 200
  # alone proves nothing, because an empty directory answers 200 too.
  # The text is `probeScript` (below), which only a mutant changes.
  probeText = ''
    set -euo pipefail
    export PATH=${
      lib.makeBinPath [
        pkgs.curl
        pkgs.jose
        pkgs.coreutils
        pkgs.gnugrep
      ]
    }
    adv=$(curl -fsS --max-time 10 http://127.0.0.1:${toString cfg.port}/adv)
    keys=$(printf '%s' "$adv" | jose fmt -j- -g payload -y -o-)
    sig=$(printf '%s' "$keys" | jose jwk use -i- -r -u verify -o-)
    printf '%s' "$sig" | jose jws ver -i <(printf '%s' "$adv") -k- -a
    thps=$(printf '%s' "$sig" | jose jwk thp -i- -a S256)
    ok=0
    for t in ${pinned}; do
      if printf '%s\n' "$thps" | grep -qxF "$t"; then ok=1; fi
    done
    if [ "$ok" != 1 ] && [ -n "${lib.concatStringsSep "" cfg.pinnedThumbprints}" ]; then
      echo "tang-probe: /adv is not signed by a pinned key: $thps" >&2
      exit 1
    fi
    curl -fsS --max-time 20 -X POST -H "Authorization: Bearer $(cat "$CREDENTIALS_DIRECTORY/token")" \
      -d '{"kind":"tang_probe"}' ${lib.escapeShellArg (toString cfg.monitor.heartbeatUrl)} >/dev/null
  '';
  probeScript = pkgs.writeShellScript "tang-probe" cfg.probeScript;

  # One event per /rec, at-least-once: the journal cursor only advances after the
  # receiver accepted the event, so a network gap delays and never drops. The event is
  # the Worker's `tang_rec` (workers/cluster-watchdog, SCHEMAS): address, key id,
  # status and time, nothing else. tangd's line carries no key material, and nothing
  # else of it is sent.
  #
  # It fails closed. tangd logs `<ip> <METHOD> <raw path> => <status>` and routes on
  # `^/+rec/+<kid>$` (tang 15, src/tangd.c), so `//rec/<kid>` and `/rec//<kid>` are
  # recoveries too, answered 200 and logged with the path as sent [RAN]: a literal
  # `POST /rec/` match let them by with no event at all. So every line that is not a GET
  # (only POST reaches /rec, and only /rec releases anything) is posted; the kid is
  # read with tangd's own route, and is `unparsed` where that fails; a line with POST
  # in it that does not even parse is posted with status 0, which the Worker treats as
  # a possible release. A routing quirk can then only make an event noisier, never
  # hide it. The text is `recNotifyScript` (below), which only a mutant changes.
  recNotifyText = ''
    import json
    import os
    import re
    import subprocess
    import time
    import urllib.request

    URL = ${builtins.toJSON (toString cfg.monitor.eventUrl)}
    TOKEN = open(os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "token")).read().strip()
    CURSOR = os.path.join(os.environ["STATE_DIRECTORY"], "cursor")
    LINE = re.compile(r"^(?P<ip>\S+) (?P<method>\S+) (?P<path>\S*) => (?P<status>\d+)")
    REC = re.compile(r"(?:^|/)rec/+(?P<kid>[0-9A-Za-z_-]+)$")
    # The Worker's ID characters; anything else would make every retry a 422.
    UNSAFE = re.compile(r"[^A-Za-z0-9._:@=/+-]")


    def clean(v):
        return UNSAFE.sub("_", v)[:128] or "unparsed"


    def classify(msg):
        """(ip, path, kid, status) for a line that may be a key recovery, else None."""
        m = LINE.match(msg)
        if m is None:
            return ("unparsed", "unparsed", "unparsed", 0) if "POST" in msg else None
        if m["method"] == "GET":
            return None
        r = REC.search(m["path"])
        return (clean(m["ip"]), m["path"], clean(r["kid"]) if r else "unparsed", int(m["status"]))


    def post(ev):
        req = urllib.request.Request(URL, data=json.dumps(ev).encode(), method="POST", headers={
            "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=20).close()


    cmd = ["journalctl", "-f", "-o", "json", "-t", "tangd", "--no-tail"]
    if os.path.exists(CURSOR):
        cmd += ["--after-cursor", open(CURSOR).read().strip()]
    else:
        cmd += ["--since", "now"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    seen = {}
    for raw in p.stdout:
        e = json.loads(raw)
        msg = e.get("MESSAGE") or ""
        if isinstance(msg, list):
            msg = bytes(msg).decode("utf-8", "replace")
        c = classify(msg)
        at = int(int(e["__REALTIME_TIMESTAMP"]) / 1000000)
        # clevis-luks-askpass retries about once a second when it cannot finish. Keyed by
        # the path as sent, so a differently written request is its own event.
        if c and at - seen.get(c[:2] + c[3:], 0) >= 60:
            seen[c[:2] + c[3:]] = at
            ev = {"kind": "tang_rec", "ip": c[0], "kid": c[2], "status": c[3], "at": at}
            while True:
                try:
                    post(ev)
                    break
                except Exception as x:
                    print("tang-rec-notify: retry:", x, flush=True)
                    time.sleep(30)
        with open(CURSOR + ".tmp", "w") as f:
            f.write(e["__CURSOR"])
        os.replace(CURSOR + ".tmp", CURSOR)
  '';
  recNotify = pkgs.writers.writePython3 "tang-rec-notify" {
    flakeIgnore = [ "E501" ];
  } cfg.recNotifyScript;

  monitored = cfg.monitor.heartbeatUrl != null || cfg.monitor.eventUrl != null;
  inRange = port: r: r.from <= port && port <= r.to;
  otherInterfacesOpening = lib.attrNames (
    lib.filterAttrs (
      name: i:
      name != cfg.privateInterface
      && (
        builtins.elem cfg.port (i.allowedTCPPorts or [ ])
        || lib.any (inRange cfg.port) (i.allowedTCPPortRanges or [ ])
      )
    ) config.networking.firewall.interfaces
  );
in
{
  options.cluster.tangServer = with lib; {
    enable = mkEnableOption "a Tang-only host";
    port = mkOption {
      type = types.port;
      default = 7654;
    };
    privateInterface = mkOption {
      type = types.str;
      description = "The only interface the Tang port is open on.";
    };
    publicInterface = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The only interface SSH is open on. null leaves SSH closed.";
    };
    allowedClients = mkOption {
      type = types.nonEmptyListOf types.str;
      example = [ "192.0.2.0/28" ];
      description = "Client prefixes for socket IPAddressAllow. Hygiene, not authentication. Loopback is added for the self-probe.";
    };
    pinnedThumbprints = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "S256 thumbprints of signing keys that must exist, visible or hidden. Public data. Empty only before `tang-keys init`.";
    };
    monitor = {
      heartbeatUrl = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Where the verified self-probe posts `tang_probe` (the watchdog Worker's /event). null: no probe.";
      };
      eventUrl = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Where each /rec is posted as `tang_rec` (the watchdog Worker's /event). null: no events.";
      };
      tokenFile = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Bearer token for the off-host receiver, delivered out of band. Required when either URL is set.";
      };
      probeInterval = mkOption {
        type = types.str;
        default = "5min";
      };
    };
    guardScript = mkOption {
      type = types.str;
      default = guardText;
      internal = true;
      description = "The key guard's text. Only a mutant changes it (flake.nix, tang-guard-existence-only).";
    };
    probeScript = mkOption {
      type = types.str;
      default = probeText;
      internal = true;
      description = "The self-probe's text. Only a mutant changes it (flake.nix, tang-probe-no-signature-check).";
    };
    recNotifyScript = mkOption {
      type = types.str;
      default = recNotifyText;
      internal = true;
      description = "tang-rec-notify's text. Only a mutant changes it (flake.nix, tang-rec-literal-path).";
    };
  };

  config = lib.mkIf cfg.enable {
    system.build.tangKeyGuardText = guardText;
    system.build.tangProbeText = probeText;
    system.build.tangRecNotifyText = recNotifyText;

    assertions = [
      {
        assertion = config.networking.firewall.enable;
        message = "tang-server: the firewall is half of the design";
      }
      {
        assertion =
          !(builtins.elem cfg.port config.networking.firewall.allowedTCPPorts)
          && !(lib.any (inRange cfg.port) config.networking.firewall.allowedTCPPortRanges);
        message = "tang-server: the Tang port must not be open globally";
      }
      # The per-interface lists too: the socket's IPAddressAllow is hygiene, and with the
      # port open on the public NIC's firewall it would be all that stood in front of
      # tangd (`surface` in tests/tang-server.py checks the firewall alone).
      {
        assertion = otherInterfacesOpening == [ ];
        message = "tang-server: the Tang port must be open on privateInterface only, not on ${lib.concatStringsSep ", " otherInterfacesOpening}";
      }
      {
        assertion = !config.services.openssh.openFirewall;
        message = "tang-server: set services.openssh.openFirewall = false; SSH opens only on publicInterface";
      }
      {
        assertion = cfg.publicInterface != cfg.privateInterface;
        message = "tang-server: public and private interfaces must differ";
      }
      # LoadCredential would otherwise read "token:" and the unit fails at runtime,
      # silently for the probe's dead-man until the Worker notices.
      {
        assertion = !monitored || cfg.monitor.tokenFile != null;
        message = "tang-server: monitor.tokenFile is required when monitor.heartbeatUrl or monitor.eventUrl is set";
      }
    ];

    services.tang = {
      enable = true;
      # Port only: an address-bound socket fails at boot, before the private address
      # exists, and a failed socket unit stays failed.
      listenStream = [ (toString cfg.port) ];
      ipAddressAllow = cfg.allowedClients ++ [ "127.0.0.1/32" ];
    };
    systemd.services."tangd@".serviceConfig.ExecStartPre = [ "${guard}" ];

    # Creates /var/lib/private/tang with the service's ownership rules before
    # `tang-keys init`, without a connection having to arrive first.
    systemd.services.tang-state-dir = {
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        StateDirectory = "tang";
        StateDirectoryMode = "700";
        ExecStart = "${pkgs.coreutils}/bin/true";
      };
    };

    networking.firewall.interfaces = {
      ${cfg.privateInterface}.allowedTCPPorts = [ cfg.port ];
    }
    // lib.optionalAttrs (cfg.publicInterface != null) {
      ${cfg.publicInterface}.allowedTCPPorts = config.services.openssh.ports;
    };
    services.openssh.openFirewall = false;

    environment.systemPackages = [
      admin
      pkgs.jose
      pkgs.curl
    ];

    systemd.services.tang-probe = lib.mkIf (cfg.monitor.heartbeatUrl != null) {
      description = "Verified Tang self-probe, reported as a heartbeat";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = probeScript;
        # It reads /adv over loopback and posts one line: nothing here needs root.
        DynamicUser = true;
        LoadCredential = [ "token:${cfg.monitor.tokenFile}" ];
      };
    };
    systemd.timers.tang-probe = lib.mkIf (cfg.monitor.heartbeatUrl != null) {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "1min";
        OnUnitActiveSec = cfg.monitor.probeInterval;
      };
    };

    systemd.services.tang-rec-notify = lib.mkIf (cfg.monitor.eventUrl != null) {
      description = "Each Tang key recovery, posted off-host";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      path = [ config.systemd.package ];
      serviceConfig = {
        ExecStart = recNotify;
        Restart = "always";
        RestartSec = 10;
        DynamicUser = true;
        SupplementaryGroups = [ "systemd-journal" ];
        StateDirectory = "tang-rec-notify";
        LoadCredential = [ "token:${cfg.monitor.tokenFile}" ];
      };
    };

    # Tang's only long-term secret is on this host's plain disk: keep it out of core
    # files. The same pipe to nowhere as a cluster node (modules/coredumps-off.nix, which
    # is not imported so that this module changes nothing while disabled), and
    # systemd-coredump told to keep nothing should anything set the pattern back.
    boot.kernel.sysctl = {
      "kernel.core_pattern" = lib.mkForce (import ../lib/core-pattern.nix);
      "fs.suid_dumpable" = 0;
    };
    systemd.settings.Manager.DefaultLimitCORE = "0";
    systemd.coredump.settings.Coredump = {
      Storage = "none";
      ProcessSizeMax = 0;
    };
  };
}
