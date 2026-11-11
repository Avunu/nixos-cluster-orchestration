# modules/pull-deploy-core.nix — the pull deploy's tick, independent of clan and of any
# flake, so that tests/deploy-safety.nix runs the real thing against specialisations.
# The timer is here too, because a rollback only sticks if the tick the timer fires after
# a reboot refuses the closure. modules/pull-deploy.nix supplies the flake on a real node.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib) mkOption types;
  cfg = config.cluster.deploy;

  # The same shell `avc boot rollback` sends (tools/avc/avc/core/refuse_later.sh), with the
  # tick's state directory. NOTHING_AFTER is this file's own: only the guard reads it.
  nothingAfter = 10;
  refuseLater = pkgs.writeShellScript "refuse-later" (
    "S=/var/lib/cluster-upgrade\nNOTHING_AFTER=${toString nothingAfter}\n"
    + builtins.readFile ../tools/avc/avc/core/refuse_later.sh
  );

  # An operator escapes a closure that fails at boot by choosing an older generation at the
  # console. The timer must not then put the bad one back: with Persistent=true and a slot
  # missed while the node was down, it fires as soon as it starts, plus at most
  # RandomizedDelaySec, long before anyone could run `avc boot rollback`. So the node does
  # that itself, before any tick: booted into something other than the profile's current
  # generation, it refuses every generation after the one it booted, exactly as rollback
  # would. Unrollback is then the way back, as it is after `avc boot rollback`.
  #
  # Only at boot. A switch in this boot makes /run/current-system differ from what booted,
  # and then the profile being ahead of the booted closure is just a pull deploy that has
  # not been rebooted into: the closure that introduces this unit gets it started in the
  # middle of its own switch, and must not refuse itself.
  #
  # Also refused this way, and on purpose: a closure whose bootloader install failed, or a
  # node that went down between `nix-env --set` and its switch. Either boots the old
  # default with the profile ahead of it. That is held with DeployRollbackHeld until
  # someone looks, rather than retried into a boot path nobody has seen work.
  rollbackGuard = pkgs.writeShellScript "cluster-upgrade-rollback-guard" ''
    set -eu
    export PATH=${
      lib.makeBinPath [
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.gnused
      ]
    }
    S=/var/lib/cluster-upgrade
    P=/nix/var/nix/profiles
    booted=$(readlink -f /run/booted-system)
    if [ "$(readlink -f /run/current-system)" != "$booted" ]; then
      echo "rollback-guard: a switch already ran this boot, so what runs is not a console choice"
      exit 0
    fi
    if [ ! -e "$P/system" ]; then
      echo "rollback-guard: no system profile, so nothing comes after $booted"
      exit 0
    fi
    newest=$(readlink -f "$P/system")
    if [ "$booted" = "$newest" ]; then
      echo "rollback-guard: booted the profile's current generation"
      exit 0
    fi
    found=
    for l in "$P"/system-*-link; do
      if [ "$(readlink -f "$l")" = "$booted" ]; then found=1; fi
    done
    if [ -n "$found" ]; then
      rc=0
      refused=$(${refuseLater}) || rc=$?
      case $rc in
        0) echo "rollback-guard: booted $booted, not the profile's $newest; refused what came after it:" $refused ;;
        ${toString nothingAfter}) echo "rollback-guard: booted $booted, not the profile's $newest, and nothing comes after it" ;;
        *) echo "rollback-guard: could not refuse what came after $booted (rc=$rc)"; exit "$rc" ;;
      esac
      exit 0
    fi
    # No generation link left for what booted, so nothing says what came after it. The
    # profile's current closure is the one a tick would otherwise go back to.
    b=''${newest##*/}
    mkdir -p "$S"
    if [ -e "$S/refused" ]; then sed -e '$a\' "$S/refused" >"$S/refused.tmp"; else : >"$S/refused.tmp"; fi
    grep -qxF -- "$b" "$S/refused.tmp" || printf '%s\n' "$b" >>"$S/refused.tmp"
    mv "$S/refused.tmp" "$S/refused"
    echo "rollback-guard: booted $booted, which is no generation of $P/system; refused the profile's $b"
  '';
in
{
  options.cluster.deploy = {
    targetCommand = mkOption {
      type = types.str;
      description = "Shell command printing the store path of the closure this node should run. A failure is a failed build.";
    };

    pullInterval = mkOption {
      type = types.str;
      description = "systemd OnCalendar for the pull loop.";
    };

    bootContract = mkOption {
      type = types.attrsOf types.anything;
      description = ''
        Everything an unlock at the next reboot depends on. Written to the closure as
        canonical JSON (builtins.toJSON sorts keys) and compared with the running closure
        before a deploy. No store paths or generated values that change with a nixpkgs
        bump: this must only differ when a human has something to approve.
      '';
    };

    bootStack = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = ''
        What this node's boot is built from and every node of the site shares: the
        nixpkgs, kernel and library sources (lib/mk-cluster.nix, modules/pull-deploy.nix).
        Written to the closure as canonical JSON, `boot-stack`. Nothing per node goes in
        here, so the canary's file and a follower's are byte for byte the same when they
        run the same stack. A change is a new boot stack, which a follower activates only
        after the canary has booted it (`canary` below).

        Every value must be a pure function of the sources, identical on every
        evaluation and every Nix: a lock's narHash, or a content-addressed store path.
        Never a flake input's `outPath` with its context discarded, which under lazy
        trees is a virtual path that changes per evaluation, so no follower would ever
        match the canary's key.
      '';
    };

    # The staged rollout (design D22). One node, the canary, activates a new boot stack
    # as soon as it is pushed, like any other closure, and someone reboots it and watches.
    # Its boot, if it unlocked cleanly, publishes the stack on a filesystem every node
    # mounts; the other nodes, followers, activate that stack only once it is published.
    # So a bump that cannot boot stops at one node instead of at every node's next reboot.
    canary = {
      role = mkOption {
        type = types.enum [
          "none"
          "canary"
          "follower"
        ];
        default = "none";
        description = ''
          `canary` publishes each boot stack it boots cleanly; `follower` refuses to
          activate a boot stack the canary has not published; `none` does neither (a
          single-node site, or one that set topology.deploy.withoutCanary).
        '';
      };

      markerDir = mkOption {
        type = types.str;
        default = "";
        description = "Where the canary's markers live, one file per boot stack, named by the sha256 of its boot-stack file.";
      };

      markerMount = mkOption {
        type = types.str;
        default = "";
        description = ''
          The shared filesystem markerDir is on. Neither side reads or writes markers
          unless it is mounted: unmounted, the directory is this node's own disk, which
          no other node sees.
        '';
      };

      requireReport = mkOption {
        type = types.bool;
        default = true;
        description = "A boot counts only with this boot's report (modules/boot-report.nix).";
      };

      requireCleanUnlock = mkOption {
        type = types.bool;
        default = false;
        description = "A boot counts only if its report shows Clevis opened every leg.";
      };

      mutate = mkOption {
        type = types.functionTo types.str;
        internal = true;
        default = lib.id;
        description = "Edits the publisher's text. Set only by flake.nix's canary-* mutants.";
      };

      publisher = mkOption {
        type = types.package;
        internal = true;
        default = import ../lib/deploy-canary-publish.nix {
          inherit lib pkgs;
          inherit (cfg.canary)
            markerDir
            markerMount
            requireReport
            requireCleanUnlock
            ;
          node = config.networking.hostName;
          edit = cfg.canary.mutate;
        };
        description = "The canary's publisher.";
      };
    };

    mutate = mkOption {
      type = types.functionTo types.str;
      internal = true;
      default = lib.id;
      description = "Edits the tick's text. Set only by flake.nix's canary-gate-off mutant.";
    };

    package = mkOption {
      type = types.package;
      internal = true;
      default = import ../lib/cluster-upgrade.nix {
        inherit lib pkgs;
        inherit (cfg) targetCommand;
        follower =
          if cfg.canary.role == "follower" then { inherit (cfg.canary) markerDir markerMount; } else null;
        edit = cfg.mutate;
      };
      description = "The tick. Set only by tests/deploy-safety's mutants.";
    };
  };

  config = {
    environment.systemPackages = [ cfg.package ];

    assertions = [
      {
        assertion =
          cfg.canary.role == "none"
          || (
            cfg.canary.markerDir != ""
            && cfg.canary.markerMount != ""
            && lib.hasPrefix "${cfg.canary.markerMount}/" cfg.canary.markerDir
          );
        message = "cluster.deploy.canary: role ${cfg.canary.role} needs markerDir on markerMount (have markerDir '${cfg.canary.markerDir}', markerMount '${cfg.canary.markerMount}').";
      }
      {
        assertion = !cfg.canary.requireCleanUnlock || cfg.canary.requireReport;
        message = "cluster.deploy.canary: requireCleanUnlock reads the boot report, so it needs requireReport.";
      }
    ];

    # Appended to, and not mkForce'd: a forced version dropped switch-to-configuration
    # from the closure when this was prototyped. The boot stack is written on every node,
    # whatever its role, so a node that becomes a follower later compares like with like.
    system.systemBuilderCommands = ''
      printf '%s\n' ${lib.escapeShellArg (builtins.toJSON cfg.bootContract)} > $out/boot-contract
      printf '%s\n' ${lib.escapeShellArg (builtins.toJSON cfg.bootStack)} > $out/boot-stack
    '';

    # The canary's half (lib/deploy-canary-publish.nix). On a timer and not once at boot,
    # because the shared filesystem may come up minutes after multi-user.target, and a
    # run that has nothing to do yet exits 0 and leaves it to the next. Only ever about
    # the BOOTED closure, so a switch restarting it would change nothing: it is not
    # restarted anyway, like the boot report.
    systemd.services.cluster-deploy-canary-publish = lib.mkIf (cfg.canary.role == "canary") {
      description = "Publish the boot stack this canary booted, for the other nodes' deploys";
      after = [
        "multi-user.target"
      ]
      ++ lib.optional cfg.canary.requireReport "cluster-boot-report.service";
      restartIfChanged = false;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe cfg.canary.publisher;
        # A oneshot has no start timeout by default, and the write is on a FUSE mount.
        TimeoutStartSec = "10min";
      };
    };
    systemd.timers.cluster-deploy-canary-publish = lib.mkIf (cfg.canary.role == "canary") {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = "10min";
      };
    };

    # Break-glass hold. `clan machines update` pushes a build from a working tree
    # that may not be pushed to git yet; the next tick of this timer (<=10 min)
    # would then rebuild from the LAST PUSHED commit and silently revert it. The
    # two paths do not conflict mechanically — both set the system profile and run
    # switch-to-configuration — they conflict logically, and a convenient CLI makes
    # that far easier to hit than it was with a manual deploy.
    #
    #   touch /run/cluster-upgrade.hold   # before `clan machines update`
    #   rm    /run/cluster-upgrade.hold   # after pushing
    #
    # /run so it clears on reboot: a hold someone forgot to remove must not
    # silently freeze a node's deploys forever.
    #
    # Automated holds use the DIRECTORY /run/cluster-upgrade.hold.d/, one file per
    # holder, so they cannot release each other: a backup dumping a database, or
    # a restore importing one, must not have a pull-deploy reload the container
    # underneath it (modules/backup-core.nix). The single file above stays the
    # human break-glass.
    systemd.services.cluster-upgrade-rollback-guard = {
      description = "Refuse what came after an older generation booted at the console";
      wantedBy = [ "multi-user.target" ];
      # Never in the middle of a switch: see rollbackGuard.
      restartIfChanged = false;
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = rollbackGuard;
      };
    };

    systemd.services.cluster-upgrade = {
      # requires as well as after: a guard that failed must stop the tick, not be skipped.
      after = [
        "network-online.target"
        "nix-daemon.service"
        "cluster-upgrade-rollback-guard.service"
      ];
      requires = [ "cluster-upgrade-rollback-guard.service" ];
      wants = [ "network-online.target" ];
      # This unit runs the switch, so the switch must never restart it: when a
      # deploy changes the unit itself, switch-to-configuration queues a start of
      # cluster-upgrade.service, which merges into the job already running it,
      # and the two wait on each other forever (node1, 2026-10-15: 45 min, until
      # the unit was stopped by hand). nixpkgs' own nixos-upgrade.service sets
      # the same for the same reason.
      restartIfChanged = false;
      unitConfig = {
        ConditionPathExists = "!/run/cluster-upgrade.hold";
        ConditionDirectoryNotEmpty = "!/run/cluster-upgrade.hold.d";
      };
      # Don't let a deploy race a rebuild-in-progress from a manual run.
      serviceConfig = {
        Type = "oneshot";
        ExecStart = lib.getExe cfg.package;
      };
    };

    systemd.timers.cluster-upgrade = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "5min";
        OnCalendar = cfg.pullInterval;
        Persistent = true;
        # Stagger nodes so they don't all hit GitHub (and rebuild) in lockstep.
        RandomizedDelaySec = "90s";
      };
    };
  };
}
