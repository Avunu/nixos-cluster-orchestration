# What a pull deploy does when something is wrong with what it was given
# (lib/cluster-upgrade.nix), and whether a frozen node resets itself. The real tick, the
# real unit, and specialisations as the candidate closures: the same store paths and
# profile a node has, with `cat` standing in for `nix build` of the site's flake.
#
# A node runs what it was told to on its own, within ten minutes, and has no console
# anyone is watching. So each of these is a state a node must get out of, or refuse to
# enter, without help.
#
# The VM has no bootloader: it always boots the closure it was started with. That is
# what makes rollback-sticks real, as a restart here is a node booted into the old
# generation with the bad one still its profile, and the real timer then fires the tick.
{
  pkgs,
  lib,
  mutant ? "",
  extraModule ? { },
  # The fleet's weekly garbage collection (modules/zfs-host.nix). A mutant swaps in plain
  # nix-collect-garbage.
  generationGc ? import ../lib/generation-gc.nix { inherit pkgs; },
}:
let
  # PID 1 stopped, not killed, so that it stops feeding the watchdog and the kernel has
  # nothing to panic about. An earlier attempt with a kernel panic also exited on the
  # control and proved nothing. PTRACE_SEIZE and PTRACE_INTERRUPT send PID 1 no signal,
  # and it would ignore most of them. The stop lasts only as long as this tracer does.
  freezePid1 = pkgs.writeScriptBin "freeze-pid1" ''
    #!${pkgs.python3}/bin/python3
    import ctypes
    import os
    import time

    libc = ctypes.CDLL(None, use_errno=True)
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    libc.ptrace.restype = ctypes.c_long
    PTRACE_SEIZE = 0x4206
    PTRACE_INTERRUPT = 0x4207
    WALL = 0x40000000

    for request in (PTRACE_SEIZE, PTRACE_INTERRUPT):
        if libc.ptrace(request, 1, None, None) != 0:
            raise OSError(ctypes.get_errno(), "ptrace of PID 1 failed")
    os.waitpid(1, WALL)
    print("frozen", flush=True)
    while True:
        time.sleep(3600)
  '';

  # Identical on the node under test and on the control, apart from the watchdog
  # setting. -no-reboot makes a reset end QEMU, which the driver can time to the
  # millisecond without waiting for a boot to print something.
  withWatchdogDevice = {
    virtualisation.memorySize = 768;
    virtualisation.qemu.options = [
      "-device i6300esb"
      "-no-reboot"
    ];
    boot.kernelModules = [ "i6300esb" ];
    environment.systemPackages = [ freezePid1 ];
  };

  # A unit the candidates differ in.
  unit =
    {
      script,
      restart ? false,
    }:
    {
      systemd.services.deploy-safety-unit = {
        wantedBy = [ "multi-user.target" ];
        inherit script;
        unitConfig.StartLimitIntervalSec = 0;
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        }
        // lib.optionalAttrs restart {
          Restart = "on-failure";
          RestartSec = "2s";
        };
      };
    };
in
pkgs.testers.runNixOSTest {
  name = "deploy-safety";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [
        ../modules/pull-deploy-core.nix
        withWatchdogDevice
        extraModule
      ];
      environment.systemPackages = [ generationGc ];

      # What the nodes run: see modules/cluster-common.nix.
      systemd.settings.Manager = import ../lib/watchdog-settings.nix;

      # Test nodes leave this out unless asked: nothing normally switches in a test.
      system.switch.enable = true;
      # This VM has no bootloader to install, and GRUB fails on trying. `badboot` below
      # is the one bootloader failure here.
      boot.loader.grub.enable = false;

      # A missing file is a failed build, and this one has to outlast a reboot.
      cluster.deploy.targetCommand = "cat /var/lib/deploy-safety-target";
      cluster.deploy.bootContract.identityHash = "the-running-one";

      # The node's timer, with only the waits shortened. The driver masks it until
      # /run clears: see quiet_timer().
      cluster.deploy.pullInterval = "hourly";
      systemd.timers.cluster-upgrade.timerConfig = {
        OnBootSec = lib.mkForce "15s";
        RandomizedDelaySec = lib.mkForce "0";
      };

      specialisation = {
        # A unit that fails during the switch.
        broken.configuration = unit { script = "exit 1"; };
        # The commit after that one.
        fixed.configuration = unit { script = "exit 0"; };
        # A login or mount unit during a quorum outage: still retrying at the end of the
        # switch, fine once the outage is over.
        transient.configuration = unit {
          script = "test ! -e /run/deploy-safety-outage";
          restart = true;
        };
        # Fails before anything activates.
        badboot.configuration.system.build.installBootLoader = lib.mkForce (
          pkgs.writeShellScript "failing-bootloader" ''
            echo "deploy-safety: the ESP is full, or whatever else it may be" >&2
            exit 1
          ''
        );
        # What a topology edit looks like from here.
        newcontract.configuration.cluster.deploy.bootContract.identityHash = lib.mkForce "another-one";
        # An admin removed: the initrd's authorized keys change.
        newkeys.configuration.cluster.deploy.bootContract.authorizedKeysSha256 = "another-key-set";
        otherwise.configuration = unit { script = "true"; };
      };
    };

  # The negative control of watchdog-fires. Same device, same freeze, and nothing has
  # told systemd about the device.
  nodes.nowatchdog = {
    imports = [ withWatchdogDevice ];
  };

  testScript = ''
    import datetime
    import runpy
    import shlex
    import time

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    PROM = "/var/lib/prometheus-node-exporter-text/deploy.prom"
    STATE = "/var/lib/cluster-upgrade"
    TARGET = "/var/lib/deploy-safety-target"
    SYSTEM = "/nix/var/nix/profiles/system"
    OUTAGE = "/run/deploy-safety-outage"
    # What `avc deploy retry`, `avc boot rollback` and `unrollback` send to a node.
    AVC = runpy.run_path("${../tools/avc/avc/core}/deploy_state.py")
    # The closure the VM boots: set in main(), once it is up.
    base = ""


    def current():
        return machine.succeed("readlink -f /run/current-system").strip()


    def profile():
        return machine.succeed(f"readlink -f {SYSTEM}").strip()


    def candidate(name):
        return machine.succeed(f"readlink -f {base}/specialisation/{name}").strip()


    def state(name):
        return machine.execute(f"cat {STATE}/{name}")[1].strip()


    def metrics():
        rc, out = machine.execute(f"cat {PROM}")
        return dict(line.split(" ", 1) for line in out.splitlines()) if rc == 0 else {}


    def booted():
        return machine.succeed("readlink -f /run/booted-system").strip()


    def switches():
        """How many times a tick has really run the switch, ever."""
        return int(machine.succeed("journalctl -u cluster-upgrade.service -o cat | grep -c 'switch rc=' || true").strip())


    def tick(target=None):
        """One tick of the timer. Returns the unit's result."""
        if target is not None:
            machine.succeed(f"echo {target} > {TARGET}")
        return machine.execute("systemctl start cluster-upgrade.service")[0]


    def basename(path):
        return path.rsplit("/", 1)[1]


    def default_entry():
        """What `avc boot reboot` reads about the default entry, from the real profile."""
        out = machine.succeed(AVC["DEFAULT_ENTRY"])
        return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


    def logged(text):
        """How many times the tick has logged a line containing this, ever."""
        return int(
            machine.succeed(
                f"journalctl -u cluster-upgrade.service -o cat | grep -cF -- {shlex.quote(text)} || true"
            ).strip()
        )


    def reboot_into_timer_tick():
        """A power cycle, with the tick that follows it left to the node's own timer. Returns
        once that tick has written its metrics and finished."""
        machine.succeed(f"rm -f {PROM}")
        machine.shutdown()
        machine.start()
        machine.wait_until_succeeds(
            f"test -e {PROM} && test \"$(systemctl show -P ActiveState cluster-upgrade.service)\" = inactive",
            timeout=180,
        )
        quiet_timer()


    def quiet_timer():
        """The subtests drive the ticks themselves. A runtime mask, because a stopped timer
        comes back with the targets at the next switch, and a reboot must clear this."""
        machine.succeed("systemctl mask --runtime --now cluster-upgrade.timer; systemctl stop cluster-upgrade.service")


    def reset():
        machine.succeed(f"nix-env -p {SYSTEM} --set {base}")
        machine.execute(f"{base}/bin/switch-to-configuration switch")
        machine.succeed(f"systemctl reset-failed; rm -rf {STATE} {PROM} {TARGET} {OUTAGE} /run/cluster-upgrade.approve")
        assert current() == base, "reset did not get back to the base closure"


    def main():
        global base
        machine.start()
        machine.wait_for_unit("multi-user.target")
        base = current()
        # It may already have fired, on this short OnBootSec.
        quiet_timer()
        reset()

        with subtest("failed-unit-retries-then-stops"):
            broken = candidate("broken")
            results, seen = [], []
            before = switches()
            for _ in range(3):
                results.append(tick(broken))
                seen.append(state("attempts"))
            # rc=4 with the closure already current, which the old gate took for done.
            on_new_closure = current() == broken and profile() == broken
            three = switches() - before == 3 and seen == ["1", "2", "3"] and all(r != 0 for r in results)
            rc4 = int(machine.succeed("journalctl -u cluster-upgrade.service -o cat | grep -c 'switch rc=4 ' || true").strip())
            before = switches()
            results = [tick(), tick()]
            nothing_more = switches() == before and state("attempts") == "3" and all(r != 0 for r in results)
            m = metrics()
            control(
                "failed-unit-retries-then-stops",
                on_new_closure
                and three
                and rc4 == 3
                and nothing_more
                and state("good") == ""
                and m.get("cluster_deploy_activation_failed") == "1"
                and m.get("cluster_deploy_attempts") == "3",
                f"{seen=} {results=} {rc4=} {m=}",
            )

            # A person says it is worth another go: the same closure, from the start.
            machine.succeed(AVC["RETRY"])
            before = switches()
            rc = tick()
            control(
                "deploy-retry-tries-again",
                rc != 0
                and switches() - before == 1
                and state("attempts") == "1"
                and state("target") == broken,
                f"{rc=} attempts={state('attempts')}",
            )

        with subtest("fixed-closure-recovers"):
            fixed = candidate("fixed")
            rc = tick(fixed)
            m = metrics()
            control(
                "fixed-closure-recovers",
                rc == 0
                and current() == fixed
                and profile() == fixed
                and state("good") == fixed
                and state("attempts") == ""
                and m.get("cluster_deploy_activation_failed") == "0"
                and m.get("cluster_deploy_attempts") == "0"
                and m.get("cluster_reboot_pending") == "1",
                f"{rc=} {m=}",
            )
            # And it is left alone from then on.
            before = switches()
            rc = tick()
            m = metrics()
            control(
                "fixed-closure-stays-done",
                rc == 0 and switches() == before and m.get("cluster_reboot_pending") == "1",
                f"{rc=} {m=}",
            )

        with subtest("reboot-pending-follows-the-booted-closure"):
            # Pull deploys never reboot, so this metric is all that says one is owed. Both
            # ways of ending a good tick report it, and a closure that is running but was
            # not booted is 1 above. Back on the one it booted, nothing is owed.
            assert booted() == base, f"this VM should still be on the closure it booted: {booted()}"
            activated_rc = tick(base)
            activated = metrics().get("cluster_reboot_pending")
            done_rc = tick()
            done = metrics().get("cluster_reboot_pending")
            control(
                "reboot-pending-follows-the-booted-closure",
                activated_rc == 0 and done_rc == 0 and current() == base and activated == "0" and done == "0",
                f"{activated_rc=} {activated=} {done_rc=} {done=}",
            )

        reset()
        with subtest("transient-failure-clears"):
            transient = candidate("transient")
            machine.succeed(f"touch {OUTAGE}")
            results = [tick(transient) for _ in range(3)]
            failing = all(r != 0 for r in results) and state("attempts") == "3" and current() == transient
            # Still out: a tick must not call this healthy. The unit is in auto-restart,
            # which is not the same as failed.
            rc = tick()
            still_failing = rc != 0 and state("good") == "" and metrics().get("cluster_deploy_activation_failed") == "1"
            machine.succeed(f"rm {OUTAGE}")
            machine.wait_until_succeeds("systemctl is-active deploy-safety-unit.service", timeout=30)

            # The node is healthy now, but this tick can't ask: both ways to reach PID 1
            # are closed to the unit, so systemctl really errors, with nothing on stdout.
            # No answer is not a healthy answer. The log line is what shows this took the
            # error path, and not that some other unit happened to be failing.
            dropin = "/run/systemd/system/cluster-upgrade.service.d"
            machine.succeed(
                f"mkdir -p {dropin} && "
                f"printf '[Service]\\nInaccessiblePaths=/run/systemd/private /run/dbus\\n' > {dropin}/no-bus.conf && "
                "systemctl daemon-reload"
            )
            rc = tick()
            m = metrics()
            said = int(machine.succeed("journalctl -u cluster-upgrade.service -o cat | grep -c 'cannot list units' || true").strip())
            control(
                "recovery-check-fails-closed",
                rc != 0
                and said == 1
                and state("good") == ""
                and state("attempts") == "3"
                and m.get("cluster_deploy_activation_failed") == "1",
                f"{rc=} {said=} good={state('good')} {m=}",
            )
            machine.succeed(f"rm -r {dropin} && systemctl daemon-reload")

            before = switches()
            rc = tick()
            m = metrics()
            control(
                "transient-failure-clears",
                failing
                and still_failing
                and rc == 0
                and switches() == before
                and state("good") == transient
                and state("attempts") == ""
                and m.get("cluster_deploy_activation_failed") == "0"
                and m.get("cluster_reboot_pending") == "1",
                f"{results=} {failing=} {still_failing=} {rc=} {m=}",
            )

        reset()
        with subtest("bootloader-failure-keeps-current"):
            rc = tick(candidate("badboot"))
            m = metrics()
            control(
                "bootloader-failure-keeps-current",
                rc != 0
                and current() == base
                and state("good") == ""
                and state("attempts") == "1"
                and m.get("cluster_deploy_activation_failed") == "1",
                f"{rc=} {m=}",
            )

        reset()
        with subtest("contract-change-refused-profile-untouched"):
            newcontract = candidate("newcontract")
            contracts = machine.succeed(f"cat {base}/boot-contract {newcontract}/boot-contract").splitlines()
            assert contracts == ['{"identityHash":"the-running-one"}', '{"identityHash":"another-one"}'], f"{contracts=}"
            before = switches()
            rc = tick(newcontract)
            m = metrics()
            control(
                "contract-change-refused-profile-untouched",
                rc == 0
                and current() == base
                and profile() == base
                and switches() == before
                and state("attempts") == ""
                and m.get("cluster_deploy_contract_blocked") == "1"
                and m.get("cluster_deploy_activation_failed") == "0",
                f"{rc=} current={current()} profile={profile()} {m=}",
            )

        with subtest("contract-key-change-names-rotation"):
            # Approving a closure that drops an admin does not retire the key: every older
            # generation signed with the same keys still has it, and still passes PCR 7. The
            # refusal is where the operator is asked to approve, so it has to say so there.
            rotation = "needs new Secure Boot signing keys and a rebind"
            names_identity = logged("contract fields that differ: identityHash")
            rotation_before = logged(rotation)
            rc = tick(candidate("newkeys"))
            control(
                "contract-key-change-names-rotation",
                rc == 0
                and current() == base
                and logged("contract fields that differ: authorizedKeysSha256") == 1
                and logged(rotation) == rotation_before + 1
                # The identity change above named its own field, and did not say this.
                and names_identity == 1
                and rotation_before == 0,
                f"{rc=} {names_identity=} {rotation_before=} after={logged(rotation)}",
            )

        with subtest("contract-approval-is-per-closure"):
            machine.succeed(f"echo {basename(candidate('fixed'))} > /run/cluster-upgrade.approve")
            rc = tick(newcontract)
            control(
                "contract-approval-is-per-closure",
                rc == 0 and current() == base and metrics().get("cluster_deploy_contract_blocked") == "1",
                f"{rc=}",
            )

        with subtest("contract-approved-activates"):
            machine.succeed(f"echo {basename(newcontract)} >> /run/cluster-upgrade.approve")
            rc = tick(newcontract)
            m = metrics()
            control(
                "contract-approved-activates",
                rc == 0
                and current() == newcontract
                and profile() == newcontract
                and state("good") == newcontract
                and m.get("cluster_deploy_contract_blocked") == "0",
                f"{rc=} {m=}",
            )
            # It is the running contract now, so what was approved is a matter of record.
            # Going back is a change of contract like any other.
            machine.succeed("rm /run/cluster-upgrade.approve")
            rc = tick(base)
            control(
                "contract-compares-with-the-running-closure",
                rc == 0 and current() == newcontract and metrics().get("cluster_deploy_contract_blocked") == "1",
                f"{rc=}",
            )

        reset()
        with subtest("build-failure-metric"):
            before = switches()
            rc = tick()
            m = metrics()
            control(
                "build-failure-metric",
                rc != 0
                and current() == base
                and profile() == base
                and switches() == before
                and m.get("cluster_deploy_build_failed") == "1",
                f"{rc=} {m=}",
            )

        reset()
        with subtest("holds-stop-the-tick"):
            # Failover restores will rely on the directory: see modules/backup-core.nix.
            fixed = candidate("fixed")
            for hold in ("touch /run/cluster-upgrade.hold", "mkdir -p /run/cluster-upgrade.hold.d && touch /run/cluster-upgrade.hold.d/x"):
                machine.succeed(hold)
                before = switches()
                rc = tick(fixed)
                control(
                    "holds-stop-the-tick",
                    rc == 0 and current() == base and switches() == before,
                    f"{hold=} {rc=}",
                )
                machine.succeed("rm -rf /run/cluster-upgrade.hold /run/cluster-upgrade.hold.d")

        reset()
        with subtest("rollback-sticks"):
            # A closure that activates and then does not come back from a reboot, and an
            # operator who has booted an older generation at the console. There is a good
            # one between them, and the bad one is what the tick will build next.
            fixed = candidate("fixed")
            bad = candidate("otherwise")
            assert tick(fixed) == 0 and tick(bad) == 0 and current() == bad, "these should activate before one goes bad"

            # Nothing refused yet: the default entry is what runs.
            before_rollback = default_entry()

            # Before the console boot nothing comes after the running closure, and to
            # refuse the running closure would be wrong in any case.
            rc = machine.execute(AVC["REFUSE_LATER"])[0]
            control(
                "rollback-on-the-newest-refuses-nothing",
                rc == AVC["NOTHING_AFTER"] and state("refused") == "",
                f"{rc=} refused={state('refused')}",
            )

            # Running the old closure, with the bad one still the profile. A restart can't
            # stand in for this step, as the timer would fire before the command got there.
            machine.succeed(f"{base}/bin/switch-to-configuration test")
            printed = machine.succeed(AVC["REFUSE_LATER"]).split()
            again = machine.succeed(AVC["REFUSE_LATER"]).split()
            want = [basename(fixed), basename(bad)]
            control(
                "rollback-refuses-what-came-after",
                printed == want
                and again == want
                and state("refused").split() == want
                and current() == base
                and profile() == bad,
                f"{printed=} {again=} refused={state('refused')} current={current()} profile={profile()}",
            )
            # The default entry is still the bad closure, and `avc boot reboot` must see that
            # it is refused: the contract cannot say so when only the kernel changed.
            after_rollback = default_entry()
            control(
                "reboot-check-sees-a-refused-default",
                before_rollback
                == {"default_entry": basename(bad), "default_refused": "no", "default_is_running": "yes"}
                and after_rollback
                == {"default_entry": basename(bad), "default_refused": "yes", "default_is_running": "no"},
                f"{before_rollback=} {after_rollback=}",
            )

            # Only a tick after the reboot can write this again. Nothing below starts the
            # unit, and the mask went with /run, so that tick is the timer's.
            reboot_into_timer_tick()
            assert booted() == base, "this VM should boot the closure it was started with"
            result = machine.succeed("systemctl show -P Result cluster-upgrade.service").strip()
            switched = machine.succeed("journalctl -b -u cluster-upgrade.service -o cat | grep -c 'switch rc=' || true").strip()
            m = metrics()
            control(
                "rollback-sticks",
                result == "success"
                and current() == base
                and switched == "0"
                and m.get("cluster_deploy_rollback_held") == "1"
                and m.get("cluster_deploy_activation_failed") == "0"
                and profile() == bad,
                f"{result=} {switched=} current={current()} profile={profile()} {m=}",
            )

            # A name not on the list is probably a typo, and the list stays as it was.
            rc = machine.execute(AVC["unrefuse_script"](basename(candidate("transient"))))[0]
            control("unrollback-of-an-unlisted-closure-fails", rc != 0 and state("refused").split() == want, f"{rc=}")
            machine.succeed(AVC["unrefuse_script"](basename(bad)))
            control(
                "unrollback-removes-only-that-closure",
                state("refused").split() == [basename(fixed)]
                and default_entry().get("default_refused") == "no",
                f"refused={state('refused')} default={default_entry()}",
            )

            # The denylist is what held it, and nothing else about this closure: off the
            # list, the same tick activates it.
            rc = tick(bad)
            control(
                "rollback-released-activates",
                rc == 0 and current() == bad and metrics().get("cluster_deploy_rollback_held") == "0",
                f"{rc=}",
            )

        reset()
        with subtest("rollback-refused-at-boot"):
            # The same escape, in the order it happens at a console: the node boots the old
            # generation first, and nobody has written anything yet. A timer slot was missed
            # while it was down, so with Persistent=true the timer fires as soon as it
            # starts: the node itself has to have refused the bad closure by then.
            fixed = candidate("fixed")
            bad = candidate("otherwise")
            assert tick(fixed) == 0 and tick(bad) == 0 and current() == bad, "these should activate before one goes bad"
            assert state("refused") == "", "nothing may be refused before the reboot"
            machine.succeed(
                "mkdir -p /var/lib/systemd/timers && "
                "touch -d '2 hours ago' /var/lib/systemd/timers/stamp-cluster-upgrade.timer"
            )
            reboot_into_timer_tick()
            assert booted() == base, "this VM should boot the closure it was started with"
            result = machine.succeed("systemctl show -P Result cluster-upgrade.service").strip()
            switched = machine.succeed("journalctl -b -u cluster-upgrade.service -o cat | grep -c 'switch rc=' || true").strip()
            guard = machine.succeed("journalctl -b -u cluster-upgrade-rollback-guard.service -o cat")
            started = machine.succeed(
                "journalctl -b -u cluster-upgrade.service -o short-monotonic | grep -m1 -E 'Start(ing|ed)' || true"
            ).strip()
            m = metrics()
            control(
                "rollback-refused-at-boot",
                result == "success"
                and current() == base
                and switched == "0"
                and state("refused").split() == [basename(fixed), basename(bad)]
                and m.get("cluster_deploy_rollback_held") == "1"
                and profile() == bad,
                f"{result=} {switched=} refused={state('refused')} current={current()} {m=}\n"
                f"first tick: {started}\n{guard}",
            )
            # Unrollback is the way back, as after `avc boot rollback`.
            machine.succeed(AVC["unrefuse_script"](basename(bad)))
            rc = tick(bad)
            control(
                "rollback-refused-at-boot-unrollback-activates",
                rc == 0 and current() == bad and metrics().get("cluster_deploy_rollback_held") == "0",
                f"{rc=}",
            )

        reset()
        with subtest("gc-keeps-the-booted-generation"):
            # Weeks of deploys on a node that has not rebooted since it booted `base`: every
            # generation a month old, and the booted one neither the newest nor the running.
            fixed = candidate("fixed")
            bad = candidate("otherwise")
            assert tick(fixed) == 0 and tick(bad) == 0 and current() == bad, "these should activate"
            machine.succeed(f"for l in {SYSTEM}-*-link; do touch -h -d '30 days ago' \"$l\"; done")
            out = machine.succeed("cluster-generation-gc 2>&1 | tail -n 5")
            links = machine.succeed(f"for l in {SYSTEM}-*-link; do readlink -f \"$l\"; done").split()
            control(
                "gc-keeps-the-booted-generation",
                booted() in links and bad in links and fixed not in links and profile() == bad,
                f"booted {booted()} kept: {booted() in links}; running kept: {bad in links}; "
                f"neither, older: {fixed in links}\n{out}",
            )
            # And a rollback still has something to start from.
            machine.succeed(f"{base}/bin/switch-to-configuration test")
            refused = machine.succeed(AVC["REFUSE_LATER"]).split()
            control(
                "gc-keeps-rollback-possible",
                refused == [basename(bad)],
                f"{refused=}",
            )

        reset()
        with subtest("unreadable-denylist-refuses"):
            # A directory where the list should be: grep can't read it, and says so with
            # rc=2. The list may name this closure, so that is a refusal, and a loud one.
            machine.succeed(f"mkdir -p {STATE}/refused")
            fixed = candidate("fixed")
            before = switches()
            rc = tick(fixed)
            m = metrics()
            control(
                "unreadable-denylist-refuses",
                rc != 0
                and current() == base
                and profile() == base
                and switches() == before
                and m.get("cluster_deploy_rollback_held") == "1",
                f"{rc=} current={current()} {m=}",
            )
            # And `avc boot reboot` can't tell either, which it refuses.
            d = default_entry()
            control("reboot-check-unreadable-denylist-is-unknown", d.get("default_refused") == "unknown", f"{d=}")

        # Last: it ends the VM.
        with subtest("watchdog-fires"):
            nowatchdog.start()
            nowatchdog.wait_for_unit("multi-user.target")

            watching = machine.succeed("systemctl show -p RuntimeWatchdogUSec --value").strip()
            unwatched = nowatchdog.succeed("systemctl show -p RuntimeWatchdogUSec --value").strip()
            assert watching == "10s", f"{watching=}"
            assert unwatched == "0", f"{unwatched=}"
            for vm in (machine, nowatchdog):
                vm.succeed("test -e /dev/watchdog0")

            def freeze(vm):
                # head returns on the tracer's first line, so this returns as PID 1 stops.
                out = vm.succeed(
                    "mkfifo /tmp/frozen && "
                    "{ setsid nohup freeze-pid1 >/tmp/frozen 2>&1 </dev/null & } && "
                    "head -n1 /tmp/frozen && grep ^State: /proc/1/status"
                )
                assert "frozen" in out and "tracing stop" in out, f"PID 1 did not stop: {out}"

            freeze(nowatchdog)
            frozen_at = time.monotonic()
            freeze(machine)
            t0 = time.monotonic()
            try:
                machine.wait_for_shutdown(timeout=datetime.timedelta(seconds=40))
                elapsed = time.monotonic() - t0
            except Exception as e:
                elapsed = None
                print(f"machine did not reset: {e}")
            print(f"watchdog-fires: reset {elapsed} s after PID 1 stopped")
            # RuntimeWatchdogSec=10s: systemd pets it every 5s, so 5 to 10s from the last
            # pet to the reset.
            control(
                "watchdog-fires",
                elapsed is not None and elapsed <= 12,
                f"{elapsed=}",
            )

            time.sleep(max(0, 45 - (time.monotonic() - frozen_at)))
            assert nowatchdog.process is not None
            alive = nowatchdog.process.poll() is None
            still = nowatchdog.succeed("grep ^State: /proc/1/status") if alive else ""
            control(
                "watchdog-control-stays-alive",
                alive and "tracing stop" in still,
                f"{alive=} {still=}",
            )


    run_main(main)
  '';
}
