# The staged rollout (design D22, modules/pull-deploy-core.nix): a node that is not the
# canary activates a new boot stack only once the canary has BOOTED it, cleanly, and said
# so on the shared store. Two VMs, the real tick and the real publisher, and the test
# driver's shared directory standing in for /mnt/jfs, which both mount.
#
# Why it matters: a nixpkgs, kernel, Lanzaboote, clan or library bump is in every node's
# next closure at once, and its kernel, initrd and unlock path first run at a reboot. A
# stack that cannot boot passes every build gate and activates everywhere, then stops the
# whole fleet at its next reboots. The canary reboots into it first, with someone
# watching, and the others wait for that.
#
# The VMs have no bootloader. A "reboot into the new closure" here is the canary started
# with init= of that closure on the kernel command line, after the base one, which is
# exactly how a boot entry for it would start it: the same kernel and initrd, and the new
# closure's stage 2, with /run/booted-system pointing at it. Which entry real firmware
# picks is not under test; the boot-* checks own that.
{
  pkgs,
  lib,
  mutant ? "",
  # One control removed, on the VM it belongs to (flake.nix, the canary-* mutants).
  canaryModule ? { },
  followerModule ? { },
}:
let
  # The publisher reads these series of the real boot report (modules/boot-report.py), and
  # the stand-in below writes them. If the report renames one, this stops at evaluation
  # rather than testing a stand-in nothing else agrees with.
  reportSeries = [
    "cluster_boot_report_timestamp_seconds"
    "cluster_boot_unlock_passphrase"
    "cluster_boot_unlock_tpm_devices"
    "cluster_boot_unlock_expected_devices"
  ];
  reportText = builtins.readFile ../modules/boot-report.py;

  # Three boot stacks: what both VMs run, a bump, and the bump after it. Each is the same
  # on both VMs, as it is on every node of a site.
  stack = nixpkgs: {
    inherit nixpkgs;
    kernel = "kernel-of-${nixpkgs}";
  };

  common =
    { lib, ... }:
    {
      imports = [ ../modules/pull-deploy-core.nix ];
      virtualisation.memorySize = 768;
      # Test nodes leave this out unless asked: nothing normally switches in a test.
      system.switch.enable = true;
      # No bootloader to install, and GRUB fails on trying (tests/deploy-safety.nix).
      boot.loader.grub.enable = false;

      cluster.deploy = {
        # A missing file is a failed build, and this one has to outlast a reboot.
        targetCommand = "cat /var/lib/canary-gate-target";
        pullInterval = "hourly";
        bootContract.fixture = "unchanged";
        bootStack = stack "nixpkgs-a";
        canary = {
          markerDir = "/tmp/shared/canary-booted";
          markerMount = "/tmp/shared";
        };
      };
      # The driver runs every tick by hand.
      systemd.timers.cluster-upgrade.wantedBy = lib.mkForce [ ];

      specialisation = {
        # The same boot stack, something else changed: an app release.
        appchange.configuration.environment.etc."canary-gate-app".text = "a new release";
        # A nixpkgs bump.
        bumped.configuration.cluster.deploy.bootStack = lib.mkForce (stack "nixpkgs-b");
        # The one after it, which no canary ever boots here.
        bumpedAgain.configuration.cluster.deploy.bootStack = lib.mkForce (stack "nixpkgs-c");
      };
    };
in
assert lib.all (s: lib.hasInfix s reportText) reportSeries;
pkgs.testers.runNixOSTest {
  name = "canary-gate";

  nodes.canary =
    { lib, ... }:
    {
      imports = [
        common
        canaryModule
      ];
      cluster.deploy.canary = {
        role = "canary";
        requireReport = true;
        requireCleanUnlock = true;
      };
      # The real timer, sooner. The driver never starts the publisher after a boot.
      systemd.timers.cluster-deploy-canary-publish.timerConfig.OnBootSec = lib.mkForce "20s";

      # Stands in for modules/boot-report.nix, which needs a real unlock to report one
      # (the boot-* checks run the real one): the same file and series, with the unlock the
      # driver chose for this boot. Two legs, as on a node. `none` is a boot whose report
      # failed or has not run yet: like the real one, it then leaves the last boot's file
      # where it was (modules/boot-report.py replaces the file only on success).
      systemd.services.cluster-boot-report = {
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
        };
        script = ''
          unlock=$(cat /var/lib/canary-gate-unlock 2>/dev/null || echo tpm)
          if [ "$unlock" = none ]; then exit 0; fi
          if [ "$unlock" = tpm ]; then p=0; n=2; else p=1; n=0; fi
          M=/var/lib/prometheus-node-exporter-text
          mkdir -p "$M"
          printf '%s\n' \
            "cluster_boot_report_timestamp_seconds $(date +%s)" \
            "cluster_boot_insecure_optout 0" \
            "cluster_boot_unlock_passphrase $p" \
            "cluster_boot_unlock_tpm_devices $n" \
            "cluster_boot_unlock_expected_devices 2" >"$M/boot_report.prom"
        '';
      };
    };

  nodes.follower = {
    imports = [
      common
      followerModule
    ];
    cluster.deploy.canary.role = "follower";
  };

  testScript = ''
    import json
    import os
    import shlex

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    MARKERS = "/tmp/shared/canary-booted"
    TARGET = "/var/lib/canary-gate-target"
    SYSTEM = "/nix/var/nix/profiles/system"
    DEPLOY = "/var/lib/prometheus-node-exporter-text/deploy.prom"
    PUBLISH = "/var/lib/prometheus-node-exporter-text/deploy_canary.prom"
    base = {}


    def current(vm):
        return vm.succeed("readlink -f /run/current-system").strip()


    def booted(vm):
        return vm.succeed("readlink -f /run/booted-system").strip()


    def profile(vm):
        return vm.succeed(f"readlink -f {SYSTEM}").strip()


    def candidate(vm, name):
        return vm.succeed(f"readlink -f {base[vm.name]}/specialisation/{name}").strip()


    def stack_key(vm, closure):
        return vm.succeed(f"sha256sum {closure}/boot-stack").split()[0]


    def metrics(vm, path):
        rc, out = vm.execute(f"cat {path}")
        return dict(line.split(" ", 1) for line in out.splitlines()) if rc == 0 else {}


    def tick(vm, target):
        vm.succeed(f"echo {target} > {TARGET}")
        return vm.execute("systemctl start cluster-upgrade.service")[0]


    def switches(vm):
        return int(vm.succeed("journalctl -u cluster-upgrade.service -o cat | grep -c 'switch rc=' || true").strip())


    def logged(vm, unit, text):
        return int(
            vm.succeed(f"journalctl -u {unit} -o cat | grep -cF -- {shlex.quote(text)} || true").strip()
        )


    def published(key):
        """Read on the host, so it holds whichever VM is up, and whatever either has mounted."""
        return (canary.shared_dir / "canary-booted" / key).is_file()


    def basename(path):
        return path.rsplit("/", 1)[1]


    def publish_ran():
        """The publisher's own timer fired after this boot and it finished."""
        canary.wait_until_succeeds(
            f"test -e {PUBLISH} && test \"$(systemctl show -P ActiveState cluster-deploy-canary-publish.service)\" = inactive",
            timeout=180,
        )


    def boot_canary_into(closure, unlock):
        """A power cycle of the canary into this closure, as its new default entry would
        boot it, with the report saying how this boot unlocked."""
        canary.succeed(f"echo {unlock} > /var/lib/canary-gate-unlock && rm -f {PUBLISH}")
        canary.shutdown()
        os.environ["QEMU_KERNEL_PARAMS"] = f"init={closure}/init"
        try:
            canary.start()
        finally:
            del os.environ["QEMU_KERNEL_PARAMS"]
        canary.wait_for_unit("multi-user.target")
        assert booted(canary) == closure, f"the canary booted {booted(canary)}, not {closure}"
        publish_ran()


    def main():
        start_all()
        for vm in (canary, follower):
            vm.wait_for_unit("multi-user.target")
            base[vm.name] = current(vm)

        key_a = stack_key(canary, base["canary"])
        assert key_a == stack_key(follower, base["follower"]), "the two VMs should share a boot stack"
        # The first boot, by the canary's own timer: the stack both run.
        publish_ran()
        assert published(key_a), "the canary should have published the stack it booted"

        with subtest("same-stack-needs-no-canary"):
            # Only a new boot stack waits. An app release on the same stack must not, or the
            # fleet stops for every commit.
            app = candidate(follower, "appchange")
            rc = tick(follower, app)
            m = metrics(follower, DEPLOY)
            control(
                "same-stack-needs-no-canary",
                rc == 0 and current(follower) == app and m.get("cluster_deploy_canary_wait") == "0",
                f"{rc=} {m=}",
            )
            follower.succeed(f"nix-env -p {SYSTEM} --set {base['follower']}")
            follower.succeed(f"{base['follower']}/bin/switch-to-configuration switch")
            assert current(follower) == base["follower"]

        bumped_f = candidate(follower, "bumped")
        bumped_c = candidate(canary, "bumped")
        key_b = stack_key(follower, bumped_f)
        assert key_b == stack_key(canary, bumped_c) and key_b != key_a

        with subtest("follower-waits-for-the-canary"):
            before = switches(follower)
            rc = tick(follower, bumped_f)
            m = metrics(follower, DEPLOY)
            control(
                "follower-waits-for-the-canary",
                rc == 0
                and current(follower) == base["follower"]
                and profile(follower) == base["follower"]
                and switches(follower) == before
                and m.get("cluster_deploy_canary_wait") == "1"
                and logged(follower, "cluster-upgrade.service", f"the canary has not booted boot stack {key_b}") == 1,
                f"{rc=} current={current(follower)} {m=}",
            )

        with subtest("canary-takes-it-first"):
            rc = tick(canary, bumped_c)
            control(
                "canary-takes-it-first",
                rc == 0 and current(canary) == bumped_c and profile(canary) == bumped_c,
                f"{rc=} current={current(canary)}",
            )

        with subtest("a-switch-is-not-a-reboot"):
            # The canary runs the new closure now and has not booted it. Its publisher runs
            # (as its timer would) and must not vouch for a kernel and initrd nobody has
            # started.
            rc = canary.execute("systemctl start cluster-deploy-canary-publish.service")[0]
            frc = tick(follower, bumped_f)
            control(
                "a-switch-is-not-a-reboot",
                rc == 0
                and booted(canary) == base["canary"]
                and not published(key_b)
                and frc == 0
                and current(follower) == base["follower"],
                f"{rc=} {frc=} published={published(key_b)}",
            )

        with subtest("passphrase-boot-vouches-for-nothing"):
            # It boots, but only because someone typed the passphrase. Every other node would
            # need the same at its next reboot.
            boot_canary_into(bumped_c, "passphrase")
            m = metrics(canary, PUBLISH)
            rc = tick(follower, bumped_f)
            control(
                "passphrase-boot-vouches-for-nothing",
                m.get("cluster_deploy_canary_unproven") == "1"
                and not published(key_b)
                and rc == 0
                and current(follower) == base["follower"]
                and metrics(follower, DEPLOY).get("cluster_deploy_canary_wait") == "1",
                f"{m=} {rc=}",
            )

        with subtest("stale-report-vouches-for-nothing"):
            # A clean TPM report, but from an earlier boot: this boot's report failed or
            # has not run, and the file under /var/lib outlives the reboot. Its timestamp is
            # all that says it is not about this stack.
            canary.succeed(
                "printf '%s\\n' "
                "\"cluster_boot_report_timestamp_seconds $(( $(date +%s) - 3600 ))\" "
                "'cluster_boot_insecure_optout 0' 'cluster_boot_unlock_passphrase 0' "
                "'cluster_boot_unlock_tpm_devices 2' 'cluster_boot_unlock_expected_devices 2' "
                "> /var/lib/prometheus-node-exporter-text/boot_report.prom"
            )
            boot_canary_into(bumped_c, "none")
            report = canary.succeed("cat /var/lib/prometheus-node-exporter-text/boot_report.prom")
            m = metrics(canary, PUBLISH)
            rc = tick(follower, bumped_f)
            control(
                "stale-report-vouches-for-nothing",
                "cluster_boot_unlock_tpm_devices 2" in report
                and m.get("cluster_deploy_canary_unproven") == "1"
                and not published(key_b)
                and logged(canary, "cluster-deploy-canary-publish.service", "no boot report from this boot") >= 1
                and rc == 0
                and current(follower) == base["follower"]
                and metrics(follower, DEPLOY).get("cluster_deploy_canary_wait") == "1",
                f"{m=} {rc=} published={published(key_b)}\n{report}",
            )

        with subtest("canary-reboot-publishes"):
            boot_canary_into(bumped_c, "tpm")
            m = metrics(canary, PUBLISH)
            marker = {}
            if published(key_b):
                marker = json.loads((canary.shared_dir / "canary-booted" / key_b).read_text())
            control(
                "canary-reboot-publishes",
                published(key_b)
                and m.get("cluster_deploy_canary_published") == "1"
                and marker.get("node") == "canary"
                and marker.get("toplevel") == basename(bumped_c),
                f"{m=} {marker=}",
            )

        with subtest("follower-activates-after-the-canary-booted-it"):
            rc = tick(follower, bumped_f)
            m = metrics(follower, DEPLOY)
            control(
                "follower-activates-after-the-canary-booted-it",
                rc == 0
                and current(follower) == bumped_f
                and profile(follower) == bumped_f
                and m.get("cluster_deploy_canary_wait") == "0"
                and logged(follower, "cluster-upgrade.service", f"the canary booted it ({key_b})") == 1,
                f"{rc=} current={current(follower)} {m=}",
            )

        with subtest("skip-is-per-closure"):
            # By hand, for a canary that cannot be rebooted: one closure, on one node.
            again = candidate(follower, "bumpedAgain")
            follower.succeed(f"echo {basename(candidate(follower, 'appchange'))} > /run/cluster-upgrade.skip-canary")
            rc1 = tick(follower, again)
            waited = current(follower) == bumped_f
            follower.succeed(f"echo {basename(again)} >> /run/cluster-upgrade.skip-canary")
            rc2 = tick(follower, again)
            control(
                "skip-is-per-closure",
                rc1 == 0
                and waited
                and rc2 == 0
                and current(follower) == again
                and logged(follower, "cluster-upgrade.service", "listed in /run/cluster-upgrade.skip-canary") == 1,
                f"{rc1=} {waited=} {rc2=} current={current(follower)}",
            )
            follower.succeed("rm /run/cluster-upgrade.skip-canary")

        with subtest("unmounted-store-is-no-proof"):
            # The shared filesystem gone, and its mount point a plain directory on this
            # node's disk. What is in it was written by nobody else, so it proves nothing,
            # even naming a stack the canary really did boot.
            follower.succeed(f"umount /tmp/shared && mkdir -p {MARKERS} && touch {MARKERS}/{key_b}")
            rc = tick(follower, bumped_f)
            control(
                "unmounted-store-is-no-proof",
                rc == 0
                and current(follower) == again
                and metrics(follower, DEPLOY).get("cluster_deploy_canary_wait") == "1"
                and logged(follower, "cluster-upgrade.service", "/tmp/shared is not mounted") == 1,
                f"{rc=} current={current(follower)}",
            )

        with subtest("canary-never-publishes-to-its-own-disk"):
            canary.succeed(f"rm {MARKERS}/{key_b} && umount /tmp/shared")
            rc = canary.execute("systemctl start cluster-deploy-canary-publish.service")[0]
            m = metrics(canary, PUBLISH)
            control(
                "canary-never-publishes-to-its-own-disk",
                rc == 0
                and canary.execute(f"test -e {MARKERS}/{key_b}")[0] != 0
                and not published(key_b)
                and m.get("cluster_deploy_canary_published") == "0",
                f"{rc=} {m=}",
            )


    run_main(main)
  '';
}
