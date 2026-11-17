# VM test: a secret's whole way to a node, with nothing replaced.
#
# Every other VM test writes fixture values where agenix would have decrypted them
# (tests/lib/cluster-harness.nix). This one does not: a site with a master key, a node
# whose age recipient is its TPM's, agenix-rekey's own app between them, and agenix
# decrypting at boot.
#
# The site is tests/fixtures/agenix (./fixtures/agenix/default.nix says what is in it
# and how it was made). It is built by mkCluster over the fixture topology, with two
# of the library's real generators generated: `canary` (shared) and node1's `wg-ctrl`
# (per machine, and owned by systemd-network). Everything else node1 declares is
# ungenerated, so most of what runs on it fails; this test is about the two that
# exist.
#
#   operator  no TPM and the master key. Runs `agenix rekey`, the app a site's flake
#             exports, from empty.
#   (a build) avc's runner over the same site, from this site's own `secrets` export:
#             it reads the committed sources with the master key, agrees with the
#             committed rekeyed files, and rekeys from empty (`avcRekeyed`).
#   good      node1, on the software TPM its recipient was made on.
#   other     the same system, identity file and rekeyed files on a TPM of its own.
#
# The rekeyed files in a node's closure have to exist when the node is evaluated, so
# they are committed, as they are on a real site, and the test cannot make them and
# boot from them in one run. What it does instead: the app's run in the test must
# produce the same file names (a hash of the recipient and the source), and what it
# produces must decrypt on `good`'s TPM to the same values the committed ones do.
#
# Run: nix build .#checks.x86_64-linux.secrets-tpm -L   (needs KVM)
{
  pkgs,
  lib,
  mkCluster,
  fixtureTopology,
  harness,
  # The operations tool (lib/avc.nix): its runner rekeys too.
  avc,
  mutant ? "",
}:
let
  fixture = import ./fixtures/agenix;
  system = pkgs.stdenv.hostPlatform.system;

  site = mkCluster {
    self = {
      inputs = { };
      outPath = fixture.directory;
    };
    # A path, as on a real site: agenix-rekey finds where a node's rekeyed files go
    # by this directory's place under the flake's root.
    inherit (fixture) directory;
    topology = fixtureTopology;
    meta.name = "fixture-agenix";
    masterIdentities = [
      {
        identity = fixture.masterIdentityAt;
        pubkey = fixture.masterPubkey;
      }
    ];
    admins = import ./fixtures/admins.nix;
    extraModules = [
      {
        # In the store rather than installed: the file is a handle to a key in one
        # TPM, and both nodes are to have the same one.
        cluster.secrets.identityPath = "${fixture.tpmIdentity}";
      }
    ];
  };
  machine = site.nixosConfigurations.node1;
  cfg = machine.config;
  net = import ../lib/net.nix { inherit lib; };

  rekey = site.agenix-rekey.${system}.rekey;

  secret = gen: file: cfg.cluster.secrets.generators.${gen}.files.${file};
  canary = secret "canary" "value";
  wgKey = secret "wg-ctrl" "private";

  # The rekeyed files the node was built with, relative to its localStorageDir (which
  # agenix-rekey reads through this same copy).
  committed = lib.sort lib.lessThan (
    map (s: lib.removePrefix "${builtins.path { path = cfg.age.rekey.localStorageDir; }}/" s.file) (
      lib.attrValues cfg.age.secrets
    )
  );

  # The same run as the test's `operator`, as a build: how the committed files are
  # made (./fixtures/agenix/default.nix).
  rekeyed = pkgs.runCommand "secrets-tpm-rekeyed" { } ''
    install -m 0400 ${fixture.masterIdentity} ${fixture.masterIdentityAt}
    mkdir site && cd site && touch flake.nix
    timeout 120 ${rekey}/bin/agenix-rekey < /dev/null
    cp -r secrets/rekeyed/node1 $out
  '';

  # What `avc secrets check` and `avc secrets rekey` do (tools/avc/avc/core/secretstore.py),
  # on the export exactly as a site's flake gives it. The scripts are left out: nothing
  # here generates, and a script in the export would be built for it.
  export = pkgs.writeText "secrets-tpm-export.json" (
    builtins.toJSON (
      lib.mapAttrs (
        _: m:
        m
        // {
          generators = lib.mapAttrs (
            _: g:
            removeAttrs g [
              "script"
              "scriptDrv"
              "runtimeInputs"
            ]
          ) m.generators;
        }
      ) site.secrets
    )
  );
  avcRekeyed =
    pkgs.runCommand "secrets-tpm-avc-rekeyed"
      {
        nativeBuildInputs = [
          (pkgs.python3.withPackages (ps: [ (ps.toPythonModule avc) ]))
          pkgs.age
        ];
      }
      ''
        install -m 0400 ${fixture.masterIdentity} ${fixture.masterIdentityAt}
        mkdir site && cp -r --no-preserve=mode ${fixture.directory}/secrets site/secrets
        python3 - <<'EOF'
        import json, shutil
        from pathlib import Path
        from avc.core.secretstore import Store

        export = json.loads(Path("${export}").read_text())
        store = Store(Path("site"), export)

        # A source `age` encrypted by hand, read with the identity the flake names.
        value = store.get("node1", "canary/value").decode()
        assert value == "${fixture.canaryValue}", value

        # The files agenix-rekey wrote are the ones the runner expects, by name.
        ready = store.readiness("node1")
        assert ready.recipient and not ready.unrekeyed and not ready.orphaned, ready
        assert sorted(store.expected_rekeyed("node1")) == ${builtins.toJSON committed}

        # Without them the node would be deployed short of both, and the check says so.
        shutil.rmtree("site/secrets/rekeyed")
        ready = store.readiness("node1")
        assert ready.unrekeyed == ("canary/value", "wg-ctrl/private") and not ready.ok, ready
        written = store.fill_rekeyed()
        assert len(written) == 2 and not store.readiness("node1").unrekeyed, written
        # This site generated two of what node1 declares: the rest is still refused.
        assert "restic/password" in store.readiness("node1").missing
        # node2 and node3 have no recipient.
        assert [p.name for p in Path("site/secrets/rekeyed").iterdir()] == ["node1"]
        EOF
        cp -r site/secrets/rekeyed/node1 $out
      '';

  tpmNode = {
    imports = [
      site.machineModules.node1
      (harness.vmModule { memoryMB = 2048; })
    ];
    virtualisation.tpm.enable = true;
  };

  textDir = "/var/lib/prometheus-node-exporter-text";
in
pkgs.testers.runNixOSTest {
  name = "secrets-tpm";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machine._module.specialArgs [ "modulesPath" ];

  nodes = {
    operator = {
      virtualisation.memorySize = 1024;
      environment.systemPackages = [ rekey ];
    };
    good = tpmNode;
    other = tpmNode;
  };

  testScript = ''
    import os, shutil

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    CANARY = "${canary.path}"
    WG_KEY = "${wgKey.path}"
    AGE = "${cfg.age.ageBin}"
    IDENTITY = "${cfg.cluster.secrets.identityPath}"
    METRIC = "${textDir}/cluster_secrets.prom"
    COMMITTED = ${builtins.toJSON committed}
    MESH_IP = "${net.meshIp fixtureTopology fixtureTopology.nodes.node1}"

    def metric(m, name):
        for line in m.succeed(f"cat {METRIC}").splitlines():
            if line.startswith(name + " "):
                return int(line.split()[1])
        return None

    def state(m, unit, prop="ActiveState"):
        return m.succeed(f"systemctl show -p {prop} --value {unit}").strip()

    def main():
        assert CANARY == "/run/secrets/shared/canary/value", CANARY
        assert WG_KEY == "/run/secrets/per-machine/node1/wg-ctrl/private", WG_KEY

        with subtest("rekey: the app a site runs, with the master key and no TPM"):
            operator.start()
            operator.wait_for_unit("multi-user.target")
            master = operator.succeed(
                "mkdir -p $(dirname ${fixture.masterIdentityAt}) /root/site"
                " && install -m 0400 ${fixture.masterIdentity} ${fixture.masterIdentityAt}"
                " && cd /root/site && touch flake.nix"
                # Its prompt on a failure reads stdin for ever; a failure must end the test.
                " && timeout 120 agenix-rekey < /dev/null 2>&1"
            )
            print(master)
            made = sorted(operator.succeed(
                "cd /root/site/secrets/rekeyed/node1 && find . -type f -printf '%P\\n'"
            ).split())
            others = operator.succeed("ls /root/site/secrets/rekeyed").split()
            detail = f"the app wrote {made} for node1 and directories for {others}; the node was built with {COMMITTED}"
            # node2 and node3 have no recipient: nothing may be rekeyed to a dummy key.
            control("rekey-writes-what-the-node-was-built-with", made == COMMITTED and others == ["node1"], detail)
            operator.succeed("tar -C /root/site/secrets/rekeyed/node1 -cf /root/rekeyed.tar .")
            operator.copy_from_machine("/root/rekeyed.tar")
            plain = operator.succeed(
                "cd /root/site/secrets/rekeyed/node1 && grep -rL 'age-encryption.org/v1' . | wc -l"
            ).strip()
            assert plain == "0", f"{plain} rekeyed files are not age files"
            operator.shutdown()

        with subtest("the right TPM: both secrets arrive, at their paths, as their generators say"):
            d = good.state_dir / "node1-swtpm"
            os.makedirs(d)
            shutil.copy("${fixture.tpmState}", d / "tpm2-00.permall")
            os.chmod(d / "tpm2-00.permall", 0o600)
            good.start()
            good.wait_for_unit("cluster-secrets.service")
            value = good.succeed(f"cat {CANARY}")
            stat = good.succeed(f"stat -c %a:%U:%G {CANARY} {WG_KEY}").split()
            pub = good.succeed(f"${pkgs.wireguard-tools}/bin/wg pubkey < {WG_KEY}").strip()
            detail = f"canary/value={value!r} {stat[0]}; wg-ctrl/private is {stat[1]} and its public half is {pub}"
            control(
                "secret-arrives",
                value == "${fixture.canaryValue}"
                and stat == ["400:root:root", "400:systemd-network:root"]
                and pub == "${harness.wg.node1.public}",
                detail,
            )
            # networkd read the key as systemd-network through the same path.
            good.wait_until_succeeds(f"ip -4 -o addr show dev ${net.meshIf} | grep -qF ' {MESH_IP}/'", timeout=120)

            gate = state(good, "cluster-secrets.service")
            missing, expected = metric(good, "cluster_secrets_missing"), metric(good, "cluster_secrets_expected")
            good.wait_until_succeeds("systemctl show -p ExecMainStartTimestampMonotonic --value nomad.service | grep -qv '^0$'", timeout=120)
            good.wait_until_succeeds(f"curl -fsS -o /tmp/metrics http://{MESH_IP}:${toString net.nodeExporterPort}/metrics && grep -qx 'cluster_secrets_missing 0' /tmp/metrics", timeout=120)
            detail = f"gate {gate}, cluster_secrets_missing {missing} of {expected}, Nomad was started, node_exporter serves the metric"
            control("gate-passes-with-every-secret", gate == "active" and missing == 0 and expected == 2, detail)

        with subtest("what the app made in this run decrypts on that TPM too"):
            good.succeed("mkdir /root/rekeyed")
            good.copy_from_host(str(operator.out_dir / "rekeyed.tar"), "/root/rekeyed.tar")
            good.succeed("tar -C /root/rekeyed -xf /root/rekeyed.tar")
            name = [c for c in COMMITTED if c.endswith("shared/canary/value.age")][0]
            fresh = good.succeed(f"{AGE} -d -i {IDENTITY} /root/rekeyed/{name}")
            control("fresh-rekey-decrypts-on-the-tpm", fresh == "${fixture.canaryValue}", f"{name} -> {fresh!r}")

        with subtest("what avc's runner rekeyed decrypts on that TPM too"):
            # Same names as the committed ones (the build asserted it); the ciphertext is avc's.
            good.copy_from_host("${avcRekeyed}", "/root/avc-rekeyed")
            got = {
                c: good.succeed(f"{AGE} -d -i {IDENTITY} /root/avc-rekeyed/{c}")
                for c in COMMITTED
            }
            canary = [v for c, v in got.items() if c.endswith("shared/canary/value.age")]
            key = [v for c, v in got.items() if c.endswith("wg-ctrl/private.age")]
            pub = good.succeed(f"${pkgs.wireguard-tools}/bin/wg pubkey < {WG_KEY}").strip()
            mine = good.succeed(f"echo {key[0].strip()} | ${pkgs.wireguard-tools}/bin/wg pubkey").strip()
            control(
                "avc-rekey-decrypts-on-the-tpm",
                canary == ["${fixture.canaryValue}"] and mine == pub == "${harness.wg.node1.public}",
                f"{sorted(got)}: canary {canary!r}, wg-ctrl/private's public half {mine}",
            )

        with subtest("a secret that goes missing on a running node: the watch, not the gate"):
            good.succeed(f"rm $(readlink -f {CANARY})")
            good.wait_until_succeeds(f"grep -qx 'cluster_secrets_missing 1' {METRIC}", timeout=180)
            watch = state(good, "cluster-secrets-watch.service")
            gate = state(good, "cluster-secrets.service")
            # A switch decrypts again, and the next check clears it.
            good.succeed("/run/current-system/activate")
            good.wait_until_succeeds(f"grep -qx 'cluster_secrets_missing 0' {METRIC}", timeout=180)
            back = good.succeed(f"cat {CANARY}")
            detail = (f"with canary/value removed: cluster_secrets_missing 1, watch {watch}, gate still {gate};"
                      f" after an activation: {back!r}, cluster_secrets_missing 0")
            control("watch-sees-a-secret-go-missing", watch == "failed" and gate == "active" and back == "${fixture.canaryValue}", detail)
            good.shutdown()

        with subtest("another TPM: nothing decrypts, and the node says so"):
            other.start()
            other.wait_until_succeeds("systemctl is-failed cluster-secrets.service", timeout=600)
            other.wait_for_unit("sshd.service")
            other.wait_for_open_port(22)
            # The boot ends: nothing that was held is left retrying.
            other.wait_for_unit("multi-user.target", timeout=600)
            absent = [p for p in (CANARY, WG_KEY) if other.execute(f"test -e {p}")[0] != 0]
            print(other.execute("journalctl -b --no-pager | grep -i -E 'agenix|age: |cluster-secrets' | head -30")[1])
            control("wrong-tpm-decrypts-nothing", sorted(absent) == sorted([CANARY, WG_KEY]),
                    f"absent on the other TPM: {absent}")

            gate = state(other, "cluster-secrets.service")
            said = other.succeed("journalctl -b -u cluster-secrets.service --no-pager")
            nomad_state = state(other, "nomad.service")
            nomad_started = state(other, "nomad.service", "ExecMainStartTimestampMonotonic")
            held = other.execute("journalctl -b --no-pager | grep -i 'Dependency failed for' | grep -qi nomad")[0] == 0
            running = other.execute("systemctl is-system-running")[1].strip()
            detail = (f"cluster-secrets is {gate} and named {said.count('is missing')} paths; nomad is {nomad_state},"
                      f" started at {nomad_started}, held by the gate={held}; the boot finished and the system is {running}; sshd is up")
            control("gate-fails-closed",
                    gate == "failed" and said.count("is missing") == 2 and nomad_state == "inactive"
                    and nomad_started == "0" and held and running == "degraded", detail)

            missing, expected = metric(other, "cluster_secrets_missing"), metric(other, "cluster_secrets_expected")
            control("metric-says-so", missing == 2 and expected == 2,
                    f"cluster_secrets_missing {missing}, cluster_secrets_expected {expected}")

    run_main(main)
  '';
}
// {
  inherit rekeyed avcRekeyed;
}
