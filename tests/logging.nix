# VM test: the log store and what it keeps, and that nothing leaves a core dump.
#
#   journald (host) / an app's container journal directory
#     -> Vector (the REAL modules/logging.nix: sources, VRL, Loki sink)
#     -> Loki (the REAL modules/logging-server.nix)
#
# Pipeline, each path the one that matters in production:
#   - a host unit carrying the payload flakes' journal field contract
#     (APP_SERVICE / APP_SITE, and a <3> priority prefix on stdout);
#   - a journal that appears in an app's container directory AFTER Vector has
#     started, the way a dormant container's first start creates its
#     <machine-id>/ directory. Written with systemd-journal-remote, so no
#     container (and no payload closure) is needed to exercise the exact
#     directory-following path.
#
# The store (design WS12), each a control (tests/lib/control.py):
#   chunks-on-local-disk       a flushed line is in chunk files under /var/lib/loki,
#                              which is its own filesystem mounted in stage 2 (as the
#                              `loki` dataset is on a node), owned by loki, 0700; the
#                              line is plaintext in the WAL there, which is why the
#                              dataset sits on LUKS; the configuration names no object
#                              store but the filesystem
#   no-s3-credentials-in-unit  the unit loads no credential, its environment holds no
#                              S3 key, the configuration has no object storage
#                              section, and Loki doesn't expand its environment into
#                              the configuration
#   retention-removes-old      a line older than topology.logging.retention has its
#                              chunk deleted from disk, not just hidden; the same
#                              chunk survived while younger than retention, and a
#                              newer line's chunk stays. The clock jumps instead of
#                              waiting, and only the compactor's interval and delete
#                              delay are shortened for the test.
#   coredump-off               a crashing process that raised its own core limit
#                              leaves nothing, on the host and in a NixOS container:
#                              no file in its working directory, nothing in
#                              systemd-coredump's store. Then the pattern is the pipe
#                              (`coredump-pattern`), and a positive control shows the
#                              same crash DOES write a file once the pattern is `core`.
#
# Mutant `coredump-enable-false` (flake.nix legacyPackages.mutants) swaps
# modules/coredumps-off.nix for the wrong fix, `systemd.coredump.enable = false`, and
# `coredump-off` has to catch the `core` file it leaves in the working directory.
#
# Vector ships over the control mesh and serves its metrics there
# (modules/mesh-control-core.nix). The mesh itself is not under test here, so its
# readiness unit is stood in for by one that puts the node's mesh address on a
# dummy interface of the mesh's name, which is all Vector and Loki need.
#
# Run: nix build .#checks.x86_64-linux.logging -L   (needs KVM)
{
  pkgs,
  lib,
  clusterLib,
  mutant ? "",
  # What every node imports from modules/cluster-common.nix. A mutant replaces it.
  coredumpsModule ? ../modules/coredumps-off.nix,
}:
let
  topology = {
    mesh.subnet = "10.25.0.0/24";
    # The fixture's value (tests/fixtures/topology.nix).
    logging.retention = "720h";
    nodes.machine = {
      index = 1;
      hostName = "machine";
      controlIp = "192.168.1.1";
      tags = [ "metrics" ];
    };
  };
  node = topology.nodes.machine;
  net = clusterLib.net;
  # Where Loki listens and Vector ships, as on a real node.
  ip = net.meshIp topology node;
  loki = "http://${ip}:${toString net.lokiPort}";

  # How far retention-removes-old moves the clock, in two steps: to 2 h short of
  # retention for the old line, then 4 h more, which puts it 2 h past retention and a
  # line written between the two 4 h old. Both steps are past the 3 h within which the
  # querier still asks the ingester, and each makes the ingester's TSDB head rotate
  # (every 15 min of wall clock), which is what puts a flushed chunk in the index the
  # compactor applies retention to.
  retentionHours = lib.toInt (lib.removeSuffix "h" topology.logging.retention);
  firstJump = (retentionHours - 2) * 3600;
  secondJump = 4 * 3600;

  # One entry in journal export format, as a container's journald would have
  # written it: the payload's fields, a unit, a warning.
  exportEntry = pkgs.writeShellScript "export-entry" ''
    printf '%s\n' \
      "__REALTIME_TIMESTAMP=$(date +%s%6N)" \
      "__MONOTONIC_TIMESTAMP=1" \
      "_BOOT_ID=0123456789abcdef0123456789abcdef" \
      "_HOSTNAME=probe" \
      "_SYSTEMD_UNIT=frappe-erp.probe.test.service" \
      "PRIORITY=4" \
      "APP_SERVICE=runtime" \
      "APP_SITE=erp.probe.test" \
      "MESSAGE=from-the-container" \
      ""
  '';
in
pkgs.testers.runNixOSTest {
  name = "cluster-logging";

  node.specialArgs = {
    inherit topology clusterLib node;
  };

  nodes.machine =
    { lib, ... }:
    {
      imports = [
        ../modules/logging.nix
        ../modules/logging-server.nix
        coredumpsModule
      ];

      # The slice of modules/app-container.nix that modules/logging.nix reads.
      options.clusterApps = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule {
            options.logging = {
              journalDirs = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
              };
              journalGroups = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
              };
            };
          }
        );
        default = { };
      };

      config = {
        clusterApps.probe = { };

        virtualisation.memorySize = 2048;
        networking.firewall.enable = false;

        # Loki's data directory on a filesystem of its own, mounted by systemd after
        # activation has created the loki user's home underneath it: the shape of the
        # `loki` dataset on a node (lib/mk-disk-layout.nix), whose fresh root is
        # root:root 0755. ext4 rather than ZFS on LUKS; what is under test is Loki on
        # a separate local mount, not the dataset.
        virtualisation.emptyDiskImages = [ 1024 ];
        virtualisation.fileSystems."/var/lib/loki" = {
          device = "/dev/vdb";
          fsType = "ext4";
          autoFormat = true;
        };

        # Test timing only. Production keeps Loki's defaults: compaction every 10 min,
        # and marked chunks deleted 2 h later.
        services.loki.configuration.compactor = {
          compaction_interval = "10s";
          retention_delete_delay = "10s";
        };

        # A container to crash a process in, as the apps' are: a NixOS container
        # sharing the host's kernel and so its core_pattern.
        containers.crashbox = {
          autoStart = true;
          config.system.stateVersion = "25.11";
        };

        # The mesh's readiness unit, standing in for the mesh: the address on a
        # dummy interface of the same name.
        systemd.services."${net.meshIf}-ready" = {
          wantedBy = [ "multi-user.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          path = [ pkgs.iproute2 ];
          script = ''
            ip link add ${net.meshIf} type dummy
            ip addr add ${ip}/${toString net.meshPrefix} dev ${net.meshIf}
            ip link set ${net.meshIf} up
          '';
        };
      };
    };

  testScript = ''
    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    import json
    import re
    import time
    import urllib.parse

    LOKI = "${loki}"
    PIPE = "${import ../lib/core-pattern.nix}"

    def query_url(q, start=None, end=None):
        params = {"limit": "100", "query": q}
        if start is None:
            params["since"] = "1h"
        else:
            params["start"] = str(start)
            params["end"] = str(end)
        return LOKI + "/loki/api/v1/query_range?" + urllib.parse.urlencode(params)

    def query(q, start=None, end=None):
        return json.loads(machine.succeed(f"curl -fsS '{query_url(q, start, end)}'"))["data"]["result"]

    def lines(result):
        return [v[1] for s in result for v in s["values"]]

    def arrives(q):
        def check(_):
            r = query(q)
            if r:
                machine.log(json.dumps(r))
            return bool(r)
        retry(check, timeout_seconds=120)

    def push_cmd(line, ts_ns):
        body = json.dumps({"streams": [{"stream": {"app": "retention-probe", "node": "machine"},
                                        "values": [[str(ts_ns), line]]}]})
        return f"curl -fsS -H 'Content-Type: application/json' --data-binary '{body}' {LOKI}/loki/api/v1/push"

    def chunk_files():
        """Chunk objects only (the tenant's directory), not the index beside them."""
        return set(machine.succeed("find /var/lib/loki/chunks/fake -type f 2>/dev/null || true").split())

    def built_index():
        """Index files the ingester has built from its rotated-out head, by name."""
        return set(machine.succeed(
            "find /var/lib/loki/tsdb-shipper-active/multitenant -name '*.tsdb' -printf '%f\\n' 2>/dev/null || true").split())

    def jump(seconds):
        """Move the clock, then wait until the ingester's head has rotated, its index
        file is built, and the compactor has downloaded that file from the store.
        Returns the files the compactor read."""
        before = built_index()
        machine.succeed(f"date -s @$(( $(date +%s) + {seconds} ))")
        deadline = time.monotonic() + 120
        while not (built_index() - before) and time.monotonic() < deadline:
            time.sleep(2)
        built = sorted(built_index() - before)
        read = []
        deadline = time.monotonic() + 180
        while built and not read and time.monotonic() < deadline:
            log = machine.succeed("journalctl -u loki.service --no-pager | grep 'downloaded file' || true")
            read = [b for b in built if f"file-name={b}.gz" in log]
            time.sleep(2)
        return read

    def flush_new(before, timeout=60):
        """Flush the ingester and wait for chunk files that weren't there before."""
        machine.succeed(f"curl -fsS -X POST {LOKI}/flush")
        deadline = time.monotonic() + timeout
        while not (chunk_files() - before) and time.monotonic() < deadline:
            time.sleep(1)
        return sorted(chunk_files() - before)

    def now_ns():
        return int(machine.succeed("date +%s%N").strip())

    def loki_config():
        execstart = machine.succeed("systemctl show -p ExecStart --value loki.service")
        m = re.search(r"--config\.file=(\S+)", execstart)
        assert m is not None, f"no --config.file in loki's ExecStart: {execstart}"
        path = m.group(1)
        return json.loads(machine.succeed(f"cat {path}"))

    def keys(o, prefix=""):
        if isinstance(o, dict):
            for k, v in o.items():
                yield prefix + k
                yield from keys(v, prefix + k + ".")
        elif isinstance(o, list):
            for v in o:
                yield from keys(v, prefix)

    def crash(prefix, d):
        """A root shell that raises its own core limit, as anything holding
        CAP_SYS_RESOURCE can, and dies of SIGSEGV in directory d."""
        rc, _ = machine.execute(
            prefix + "bash -c 'mkdir -p " + d + " && cd " + d
            + " && ulimit -c unlimited && kill -SEGV $$'")
        return rc

    def main():
        machine.wait_for_unit("loki.service")
        machine.wait_for_unit("vector.service")
        machine.wait_until_succeeds(f"curl -fsS {LOKI}/ready", timeout=120)

        with subtest("the container journal directory exists before any container ran"):
            machine.succeed("test -d /var/lib/nixos-containers/probe/var/log/journal")

        with subtest("host unit: field contract and <N> priority become labels"):
            machine.succeed(
                "systemd-run --unit=probe-web --wait "
                "-p LogExtraFields=APP_SERVICE=web -p LogExtraFields=APP_SITE=probe.test "
                "sh -c 'echo \"<3>boom-from-the-host\"'"
            )
            arrives('{app="platform", service="web", site="probe.test", level="err", node="machine"} |= "boom-from-the-host"')

        with subtest("a journal that appears later in an app's directory ships as that app"):
            d = "/var/lib/nixos-containers/probe/var/log/journal"
            machine.succeed(
                "mkdir -p /tmp/j && ${exportEntry} | ${pkgs.systemd}/lib/systemd/systemd-journal-remote -o /tmp/j/system.journal -",
                # The guest's journald writes root:systemd-journal 0640 into a
                # setgid directory; mirror that, and move it in whole.
                f"mkdir -m 2755 {d}/0123456789abcdef0123456789abcdef && chgrp systemd-journal {d}/0123456789abcdef0123456789abcdef",
                f"install -m 0640 -g systemd-journal /tmp/j/system.journal {d}/0123456789abcdef0123456789abcdef/.system.journal.tmp",
                f"mv {d}/0123456789abcdef0123456789abcdef/.system.journal.tmp {d}/0123456789abcdef0123456789abcdef/system.journal",
            )
            arrives('{app="probe", service="runtime", site="erp.probe.test", level="warning"} |= "from-the-container"')

        with subtest("structured metadata carries the unit"):
            r = query('{app="probe"} | unit="frappe-erp.probe.test.service"')
            assert r, "unit structured metadata not queryable"

        with subtest("Vector exposes its metrics for Prometheus"):
            # Match in Python: `curl | grep -q` races, as grep exits on the first
            # match and curl then fails writing the rest (exit 23).
            metrics = machine.succeed("curl -fsS http://${ip}:${toString net.vectorMetricsPort}/metrics")
            assert "vector_component_sent_events_total" in metrics, "Vector metrics lack vector_component_sent_events_total"

        cfg = loki_config()

        with subtest("chunks-on-local-disk: Loki's store is the node's own disk"):
            before = chunk_files()
            machine.succeed("logger -t ci-probe chunk-probe-marker")
            arrives('{node="machine"} |= "chunk-probe-marker"')
            new = flush_new(before)
            target, source = machine.succeed("findmnt -no TARGET,SOURCE -T /var/lib/loki/chunks").split()
            owner = machine.succeed("stat -c '%U:%G %a' /var/lib/loki").strip()
            wal = machine.succeed("grep -rlF chunk-probe-marker /var/lib/loki/wal || true").split()
            after = machine.succeed("systemctl show -p After --value loki.service").split()
            stores = [c["object_store"] for c in cfg["schema_config"]["configs"]]
            storage = sorted(cfg["common"]["storage"])
            delete_store = cfg["compactor"]["delete_request_store"]
            detail = (f"new chunk files {new[:3]} ({len(new)}); {target} from {source}, {owner}; "
                      f"marker in WAL {wal}; after var-lib-loki.mount {'var-lib-loki.mount' in after}; "
                      f"object stores {stores}, common.storage {storage}, delete requests {delete_store}")
            print(f"chunks-on-local-disk: {detail}")
            control("chunks-on-local-disk",
                    bool(new) and target == "/var/lib/loki" and source == "/dev/vdb"
                    and owner == "loki:loki 700" and bool(wal) and "var-lib-loki.mount" in after
                    and stores == ["filesystem"] and storage == ["filesystem"] and delete_store == "filesystem",
                    detail)

        with subtest("no-s3-credentials-in-unit: Loki is handed no object storage key"):
            # From the unit files and drop-ins as loaded: `systemctl show` prints these
            # properties as "[unprintable]".
            unit = machine.succeed("systemctl cat loki.service")
            loaded = [l.strip() for l in unit.splitlines()
                      if re.match(r"\s*(Load|Set|Import)Credential", l)]
            execstart = machine.succeed("systemctl show -p ExecStart --value loki.service")
            pid = machine.succeed("systemctl show -p MainPID --value loki.service").strip()
            env = machine.succeed(f"tr '\\0' '\\n' < /proc/{pid}/environ").split()
            env_hits = [e.split("=", 1)[0] for e in env if re.match(r"(S3|AWS)_", e)]
            run_creds = machine.succeed("ls -A /run/credentials/loki.service 2>/dev/null || true").split()
            key_hits = [k for k in keys(cfg)
                        if re.search(r"(^|\.)(s3|aws|gcs|azure|swift|bos|cos|alibabacloud)($|\.)|access_key|secret", k)]
            detail = (f"credentials {loaded}, in /run/credentials {run_creds}, environment {env_hits}, "
                      f"config keys {key_hits}, expand-env {'expand-env' in execstart}")
            print(f"no-s3-credentials-in-unit: {detail}")
            control("no-s3-credentials-in-unit",
                    not loaded and not run_creds and not env_hits and not key_hits and "expand-env" not in execstart,
                    detail)

        with subtest("coredump-off: a crash leaves nothing, on the host and in a container"):
            machine.wait_for_unit("container@crashbox.service")
            machine.wait_until_succeeds("nixos-container run crashbox -- true", timeout=60)
            host_rc = crash("", "/var/tmp/crash-host")
            host_left = machine.succeed("ls -A /var/tmp/crash-host").split()
            ctr_rc = crash("nixos-container run crashbox -- ", "/root/crash")
            ctr_left = machine.succeed("ls -A /var/lib/nixos-containers/crashbox/root/crash").split()
            stored = machine.succeed(
                "find /var/lib/systemd/coredump /var/lib/nixos-containers/crashbox/var/lib/systemd/coredump"
                " -type f 2>/dev/null || true").split()
            detail = (f"host rc {host_rc}, left {host_left}; container rc {ctr_rc}, left {ctr_left}; "
                      f"systemd-coredump store {stored}")
            print(f"coredump-off: {detail}")
            # 139 is 128 + SIGSEGV: the shell did crash, so an empty directory means
            # something. The container's goes through su, which reports it its own way.
            control("coredump-off",
                    host_rc == 139 and ctr_rc != 0 and not host_left and not ctr_left and not stored,
                    detail)

            pattern = machine.succeed("cat /proc/sys/kernel/core_pattern").strip()
            ctr_pattern = machine.succeed("nixos-container run crashbox -- cat /proc/sys/kernel/core_pattern").strip()
            suid = machine.succeed("cat /proc/sys/fs/suid_dumpable").strip()
            limit = machine.succeed("systemctl show -p DefaultLimitCORE --value").strip()
            detail = f"pattern {pattern!r}, in the container {ctr_pattern!r}, suid_dumpable {suid}, DefaultLimitCORE {limit}"
            print(f"coredump-pattern: {detail}")
            control("coredump-pattern",
                    pattern == PIPE and ctr_pattern == PIPE and suid == "0" and limit == "0",
                    detail)

            # Positive control: the same crash with the pattern a file writes one, so
            # an empty directory above is the pipe's doing and not the method's.
            machine.succeed("sysctl -w kernel.core_pattern=core")
            pos_rc = crash("", "/var/tmp/crash-positive")
            pos_left = machine.succeed("ls -A /var/tmp/crash-positive").split()
            machine.succeed("systemctl restart systemd-sysctl.service")
            restored = machine.succeed("cat /proc/sys/kernel/core_pattern").strip()
            detail = f"pattern core: rc {pos_rc}, left {pos_left}; after systemd-sysctl, {restored!r}"
            print(f"coredump-positive-control: {detail}")
            control("coredump-positive-control", pos_rc == 139 and bool(pos_left) and restored == PIPE, detail)

        with subtest("retention-removes-old: lines past retention are deleted from disk"):
            # The old line, flushed to a chunk of its own.
            before = chunk_files()
            t0 = now_ns()
            machine.succeed(push_cmd("retention-old-marker", t0))
            old_seen = "retention-old-marker" in lines(query('{app="retention-probe"}'))
            old_chunks = set(flush_new(before))

            # 2 h short of retention: in the index the compactor has read, through
            # three more rounds of retention (every 15 s here), and still there.
            # Retention must not take what is younger than it.
            idx1 = jump(${toString firstJump})
            time.sleep(50)
            young_kept = old_chunks <= chunk_files()

            # The recent line, in a chunk of its own, with the ring's heartbeats (wall
            # clock) given a few seconds to catch up after the jump.
            before = chunk_files()
            retry(lambda _: machine.execute(push_cmd("retention-new-marker", now_ns()))[0] == 0, timeout_seconds=60)
            t1 = now_ns()
            new_chunks = set(flush_new(before))

            # 2 h past retention for the old line, 4 h old for the recent one.
            idx2 = jump(${toString secondJump})

            # Done when the old chunk files are gone from disk and the recent ones and
            # the recent line are still there.
            window = 600 * 10**9
            old_url = query_url('{app="retention-probe"}', t0 - window, t0 + window)
            new_url = query_url('{app="retention-probe"}', t1 - window, t1 + window)
            started = time.monotonic()
            while True:
                left = sorted(old_chunks & chunk_files())
                kept = new_chunks <= chunk_files()
                rc, out = machine.execute(f"curl -fsS '{new_url}'")
                new_lines = lines(json.loads(out)["data"]["result"]) if rc == 0 else [f"query failed: {out.strip()[:200]}"]
                done = not left and kept and "retention-new-marker" in new_lines
                if done or time.monotonic() - started > 600:
                    break
                time.sleep(5)
            waited = int(time.monotonic() - started)
            # Recorded, not asserted: a query over the old window can still answer for
            # up to 20 min after the deletion here. The ingester keeps each index file
            # it uploaded, and serves queries from it, for index_cache_validity + 3 x
            # resync_interval (Loki 3.7.9 pkg/loki/modules.go,
            # shipperQuerierIndexUpdateDelay), and the chunk itself then comes from the
            # in-memory chunk cache. Only the clock jumps make that window overlap a
            # line's retention age; on a node, a line reaches retention weeks after
            # that index left the ingester. What retention is for, the line gone from
            # disk, is what the control holds.
            rc, out = machine.execute(f"curl -fsS '{old_url}'")
            old_lines = lines(json.loads(out)["data"]["result"]) if rc == 0 else [f"query failed: {out.strip()[:200]}"]
            print(machine.succeed("journalctl -u loki.service --no-pager | grep -E 'mark|compacting table index_20' | tail -n 8 || true"))
            detail = (f"old line seen {old_seen}, its chunks {sorted(old_chunks)[:2]}; first jump: index read by the compactor {idx1[:2]}, "
                      f"old chunks kept while 2 h short of retention {young_kept}; recent chunks {sorted(new_chunks)[:2]}; "
                      f"second jump: index read by the compactor {idx2[:2]}; after {waited} s: old chunks left {left[:2]}, recent kept {kept}, "
                      f"recent window {new_lines[:2]}; old window (not asserted) {old_lines[:2]}")
            print(f"retention-removes-old: {detail}")
            control("retention-removes-old",
                    old_seen and bool(old_chunks) and bool(idx1) and young_kept and bool(new_chunks)
                    and bool(idx2) and not left and kept and "retention-new-marker" in new_lines,
                    detail)

    run_main(main)
  '';
}
