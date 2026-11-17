# VM test: a three-node cluster forms, shares storage, and runs containers
# under Nomad.
#
# The same site as the fixture cluster (`mkSite`, tests/fixtures) over its
# topology with ONE change: node2 and node3 are provisioned voters, which is
# exactly the commit a topology needs when their machines land. node1 keeps
# every singleton. Every node boots its real machine module plus
# tests/lib/cluster-harness.nix, so this is the first time anything has run
# what a quorum needs:
#
#   - etcd forms one 3-member cluster from etcdInitialCluster
#   - three Nomad servers find each other (server_join) and elect one leader;
#     all three clients join and advertise jfs_ready once /mnt/jfs is up
#   - every node mounts the ONE JuiceFS volume, whose metadata database has a member
#     on each; the primary killed, a replica takes over and the mounts carry on
#     over the WireGuard control mesh: a write on one node is read on another
#   - the mesh: every node has a handshake with both others, and etcd, Loki,
#     Prometheus and the exporters are reached at mesh addresses
#   - Nomad starts containers (mk-app-container's raw_exec wrapper) on the
#     nodes it chose, gated on jfs_ready, with host-decrypted secrets and
#     JuiceFS bind-mounted in; containers on different nodes reach each other
#     over the app-VLAN routes, on the one port the probe declares (network.peerAccess:
#     container to container is default-deny, modules/overlay-network.nix)
#   - an app held to node2 by a Nomad constraint lands there only, and a container started behind
#     Nomad's back elsewhere is fenced (modules/nomad-bootstrap.nix), by the fence's
#     own scoped token; a healthy fence stops nothing that Nomad placed
#   - with no leader (Nomad stopped on two of three voters), the fence on the third
#     gets a 5xx and stops nothing (`fence-failsafe-on-5xx`; mutant
#     `fence-5xx-reads-empty`)
#   - no voter is the one that registers jobs: each holds the management token and the
#     `registrar` login, applies a generation once, and registers again what the
#     cluster lost (`any-server-registers`). Their raft.db holds working management
#     tokens as well, design D6, asserted so that a change shows. A client-only
#     worker holds none: control-plane-failure.
#   - node1's Prometheus scrapes, and its Loki receives the logs of, all three
#   - every container's task runs as nomad-apps, which starts and stops it through
#     polkit (lib/mk-app-container.nix): `nomad job restart` stops each cleanly and
#     starts it again, and Vector still ships container journals through the 0750
#     directories a task can't read (`vector-still-ships`)
#
# The fixture app catalogue is replaced by two probe apps (see probeApps): the
# probes actually run, and the catalogue's containers are built — and that config
# booted — by tests/cluster-single.nix.
#
# Run: nix build .#checks.x86_64-linux.cluster -L   (needs KVM; ~9 GB RAM)
{
  pkgs,
  lib,
  mkSite,
  topology,
  # tests/lib/cluster-harness.nix, as a function of the topology: the voters below
  # need server certificates, which follow the tag.
  harnessFor,
  # tests/lib/control.py: a mutant removes one control (extraModule) and names the
  # assertion that must then fail (mutant).
  mutant ? "",
  extraModule ? { },
}:
let
  voter = {
    provisioned = true;
    tags = [
      "worker"
      "nomad-server"
      "etcd"
    ];
  };
  testTopology = lib.recursiveUpdate topology {
    nodes.node2 = voter;
    nodes.node3 = voter;
  };
  site = mkSite testTopology;
  harness = harnessFor testTopology;
  names = [
    "node1"
    "node2"
    "node3"
  ];
  nodes = lib.genAttrs names (n: testTopology.nodes.${n});

  # One module, every node: the cluster's apps for this test.
  probeApps =
    { lib, ... }:
    {
      clusterApps = lib.mkForce {
        # On every node (count 3, distinct hosts), on the shared volume. Each
        # replica records its own address there and serves the directory.
        probe = {
          nomad = {
            count = 3;
            distinctHosts = true;
          };
          # Its replicas serve each other on 8080, across nodes. Without this the
          # cross-node subtest below is refused (container default-deny).
          network.peerAccess = [
            {
              app = "probe";
              port = 8080;
            }
          ];
          juicefsPaths."/srv/shared" = "probe";
          resources = {
            cpu = 200;
            memoryMB = 256;
          };
          module =
            { pkgs, ... }:
            {
              networking.firewall.allowedTCPPorts = [ 8080 ];
              # The test reaches one replica from another with it.
              environment.systemPackages = [ pkgs.curl ];
              systemd.services.probe = {
                wantedBy = [ "multi-user.target" ];
                path = [
                  pkgs.iproute2
                  pkgs.gawk
                  pkgs.python3
                ];
                script = ''
                  until ip4=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1) && [ -n "$ip4" ]; do
                    sleep 1
                  done
                  echo "$ip4" > /srv/shared/"$ip4"
                  exec python3 -m http.server 8080 --bind 0.0.0.0 --directory /srv/shared
                '';
              };
            };
        };

        # Pinned to node2, with local state and a host-decrypted secret. Its journal
        # is kept under /state/clients and declared, as FreeIPA's is
        # (modules/kinds/freeipa.nix), so `vector-still-ships` covers both places a
        # container journal can live behind a directory a task can't read.
        pinned = {
          # Nomad's own way to say where; nothing in the library names a node.
          nomad.constraints = [
            {
              LTarget = "\${node.unique.name}";
              Operand = "=";
              RTarget = "node2";
            }
          ];
          tier = "monolith";
          localState."/var/lib/pinned" = "/state/clients/pinned";
          localState."/var/log/journal" = "/state/clients/pinned-journal";
          logging.journalDirs = [ "/state/clients/pinned-journal" ];
          # Any generated vars file will do: what is under test is the bind
          # mount of the host's /run/secrets path into the guest.
          secrets.token = {
            generator = "juicefs-pg";
            file = "password";
          };
          resources = {
            cpu = 100;
            memoryMB = 128;
          };
          module = {
            systemd.services.pinned = {
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                Type = "oneshot";
                RemainAfterExit = true;
              };
              script = "date > /var/lib/pinned/started";
            };
          };
        };
      };
    };

  ctrlIps = lib.mapAttrs (_: n: n.controlIp) nodes;
  inherit (import ../lib/nomad.nix) appsUser appsUid;
in
pkgs.testers.runNixOSTest {
  name = "cluster";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs site.nixosConfigurations.node1._module.specialArgs [
    "modulesPath"
  ];

  nodes = {
    wan = harness.wanNode;
  }
  // lib.genAttrs names (name: {
    imports = [
      site.machineModules.${name}
      (harness.nodeModule { memoryMB = if name == "node1" then 3072 else 2048; })
      probeApps
      extraModule
    ];
  });

  testScript = ''
    ${harness.pythonHelpers}

    CTRL = ${builtins.toJSON ctrlIps}
    NODES = [node1, node2, node3]
    NODE1 = CTRL["node1"]
    M1 = MESH["node1"]

    MUTANT = "${mutant}"
    import re
    import time
    nodes_by_name = {"node1": node1, "node2": node2, "node3": node3}

    def fence_ts(n):
        out = n.execute("awk '/^cluster_fence_last_success_timestamp_seconds/ {print $2}'"
                        " /var/lib/prometheus-node-exporter-text/nomad_fence.prom")[1].strip()
        return int(float(out or 0))

    def journal_mark(n):
        # Where the journal ends now, as a cursor for `--after-cursor`. Not `date +%s`
        # with `--since=@`: that has one-second resolution and takes in whatever was
        # logged earlier in the same second, such as the previous subtest's fencing.
        out = n.succeed("journalctl -q -n 1 --show-cursor --no-pager | tail -n 1").strip()
        assert out.startswith("-- cursor: "), f"{n.name}: no journal cursor: {out!r}"
        return out[len("-- cursor: "):]
    ${builtins.readFile ./lib/control.py}

    def main():

        wan.start()
        wan.wait_for_unit("s3.service")
        wan.wait_for_open_port(443)
        for n in NODES:
            n.start()

        with subtest("every node boots"):
            for n in NODES:
                n.wait_for_unit("multi-user.target")

        with subtest("the mesh: every node has a handshake with both others"):
            wg = "${pkgs.wireguard-tools}/bin/wg"
            for n in NODES:
                n.wait_for_unit(f"{MESH_IF}-ready.service")
            def handshakes(_):
                ok = True
                for n in NODES:
                    for other in NODES:
                        if other is not n:
                            n.execute(f"ping -c1 -W2 {MESH[other.name]}")
                    times = [int(l.split()[1]) for l in n.succeed(f"{wg} show {MESH_IF} latest-handshakes").splitlines()]
                    ok = ok and len(times) == 2 and all(t > 0 for t in times)
                return ok
            retry(handshakes, timeout_seconds=120)

        with subtest("etcd: one cluster of three, on the mesh"):
            for n in NODES:
                n.wait_for_unit("etcd.service")
            node1.wait_until_succeeds(
                "etcdctl --endpoints=" + ",".join(f"http://{ip}:2379" for ip in MESH.values())
                + " endpoint health",
                timeout=180,
            )
            members = node1.succeed(f"etcdctl --endpoints=http://{M1}:2379 member list -w json")
            assert len(json.loads(members)["members"]) == 3, members

        with subtest("Nomad: three servers, one leader, three ready clients"):
            for n in NODES:
                n.wait_for_unit("nomad.service")
            node1.wait_until_succeeds(f"curl -fsS {TLSCURL} {nomad_url(NODE1, '/v1/status/leader')} | grep -q :", timeout=300)
            node1.wait_for_unit("nomad-bootstrap.service")
            node1.wait_until_succeeds(
                f"test $(curl -fsS {TLSCURL} {nomad_url(NODE1, '/v1/status/peers')} | jq length) = 3", timeout=120
            )
            # Three servers in raft means each one's certificate passed the others'
            # verify_server_hostname, and they gossip with one key.
            for n in NODES:
                n.succeed("${pkgs.openssl}/bin/openssl x509 -noout -subject -in /run/secrets/per-machine/" + n.name + "/nomad-tls/agent.crt | grep -q 'CN *= *server.global.nomad'")
            members = nomad_api(node1, NODE1, "/v1/agent/members")["Members"]
            assert len([m for m in members if m["Status"] == "alive"]) == 3, members
            def all_ready(_):
                ns = [nomad_api(node1, NODE1, f"/v1/node/{x['ID']}") for x in nomad_api(node1, NODE1, "/v1/nodes")]
                ok = [x for x in ns if x["Status"] == "ready" and x["Meta"].get("jfs_ready") == "true"]
                return len(ok) == 3
            retry(all_ready, timeout_seconds=300)

        with subtest("JuiceFS: one volume, mounted everywhere"):
            for n in NODES:
                n.wait_for_unit("jfs-health.service")
            node2.succeed("echo from-node2 > /mnt/jfs/ci-shared")
            node3.wait_until_succeeds("grep -qx from-node2 /mnt/jfs/ci-shared", timeout=60)
            node1.succeed("grep -qx from-node2 /mnt/jfs/ci-shared")

        with subtest("Nomad runs the probe container on all three nodes"):
            def probe_running(_):
                allocs = nomad_api(node1, NODE1, f"/v1/job/app-probe/allocations?namespace={NS}")
                return len([a for a in allocs if a["ClientStatus"] == "running"]) == 3
            retry(probe_running, timeout_seconds=600)
            for n in NODES:
                n.wait_for_unit("container@probe.service", timeout=300)

        def container_ip(n, app):
            return n.succeed(
                f"nixos-container run {app} -- ip -4 -o addr show eth0 | awk '{{print $4}}' | cut -d/ -f1"
            ).strip()

        with subtest("containers take DHCP from their own node's br-app"):
            ips = {}
            for n, k in [(node1, 1), (node2, 2), (node3, 3)]:
                n.wait_until_succeeds(f"nixos-container run probe -- ip -4 -o addr show eth0 | grep -q 'inet 10.20.{k}.'", timeout=120)
                ips[n.name] = container_ip(n, "probe")

        with subtest("each replica wrote to the shared volume, and every node sees all three"):
            for n in NODES:
                for ip in ips.values():
                    n.wait_until_succeeds(f"grep -qx {ip} /mnt/jfs-app/probe/probe/{ip}", timeout=120)

        with subtest("app-volume-own-bucket: probe's files are in its own volume, bucket and database"):
            mounted = {n.name: n.succeed("findmnt -n -o FSTYPE,SOURCE -M /mnt/jfs-app/probe").strip() for n in NODES}
            own = wan.execute("find /srv/s3/${topology.objectStorage.juicefsBucket}-probe/probe/chunks -type f | grep -q .")[0] == 0
            in_shared = node1.execute("test -e /mnt/jfs/probe")[0] == 0
            dbs = node1.succeed(
                "PGPASSWORD=$(cat /run/secrets/shared/juicefs-patroni/superuser) psql -h 127.0.0.1 -p 5432 -U postgres -d postgres -Atc"
                " \"SELECT datname FROM pg_database WHERE datname LIKE 'jfs_%' OR datname = 'juicefs' ORDER BY 1\"").split()
            # Its role opens its own database and not the cluster volume's.
            crossed = node1.execute(
                "PGPASSWORD=$(cat /run/secrets/shared/probe-jfs/pg-password) psql -h 127.0.0.1 -p 5432 -U jfs_probe -d juicefs -Atc 'select 1'")[0] == 0
            unlabelled = node1.succeed("cat /var/lib/prometheus-node-exporter-text/jfs_encrypted-probe.prom").strip()
            detail = (f"mounts {mounted}; objects in the app's bucket={own}; a probe directory in the cluster volume={in_shared};"
                      f" databases {dbs}; probe's role opens the cluster volume's database={crossed}; metric {unlabelled!r}")
            print(f"app-volume-own-bucket: {detail}")
            control("app-volume-own-bucket",
                    all(m.startswith("fuse.juicefs") for m in mounted.values()) and own and not in_shared
                    and "jfs_probe" in dbs and "juicefs" in dbs and not crossed
                    and unlabelled == 'cluster_jfs_encrypted{volume="probe"} 1',
                    detail)

        with subtest("containers on different nodes reach each other over the app VLAN"):
            node1.wait_until_succeeds(
                f"nixos-container run probe -- curl -fsS --max-time 5 http://{ips['node3']}:8080/{ips['node2']}"
                f" | grep -qx {ips['node2']}",
                timeout=120,
            )

        with subtest("the app held to node2 runs there only, with its secret and local state"):
            def pinned_on_node2(_):
                allocs = nomad_api(node1, NODE1, f"/v1/job/app-pinned/allocations?namespace={NS}")
                running = [a for a in allocs if a["ClientStatus"] == "running"]
                return len(running) == 1 and running[0]["NodeName"] == "node2"
            retry(pinned_on_node2, timeout_seconds=300)
            node2.wait_for_unit("container@pinned.service", timeout=300)
            node2.wait_until_succeeds("test -s /state/clients/pinned/started", timeout=120)
            node2.succeed(
                "test \"$(nixos-container run pinned -- cat /run/secrets/token)\""
                " = \"$(cat /run/secrets/shared/juicefs-pg/password)\""
            )
            for n in (node1, node3):
                n.fail("systemctl is-active --quiet container@pinned.service")

        with subtest("fence-stops-orphan: a container started behind Nomad's back is fenced"):
            # By the fence's own scoped token, through the apps namespace. Mutant
            # `fence-no-namespace` drops the namespace from its query: the token is then
            # refused, so the fence fences nothing, and this must notice.
            node3.succeed("systemctl start container@pinned.service")
            stopped = False
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                if node3.execute("systemctl is-active --quiet container@pinned.service")[0] != 0:
                    stopped = True
                    break
                time.sleep(3)
            fenced = node3.execute(
                "journalctl -u nomad-fence.service --no-pager | grep -q 'fencing orphan container@pinned'"
            )[0] == 0
            last = node3.execute("journalctl -u nomad-fence.service --no-pager -n 5 -o cat")[1].strip()
            print(f"fence-stops-orphan: stopped={stopped} fence-logged-it={fenced}")
            control("fence-stops-orphan", stopped and fenced,
                    f"stopped={stopped} fence-logged-it={fenced}; fence's last words: {last}")

        with subtest("fence-stops-nothing-on-empty: a healthy scoped query stops nothing Nomad placed"):
            # The hazard: a query that comes back empty for the wrong reason (a
            # management token asking `default` gets 200 []) reads as "nothing runs",
            # and every container would be an orphan. Every node runs a probe, node2
            # the pinned app too; two successful fence runs on each must stop none.
            running = {(n.name, a): n.succeed(f"systemctl show -p InvocationID --value container@{a}.service").strip()
                       for n in NODES for a in (["probe", "pinned"] if n is node2 else ["probe"])}
            jmark = {n.name: journal_mark(n) for n in NODES}
            runs: dict = {}
            for n in NODES:
                ok = 0
                for _ in range(2):
                    before = fence_ts(n)
                    time.sleep(1.1)
                    rc = n.execute("systemctl start nomad-fence.service")[0]
                    if rc == 0 and fence_ts(n) > before:
                        ok += 1
                runs[n.name] = ok
            after = {k: nodes_by_name[k[0]].succeed(f"systemctl show -p InvocationID --value container@{k[1]}.service").strip()
                     for k in running}
            fenced = {n.name: n.execute(
                f"journalctl -u nomad-fence.service --after-cursor='{jmark[n.name]}' --no-pager | grep 'fencing orphan'")[1].strip()
                for n in NODES}
            print(f"fence-stops-nothing-on-empty: successful runs={runs} containers={after} fenced={fenced}")
            control(
                "fence-stops-nothing-on-empty",
                all(v == 2 for v in runs.values()) and after == running and all(v != "" for v in after.values())
                and not any(fenced.values()),
                f"successful runs={runs} containers before={running} after={after} fenced={fenced}",
            )

        with subtest("fence-failsafe-on-5xx: no leader, a 5xx from Nomad, and the fence stops nothing"):
            # The fence's named hazard: an answer that reads as "nothing runs here" stops
            # every container. A 5xx must not be that answer. Nomad stopped on node1 and
            # node3 (servers and clients; their tasks keep running, KillMode=process):
            # node2's server has no quorum, so its agent answers /v1/allocations with a
            # 5xx while /v1/agent/self still answers locally, which is the case a careless
            # fence would get wrong. Mutant `fence-5xx-reads-empty` (flake.nix).
            apps2 = ["probe", "pinned"]
            running = {a: node2.succeed(f"systemctl show -p InvocationID --value container@{a}.service").strip() for a in apps2}
            for n in (node1, node3):
                n.succeed("systemctl stop nomad.service")
            alloc_url = nomad_url(CTRL["node2"], f"/v1/allocations?namespace={NS}")
            def allocs_code():
                return node2.succeed(
                    f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10 {TLSCURL}"
                    f" -H \"X-Nomad-Token: $(cat {TOKENS}/fence)\" '{alloc_url}' || true"
                ).strip()
            retry(lambda _: allocs_code().startswith("5"), timeout_seconds=120)
            code = allocs_code()
            self_code = node2.succeed(
                f"curl -sS -o /dev/null -w '%{{http_code}}' --max-time 10 {TLSCURL}"
                f" -H \"X-Nomad-Token: $(cat {TOKENS}/fence)\" '{nomad_url(CTRL['node2'], '/v1/agent/self')}' || true"
            ).strip()
            ts_before = fence_ts(node2)
            jmark = journal_mark(node2)
            time.sleep(1.1)
            rc = node2.execute("systemctl start nomad-fence.service")[0]
            log = node2.succeed(f"journalctl -u nomad-fence.service --after-cursor='{jmark}' --no-pager -o cat")
            said_5xx = re.search(r"HTTP 5[0-9][0-9], Nomad not answering; fencing nothing", log) is not None
            after = {a: node2.succeed(f"systemctl show -p InvocationID --value container@{a}.service").strip() for a in apps2}
            active = {a: node2.execute(f"systemctl is-active --quiet container@{a}.service")[0] == 0 for a in apps2}
            ts_after = fence_ts(node2)
            detail = (f"/v1/allocations HTTP {code}, /v1/agent/self HTTP {self_code}; fence rc={rc}, logged the 5xx={said_5xx};"
                      f" containers before {running} after {after} active {active}; metric {ts_before} -> {ts_after};"
                      f" fence said: {log.strip()[-400:]!r}")
            print(f"fence-failsafe-on-5xx: {detail}")
            # The cluster back before the verdict, so a failure leaves the rest runnable.
            for n in (node1, node3):
                n.succeed("systemctl start nomad.service")
            node1.wait_until_succeeds(f"curl -fsS {TLSCURL} {nomad_url(NODE1, '/v1/status/leader')} | grep -q :", timeout=300)
            def statuses():
                return {x["Name"]: (x["Status"], x.get("Meta", {}).get("jfs_ready"))
                        for x in [nomad_api(node1, NODE1, f"/v1/node/{y['ID']}") for y in nomad_api(node1, NODE1, "/v1/nodes")]}
            retry(lambda _: all(st == "ready" for st, _ in statuses().values()) and len(statuses()) == 3, timeout_seconds=300)
            retry(probe_running, timeout_seconds=300)
            retry(pinned_on_node2, timeout_seconds=300)
            print(f"fence-failsafe-on-5xx: cluster back: {statuses()}")
            control(
                "fence-failsafe-on-5xx",
                code.startswith("5") and self_code == "200" and rc == 0 and said_5xx
                and after == running and all(active.values()) and ts_after == ts_before,
                detail,
            )

        with subtest("any-server-registers: every voter holds what registering jobs and applying ACLs takes, and does both by itself"):
            # No node is the one that registers: node2 and node3 hold the management
            # token (read by nomad-acl-init and the audit trail's ACL stream, nothing
            # else) and log in as `registrar`. A client-only worker holds neither
            # (checks.control-plane-failure, `management-absent-from-workers`).
            for n in (node2, node3):
                n.wait_for_unit("nomad-acl-init.service")
                n.wait_for_unit("nomad-bootstrap.service")
                present = n.execute("test -e /run/secrets/shared/nomad-acl")[0] == 0
                readers = units_reading(n, "nomad-acl/token")
                held = sorted(n.succeed(f"ls {TOKENS}").split())
                detail = f"{n.name}: nomad-acl deployed={present} readers={readers} tokens={held}"
                print(f"any-server-registers: {detail}")
                assert present and readers == ["cluster-audit-nomad-acl.service", "nomad-acl-init.service"] \
                    and held == ["avc", "fence", "node-meta", "registrar"], detail
            # Three servers applied the same ACLs at the same boot. Two that both found a
            # binding rule missing both made it; one of each is left.
            def rules_unique(_):
                # The list is stubs: each rule in full.
                rules = [nomad_api(node1, NODE1, f"/v1/acl/binding-rule/{r['ID']}")
                         for r in nomad_api(node1, NODE1, "/v1/acl/binding-rules")]
                keys = [(r["BindType"], r["BindName"], r["Selector"]) for r in rules]
                return len(keys) >= 4 and len(keys) == len(set(keys))
            retry(rules_unique, timeout_seconds=60)

            # A server registers a generation once. Started again with nothing lost (a
            # reboot), it submits nothing and applies nothing: one on an older
            # generation would otherwise put its jobs and policies back at every boot.
            mark = journal_mark(node3)
            node3.succeed("systemctl restart nomad-acl-init.service nomad-bootstrap.service")
            said = node3.succeed(f"journalctl -q -o cat --no-pager --after-cursor='{mark}' -u nomad-acl-init -u nomad-bootstrap")
            assert "already applied" in said and "registering" not in said and "policy " not in said, said

            # What the cluster lost, it registers again, with node1 having no part in it.
            code, body = as_token(node1, NODE1, NOMAD_TOKEN, f"/v1/job/app-pinned?namespace={NS}&purge=true", method="DELETE")
            assert code == 200, (code, body)
            node2.wait_until_fails("systemctl is-active --quiet container@pinned.service", timeout=120)
            assert as_token(node1, NODE1, NOMAD_TOKEN, f"/v1/job/app-pinned?namespace={NS}")[0] == 404
            mark = journal_mark(node3)
            node3.succeed("systemctl restart nomad-bootstrap.service")
            said = node3.succeed(f"journalctl -q -o cat --no-pager --after-cursor='{mark}' -u nomad-bootstrap")
            assert "app-pinned is not registered: registering it" in said and "app-probe" not in said, said
            retry(pinned_on_node2, timeout_seconds=300)
            node2.wait_for_unit("container@pinned.service", timeout=300)

        with subtest("voters-hold-acl-state-in-raft: the documented limit (design D6)"):
            # Every voter replicates the ACL tables, secrets included, so root on any
            # voter can read a working management token out of its raft.db. Accepted
            # (D6, section 6). Asserted rather than assumed, so that the day it stops
            # being true this test says so and the documentation can be changed.
            mgmt: dict = {}
            for n in (node2, node3):
                uuids = n.succeed(
                    f"grep -aoE '{UUID_RE}' /var/lib/nomad/server/raft/raft.db | sort -u"
                ).split()
                working = []
                for t in uuids:
                    code, body = as_token(n, CTRL[n.name], t, "/v1/acl/token/self")
                    if code == 200 and json.loads(body).get("Type") == "management":
                        working.append(t[:8])
                mgmt[n.name] = (len(uuids), working)
            print(f"voters-hold-acl-state-in-raft: (UUIDs in raft.db, working management tokens among them) {mgmt}")
            assert all(len(w) > 0 for _, w in mgmt.values()), f"expected each voter's raft.db to hold a management token: {mgmt}"

        with subtest("node1's Prometheus scrapes, and its Loki receives the logs of, every node"):
            def all_up(_):
                r = prom_query(node1, M1, 'up{job="nixos-hosts"} == 1')
                return len(r) == 3
            retry(all_up, timeout_seconds=300)
            # And every node's Nomad, over https with the scraper's certificate.
            def nomad_up(_):
                return len(prom_query(node1, M1, 'up{job="nomad"} == 1')) == 3
            retry(nomad_up, timeout_seconds=300)
            node1.wait_until_succeeds(f"curl -fsS http://{M1}:3100/ready", timeout=180)
            node3.succeed("logger -t ci-probe cluster-log-marker-node3")
            node1.wait_until_succeeds(
                f"curl -fsS -G http://{M1}:3100/loki/api/v1/query_range"
                " --data-urlencode 'query={node=\"node3\"} |= \"cluster-log-marker-node3\"'"
                " | jq -e '.data.result | length > 0'",
                timeout=180,
            )

        with subtest("containers run under nomad-apps on every node, started through polkit"):
            # The task names the account (lib/mk-app-container.nix); raw_exec refuses
            # every other one, root included. So a running container here was started
            # by nomad-apps asking systemd, which only the polkit rule allows.
            spec = nomad_api(node1, NODE1, f"/v1/job/app-probe?namespace={NS}")
            users = {t["User"] for g in spec["TaskGroups"] for t in g["Tasks"]}
            [wrapper] = {t["Config"]["command"] for g in spec["TaskGroups"] for t in g["Tasks"]}
            wrappers: dict = {}
            for n in NODES:
                n.succeed("grep -qF '\"container@probe.service\"' /etc/polkit-1/rules.d/10-nixos.rules")
                n.wait_for_unit("container@probe.service")
                # The wrapper's own process: the script is its last argument.
                wrappers[n.name] = sorted(set(n.succeed(f"ps -eo uid=,args= | awk -v c={wrapper} '$NF == c {{print $1}}'").split()))
            print(f"tasks run as: job {users}, wrappers' uids {wrappers}")
            control("containers-start-as-nomad-apps",
                    users == {"${appsUser}"} and all(v == ["${toString appsUid}"] for v in wrappers.values()),
                    f"job {users}; wrappers' uids {wrappers}")

        with subtest("nomad job restart: every probe stops cleanly and starts again"):
            # The stop is the wrapper's trap (systemctl stop, as nomad-apps), the start a
            # new wrapper's: both through polkit. A refused stop would leave the
            # container up and its InvocationID unchanged.
            before = {n.name: n.succeed("systemctl show -p InvocationID --value container@probe.service").strip() for n in NODES}
            jmark = {n.name: journal_mark(n) for n in NODES}
            node1.succeed(f"NOMAD_TOKEN={NOMAD_TOKEN} timeout 600 nomad job restart -yes -namespace={NS}"
                          f" -address=https://{NODE1}:4646 app-probe")
            after: dict = {}
            stops: dict = {}
            for n in NODES:
                n.wait_until_succeeds(
                    "systemctl is-active --quiet container@probe.service"
                    f" && test \"$(systemctl show -p InvocationID --value container@probe.service)\" != {before[n.name]}",
                    timeout=300,
                )
                after[n.name] = n.succeed("systemctl show -p InvocationID --value container@probe.service").strip()
                log = n.succeed(f"journalctl -u container@probe.service --after-cursor='{jmark[n.name]}' --no-pager -o cat")
                stops[n.name] = ("Deactivated successfully" in log, "Failed with result" in log)
            print(f"nomad job restart: before={before} after={after} (deactivated cleanly, failed)={stops}")
            control("job-restart-stops-cleanly",
                    all(after[k] != before[k] for k in before) and all(ok and not bad for ok, bad in stops.values()),
                    f"before={before} after={after} (deactivated cleanly, failed)={stops}")

        with subtest("vector-still-ships: container journals reach Loki through the 0750 directories"):
            modes = {n.name: n.succeed("stat -c '%n %a %U:%G' /var/lib/nixos-containers /state/clients").split("\n")[:2]
                     for n in NODES}
            print(f"vector-still-ships: modes {modes}")
            for n in NODES:
                for path in ("/var/lib/nixos-containers", "/state/clients"):
                    n.succeed(f"test \"$(stat -c '%a %U:%G' {path})\" = '750 root:systemd-journal'")
            node2.wait_until_succeeds("ls /state/clients/pinned-journal/*/system.journal", timeout=120)
            # A container root (node3's probe), and a declared journal under
            # /state/clients (node2's pinned), each from inside the container.
            marks = [("probe", node3, "ci-ws7-vector-probe-node3"), ("pinned", node2, "ci-ws7-vector-pinned-node2")]
            for app, n, mark in marks:
                n.succeed(f"nixos-container run {app} -- logger -t ci-ws7 {mark}")
            for app, n, mark in marks:
                node1.wait_until_succeeds(
                    f"curl -fsS -G http://{M1}:3100/loki/api/v1/query_range"
                    f" --data-urlencode 'query={{app=\"{app}\", node=\"{n.name}\"}} |= \"{mark}\"'"
                    " | jq -e '.data.result | length > 0'",
                    timeout=180,
                )

        with subtest("jfs-meta-ha: one metadata database, a member on every node, and it outlives its primary"):
            def members():
                rc, out = node2.execute("patronictl -c /etc/patroni-jfs-meta-node2.yaml list -f json 2>/dev/null")
                if rc != 0:
                    rc, out = node3.execute("patronictl -c /etc/patroni-jfs-meta-node3.yaml list -f json 2>/dev/null")
                try:
                    return {m["Member"]: (m["Role"], m["State"]) for m in json.loads(out)}
                except Exception:
                    return {}
            def formed(_=None):
                ms = members()
                leaders = [m for m, (role, _s) in ms.items() if role == "Leader"]
                following = [m for m, (role, state) in ms.items() if role != "Leader" and state == "streaming"]
                return len(ms) == 3 and len(leaders) == 1 and len(following) == 2
            retry(formed, timeout_seconds=300)
            before = members()
            first = [m for m, (role, _s) in before.items() if role == "Leader"][0]
            # A commit waits for one of the others (quorum commit): Patroni names them so.
            quorum = sorted(role for role, _s in before.values() if role != "Leader")
            by_name = {n.name: n for n in NODES}
            victim = by_name[first]
            survivors = [n for n in NODES if n is not victim]
            # No JuiceFS client names a node: each asks its own loopback.
            local_only = all(
                n.succeed("systemctl cat juicefs-mount.service | grep ExecStart= | cut -d= -f2 | xargs cat"
                          " | grep -c '@127.0.0.1:5432/'").strip() == "1" for n in NODES)
            survivors[0].succeed("echo before-the-loss > /mnt/jfs/ci-meta-ha && sync")
            # The primary dies without a word: Patroni and PostgreSQL killed, the lock
            # left in etcd to run out. (Then stopped, so systemd doesn't bring it back
            # before anybody has had to take over.)
            victim.succeed("systemctl kill -s KILL patroni.service; systemctl stop patroni.service")
            t0 = time.monotonic()
            wrote = None
            while time.monotonic() - t0 < 180:
                if survivors[1].execute("timeout 5 sh -c 'echo after-the-loss > /mnt/jfs/ci-meta-ha2 && sync'")[0] == 0:
                    wrote = round(time.monotonic() - t0, 1)
                    break
                time.sleep(1)
            after = members()
            second = [m for m, (role, _s) in after.items() if role == "Leader"]
            kept = survivors[1].execute("grep -qx before-the-loss /mnt/jfs/ci-meta-ha")[0] == 0
            mounts = {n.name: n.execute("mountpoint -q /mnt/jfs && systemctl is-active --quiet juicefs-mount.service")[0] == 0
                      for n in NODES}
            # The old primary comes back as a replica of the new one, by itself.
            victim.succeed("systemctl start patroni.service")
            rejoined = True
            try:
                retry(formed, timeout_seconds=300)
            except Exception:
                rejoined = False
            again = members()
            victim.wait_until_succeeds("grep -qx after-the-loss /mnt/jfs/ci-meta-ha2", timeout=60)
            detail = (f"members {before}; every mount asks 127.0.0.1={local_only}; primary {first} killed;"
                      f" a survivor wrote again after {wrote}s; primary now {second}; the write acknowledged before the loss"
                      f" is there={kept}; mounts alive {mounts}; after {first} returned: {again}, formed={rejoined}")
            print(f"jfs-meta-ha: {detail}")
            control("jfs-meta-ha",
                    local_only and quorum == ["Quorum Standby", "Quorum Standby"]
                    and wrote is not None and wrote <= 90 and len(second) == 1 and second[0] != first
                    and kept and all(mounts.values()) and rejoined,
                    detail)

        with subtest("jfs-meta-member-rebuilt: a member that lost its disk copies the database back"):
            ms = members()
            replica = by_name[[m for m, (role, _s) in ms.items() if role != "Leader"][0]]
            replica.succeed("systemctl stop patroni.service && rm -rf /var/lib/postgresql/* && systemctl start patroni.service")
            rebuilt = True
            try:
                retry(formed, timeout_seconds=300)
            except Exception:
                rebuilt = False
            # It joined; nobody formatted or restored anything.
            restored = {n.name: n.succeed("journalctl -u juicefs-format --no-pager | grep -c 'restoring\\|refusing' || true").strip()
                        for n in NODES}
            detail = f"{replica.name}'s data directory removed; members after: {members()}; restores or refusals in juicefs-format: {restored}"
            print(f"jfs-meta-member-rebuilt: {detail}")
            control("jfs-meta-member-rebuilt", rebuilt and all(v == "0" for v in restored.values()), detail)

        with subtest("no failed units anywhere"):
            for n in NODES:
                no_failed_units(n)

    run_main(main)
  '';
}
