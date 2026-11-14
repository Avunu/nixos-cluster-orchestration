# VM test: a three-node cluster forms, shares storage, and runs containers
# under Nomad.
#
# The same clan as the fixture cluster (`mkClan`, tests/fixtures) over its
# topology with ONE change: node2 and node3 are provisioned voters, which is
# exactly the commit a topology needs when their machines land. node1 keeps
# every singleton. Every node boots its real machine module plus
# tests/lib/cluster-harness.nix, so this is the first time anything has run
# what a quorum needs:
#
#   - etcd forms one 3-member cluster from etcdInitialCluster
#   - three Nomad servers find each other (server_join) and elect one leader;
#     all three clients join and advertise jfs_ready once /mnt/jfs is up
#   - every node mounts the ONE JuiceFS volume through node1's metadata engine
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
#   - the voters that are not the nomad-leader are given no management token, and log
#     in only as their own roles (modules/nomad-acl.nix); their raft.db does hold
#     working management tokens, which is the accepted limit of design D6, asserted so
#     that a change shows. A client-only worker is checked in control-plane-failure.
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
  mkClan,
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
  clan = mkClan testTopology;
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
  node.specialArgs = removeAttrs clan.config.nixosConfigurations.node1._module.specialArgs [
    "modulesPath"
  ];

  nodes = {
    wan = harness.wanNode;
  }
  // lib.genAttrs names (name: {
    imports = [
      clan.config.nixosModules."clan-machine-${name}"
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
                    n.wait_until_succeeds(f"grep -qx {ip} /mnt/jfs/probe/{ip}", timeout=120)

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

        with subtest("management-absent-from-deployed-secrets: a voter that isn't the nomad-leader is given no management token"):
            # What this shows on voters, and only that: nothing deployed to node2 or node3
            # (secrets, token files, the environment) is a management token. Their raft
            # state is another matter, below. A client-only worker, which has no raft
            # state, is checked in checks.control-plane-failure.
            for n in (node2, node3):
                # Not deployed, read by nothing.
                present = n.execute("test -e /run/secrets/shared/nomad-acl")[0] == 0
                readers = units_reading(n, "nomad-acl/token")
                # Its own roles only: no registrar, no autoscaler.
                held = sorted(n.succeed(f"ls {TOKENS}").split())
                # Every token-shaped value deployed to the node, tried against the API.
                found = n.succeed(
                    f"grep -rhoE '{UUID_RE}' /run/secrets /run/nomad-tokens /etc/secret-vars 2>/dev/null | sort -u || true"
                ).split()
                kinds: dict = {}
                for t in found:
                    code, body = as_token(n, CTRL[n.name], t, "/v1/acl/token/self")
                    kinds[t[:8]] = json.loads(body)["Type"] if code == 200 else code
                print(f"management-absent-from-deployed-secrets: {n.name}: nomad-acl deployed={present} readers={readers}"
                      f" tokens={held} tried={kinds}")
                control(
                    "management-absent-from-deployed-secrets",
                    not present and readers == [] and held == ["avc", "fence", "node-meta"]
                    and len(found) >= 3 and "management" not in kinds.values(),
                    f"{n.name}: nomad-acl deployed={present} readers={readers} tokens={held} tried={kinds}",
                )

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

        with subtest("no failed units anywhere"):
            for n in NODES:
                no_failed_units(n)

    run_main(main)
  '';
}
