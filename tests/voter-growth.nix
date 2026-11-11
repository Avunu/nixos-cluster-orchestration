# VM test: one Nomad voter to three, on the real modules, the way a site grows.
#
# Two topologies of the fixture site (tests/fixtures), as two commits of a private repo:
#
#   single  node1 the only voter (no `etcd` tag anywhere: a single-voter topology
#           doesn't create etcd), node3 an installed worker with data, node2 not in
#           the site yet. This is the bootstrap plan's Phase 5.
#   voters  node1 as the fixture has it (with `etcd`), node2 and node3 tagged
#           `worker nomad-server etcd`. The commit that brings the voters (Phase 7).
#
# node1 and node3 boot the single-voter closures. node2 boots the three-voter one, as a
# fresh install would. node1v and node3v are never started: they are the three-voter
# closures of node1 and node3, built as test VMs so that the parts a VM needs (the store
# share, the NICs by MAC, the hostname) match the running node1 and node3, and the test
# activates them there with `switch-to-configuration test`, which is what a pull or a
# push does. Nothing about the switch is simulated.
#
#   first-voter-flips-no-outage  node1's switch to bootstrap_expect = 3: it keeps raft
#                                state, so expect is ignored and it is leader again within
#                                seconds; the job, its allocations and the task's PID are
#                                unchanged
#   order-a-first-voter-first    (the check) node1 switches first, then node2 is installed
#                                and node3 switched; three voters, node1 leader throughout
#   order-b-new-voters-first     (legacyPackages.mutants.voter-growth-order-b, a second
#                                fresh cluster) node2 and node3 first, node1 still on
#                                expect = 1; they join it, then node1 switches
#   mesh-peers-applied           node1's mesh gains node2 on the switch (node2 was not in
#                                the single-voter site, so its peer is new), and node2
#                                reaches node1's and node3's mesh services
#   two-more-voters-converge     three voters, autopilot healthy, FailureTolerance 1
#   promotion-heartbeat-gap      node3's client is registered again within 8 s of its old
#                                agent stopping, inside the servers' 10 s heartbeat_grace,
#                                so no TTL draw marks it down. Its new client registers
#                                through its own new server, which knows no leader until
#                                it has joined; before the module denied the cloud
#                                fingerprinters this took 9.9 to 17 s, and once (order B)
#                                the leader marked node3 down and moved its allocation
#   worker-promoted-to-voter     node3, a worker with an allocation, a Nomad node ID and
#                                data, becomes a voter: a server certificate, the gossip
#                                key, the same node, allocation, task and data
#   state-replicated             the job, a variable and an ACL token made on the single
#                                voter are in node2's and node3's own state (stale reads)
#   etcd-forms-with-three        etcd, created by the commit that tags three nodes, forms
#                                one cluster on the mesh
#   trap-two-expect-1-diverge    built-in negative control: node2 removed as a dead
#                                server, then reinstalled as the single voter of its
#                                own topology (fresh state, expect = 1, joining only
#                                itself; the real config otherwise) on the same gossip
#                                key: it elects itself and accepts a second `acl
#                                bootstrap`. Two
#                                clusters, two management tokens. That is why expect
#                                comes only from the topology's voter count, and why
#                                modules/cluster-common.nix refuses any other. Started
#                                a second after the removal (as this test once did), the
#                                fresh server was reached by the old cluster instead
#                                (serf's reconnect, or raft's last replication to the
#                                removed peer), took it over, and the real voters
#                                cleared their logs: worse, and timing-dependent, so the
#                                test waits until node2 is gone from both (see the trap)
#
# What a switch returns is recorded, not asserted beyond "it took effect" (rc 0 or 4):
# etcd is a notify unit that is not ready until it has a quorum, so the first node to
# carry the `etcd` tag waits for the others (see the FINDING lines).
#
# Run: nix build .#checks.x86_64-linux.voter-growth -L   (needs KVM; ~9 GB RAM)
{
  pkgs,
  lib,
  mkClan,
  topology,
  # tests/lib/cluster-harness.nix, as a function of { topology, fixturePki ? null }.
  harnessFor,
  # "a": the first voter switches first. "b": the new voters come first.
  order ? "a",
  # tests/lib/control.py: a mutant removes one control and names the assertion that
  # must then fail.
  mutant ? "",
  # On every node, every closure.
  extraModule ? { },
  # On node1's three-voter closure only: what the first voter switches to.
  firstVoterModule ? { },
}:
assert lib.elem order [
  "a"
  "b"
];
let
  net = import ../lib/net.nix { inherit lib; };
  nomadPki = import ../lib/nomad-pki.nix { inherit lib; };
  inherit (import ../lib/nomad.nix) appsUser;
  wg = import ./lib/fixture-wg.nix;

  voterTags = [
    "worker"
    "nomad-server"
    "etcd"
  ];

  topologies = {
    voters = lib.recursiveUpdate topology {
      nodes.node2 = {
        provisioned = true;
        tags = voterTags;
      };
      nodes.node3 = {
        provisioned = true;
        tags = voterTags;
      };
    };
    single = topology // {
      nodes = removeAttrs topology.nodes [ "node2" ] // {
        node1 = topology.nodes.node1 // {
          tags = lib.remove "etcd" topology.nodes.node1.tags;
        };
        node3 = topology.nodes.node3 // {
          provisioned = true;
          tags = [ "worker" ];
        };
      };
    };
  };

  # One CA, gossip key and JWT key for both: the commit that adds voters regenerates no
  # shared secret. The single-voter site's PKI is the three-voter one with node3's agent
  # certificate a worker's, which is what clan's `validation` reissues on promotion
  # (modules/vars.nix: nomad-tls's validation carries isServer).
  votersPki = import ./lib/fixture-pki.nix {
    inherit pkgs lib;
    topology = topologies.voters;
  };
  singlePki =
    pkgs.runCommand "fixture-nomad-pki-single-voter"
      {
        nativeBuildInputs = [
          pkgs.openssl
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        ${nomadPki.functions}
        cp -r --no-preserve=mode ${votersPki} $out
        pki_ca_crt=${votersPki}/ca.crt
        pki_ca_key=${votersPki}/ca.key
        pki_days=36500
        ${lib.concatStrings (
          lib.mapAttrsToList (
            name: nd:
            let
              isServer = net.hasTag "nomad-server" nd;
            in
            lib.optionalString (isServer != net.hasTag "nomad-server" topologies.voters.nodes.${name}) ''
              rm -f $out/${name}/agent.crt $out/${name}/agent.key
              pki_out=$out/${name}
              issue agent ${nomadPki.agentName isServer} ${
                lib.escapeShellArg (
                  nomadPki.agentSans {
                    inherit isServer;
                    inherit (nd) controlIp;
                  }
                )
              }
            ''
          ) topologies.single.nodes
        )}
        # node3 is the one that differs, and it is a worker's now.
        openssl x509 -noout -subject -in $out/node3/agent.crt | grep -q 'CN *= *${nomadPki.clientName}'
      '';

  site = lib.mapAttrs (name: t: {
    topology = t;
    clan = mkClan t;
    harness = harnessFor {
      topology = t;
      fixturePki = if name == "single" then singlePki else votersPki;
    };
  }) topologies;

  # A node of one site: its real machine module, the harness, and the topology it was
  # built from. `topology` is a clan-wide specialArg, which a NixOS test shares between
  # all its nodes, so here it is each node's own module argument instead.
  machineIn =
    which: name:
    {
      memoryMB,
      extra ? [ ],
    }:
    {
      imports = [
        site.${which}.clan.config.nixosModules."clan-machine-${name}"
        (site.${which}.harness.nodeModule { inherit memoryMB; })
        noApps
        extraModule
      ]
      ++ extra;
      _module.args.topology = site.${which}.topology;
      # A NixOS test leaves switch-to-configuration out of a closure unless it has
      # specialisations. A node has it in production, and this test switches with it.
      system.switch.enable = true;
    };

  # The fixture's app catalogue is not what grows here, and its containers would cost a
  # gigabyte of evaluation per closure. The test runs its own job.
  noApps =
    { lib, ... }:
    {
      clusterApps = lib.mkForce { };
    };

  # Never started: the three-voter closure of a running node, with that node's identity
  # as a test VM (the MACs its NICs are named by, its hostname).
  closureOf = name: {
    virtualisation.test.nodeName = lib.mkForce name;
  };

  memory = {
    node1 = 3584;
    node2 = 2048;
    node3 = 2048;
  };
  ctrlIps = lib.mapAttrs (_: n: n.controlIp) topologies.voters.nodes;
  vcfg = site.voters.clan.config.nixosConfigurations;
  gossipPath = vcfg.node3.config.clan.core.vars.generators.nomad-gossip.files."gossip.hcl".path;
  tlsCrtPath = n: vcfg.${n}.config.clan.core.vars.generators.nomad-tls.files."agent.crt".path;
in
pkgs.testers.runNixOSTest {
  name = "voter-growth${lib.optionalString (order != "a") "-order-${order}"}";

  node.pkgs = lib.mkForce null;
  node.specialArgs =
    removeAttrs site.voters.clan.config.nixosConfigurations.node1._module.specialArgs
      [
        "modulesPath"
        "topology"
      ];

  nodes = {
    wan = site.voters.harness.wanNode;
    node1 = machineIn "single" "node1" { memoryMB = memory.node1; };
    node3 = machineIn "single" "node3" { memoryMB = memory.node3; };
    node2 = machineIn "voters" "node2" { memoryMB = memory.node2; };
    node1v = machineIn "voters" "node1" {
      memoryMB = memory.node1;
      extra = [
        (closureOf "node1")
        firstVoterModule
      ];
    };
    node3v = machineIn "voters" "node3" {
      memoryMB = memory.node3;
      extra = [ (closureOf "node3") ];
    };
  };

  testScript =
    { nodes, ... }:
    ''
      import re
      import time

      ${site.voters.harness.pythonHelpers}

      MUTANT = "${mutant}"
      ${builtins.readFile ./lib/control.py}

      ORDER = "${order}"
      CTRL = json.loads(r"""${builtins.toJSON ctrlIps}""")
      NODE1 = CTRL["node1"]
      M1 = MESH["node1"]
      VOTERS_CLOSURE = {"node1": "${nodes.node1v.system.build.toplevel}", "node3": "${nodes.node3v.system.build.toplevel}"}
      WG = "${pkgs.wireguard-tools}/bin/wg"
      PUB = json.loads(r"""${
        builtins.toJSON (lib.mapAttrs (_: k: k.public) (removeAttrs wg [ "rotated" ]))
      }""")
      NETDEV = "/etc/systemd/network/30-${net.meshIf}.netdev"
      GOSSIP = "${gossipPath}"
      AGENT_CRT = {n: p for n, p in [("node1", "${tlsCrtPath "node1"}"), ("node2", "${tlsCrtPath "node2"}"), ("node3", "${tlsCrtPath "node3"}")]}
      OPENSSL = "${pkgs.openssl}/bin/openssl"
      DATE = "${pkgs.coreutils}/bin/date"
      SERVER_CN = "${nomadPki.serverName}"
      CLIENT_CN = "${nomadPki.clientName}"
      # The task's own command line, unique on these machines. `[s]leep` in a pattern
      # keeps pgrep from matching the shell that runs it.
      SLEEP_ARG = "1000017"
      NODES = [node1, node2, node3]
      FINDINGS: list = []

      def finding(text):
          FINDINGS.append(text)
          print(f"FINDING: {text}")

      # ── reading the cluster ───────────────────────────────────────────────────
      def leader(ips):
          """The first leader any of these servers reports, asked from node1, or ""."""
          for ip in ips:
              rc, out = node1.execute(
                  f"curl -fsS --connect-timeout 1 --max-time 2 {TLSCURL} {nomad_url(ip, '/v1/status/leader')}"
              )
              out = out.strip().strip('"')
              if rc == 0 and out:
                  return out
          return ""

      def api_any(path, ips=None):
          """A management-token GET from node1, at the first of these servers that answers."""
          last = None
          for ip in (ips or list(CTRL.values())):
              rc, out = node1.execute(
                  f"curl -fsS --connect-timeout 1 --max-time 5 {TLSCURL} -H 'X-Nomad-Token: {NOMAD_TOKEN}' '{nomad_url(ip, path)}'"
              )
              if rc == 0:
                  return json.loads(out)
              last = out
          raise Exception(f"no server answered {path}: {last}")

      def raft_servers(ips=None):
          return api_any("/v1/operator/raft/configuration", ips)["Servers"]

      def voters(ips=None):
          return sorted(s["Node"] for s in raft_servers(ips) if s["Voter"])

      def allocs():
          al = api_any(f"/v1/job/ci-sleep/allocations?namespace={NS}")
          return sorted((a["ID"], a["NodeName"]) for a in al if a["ClientStatus"] == "running")

      def task_pids():
          return {n.name: n.succeed(f"pgrep -f '[s]leep {SLEEP_ARG}' || true").split() for n in (node1, node3)}

      def node_ids():
          return {x["Name"]: x["ID"] for x in api_any("/v1/nodes")}

      def cn_of(n):
          return n.succeed(f"{OPENSSL} x509 -noout -subject -in {AGENT_CRT[n.name]}").strip()

      def fingerprint(n):
          return n.succeed(f"{OPENSSL} x509 -noout -fingerprint -sha256 -in {AGENT_CRT[n.name]}").strip()

      def mesh_peers(n):
          return sorted(n.succeed(f"{WG} show {MESH_IF} peers").split())

      # ── switching a running node to another closure ───────────────────────────
      def start_switch(n, closure):
          """`switch-to-configuration test` in a unit of its own, as the pull loop runs it
          (modules/pull-deploy.nix), so the test can watch the cluster while it runs.
          The rc and seconds go to /tmp/ci-switch.rc."""
          n.succeed("rm -f /tmp/ci-switch.rc /tmp/ci-switch.log /tmp/ci-switch.start")
          n.succeed(
              "cat > /tmp/ci-switch.sh <<'EOF'\n"
              f"s=$({DATE} +%s)\n"
              "echo $s > /tmp/ci-switch.start\n"
              f"{closure}/bin/switch-to-configuration test > /tmp/ci-switch.log 2>&1\n"
              "rc=$?\n"
              f"echo \"$rc $(( $({DATE} +%s) - s ))\" > /tmp/ci-switch.rc\n"
              "EOF"
          )
          n.succeed("systemd-run --unit=ci-switch --collect --setenv=PATH=/run/current-system/sw/bin"
                    " ${pkgs.bash}/bin/bash /tmp/ci-switch.sh")

      def finish_switch(n, closure, timeout=600):
          n.wait_until_succeeds("test -s /tmp/ci-switch.rc", timeout=timeout)
          rc, secs = n.succeed("cat /tmp/ci-switch.rc").split()
          current = n.succeed("readlink -f /run/current-system").strip()
          failed = n.execute("grep -iE 'failed|error' /tmp/ci-switch.log | head -5")[1].strip()
          finding(f"{n.name}'s switch to the three-voter closure: rc={rc} after {secs}s; what it reported: {failed or 'nothing'}")
          # 0, or 4 (a unit not up yet, see the header): the system switched either way.
          # Anything else means the activation itself failed.
          assert rc in ("0", "4") and current == closure, f"{n.name}: switch rc={rc}, current {current}"
          return int(rc), int(secs)

      def flip_first_voter(server_ips):
          """node1 to its three-voter closure. Returns the longest leaderless window seen,
          whether node1's Nomad was really restarted, and the switch's outcome."""
          before = node1.succeed("systemctl show -p InvocationID --value nomad.service").strip()
          start_switch(node1, VOTERS_CLOSURE["node1"])
          t0 = time.monotonic()
          samples = []
          restarted_at = None
          stable_since = None
          while time.monotonic() - t0 < 300:
              now = round(time.monotonic() - t0, 1)
              inv = node1.execute("systemctl show -p InvocationID --value nomad.service")[1].strip()
              lead = leader(server_ips)
              samples.append((now, lead))
              if restarted_at is None and inv not in ("", before):
                  restarted_at = now
              if restarted_at is not None and lead:
                  stable_since = stable_since if stable_since is not None else now
                  if now - stable_since >= 10:
                      break
              else:
                  stable_since = None
              time.sleep(0.5)
          gap, run_start = 0.0, None
          for t, lead in samples:
              if not lead and run_start is None:
                  run_start = t
              if lead and run_start is not None:
                  gap = max(gap, t - run_start)
                  run_start = None
          if run_start is not None:
              gap = max(gap, samples[-1][0] - run_start)
          rc, secs = finish_switch(node1, VOTERS_CLOSURE["node1"])
          leaders = sorted({lead for _, lead in samples if lead})
          return round(gap, 1), restarted_at, leaders, rc, secs

      # The servers mark a client down heartbeat_grace (Nomad's default 10 s; the module
      # sets none) after its heartbeat was due. A restart can begin just before that
      # moment, so it keeps the node's allocations for every TTL draw only if the client
      # registers again within the grace. GAP_MAX leaves 2 s of it for a slower machine.
      GRACE = 10
      GAP_MAX = 8
      PROMO_EVENTS = ("Starting Nomad agent|client: started client|failed to get previous log"
                      "|node registration complete|error registering|error heartbeating|No cluster leader")

      def promotion_window(n):
          """Seconds from n's old Nomad agent stopping in its switch to the new agent's
          client registering, by n's journal; and what happened in between."""
          since = n.succeed("cat /tmp/ci-switch.start").strip()
          journal = f"journalctl -u nomad.service --since=@{since} -o short-unix --no-pager"
          n.wait_until_succeeds(f"{journal} | grep -A100000 'Caught signal' | grep -q 'node registration complete'", timeout=180)
          t_stop: float | None = None
          t_reg: float | None = None
          timeline: list = []
          for line in n.succeed(journal).splitlines():
              head, _, msg = line.partition(": ")
              try:
                  t = float(head.split()[0])
              except (ValueError, IndexError):
                  continue
              if t_stop is None:
                  if "Caught signal" in msg:
                      t_stop = t
                  continue
              # The scheduler workers' "No cluster leader" says nothing about the client.
              if t_reg is None and "worker:" not in msg and re.search(PROMO_EVENTS, msg):
                  timeline.append((round(t - t_stop, 1), msg.strip()[:110]))
                  if "node registration complete" in msg:
                      t_reg = t
          gap = round(t_reg - t_stop, 1) if t_stop is not None and t_reg is not None else None
          return gap, timeline

      def converge(ips, timeout=360):
          """Three voters, a leader, autopilot healthy with FailureTolerance 1."""
          t0 = time.monotonic()
          last = None
          while time.monotonic() - t0 < timeout:
              try:
                  v = voters(ips)
                  ap = api_any("/v1/operator/autopilot/health", ips)
                  last = (v, ap.get("Healthy"), ap.get("FailureTolerance"))
                  if v == ["node1.global", "node2.global", "node3.global"] and ap.get("Healthy") and ap.get("FailureTolerance") == 1:
                      return round(time.monotonic() - t0), last
              except Exception as e:
                  last = str(e)[:200]
              time.sleep(3)
          return None, last

      def main():
          wan.start()
          wan.wait_for_unit("s3.service")
          node1.start()
          node3.start()

          # ── the single-voter site ───────────────────────────────────────────────
          with subtest("the single-voter site: node1 the only voter, node3 a worker, no etcd"):
              node1.wait_for_unit("nomad-acl-init.service", timeout=600)
              for n in (node1, node3):
                  n.wait_for_unit(f"{MESH_IF}-ready.service")
                  n.wait_for_unit("jfs-health.service", timeout=600)
              def ready(_):
                  st = {x["Name"]: x["Status"] for x in api_any("/v1/nodes", [NODE1])}
                  return st == {"node1": "ready", "node3": "ready"}
              retry(ready, timeout_seconds=300)
              assert voters([NODE1]) == ["node1.global"], raft_servers([NODE1])
              for n in (node1, node3):
                  n.fail("systemctl cat etcd.service")
                  assert n.succeed("jq -r '.server.bootstrap_expect // \"none\"' /etc/nomad.json").strip() == ("1" if n is node1 else "none")
              assert CLIENT_CN in cn_of(node3), cn_of(node3)
              node3.fail(f"test -e {GOSSIP}")
              # node2 is not in this site: no node lists it as a peer yet.
              assert PUB["node2"] not in node1.succeed(f"cat {NETDEV}")
              assert mesh_peers(node1) == [PUB["node3"]], mesh_peers(node1)

          with subtest("state on the single voter: a job on both nodes, a variable, a token, node3's data"):
              job = json.dumps({"Job": {
                  "ID": "ci-sleep", "Name": "ci-sleep", "Namespace": NS, "Type": "service",
                  "Datacenters": ["${topology.datacenter}"],
                  "TaskGroups": [{"Name": "g", "Count": 2,
                                  "Constraints": [{"Operand": "distinct_hosts", "RTarget": "true"}],
                                  "Tasks": [{"Name": "t", "Driver": "raw_exec", "User": "${appsUser}",
                                             "Config": {"command": "/run/current-system/sw/bin/sleep", "args": [SLEEP_ARG]}}]}],
              }})
              code, body = as_token(node1, NODE1, NOMAD_TOKEN, "/v1/jobs", "POST", job)
              assert code == 200, body
              retry(lambda _: len(allocs()) == 2, timeout_seconds=180)
              code, body = as_token(node1, NODE1, NOMAD_TOKEN, f"/v1/var/ci/growth?namespace={NS}", "PUT",
                                    json.dumps({"Namespace": NS, "Path": "ci/growth", "Items": {"seed": "before-growth"}}))
              assert code == 200, body
              code, body = as_token(node1, NODE1, NOMAD_TOKEN, "/v1/acl/token", "POST",
                                    json.dumps({"Name": "ci-growth", "Type": "client", "Policies": ["avc"]}))
              assert code == 200, body
              token_accessor = json.loads(body)["AccessorID"]
              node3.succeed("mkdir -p /var/lib/ci-worker && echo worker-data > /var/lib/ci-worker/marker")
              node3.succeed("echo from-the-worker > /mnt/jfs/ci-worker && sync")
              seed = {
                  "allocs": allocs(),
                  "pids": task_pids(),
                  "ids": node_ids(),
                  "job_version": api_any(f"/v1/job/ci-sleep?namespace={NS}")["Version"],
                  "node3_cert": fingerprint(node3),
                  "token": token_accessor,
              }
              assert sorted(nd for _, nd in seed["allocs"]) == ["node1", "node3"], seed
              assert all(len(v) == 1 for v in seed["pids"].values()), seed
              print(f"seeded: {seed}")

          def unchanged(what):
              now = {"allocs": allocs(), "pids": task_pids(),
                     "job_version": api_any(f"/v1/job/ci-sleep?namespace={NS}")["Version"]}
              same = all(now[k] == seed[k] for k in now)
              return same, f"{what}: allocations {now['allocs']} (were {seed['allocs']}), task PIDs {now['pids']} (were {seed['pids']}), job version {now['job_version']} (was {seed['job_version']})"

          def first_voter_subtest(server_ips):
              with subtest("first-voter-flips-no-outage: node1 switches to bootstrap_expect = 3"):
                  gap, restarted_at, leaders, rc, secs = flip_first_voter(server_ips)
                  expect = node1.succeed("jq -r .server.bootstrap_expect /etc/nomad.json").strip()
                  same, state = unchanged("after node1's switch")
                  detail = (f"Nomad restarted at {restarted_at}s; longest leaderless window {gap}s; leaders seen {leaders};"
                            f" expect now {expect}; switch rc {rc} after {secs}s; {state}")
                  print(f"first-voter-flips-no-outage: {detail}")
                  control("first-voter-flips-no-outage",
                          restarted_at is not None and gap <= 20 and expect == "3" and leaders != [] and same,
                          detail)
                  return leaders

          def promotion_gap_subtest():
              # Right after node3's switch, before anything that looks at its allocation:
              # a node marked down shows here first, with what its client went through.
              with subtest("promotion-heartbeat-gap: node3's client registered again well inside the servers' grace"):
                  gap, timeline = promotion_window(node3)
                  detail = (f"node3's client was without a registration for {gap}s across its promotion (at most {GAP_MAX}s;"
                            f" the servers' heartbeat_grace is {GRACE}s); seconds after the old agent's stop: {timeline}")
                  print(f"promotion-heartbeat-gap: {detail}")
                  control("promotion-heartbeat-gap", gap is not None and gap <= GAP_MAX, detail)

          def bring_new_voters():
              """Install node2 and switch node3, together, as the design's growth order says."""
              node2.start()
              start_switch(node3, VOTERS_CLOSURE["node3"])
              return time.monotonic()

          # ── the growth, in the order this build runs ───────────────────────────
          if ORDER == "a":
              first_voter_subtest([NODE1])
              with subtest("order-a-first-voter-first: node2 installed and node3 switched after node1"):
                  t0 = bring_new_voters()
                  seen = set()
                  longest, run_start = 0.0, None
                  converged_after, last = None, None
                  while time.monotonic() - t0 < 360:
                      lead = leader(list(CTRL.values()))
                      now = time.monotonic() - t0
                      if lead:
                          seen.add(lead)
                          if run_start is not None:
                              longest = max(longest, now - run_start)
                              run_start = None
                      elif run_start is None:
                          run_start = now
                      took, last = converge(list(CTRL.values()), timeout=1)
                      if took is not None:
                          converged_after = round(now)
                          break
                      time.sleep(2)
                  finish_switch(node3, VOTERS_CLOSURE["node3"])
                  detail = (f"three voters, autopilot healthy, FailureTolerance 1 after {converged_after}s"
                            f" (last seen {last}); leaders seen {sorted(seen)}; longest leaderless window {round(longest, 1)}s")
                  print(f"order-a-first-voter-first: {detail}")
                  control("order-a-first-voter-first",
                          converged_after is not None and seen == {f"{NODE1}:4647"} and longest <= 20,
                          detail)
              promotion_gap_subtest()
          else:
              with subtest("order-b-new-voters-first: node2 installed and node3 switched while node1 expects 1"):
                  t0 = bring_new_voters()
                  took, last = converge(list(CTRL.values()))
                  finish_switch(node3, VOTERS_CLOSURE["node3"])
                  expect1 = node1.succeed("jq -r .server.bootstrap_expect /etc/nomad.json").strip()
                  lead = leader(list(CTRL.values()))
                  conflicting = {n.name: n.succeed("journalctl -u nomad --no-pager | grep -c 'conflicting expect' || true").strip()
                                 for n in (node2, node3)}
                  detail = (f"three voters, autopilot healthy, FailureTolerance 1 after {took}s (last seen {last});"
                            f" node1 still expects {expect1}; leader {lead}; 'conflicting expect' lines {conflicting}")
                  print(f"order-b-new-voters-first: {detail}")
                  control("order-b-new-voters-first", took is not None and expect1 == "1" and lead == f"{NODE1}:4647", detail)
              promotion_gap_subtest()
              first_voter_subtest(list(CTRL.values()))

          # ── after the growth: the mesh first, because everything on it depends on it ─
          with subtest("mesh-peers-applied: the switch put node2 on node1's mesh, and node2 reaches its services"):
              others = {n.name: sorted(PUB[o.name] for o in NODES if o is not n) for n in NODES}
              def mesh_state():
                  for n in NODES:
                      for o in NODES:
                          if o is not n:
                              n.execute(f"ping -c1 -W2 {MESH[o.name]}")
                  peers = {n.name: mesh_peers(n) for n in NODES}
                  shakes = {n.name: [int(l.split()[1]) for l in n.succeed(f"{WG} show {MESH_IF} latest-handshakes").splitlines()]
                            for n in NODES}
                  reach = {
                      "node2->node1 loki": node2.execute(f"curl -fsS --max-time 5 http://{M1}:3100/ready")[0] == 0,
                      "node2->node1 postgres": node2.execute(f"nc -z -w 5 {M1} 5432")[0] == 0,
                      "node2->node3 exporter": node2.execute(f"curl -fsS --max-time 5 -o /dev/null http://{MESH['node3']}:9100/metrics")[0] == 0,
                      "node1->node2 exporter": node1.execute(f"curl -fsS --max-time 5 -o /dev/null http://{MESH['node2']}:9100/metrics")[0] == 0,
                  }
                  ok = (peers == others and all(len(v) == 2 and all(t > 0 for t in v) for v in shakes.values())
                        and all(reach.values()))
                  return ok, peers, shakes, reach
              t0 = time.monotonic()
              ok, peers, shakes, reach = mesh_state()
              while not ok and time.monotonic() - t0 < 240:
                  time.sleep(5)
                  ok, peers, shakes, reach = mesh_state()
              listed = PUB["node2"] in node1.succeed(f"cat {NETDEV}")
              detail = (f"node1's netdev lists node2 now={listed}; peers by node {peers} (want {others});"
                        f" handshakes {shakes}; reach {reach}")
              print(f"mesh-peers-applied: {detail}")
              control("mesh-peers-applied", ok and listed, detail)

          with subtest("two-more-voters-converge: three voters, FailureTolerance 1"):
              took, last = converge(list(CTRL.values()), timeout=300)
              members = [m for m in api_any("/v1/agent/members")["Members"] if m["Status"] == "alive"]
              def all_ready(_):
                  return {x["Name"]: x["Status"] for x in api_any("/v1/nodes")} == {n.name: "ready" for n in NODES}
              retry(all_ready, timeout_seconds=300)
              servers = raft_servers()
              detail = (f"voters/healthy/tolerance {last} (after {took}s more); raft {[(s['Node'], s['Voter'], s['Leader']) for s in servers]};"
                        f" serf alive {sorted(m['Name'] for m in members)}")
              print(f"two-more-voters-converge: {detail}")
              control("two-more-voters-converge",
                      took is not None and len(members) == 3 and sum(1 for s in servers if s["Leader"]) == 1,
                      detail)

          with subtest("worker-promoted-to-voter: node3 keeps its node, allocation, task and data"):
              cn = cn_of(node3)
              reissued = fingerprint(node3) != seed["node3_cert"]
              gossip = node3.execute(f"grep -q 'encrypt' {GOSSIP}")[0] == 0
              ids = node_ids()
              voter3 = [s for s in raft_servers() if s["Node"] == "node3.global"]
              same, state = unchanged("after node3's promotion")
              data = node3.succeed("cat /var/lib/ci-worker/marker").strip()
              jfs = node2.succeed("cat /mnt/jfs/ci-worker").strip()
              node3_status = {x["Name"]: (x["Status"], x["SchedulingEligibility"]) for x in api_any("/v1/nodes")}["node3"]
              detail = (f"certificate {cn}, reissued={reissued}; gossip key present={gossip};"
                        f" raft entry {voter3}; Nomad node ID {ids.get('node3')} (was {seed['ids'].get('node3')}), status {node3_status};"
                        f" local data {data!r}; its JuiceFS file read on node2 {jfs!r}; {state}")
              print(f"worker-promoted-to-voter: {detail}")
              control("worker-promoted-to-voter",
                      SERVER_CN in cn and reissued and gossip and len(voter3) == 1 and voter3[0]["Voter"]
                      and ids.get("node3") == seed["ids"]["node3"] and node3_status == ("ready", "eligible")
                      and same and data == "worker-data" and jfs == "from-the-worker",
                      detail)

          with subtest("state-replicated: the job, the variable and the token are in each new voter's own state"):
              got: dict = {}
              for name in ("node2", "node3"):
                  ip = [CTRL[name]]
                  # stale=true: the agent answers from its own raft state, not the leader's.
                  j = api_any(f"/v1/job/ci-sleep?namespace={NS}&stale=true", ip)
                  v = api_any(f"/v1/var/ci/growth?namespace={NS}&stale=true", ip)
                  t = api_any(f"/v1/acl/token/{seed['token']}?stale=true", ip)
                  got[name] = (j.get("ID"), j.get("Version"), v.get("Items"), t.get("Name"), t.get("Policies"))
              want = ("ci-sleep", seed["job_version"], {"seed": "before-growth"}, "ci-growth", ["avc"])
              detail = f"read from each server's own state: {got}; want {want} on both"
              print(f"state-replicated: {detail}")
              control("state-replicated", all(g == want for g in got.values()), detail)

          with subtest("etcd-forms-with-three: created by the commit that tags three nodes, on the mesh"):
              for n in NODES:
                  n.wait_until_succeeds("systemctl is-active --quiet etcd.service", timeout=420)
              eps = ",".join(f"http://{MESH[n.name]}:2379" for n in NODES)
              healthy = node1.execute(f"etcdctl --endpoints={eps} endpoint health")[0] == 0
              members = json.loads(node1.succeed(f"etcdctl --endpoints=http://{M1}:2379 member list -w json"))["members"]
              names = sorted(m.get("name", "") for m in members)
              peer_urls = sorted(u for m in members for u in m.get("peerURLs", []))
              node1.succeed(f"etcdctl --endpoints=http://{M1}:2379 put ci-growth three")
              read = {n.name: n.succeed(f"etcdctl --endpoints=http://{MESH[n.name]}:2379 get ci-growth --print-value-only").strip()
                      for n in (node2, node3)}
              want_urls = sorted(f"http://{MESH[n.name]}:2380" for n in NODES)
              detail = f"health of all three={healthy}; members {names}, peer URLs {peer_urls}; read back {read}"
              print(f"etcd-forms-with-three: {detail}")
              control("etcd-forms-with-three",
                      healthy and names == ["node1", "node2", "node3"] and peer_urls == want_urls
                      and all(v == "three" for v in read.values()),
                      detail)

          with subtest("no failed units"):
              for n in NODES:
                  no_failed_units(n)

          # Last: it breaks the cluster on purpose.
          with subtest("trap-two-expect-1-diverge: node2 reinstalled with expect = 1 makes a second cluster"):
              ip2 = CTRL["node2"]
              survivors = [NODE1, CTRL["node3"]]
              old = [s for s in raft_servers() if s["Node"] == "node2.global"]
              assert len(old) == 1, raft_servers()
              node2.succeed("systemctl stop nomad.service")
              # node2 may have been the leader (order B): the survivors elect one first.
              retry(lambda _: leader(survivors) not in ("", f"{ip2}:4647"), timeout_seconds=60)
              # The dead node taken out of the cluster first, as an operator (or autopilot's
              # dead-server cleanup) does before a reinstall. Without this the leader keeps
              # replicating to the address and absorbs the fresh server before it can elect
              # itself (seen in run 2 of this test; see the implementation log).
              #
              # And taken out for good, which a reinstall minutes later gets for free and a
              # test a second later does not. Twice in order B the fresh agent, started at
              # once, did not stay alone: it ended up leading node1 and node3, which cleared
              # their raft logs to follow it (the original token refused everywhere). Two ways:
              #   serf  force-leave acts only on a member serf already holds as failed. Sent
              #         while the survivors still saw node2 alive, it did nothing; they then
              #         marked it failed, and serf's reconnect (every 30 s, for 24 h) rejoined
              #         the fresh agent at the same name, address and gossip key. Each leader
              #         saw the others' servers and added them; the fresh one won the term.
              #   raft  the leader makes one last replication to a peer it removes (to tell it
              #         it is out), after the replication goroutine's failure backoff, up to
              #         about 10 s. It reached the fresh agent 2 s after the removal, which
              #         took the old cluster's log and configuration from it.
              # So: node2 no longer alive in both survivors' serf before the force-leave, left
              # after it, and no raft traffic towards it from either survivor for 15 s before
              # the fresh agent starts. The outcome the control asks for is unchanged.
              #
              # Autopilot's dead-server cleanup (on by default) may get there first: about
              # 0.3 s after serf marks node2 failed, the leader removes its raft peer and
              # force-leaves it itself. So "failed" can be gone before a poll sees it, and
              # the peer may already be out of raft when the test would remove it.
              def serf_status(ip):
                  return {m["Name"]: m["Status"] for m in api_any("/v1/agent/members", [ip])["Members"]}.get("node2.global")
              retry(lambda _: all(serf_status(ip) in ("failed", "left") for ip in survivors), timeout_seconds=180)
              if old[0]["ID"] in [s["ID"] for s in raft_servers(survivors)]:
                  code, body = as_token(node1, NODE1, NOMAD_TOKEN, f"/v1/operator/raft/peer?id={old[0]['ID']}", "DELETE")
                  # 200, or autopilot removed it in between.
                  assert code == 200 or old[0]["ID"] not in [s["ID"] for s in raft_servers(survivors)], body
              else:
                  print("trap: autopilot had already removed node2's raft peer")
              code, body = as_token(node1, NODE1, NOMAD_TOKEN, "/v1/agent/force-leave?node=node2.global", "PUT")
              assert code == 200, body
              retry(lambda _: "node2.global" not in [s["Node"] for s in raft_servers(survivors)], timeout_seconds=60)
              retry(lambda _: all(serf_status(ip) == "left" for ip in survivors), timeout_seconds=60)
              removed_at = time.monotonic()
              def raft_quiet(_):
                  if time.monotonic() - removed_at < 15:
                      return False
                  return all(n.succeed(f"journalctl -u nomad.service --since=-15s -o cat --no-pager"
                                       f" | grep 'nomad.raft' | grep -c '{ip2}:4647' || true").strip() == "0"
                             for n in (node1, node3))
              retry(raft_quiet, timeout_seconds=120)
              # The real agent configuration, with what a reinstall from a topology in which
              # node2 is the single voter differs in: no raft state, expect = 1, and itself as
              # the only server to join.
              node2.succeed(
                  "mkdir -p /var/lib/ci-fresh-nomad && jq '.data_dir = \"/var/lib/ci-fresh-nomad\""
                  " | .server.bootstrap_expect = 1"
                  f" | .server.server_join.retry_join = [\"{ip2}\"] | .client.server_join.retry_join = [\"{ip2}\"]'"
                  " /etc/nomad.json > /tmp/ci-expect1.json"
              )
              nomad_bin = node2.succeed("readlink -f $(command -v nomad)").strip()
              node2.succeed(f"systemd-run --unit=ci-fresh-nomad --collect --setenv=PATH=/run/current-system/sw/bin"
                            f" {nomad_bin} agent -config=/tmp/ci-expect1.json -config={GOSSIP}")
              def own_leader(_):
                  return leader([ip2]) == f"{ip2}:4647"
              retry(own_leader, timeout_seconds=120)
              def second_bootstrap(_):
                  out = node2.succeed(
                      f"curl -sS {TLSCURL} -o /tmp/ci-boot.json -w '%{{http_code}}' -X POST {nomad_url(ip2, '/v1/acl/bootstrap')} || true"
                  ).strip()
                  return out == "200"
              retry(second_bootstrap, timeout_seconds=60)
              second = json.loads(node2.succeed("cat /tmp/ci-boot.json"))["SecretID"]
              on_fresh = as_token(node2, ip2, second, "/v1/acl/token/self")
              on_cluster = as_token(node1, NODE1, second, "/v1/acl/token/self")
              original_on_fresh = as_token(node2, ip2, NOMAD_TOKEN, "/v1/acl/token/self")
              original_on_cluster = as_token(node1, NODE1, NOMAD_TOKEN, "/v1/acl/token/self")
              fresh_raft = [s["Node"] for s in json.loads(as_token(node2, ip2, second, "/v1/operator/raft/configuration")[1]).get("Servers", [])]
              cluster_leader = leader(survivors)
              typ = lambda r: (r[0], json.loads(r[1]).get("Type") if r[0] == 200 else r[1].strip()[:60])
              diverged = (on_fresh[0] == 200 and json.loads(on_fresh[1]).get("Type") == "management"
                          and on_cluster[0] != 200 and original_on_fresh[0] != 200 and original_on_cluster[0] == 200
                          and fresh_raft == ["node2.global"] and cluster_leader not in ("", f"{ip2}:4647"))
              detail = (f"node2 leads itself; a second acl bootstrap returned a token: on node2 {typ(on_fresh)}, on the cluster"
                        f" {typ(on_cluster)}; the original token on node2 {typ(original_on_fresh)}, on the cluster"
                        f" {typ(original_on_cluster)}; node2's raft {fresh_raft}; the cluster's leader {cluster_leader}")
              print(f"trap-two-expect-1-diverge: {detail}")
              control("trap-two-expect-1-diverge", diverged, detail)
              node2.succeed("systemctl stop ci-fresh-nomad.service || true")

          for f in FINDINGS:
              print(f"FINDING: {f}")

      run_main(main)
    '';
}
