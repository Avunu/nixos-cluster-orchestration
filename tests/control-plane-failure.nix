# VM test: what the control plane does when its own pieces fail, on two real nodes:
# node1 (every singleton: Nomad server, etcd, the JuiceFS metadata engine, metrics)
# and node2, an installed worker. Their real machine modules, as tests/cluster.nix
# boots them, over the fixture topology with node2 provisioned.
#
# Not attacks: behaviour, recorded. Most of it is about the control mesh
# (modules/mesh-control-core.nix), whose failure modes are quiet ones:
#
#   gossip-key-on-servers-only   the server has the gossip key, the worker has none,
#                                and the worker's agent is a client by certificate
#   wg-key-rotation-restarts-networkd
#                                the networkd unit carries the key's ciphertext hash,
#                                so a switch with a new key restarts it; and that is
#                                needed: `networkctl reload` does not apply a new
#                                private key, a restart does
#   one-sided-key-change-recovers
#                                node2's key rotated, node1 not yet switched: the mesh
#                                between them is down; once node1 lists the new key it
#                                comes back, with nothing done on node2
#   mesh-down-jfs-recovers       the mesh cut between the nodes: a write on node2 hangs
#                                (killed at 80s), the mount survives, and writes work
#                                again within 15s of the mesh returning
#   nomad-cert-expired-outage-and-recovery
#                                every agent certificate expired: every node `down`
#                                within about 90s; a good certificate again, and up to
#                                5 minutes to see whether allocations are re-placed.
#                                That last part answers an open question, so it is
#                                recorded, not asserted
#   management-absent-from-workers
#                                node2, a client-only worker: no management token in
#                                what it was given or in /var/lib/nomad, and no raft
#   control-vlan-late-nomad-waits
#                                node2 boots with its vRack trunk's link off for a
#                                minute: Nomad can't bind, waits instead of hitting the
#                                start limit, and is back with nothing done by hand
#                                once the link returns (mutant
#                                `nomad-start-limit-default`)
#   missing-wg-key-boots         node1 boots with no mesh key: no interface, the boot
#                                completes, the mesh services wait; with the key back
#                                (and nothing restarted by hand) node2's JuiceFS client
#                                works again: PostgreSQL listens on every address, so
#                                a mesh address that arrives late is still served
#
# Every job is held off the fixture's own apps (node pool `ci-hold`), as in
# tests/cluster-single.nix; the test places its own.
#
# Run: nix build .#checks.x86_64-linux.control-plane-failure -L   (needs KVM; ~7 GB RAM)
{
  pkgs,
  lib,
  mkClan,
  topology,
  harnessFor,
  mutant ? "",
  extraModule ? { },
}:
let
  testTopology = lib.recursiveUpdate topology {
    nodes.node2.provisioned = true;
  };
  clan = mkClan testTopology;
  harness = harnessFor testTopology;
  net = import ../lib/net.nix { inherit lib; };
  clusterLib = import ../lib { inherit lib; };
  nomadPki = import ../lib/nomad-pki.nix { inherit lib; };
  wg = harness.wg;
  pki = harness.pki;
  machines = clan.config.nixosConfigurations;
  cfg1 = machines.node1.config;
  cfg2 = machines.node2.config;

  keyPath = n: machines.${n}.config.clan.core.vars.generators.wg-ctrl.files.private.path;
  tlsPath = n: f: machines.${n}.config.clan.core.vars.generators.nomad-tls.files.${f}.path;

  # What a switch would do to node1's netdev once node2's rotated key is committed:
  # the real module's rendering of it, for node1, with that one key changed. The test
  # also checks that it differs from node1's running file in that key alone.
  oneSidedNetdev =
    (lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        ../modules/mesh-control-core.nix
        {
          _module.args = {
            topology = testTopology;
            node = testTopology.nodes.node1;
            nodeName = "node1";
            inherit clusterLib;
          };
          cluster.mesh = {
            inherit (cfg1.cluster.mesh) privateKeyFile;
            publicKeys = cfg1.cluster.mesh.publicKeys // {
              node2 = wg.rotated.public;
            };
          };
          # As on the node (modules/overlay-network.nix): the units are rendered only then.
          systemd.network.enable = true;
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "/dev/null";
            fsType = "ext4";
          };
          system.stateVersion = "25.11";
        }
      ];
    }).config.environment.etc."systemd/network/30-${net.meshIf}.netdev".source;

  # The restart trigger: node2's unit carries the hash of its key's ciphertext, and a
  # different ciphertext (a rotation) gives a different one, so the switch that brings
  # it restarts networkd.
  triggersWith =
    cipher:
    (machines.node2.extendModules {
      modules = [ { cluster.mesh.keyCiphertext = lib.mkForce cipher; } ];
    }).config.systemd.services.systemd-networkd.restartTriggers;
  trigger = {
    hash = builtins.hashFile "sha256" cfg2.cluster.mesh.keyCiphertext;
    ours = cfg2.systemd.services.systemd-networkd.restartTriggers;
    # Any other file stands in for the new ciphertext: what matters is its hash. A
    # source file, because hashing a build output here would be import-from-derivation.
    rotated = triggersWith ./lib/fixture-wg.nix;
  };

  # Every node's agent certificate, expired: issued by the fixture CA 2000 days in the
  # past, for one day. Same names as the real ones, so the only fault is the date.
  expired =
    pkgs.runCommand "expired-agent-certs"
      {
        nativeBuildInputs = [
          pkgs.openssl
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        ${nomadPki.functions}
        pki_ca_crt=${pki}/ca.crt
        pki_ca_key=${pki}/ca.key
        pki_days=1
        ${lib.concatStrings (
          lib.mapAttrsToList (
            name: nd:
            let
              isServer = net.hasTag "nomad-server" nd;
            in
            ''
              mkdir -p $out/${name}
              pki_out=$out/${name}
              # libfaketime for this one call: the certificate's dates, 2000 days back.
              export FAKETIME=-2000d LD_PRELOAD=${pkgs.libfaketime}/lib/libfaketime.so.1
              issue agent ${nomadPki.agentName isServer} ${
                lib.escapeShellArg (
                  nomadPki.agentSans {
                    inherit isServer;
                    inherit (nd) controlIp;
                  }
                )
              }
              unset FAKETIME LD_PRELOAD
              # Expired, by the clock the nodes use.
              ! openssl x509 -checkend 0 -noout -in $out/${name}/agent.crt
            ''
          ) (lib.filterAttrs (n: _: n == "node1" || n == "node2") testTopology.nodes)
        )}
      '';

  # node1 can be booted with its mesh key removed, by a marker file on its disk: the
  # fixture writer puts every secret back at each activation.
  noKeyModule =
    { lib, ... }:
    {
      system.activationScripts.ci-no-wg-key = lib.stringAfter [ "setupSecrets" ] ''
        if [ -e /var/lib/ci-no-wg-key ]; then rm -f ${keyPath "node1"}; fi
      '';
    };
in
pkgs.testers.runNixOSTest {
  name = "control-plane-failure";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machines.node1._module.specialArgs [ "modulesPath" ];

  nodes = {
    wan = harness.wanNode;
    node1 = {
      imports = [
        clan.config.nixosModules."clan-machine-node1"
        (harness.nodeModule { memoryMB = 3584; })
        noKeyModule
        extraModule
      ];
      services.nomad.settings.client.node_pool = "ci-hold";
    };
    node2 = {
      imports = [
        clan.config.nixosModules."clan-machine-node2"
        (harness.nodeModule { memoryMB = 2048; })
        extraModule
      ];
      services.nomad.settings.client.node_pool = "ci-hold";
    };
  };

  testScript = ''
    import time

    ${harness.pythonHelpers}

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    CTRL = {"node1": "${testTopology.nodes.node1.controlIp}", "node2": "${testTopology.nodes.node2.controlIp}"}
    NODE1 = CTRL["node1"]
    M1 = MESH["node1"]
    M2 = MESH["node2"]
    WG = "${pkgs.wireguard-tools}/bin/wg"
    PUB = {"node1": "${wg.node1.public}", "node2": "${wg.node2.public}", "rotated": "${wg.rotated.public}"}
    KEY_PATH = {"node1": "${keyPath "node1"}", "node2": "${keyPath "node2"}"}
    KEY = {"node1": "${wg.node1.private}", "node2": "${wg.node2.private}", "rotated": "${wg.rotated.private}"}
    NETDEV = "/etc/systemd/network/30-${net.meshIf}.netdev"
    ONE_SIDED_NETDEV = "${oneSidedNetdev}"
    TRIGGER = json.loads(r"""${builtins.toJSON trigger}""")
    EXPIRED = "${expired}"
    PKI = "${pki}"
    TLS = {n: {"crt": p, "key": k} for n, p, k in [
        ("node1", "${tlsPath "node1" "agent.crt"}", "${tlsPath "node1" "agent.key"}"),
        ("node2", "${tlsPath "node2" "agent.crt"}", "${tlsPath "node2" "agent.key"}"),
    ]}
    GOSSIP = "${cfg1.clan.core.vars.generators.nomad-gossip.files."gossip.hcl".path}"
    NODES = [node1, node2]
    VRACK2 = "${testTopology.nodes.node2.vrackInterface}"
    CTRL_VLAN = ${toString testTopology.vlans.control.id}

    def mesh_up(a, b, timeout=90):
        a.wait_until_succeeds(f"ping -c1 -W2 {MESH[b.name]}", timeout=timeout)
        b.wait_until_succeeds(f"ping -c1 -W2 {MESH[a.name]}", timeout=timeout)

    def mesh_pings(a, b):
        return a.execute(f"ping -c2 -W2 {MESH[b.name]}")[0] == 0

    def jfs_write(n, name, seconds=10):
        return n.execute(f"timeout {seconds} sh -c 'echo {name} > /mnt/jfs/{name} && sync'")[0] == 0

    def set_key(n, which):
        n.succeed(f"printf %s '{KEY[which]}' > {KEY_PATH[n.name]}.new"
                  f" && chown systemd-network {KEY_PATH[n.name]}.new && chmod 0400 {KEY_PATH[n.name]}.new"
                  f" && mv {KEY_PATH[n.name]}.new {KEY_PATH[n.name]}")

    def pub_of(n):
        return n.succeed(f"{WG} show {MESH_IF} public-key").strip()

    # Nomad's API from the outside, during a certificate outage: the server's own
    # certificate is expired then, so this observer does not verify it (-k). It still
    # presents the CLI certificate, which is valid.
    def nomad_k(path):
        return json.loads(node1.succeed(
            f"curl -fsS -k --cert \"$NOMAD_CLIENT_CERT\" --key \"$NOMAD_CLIENT_KEY\""
            f" -H 'X-Nomad-Token: {NOMAD_TOKEN}' https://{NODE1}:4646{path}"
        ))

    def node_status():
        return {x["Name"]: x["Status"] for x in nomad_k("/v1/nodes")}

    # `systemctl reload nomad` returns once the HUP is sent. When the certificate files
    # changed, Nomad then closes its HTTPS listener and opens a new one ("agent:
    # reloading HTTP server with new TLS configuration"), and a request in between is
    # refused (curl exit 7). So after such a reload, wait, bounded, until node1's
    # listeners on 4646 are new sockets (none of the inodes from before the reload) and
    # answer TLS with the CLI certificate. Any HTTP status counts as answering here: the
    # statuses are node_status()'s business. A listener that never comes back, or a
    # reload that never reopens it, fails the wait loudly; neither is taken as the outage.
    def http_listeners():
        import re
        return set(re.findall(r"ino:(\d+)", node1.succeed("ss -Htlne 'sport = :4646'")))

    def await_http_reload(old, timeout_seconds=60):
        assert old, "node1 had no listener on 4646 before the reload"
        def back(_):
            now = http_listeners()
            if not now or now & old:
                return False
            return node1.execute(
                f"curl -sS -k -o /dev/null --cert \"$NOMAD_CLIENT_CERT\" --key \"$NOMAD_CLIENT_KEY\""
                f" https://{NODE1}:4646/v1/agent/health"
            )[0] == 0
        retry(back, timeout_seconds=timeout_seconds)

    def main():
        wan.start()
        wan.wait_for_unit("s3.service")
        for n in NODES:
            n.start()

        with subtest("both nodes up: Nomad, the mesh, JuiceFS through node1's metadata engine"):
            node1.wait_for_unit("nomad-bootstrap.service", timeout=600)
            for n in NODES:
                n.wait_for_unit(f"{MESH_IF}-ready.service")
                n.wait_for_unit("jfs-health.service", timeout=600)
            mesh_up(node1, node2)
            def both_ready(_):
                st = node_status()
                return st.get("node1") == "ready" and st.get("node2") == "ready"
            retry(both_ready, timeout_seconds=300)
            assert jfs_write(node2, "ci-baseline"), "node2 cannot write to /mnt/jfs"

        with subtest("gossip-key-on-servers-only: the server holds the key, the worker holds none"):
            server_has = node1.execute(f"grep -q 'encrypt' {GOSSIP}")[0] == 0
            worker_has = node2.execute("ls /run/secrets/shared/nomad-gossip 2>/dev/null; test -e /run/secrets/shared/nomad-gossip")[0] == 0
            found = node2.succeed("grep -rl 'encrypt *=' /run/secrets /etc/nomad* 2>/dev/null || true").split()
            # And the worker's agent is a client by its certificate: it can't be a server.
            cn = node2.succeed(f"${pkgs.openssl}/bin/openssl x509 -noout -subject -in {TLS['node2']['crt']}").strip()
            members = [m["Name"] for m in nomad_api(node1, NODE1, "/v1/agent/members")["Members"]]
            detail = (f"node1 has the key={server_has}; node2 has nomad-gossip={worker_has}, files with a key={found},"
                      f" its agent certificate {cn}; servers in serf {members}")
            print(f"gossip-key-on-servers-only: {detail}")
            control("gossip-key-on-servers-only",
                    server_has and not worker_has and found == [] and "client.global.nomad" in cn
                    and members == ["node1.global"],
                    detail)

        with subtest("management-absent-from-workers: a client-only worker holds no management token anywhere"):
            # node2 is no voter, so unlike checks.cluster's voters it has no raft state:
            # its whole Nomad data directory is searched too, with what was deployed.
            n = node2
            present = n.execute("test -e /run/secrets/shared/nomad-acl")[0] == 0
            readers = units_reading(n, "nomad-acl/token")
            held = sorted(n.succeed(f"ls {TOKENS}").split())
            no_raft = n.execute("test -e /var/lib/nomad/server/raft/raft.db")[0] != 0
            found = n.succeed(
                f"grep -rhoaE '{UUID_RE}' /run/secrets /run/nomad-tokens /etc/secret-vars /var/lib/nomad 2>/dev/null | sort -u || true"
            ).split()
            kinds: dict = {}
            for t in found:
                code, body = as_token(n, CTRL[n.name], t, "/v1/acl/token/self")
                kinds[t[:8]] = json.loads(body)["Type"] if code == 200 else code
            detail = (f"nomad-acl deployed={present} readers={readers} tokens={held} no raft.db={no_raft};"
                      f" {len(found)} UUIDs tried: {kinds}")
            print(f"management-absent-from-workers: {detail}")
            control("management-absent-from-workers",
                    not present and readers == [] and no_raft
                    and held and not set(held) & {"registrar", "autoscaler"}
                    and "client" in kinds.values() and "management" not in kinds.values(),
                    detail)

        with subtest("wg-key-rotation-restarts-networkd: a new private key needs a restart, and the switch gives it one"):
            # An upstream unit: NixOS's settings, the triggers among them, are in its
            # drop-in, which names a store file holding them. The hash is in there.
            unit = node2.succeed(
                "u=/etc/systemd/system/systemd-networkd.service; cat $u $u.d/*.conf;"
                " for f in $(cat $u $u.d/*.conf | sed -n 's/^X-Restart-Triggers=//p'); do cat \"$f\"; done"
            )
            in_unit = TRIGGER["hash"] in unit
            differs = TRIGGER["ours"] != TRIGGER["rotated"] and TRIGGER["hash"] in TRIGGER["ours"]
            before = pub_of(node2)
            set_key(node2, "rotated")
            node2.succeed("networkctl reload")
            time.sleep(3)
            after_reload = pub_of(node2)
            node2.succeed("systemctl restart systemd-networkd")
            node2.wait_until_succeeds(f"{WG} show {MESH_IF} public-key | grep -qxF '{PUB['rotated']}'", timeout=60)
            after_restart = pub_of(node2)
            # Back to the key node1 lists.
            set_key(node2, "node2")
            node2.succeed("systemctl restart systemd-networkd")
            node2.wait_until_succeeds(f"{WG} show {MESH_IF} public-key | grep -qxF '{PUB['node2']}'", timeout=60)
            mesh_up(node1, node2)
            detail = (f"unit carries the ciphertext hash={in_unit}; a different ciphertext changes the triggers={differs};"
                      f" public key: before {before}, after reload {after_reload}, after restart {after_restart}")
            print(f"wg-key-rotation-restarts-networkd: {detail}")
            control("wg-key-rotation-restarts-networkd",
                    in_unit and differs and before == PUB["node2"] and after_reload == PUB["node2"]
                    and after_restart == PUB["rotated"],
                    detail)

        with subtest("one-sided-key-change-recovers: node2 rotated first, node1 catches up"):
            set_key(node2, "rotated")
            node2.succeed("systemctl restart systemd-networkd")
            node2.wait_until_succeeds(f"{WG} show {MESH_IF} public-key | grep -qxF '{PUB['rotated']}'", timeout=60)
            # node1 still lists node2's old key: nothing gets through, either way.
            time.sleep(10)
            down = not mesh_pings(node2, node1) and not mesh_pings(node1, node2)
            # node1 "switches": its netdev as the module renders it with node2's new key,
            # and what switch-to-configuration does for a changed netdev, a restart.
            diff = node1.execute(f"diff {NETDEV} {ONE_SIDED_NETDEV}")[1]
            changed = [l for l in diff.splitlines() if l.startswith(("<", ">"))]
            only_the_key = changed == [f"< PublicKey={PUB['node2']}", f"> PublicKey={PUB['rotated']}"]
            node2_invocation = node2.succeed("systemctl show -p InvocationID --value systemd-networkd").strip()
            node1.succeed(f"ln -sfn {ONE_SIDED_NETDEV} {NETDEV} && systemctl restart systemd-networkd")
            start = time.monotonic()
            back = False
            while time.monotonic() - start < 90:
                if mesh_pings(node2, node1) and mesh_pings(node1, node2):
                    back = True
                    break
                time.sleep(2)
            took = round(time.monotonic() - start)
            wrote = back and jfs_write(node2, "ci-one-sided", 60)
            untouched = node2.succeed("systemctl show -p InvocationID --value systemd-networkd").strip() == node2_invocation
            # Put both back as they were.
            node1.succeed(f"ln -sfn $(readlink -f /etc/static/systemd/network/30-{MESH_IF}.netdev) {NETDEV}"
                          " && systemctl restart systemd-networkd")
            set_key(node2, "node2")
            node2.succeed("systemctl restart systemd-networkd")
            mesh_up(node1, node2)
            detail = (f"down while one-sided={down}; the new netdev differs only in node2's key={only_the_key} {changed};"
                      f" mesh back {back} after {took}s; node2 wrote to /mnt/jfs={wrote}; node2's networkd not touched={untouched}")
            print(f"one-sided-key-change-recovers: {detail}")
            control("one-sided-key-change-recovers", down and only_the_key and back and wrote and untouched, detail)

        with subtest("mesh-down-jfs-recovers: a write hangs while the mesh is down, and the mount comes back"):
            assert jfs_write(node2, "ci-before-cut", 30)
            node2.succeed(
                "nft -f - <<'EOF'\n"
                "table inet ci-meshdown {\n"
                f"  chain o {{ type filter hook output priority -10; ip daddr {NODE1} udp dport 51820 drop; }}\n"
                f"  chain i {{ type filter hook input priority -10; ip saddr {NODE1} udp sport 51820 drop; }}\n"
                "}\n"
                "EOF"
            )
            node2.succeed(
                "systemd-run --unit=ci-hung-write --setenv=PATH=/run/current-system/sw/bin sh -c"
                " 'timeout 80 dd if=/dev/urandom of=/mnt/jfs/ci-hung bs=1M count=4 conv=fsync status=none;"
                " echo $? > /tmp/hung-rc'"
            )
            node2.wait_until_succeeds("test -s /tmp/hung-rc", timeout=120)
            rc = node2.succeed("cat /tmp/hung-rc").strip()
            mounted = node2.execute("mountpoint -q /mnt/jfs")[0] == 0
            alive = node2.execute("systemctl is-active --quiet juicefs-mount.service")[0] == 0
            node2.succeed("nft delete table inet ci-meshdown")
            start = time.monotonic()
            recovered = None
            while time.monotonic() - start < 120:
                if jfs_write(node2, "ci-after-cut", 5):
                    recovered = round(time.monotonic() - start, 1)
                    break
                time.sleep(1)
            seen = node1.execute("grep -qx ci-after-cut /mnt/jfs/ci-after-cut")[0] == 0
            detail = (f"write during the cut: rc={rc} (124 = killed by timeout at 80s); mount survived={mounted},"
                      f" juicefs-mount active={alive}; writes again after {recovered}s; node1 reads it={seen}")
            print(f"mesh-down-jfs-recovers: {detail}")
            control("mesh-down-jfs-recovers",
                    rc == "124" and mounted and alive and recovered is not None and recovered <= 15 and seen,
                    detail)

        with subtest("nomad-cert-expired-outage-and-recovery: every agent certificate expires at once"):
            job = json.dumps({"Job": {
                "ID": "ci-sleep", "Name": "ci-sleep", "Namespace": NS, "Type": "service",
                "Datacenters": ["${testTopology.datacenter}"], "NodePool": "ci-hold",
                "TaskGroups": [{"Name": "g", "Count": 2,
                                "Constraints": [{"Operand": "distinct_hosts", "RTarget": "true"}],
                                "Tasks": [{"Name": "t", "Driver": "raw_exec", "User": "${clusterLib.nomad.appsUser}",
                                           "Config": {"command": "/run/current-system/sw/bin/sleep", "args": ["1000000"]}}]}],
            }})
            code, body = as_token(node1, NODE1, NOMAD_TOKEN, "/v1/jobs", "POST", job)
            assert code == 200, body
            def placed(_):
                al = [a for a in nomad_api(node1, NODE1, f"/v1/job/ci-sleep/allocations?namespace={NS}") if a["ClientStatus"] == "running"]
                return len(al) == 2
            retry(placed, timeout_seconds=180)
            before = sorted((a["ID"], a["NodeName"]) for a in nomad_api(node1, NODE1, f"/v1/job/ci-sleep/allocations?namespace={NS}")
                            if a["ClientStatus"] == "running")
            listening = http_listeners()
            for n in NODES:
                n.succeed(f"install -m 0400 -o root {EXPIRED}/{n.name}/agent.crt {TLS[n.name]['crt']}"
                          f" && install -m 0400 -o root {EXPIRED}/{n.name}/agent.key {TLS[n.name]['key']}"
                          " && systemctl reload nomad")
            start = time.monotonic()
            await_http_reload(listening)
            down_after = None
            seen: list = []
            while time.monotonic() - start < 240:
                st = node_status()
                seen.append((round(time.monotonic() - start), st))
                if all(v == "down" for v in st.values()):
                    down_after = round(time.monotonic() - start)
                    break
                time.sleep(5)
            handshake_errors = node2.execute("journalctl -u nomad --no-pager --since=-5min | grep -ciE 'x509|certificate has expired|tls' || true")[1].strip()
            # A good certificate again: the fixture's own.
            listening = http_listeners()
            for n in NODES:
                n.succeed(f"install -m 0400 -o root {PKI}/{n.name}/agent.crt {TLS[n.name]['crt']}"
                          f" && install -m 0400 -o root {PKI}/{n.name}/agent.key {TLS[n.name]['key']}"
                          " && systemctl reload nomad")
            start = time.monotonic()
            await_http_reload(listening)
            ready_after = None
            allocs_seen: list = []
            while time.monotonic() - start < 300:
                try:
                    st = node_status()
                except Exception:
                    st = {}
                if ready_after is None and st and all(v == "ready" for v in st.values()):
                    ready_after = round(time.monotonic() - start)
                try:
                    al = nomad_api(node1, NODE1, f"/v1/job/ci-sleep/allocations?namespace={NS}")
                    allocs_seen = sorted((a["ID"][:8], a["NodeName"], a["ClientStatus"]) for a in al)
                except Exception:
                    pass
                time.sleep(10)
            running = [a for a in allocs_seen if a[2] == "running"]
            replaced = sorted(a[0] for a in running) != sorted(i[:8] for i, _ in before)
            finding = (f"FINDING: after the good certificate, {len(running)} of 2 allocations running;"
                       f" {'new allocations (re-placed)' if replaced else 'the original allocations'};"
                       f" all allocations seen: {allocs_seen}; originally {before}")
            print(f"nomad-cert-expired-outage-and-recovery: {finding}")
            detail = (f"all nodes down after {down_after}s (statuses seen: {seen[-3:]}); TLS errors logged on node2: {handshake_errors};"
                      f" ready again after {ready_after}s; {finding}")
            print(f"nomad-cert-expired-outage-and-recovery: {detail}")
            as_token(node1, NODE1, NOMAD_TOKEN, f"/v1/job/ci-sleep?namespace={NS}&purge=true", "DELETE")
            control("nomad-cert-expired-outage", down_after is not None and down_after <= 180, detail)
            control("nomad-cert-expired-recovery", ready_after is not None, detail)

        with subtest("missing-wg-key-boots: node1 boots without its mesh key, and recovers once it is back"):
            node1.succeed("touch /var/lib/ci-no-wg-key")
            node1.shutdown()
            node1.start()
            node1.wait_for_unit("multi-user.target", timeout=600)
            key_absent = node1.execute(f"test -e {KEY_PATH['node1']}")[0] != 0
            no_if = node1.execute(f"ip link show {MESH_IF}")[0] != 0
            node1.wait_until_succeeds(f"systemctl show -p ActiveState --value {MESH_IF}-ready | grep -qx active", timeout=120)
            ready_said = node1.execute(f"journalctl -b -u {MESH_IF}-ready --no-pager | grep -q 'no mesh address after 30s'")[0] == 0
            pg_up = node1.execute("systemctl is-active --quiet postgresql.service")[0] == 0
            pg_pid = node1.succeed("systemctl show -p MainPID --value postgresql.service").strip()
            pg_everywhere = node1.execute("ss -Htln 'sport = :5432' | grep -qE '(0\\.0\\.0\\.0|\\*):5432'")[0] == 0
            stuck = not jfs_write(node2, "ci-while-keyless", 10)
            # The repair: the key back where the vars put it, and the restart a switch with
            # a new ciphertext would do (wg-key-rotation-restarts-networkd). Nothing else.
            node1.succeed("rm -f /var/lib/ci-no-wg-key")
            set_key(node1, "node1")
            node1.succeed("systemctl restart systemd-networkd")
            node1.wait_until_succeeds(f"ip -4 -o addr show dev {MESH_IF} | grep -qF ' {M1}/'", timeout=60)
            start = time.monotonic()
            recovered = None
            while time.monotonic() - start < 300:
                if jfs_write(node2, "ci-after-key", 10):
                    recovered = round(time.monotonic() - start)
                    break
                time.sleep(3)
            same_pg = node1.succeed("systemctl show -p MainPID --value postgresql.service").strip() == pg_pid
            # The mesh-bound units on node1 came up by themselves too.
            units = ["etcd", "prometheus-node-exporter", "loki", "vector", "prometheus", "juicefs-mount"]
            def all_active(_):
                return all(node1.execute(f"systemctl is-active --quiet {u}.service")[0] == 0 for u in units)
            retry(all_active, timeout_seconds=300)
            states = {u: node1.succeed(f"systemctl show -p ActiveState --value {u}.service").strip() for u in units}
            detail = (f"booted without the key: key absent={key_absent}, no {MESH_IF}={no_if}, {MESH_IF}-ready exited and said so={ready_said};"
                      f" postgresql up={pg_up} on every address={pg_everywhere}; node2 could not write meanwhile={stuck};"
                      f" after the repair node2 wrote after {recovered}s, postgresql not restarted={same_pg}; node1's mesh units {states}")
            print(f"missing-wg-key-boots: {detail}")
            control("missing-wg-key-boots", key_absent and no_if and ready_said and pg_up and pg_everywhere and stuck, detail)
            control("missing-wg-key-boots-recovers", recovered is not None and same_pg, detail)

        with subtest("control-vlan-late-nomad-waits: node2 boots with its vRack trunk without carrier, and Nomad waits"):
            # Nomad binds the control VLAN address alone, which networkd configures only
            # once the trunk has carrier, and that can be seconds after network-online
            # (br-wan). The nixpkgs unit gave up after 3 starts in 10 s, leaving Nomad
            # failed until someone restarted it. Here the trunk has no carrier for over a
            # minute from power-on (QEMU's set_link), longer than control-vlan-ready waits,
            # so it is the unit's restart policy that carries Nomad through. Mutant
            # `nomad-start-limit-default` (flake.nix) puts the nixpkgs unit back.
            mac = node2.succeed(f"cat /sys/class/net/{VRACK2}/address").strip()
            info = node2.send_monitor_command("info network")
            devs = [l.split(":")[0].strip(" \\") for l in info.splitlines() if f"macaddr={mac}" in l]
            assert len(devs) == 1, f"no single QEMU NIC with {mac}: {info}"
            node2.shutdown()
            node2.start()
            node2.send_monitor_command(f"set_link {devs[0]} off")
            node2.wait_for_unit("multi-user.target", timeout=600)
            no_addr = node2.execute(f"ip -4 -o addr show dev {VRACK2}.{CTRL_VLAN} | grep -qF ' {CTRL['node2']}/'")[0] != 0
            # Past control-vlan-ready's 30 s, and past many of Nomad's starts.
            time.sleep(60)
            during = node2.succeed("systemctl show -p ActiveState -p SubState -p Result -p NRestarts nomad.service").split()
            st = dict(x.split("=", 1) for x in during)
            ready_said = node2.execute("journalctl -b -u control-vlan-ready --no-pager | grep -q 'after 30s'")[0] == 0
            bind_failed = node2.execute("journalctl -b -u nomad --no-pager | grep -q 'cannot assign requested address'")[0] == 0
            node2.send_monitor_command(f"set_link {devs[0]} on")
            t0 = time.monotonic()
            back = None
            while time.monotonic() - t0 < 240:
                if (node2.execute("systemctl is-active --quiet nomad.service")[0] == 0
                        and node_status().get("node2") == "ready"):
                    back = round(time.monotonic() - t0)
                    break
                time.sleep(3)
            # The rest of node2 had the same outage: no mesh (its endpoints are control
            # addresses), so no JuiceFS (jfs-health fails at 60 s) and no logins (the
            # fence fails loudly on no token). Both come back by themselves, jfs-health
            # through jfs-nomad-meta's retries and the fence at its next timer run; the
            # final "no failed units" holds them to that. Recorded here: how long.
            settled = None
            t1 = time.monotonic()
            while time.monotonic() - t1 < 300:
                if node2.succeed("systemctl list-units --failed --plain --no-legend | wc -l").strip() == "0":
                    settled = round(time.monotonic() - t0)
                    break
                time.sleep(5)
            left = node2.succeed("systemctl list-units --failed --plain --no-legend | awk '{print $1}'").split()
            # Whether the old unit's 3 starts in 10 s, 2 s apart, are reached depends on how
            # fast Nomad dies on the bind: under about 1.3 s an attempt, the 4th start comes
            # inside 10 s and is refused. In this VM an attempt takes seconds, so the old
            # unit survives here too [RAN, the mutant's first build: 12 restarts, never
            # failed]; on a fast host the agent exits "at once" [RAN, the review]. So what
            # makes the outcome independent of that speed is asserted as well: no start
            # limit, and the wait for the address.
            unit = dict(x.split("=", 1) for x in node2.succeed(
                "systemctl show -p StartLimitIntervalUSec -p RestartUSec -p After nomad.service").splitlines() if "=" in x)
            detail = (f"control address absent at boot={no_addr}; control-vlan-ready gave up and said so={ready_said};"
                      f" Nomad failed to bind={bind_failed}; Nomad 60s later {st}; after the link returned, active and"
                      f" ready in Nomad after {back}s (nothing restarted by hand); no failed unit on node2 after"
                      f" {settled}s (still failed: {left}); unit StartLimitIntervalUSec={unit.get('StartLimitIntervalUSec')}"
                      f" RestartUSec={unit.get('RestartUSec')} after control-vlan-ready="
                      f"{'control-vlan-ready.service' in unit.get("After", "")}")
            print(f"control-vlan-late-nomad-waits: {detail}")
            control("control-vlan-late-nomad-waits",
                    no_addr and ready_said and bind_failed
                    and st.get("ActiveState") != "failed" and st.get("Result") != "start-limit-hit"
                    and int(st.get("NRestarts", "0")) >= 1 and back is not None
                    and unit.get("StartLimitIntervalUSec") == "0"
                    and "control-vlan-ready.service" in unit.get("After", ""),
                    detail)

        with subtest("no failed units"):
            for n in NODES:
                # The write probe failed while node1 had no mesh: a passing run supersedes it.
                # It needs the JuiceFS mount itself now (it used to pass on the bare directory
                # an unmounted /mnt/jfs is), and node2's comes back on its own some time after
                # the trunk does: wait for that, then the probe must pass on it.
                print(f"{n.name} before the probe: " + n.execute(
                    "findmnt -n -o FSTYPE,SOURCE -M /mnt/jfs; systemctl is-active juicefs-mount.service jfs-health.service")[1].replace("\n", " "))
                n.wait_until_succeeds("mountpoint -q /mnt/jfs && systemctl is-active --quiet jfs-health.service", timeout=300)
                n.succeed("systemctl start jfs-probe.service")
                no_failed_units(n)

    run_main(main)
  '';
}
