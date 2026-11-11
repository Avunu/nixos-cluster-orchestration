# VM test: a single real node boots and its infrastructure comes up.
#
# The machine is nixosConfigurations.node1's own module (the fixture topology,
# real role assignment, the fixture app catalogue), plus only what
# tests/lib/cluster-harness.nix describes: fixture secrets, a VM's NICs under
# the topology's names, and a stand-in internet that answers for its object
# storage. It then walks the cold-start chain every reinstall depends on:
#
#   secrets -> networkd (br-wan, vRack VLANs, br-app) + nftables
#     -> etcd
#     -> PostgreSQL -> juicefs-pg-password -> juicefs-format (encrypted) -> juicefs-mount
#        -> jfs-health -> jfs-nomad-meta (jfs_ready=true)
#     -> Nomad leader (mTLS, gossip key) -> ACL bootstrap with OUR token
#        -> namespaces, policies, JWT auth method -> each role's scoped token
#        -> every app's job, registered as `registrar` into `apps`
#     -> Prometheus / Alertmanager / Loki (on the node's own disk) / Vector
#
# and does it twice: the second boot is the steady state (volume already
# formatted, ACLs already bootstrapped), which is a different code path in
# both and the one every reboot takes.
#
# What it does NOT do is run the apps. The client joins a node pool no job
# targets, so every job registers and evaluates but nothing is placed: the
# fixture catalogue is stubs of ERPNext and Odoo, and FreeIPA, which needs the
# internet and far more memory than a CI VM. Their containers are still BUILT
# (the toplevel is this machine's closure), and the container lifecycle under
# Nomad is exercised by tests/cluster.nix with probe apps.
#
# Run: nix build .#checks.x86_64-linux.cluster-single -L   (needs KVM)
{
  pkgs,
  lib,
  clan,
  harness,
}:
let
  machine = clan.config.nixosConfigurations.node1;
  inherit (machine._module.specialArgs) topology;
  node = topology.nodes.node1;
  apps = lib.attrNames machine.config.clusterApps;
  ctrl = node.controlIp;
  nomadPki = import ../lib/nomad-pki.nix { inherit lib; };
  meshMtu = (import ../lib/net.nix { inherit lib; }).meshMtu topology;
  # A login from the wan VM, for ssh-login-event: a key of the test's own on root, beside
  # the fixture admins' (whose private half nobody has).
  sshKeys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
in
pkgs.testers.runNixOSTest {
  name = "cluster-single";

  # The machine module sets nixpkgs.config (unfree Nomad) and overlays, so the
  # nodes build their own pkgs from it, as in production.
  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machine._module.specialArgs [ "modulesPath" ];

  nodes = {
    wan = harness.wanNode;

    node1 = {
      imports = [
        clan.config.nixosModules."clan-machine-node1"
        (harness.nodeModule { memoryMB = 4096; })
      ];

      # Register every job, place none (see the header).
      services.nomad.settings.client.node_pool = "ci-hold";

      users.users.root.openssh.authorizedKeys.keys = [ sshKeys.snakeOilEd25519PublicKey ];
    };
  };

  testScript = ''
    ${harness.pythonHelpers}

    APPS = ${builtins.toJSON apps}
    CTRL = "${ctrl}"
    # Everything but Nomad is on the control mesh.
    M1 = MESH["node1"]
    # node1 is the nomad-leader and metrics node, so it logs in as every role.
    ROLES = ${builtins.toJSON (nomadPki.loginRoles node)}
    POLICY = {"fence": "fence", "node-meta": "node-meta", "avc": "operator-read",
              "registrar": "registrar", "autoscaler": "autoscaler"}
    assert sorted(ROLES) == sorted(POLICY), f"node1 should hold every role: {ROLES}"

    wan.start()
    wan.wait_for_unit("s3.service")
    wan.wait_for_open_port(443)

    def converged():
        with subtest("boot reaches multi-user"):
            node1.wait_for_unit("multi-user.target")

        with subtest("secrets land where clan's age backend puts them"):
            node1.succeed("test \"$(stat -c %a:%U /run/secrets/shared/nomad-acl/token)\" = 400:root")
            node1.succeed("grep -qx ${harness.nomadToken} /run/secrets/shared/nomad-acl/token")
            # node1 is a server: its agent certificate names server.global.nomad, and
            # it has the gossip key. The certificate is per machine, the key shared.
            node1.succeed("test \"$(stat -c %a:%U /run/secrets/per-machine/node1/nomad-tls/agent.key)\" = 400:root")
            node1.succeed("${pkgs.openssl}/bin/openssl x509 -noout -subject -in /run/secrets/per-machine/node1/nomad-tls/agent.crt | grep -q 'CN *= *server.global.nomad'")
            node1.succeed("grep -q 'encrypt' /run/secrets/shared/nomad-gossip/gossip.hcl")

        with subtest("networkd: WAN bridge, vRack VLANs, container bridge"):
            node1.wait_for_unit("systemd-networkd-wait-online.service")
            node1.succeed("ip -br addr show br-wan | grep -q ${node.publicIp4}/32")
            node1.succeed("ip -d link show ${node.wanInterface} | grep -q 'master br-wan'")
            node1.succeed("ip -br addr show ${node.vrackInterface}.10 | grep -q ${ctrl}/24")
            node1.succeed("ip -br addr show ${node.vrackInterface}.30 | grep -q ${node.storageIp}/24")
            node1.succeed("ip -br addr show ${node.vrackInterface}.20 | grep -q 10.20.0.${toString node.index}/24")
            node1.succeed("ip -br addr show br-app | grep -q ${node.appBridgeIp}/24")
            node1.succeed("ip route show default | grep -q 'via ${node.publicGw4}'")
            node1.succeed("ping -c1 -W5 ${node.publicGw4}")

        with subtest("the control mesh: its address, its MTU, and the services on it"):
            node1.wait_for_unit(f"{MESH_IF}-ready.service")
            node1.succeed(f"ip -br addr show {MESH_IF} | grep -qF ' {M1}/24'")
            # The fixture's VLANs are 1500, so the mesh follows to 1420 (D25).
            node1.succeed(f"test \"$(cat /sys/class/net/{MESH_IF}/mtu)\" = ${toString meshMtu}")
            node1.succeed(f"${pkgs.wireguard-tools}/bin/wg show {MESH_IF} private-key | grep -qx '${harness.wg.node1.private}'")
            # The exporters listen on the mesh address alone: nothing on the control IP.
            for port in (9100, 9633, 9598, 3100, 9090, 2379, 2380):
                node1.wait_until_succeeds(f"ss -Htln 'sport = :{port}' | grep -qF '{M1}:{port}'", timeout=180)
                node1.fail(f"ss -Htln 'sport = :{port}' | grep -qF '{CTRL}:{port}'")

        with subtest("nftables is authoritative and drops by default"):
            node1.succeed("nft list chain inet filter input | grep -q 'policy drop'")
            # From the WAN, SSH answers; PostgreSQL listens on every address
            # (the JuiceFS metadata engine) but the WAN must not reach it.
            node1.wait_for_open_port(5432)
            wan.succeed("nc -z -w5 ${node.publicIp4} 22")
            wan.fail("nc -z -w5 ${node.publicIp4} 5432")

        with subtest("etcd: the shared DCS is healthy"):
            node1.wait_for_unit("etcd.service")
            node1.succeed(f"etcdctl --endpoints=http://{M1}:2379 endpoint health")

        with subtest("JuiceFS: metadata engine, format, mount, health"):
            for u in ["postgresql.service", "juicefs-pg-password.service",
                      "juicefs-format.service", "juicefs-mount.service", "jfs-health.service"]:
                node1.wait_for_unit(u)
            node1.wait_until_succeeds("mountpoint -q /mnt/jfs", timeout=120)
            node1.succeed("juicefs version >/dev/null")

        with subtest("JuiceFS: the fixture volume is encrypted, and the mount said so"):
            # Formatted with the key on the first boot, checked by the mount's gate on
            # both (tests/jfs-encrypted.nix is where a plaintext volume is refused).
            node1.succeed(
                "pgpass=$(cat /run/secrets/shared/juicefs-pg/password);"
                f" juicefs status \"postgres://juicefs:$pgpass@{M1}:5432/juicefs\" 2>/dev/null"
                " | jq -e '.Setting.EncryptKey == \"removed\"'"
            )
            node1.succeed("grep -qx 'cluster_jfs_encrypted 1' /var/lib/prometheus-node-exporter-text/jfs_encrypted.prom")

        with subtest("Nomad: leader, ACLs bootstrapped with our token, jfs_ready"):
            node1.wait_for_unit("nomad.service")
            node1.wait_until_succeeds(f"curl -fsS {TLSCURL} {nomad_url(CTRL, '/v1/status/leader')} | grep -q :", timeout=180)
            # The CLI an operator gets in a root shell: https and the certificate from
            # the environment (modules/cluster-common.nix), nothing on the command line.
            node1.succeed(f"NOMAD_TOKEN={NOMAD_TOKEN} nomad server members >/dev/null")
            # Anonymous access is denied once bootstrapped; our token is management.
            # With the certificate and no token: the ACL's 403.
            node1.wait_until_succeeds(
                f"test \"$(curl -s -o /dev/null -w '%{{http_code}}' {TLSCURL} {nomad_url(CTRL, '/v1/jobs')})\" = 403",
                timeout=120,
            )
            node1.wait_until_succeeds(
                f"curl -fsS {TLSCURL} -H 'X-Nomad-Token: {NOMAD_TOKEN}' {nomad_url(CTRL, '/v1/acl/token/self')} | grep -q management",
                timeout=60,
            )
            # Without a certificate there is no HTTP at all, so no anonymous policy:
            # the handshake fails (curl gets no status), token or not. And plain http
            # is not served.
            for path in ["/v1/jobs", "/v1/status/leader", "/v1/metrics"]:
                code = node1.execute(
                    f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 --cacert \"$NOMAD_CACERT\""
                    f" -H 'X-Nomad-Token: {NOMAD_TOKEN}' {nomad_url(CTRL, path)}"
                )
                assert code[0] != 0 and code[1].strip() == "000", f"{path} without a client certificate: {code}"
            code = node1.execute(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 http://{CTRL}:4646/v1/status/leader")
            assert code[1].strip() in ("000", "400"), f"plain http answered: {code}"
            # /v1/metrics has no ACL check: the certificate alone is what it wants.
            # To a file: `| grep -q` closes the pipe early, and curl's write error then
            # fails the command under pipefail.
            node1.succeed(f"curl -fsS {TLSCURL} -o /tmp/nomad-metrics '{nomad_url(CTRL, '/v1/metrics')}?format=prometheus'")
            node1.succeed("grep -q '^nomad_' /tmp/nomad-metrics")
            node1.wait_for_unit("jfs-nomad-meta.service")
            def jfs_ready(_):
                [n] = nomad_api(node1, CTRL, "/v1/nodes")
                return nomad_api(node1, CTRL, f"/v1/node/{n['ID']}")["Meta"].get("jfs_ready") == "true"
            retry(jfs_ready, timeout_seconds=120)

        with subtest("scoped tokens: one per role, and only nomad-acl-init reads the management token"):
            node1.wait_for_unit("nomad-acl-init.service")
            for role in ROLES:
                # A oneshot that exits: wait for what it leaves, not for the unit.
                node1.wait_until_succeeds(f"test -s {TOKENS}/{role}", timeout=180)
                node1.succeed(f"test \"$(stat -c %a:%U {TOKENS}/{role})\" = 400:root")
                me = json.loads(as_token(node1, CTRL, role_token(node1, role), "/v1/acl/token/self")[1])
                assert me["Type"] == "client" and me["Policies"] == [POLICY[role]], f"{role}: {me}"
            node1.succeed(f"test \"$(stat -c %a:%U {TOKENS})\" = 700:root")
            # The exit criterion's grep: the management token's path appears in no unit
            # but nomad-acl-init, nor in anything those units run.
            # And the audit trail's ACL stream (modules/audit-ship.nix), which needs it.
            readers = units_reading(node1, "nomad-acl/token")
            assert readers == ["cluster-audit-nomad-acl.service", "nomad-acl-init.service"], f"units reading nomad-acl/token: {readers}"
            # What an operator types: the avc token, the namespace from the environment.
            node1.wait_until_succeeds(f"NOMAD_TOKEN=$(cat {TOKENS}/avc) nomad job status > /tmp/job-status && grep -q app- /tmp/job-status", timeout=180)

        with subtest("every app in the catalogue has a registered job and a container"):
            node1.wait_for_unit("nomad-bootstrap.service")
            jobs = {j["ID"] for j in nomad_api(node1, CTRL, f"/v1/jobs?namespace={NS}")}
            missing = [a for a in APPS if f"app-{a}" not in jobs]
            assert not missing, f"jobs not registered: {missing} (have {sorted(jobs)})"
            # And none in `default`, which may run nothing.
            assert nomad_api(node1, CTRL, "/v1/jobs?namespace=default") == [], "jobs in the default namespace"
            for a in APPS:
                node1.succeed(f"test -f /etc/nixos-containers/{a}.conf")
            # Held: no placement, so no container was started.
            for a in APPS:
                node1.fail(f"systemctl is-active --quiet container@{a}.service")

        with subtest("monitoring: Prometheus scrapes the node, Alertmanager and Loki up"):
            for u in ["prometheus.service", "alertmanager.service", "loki.service", "vector.service",
                      "prometheus-node-exporter.service"]:
                node1.wait_for_unit(u)
            node1.wait_until_succeeds(f"curl -fsS http://{M1}:3100/ready", timeout=180)
            node1.wait_until_succeeds(
                f"curl -fsS 'http://{M1}:9090/api/v1/query?query=up%7Bjob%3D%22nixos-hosts%22%7D' | jq -e '.data.result[0].value[1] == \"1\"'",
                timeout=180,
            )
            # Nomad's own scrape, over https with the CLI certificate it gets as a
            # systemd credential (modules/monitoring-server.nix).
            node1.wait_until_succeeds(
                f"curl -fsS 'http://{M1}:9090/api/v1/query?query=up%7Bjob%3D%22nomad%22%7D' | jq -e '.data.result[0].value[1] == \"1\"'",
                timeout=180,
            )
            # The autoscaler holds the same certificate the same way. Nothing in this
            # fixture scales, so the most it can show is that it is not refused.
            node1.wait_for_unit("nomad-autoscaler.service")
            node1.fail("journalctl -u nomad-autoscaler.service --no-pager | grep -Ei 'x509|tls: |certificate required|bad certificate'")

    with subtest("first boot: cold start"):
        node1.start()
        converged()

    with subtest("data written to /mnt/jfs reaches the object storage"):
        node1.succeed("dd if=/dev/urandom of=/mnt/jfs/ci-probe bs=1M count=8 && sync")
        probe_sum = node1.succeed("sha256sum < /mnt/jfs/ci-probe")
        wan.wait_until_succeeds("find /srv/s3/${topology.objectStorage.juicefsBucket}/appfs/chunks -type f | grep -q .", timeout=60)

    with subtest("a client that dies under its mount is detached and remounted"):
        # The 2026-10-30 outage: the client died, left a dead FUSE endpoint
        # (ENOTCONN), and juicefs-mount's restarts all failed on it.
        node1.succeed("systemctl kill -s KILL juicefs-mount.service")
        node1.wait_until_succeeds("journalctl -u juicefs-mount.service | grep -q 'detached a dead mount'", timeout=60)
        node1.wait_until_succeeds("mountpoint -q /mnt/jfs && test -w /mnt/jfs", timeout=60)
        # The restart takes jfs-health (and so the containers) with it; it
        # must come back up on the new mount, not fail on the dead one.
        node1.wait_for_unit("jfs-health.service")
        node1.wait_for_unit("jfs-nomad-meta.service")
        assert node1.succeed("sha256sum < /mnt/jfs/ci-probe") == probe_sum, "/mnt/jfs/ci-probe changed across the remount"
        # The write probe passes again (and supersedes a run its timer may have
        # failed in the dead window, which no_failed_units would otherwise see).
        node1.succeed("systemctl start jfs-probe.service")

    with subtest("a log line travels Vector -> Loki"):
        node1.succeed("logger -t ci-probe cluster-single-log-marker")
        node1.wait_until_succeeds(
            f"curl -fsS -G http://{M1}:3100/loki/api/v1/query_range --data-urlencode 'query={{node=\"node1\"}} |= \"cluster-single-log-marker\"'"
            " | jq -e '.data.result | length > 0'",
            timeout=180,
        )

    with subtest("Nomad exports the TLS expiry gauges NomadTls*Expiring read"):
        # Their names are read from Nomad 1.11's source (command/agent/tls_metrics.go);
        # this is where they are confirmed, from the agent's own /v1/metrics.
        node1.succeed(f"curl -fsS {TLSCURL} -o /tmp/nomad-metrics '{nomad_url(CTRL, '/v1/metrics')}?format=prometheus'")
        for gauge in ["nomad_agent_tls_cert_expiration_seconds", "nomad_agent_tls_ca_expiration_seconds"]:
            node1.succeed(f"grep -E '^{gauge}(\\{{| )' /tmp/nomad-metrics")
        # The fixture's certificates are made for 100 years: nothing near either threshold.
        node1.succeed("awk '/^nomad_agent_tls_cert_expiration_seconds/ { if ($NF < 30 * 86400) exit 1 }' /tmp/nomad-metrics")

    with subtest("an opted-out node says so: cluster_boot_insecure_optout 1, and BootSecurityOptedOut fires"):
        node1.wait_until_succeeds("test \"$(systemctl show -p ActiveState --value cluster-boot-report.service)\" = active", timeout=120)
        report = node1.succeed("cat /var/lib/prometheus-node-exporter-text/boot_report.prom")
        lines = sorted(l.split()[0] for l in report.splitlines() if l.strip())
        assert "cluster_boot_insecure_optout 1" in report.splitlines(), report
        # Nothing about an unlock it did not have.
        assert lines == ["cluster_boot_insecure_optout", "cluster_boot_report_timestamp_seconds"], report
        node1.wait_until_succeeds(
            f"curl -fsS 'http://{M1}:9090/api/v1/query?query=ALERTS%7Balertname%3D%22BootSecurityOptedOut%22%2Calertstate%3D%22firing%22%7D'"
            " | jq -e '.data.result | length == 1'",
            timeout=300,
        )
        assert audit_stored("boot") == [], f"an opted-out node sent a boot event: {audit_stored('boot')}"

    with subtest("ssh-login-event: a root login over SSH reaches the off-host trail"):
        wan.succeed("install -m 0600 ${sshKeys.snakeOilEd25519PrivateKey} /root/id")
        fingerprint = wan.succeed("ssh-keygen -lf /root/id | cut -d' ' -f2").strip()
        wan.succeed(
            "ssh -n -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
            " -o ConnectTimeout=10 -i /root/id root@${node.publicIp4} true"
        )
        def logged_in(_):
            return [e for e in audit_stored("ssh_login") if e["key"] == fingerprint]
        found = retry(logged_in, timeout_seconds=120) or logged_in(None)
        e = found[-1]
        assert (e["sender"], e["node"], e["user"], e["from"]) == ("node1", "node1", "root", "${node.publicGw4}"), e
        # Nothing but the allowlisted fields left the node.
        assert set(e) == {"kind", "node", "user", "from", "key", "at", "sender", "received"}, e

    with subtest("nomad-acl-event-no-secret: an ACL change reaches the trail, its secret does not"):
        code, body = as_token(node1, CTRL, NOMAD_TOKEN, "/v1/acl/token", "POST",
                              json.dumps({"Name": "ci-audit-probe", "Type": "client", "Policies": ["operator-read"]}))
        assert code == 200, (code, body)
        created = json.loads(body)
        accessor, secret = created["AccessorID"], created["SecretID"]
        assert secret and accessor != secret
        code, body = as_token(node1, CTRL, NOMAD_TOKEN, f"/v1/acl/token/{accessor}", "DELETE")
        assert code == 200, (code, body)
        def acl_seen(_):
            types = {e["type"] for e in audit_stored("nomad_acl") if e["accessor"] == accessor}
            return types if types >= {"ACLTokenUpserted", "ACLTokenDeleted"} else None
        retry(acl_seen, timeout_seconds=120)
        mine = [e for e in audit_stored("nomad_acl") if e["accessor"] == accessor]
        assert all(e["sender"] == "node1" and e["name"] == "ci-audit-probe" and e["topic"] == "ACLToken" for e in mine), mine
        # nomad-acl-init's own changes at boot went the same way.
        policies = {e["name"] for e in audit_stored("nomad_acl") if e["topic"] == "ACLPolicy"}
        assert "fence" in policies, policies
        # Neither the new token's secret nor the management token appears in anything the
        # receiver was sent, or in what the node kept on the way.
        sent = wan.succeed(f"cat {AUDIT_OUT}/requests.jsonl {AUDIT_OUT}/audit.jsonl")
        for value in (secret, NOMAD_TOKEN):
            assert value not in sent, f"{value} reached the audit receiver"
            node1.fail(f"grep -rqF {value} /var/lib/cluster-audit")
            node1.fail(f"journalctl -b -o cat -u cluster-audit-nomad-acl -u cluster-audit-send | grep -qF {value}")
        # The receiver refused nothing the node sent (a field the Worker does not take, a
        # kind the token may not send).
        refused = [r for r in audit_received() if r["status"] != 204]
        assert refused == [], refused

    with subtest("audit-producers-alive: each producer says it works, and the stream answers 200"):
        # They restart for ever and never fail, so these metrics are what AuditProducerStale
        # and AuditNomadStreamRefused read (lib/alert-rules.nix).
        import re
        def alive(_):
            out = node1.succeed("cat /var/lib/prometheus-node-exporter-text/audit_*.prom 2>/dev/null || true")
            now = int(node1.succeed("date +%s").strip())
            beats = {m.group(1): int(m.group(2)) for m in re.finditer(
                r'^cluster_audit_producer_heartbeat_timestamp_seconds\{producer="(\w+)"\} (\d+)$', out, re.M)}
            fresh = {p for p, t in beats.items() if now - t < 120}
            return out if fresh >= {"send", "journal", "nomad_acl"} and "cluster_audit_nomad_stream_status 200" in out else None
        retry(alive, timeout_seconds=120)

    with subtest("deploy-event: a pull-deploy outcome reaches the off-host trail"):
        # Offline, the tick cannot fetch its flake: "build failed", which is an outcome the
        # trail records. The unit fails for it, as it does on a node; reset afterwards.
        node1.execute("systemctl start cluster-upgrade.service", timeout=600)
        node1.succeed("journalctl -u cluster-upgrade.service -o cat | grep -qx 'cluster-upgrade: build failed'")
        def deployed(_):
            return [e for e in audit_stored("deploy") if e["result"] == "build_failed"]
        retry(deployed, timeout_seconds=120)
        e = deployed(None)[-1]
        assert (e["sender"], e["node"], e["toplevel"], e["generation"]) == ("node1", "node1", "unknown", -1), e
        node1.succeed("systemctl reset-failed cluster-upgrade.service")

    with subtest("first boot leaves no failed unit"):
        no_failed_units(node1)

    with subtest("second boot: the steady state (formatted volume, bootstrapped ACLs)"):
        node1.shutdown()
        node1.start()
        converged()
        # The file written on the first boot survived: the second boot took
        # juicefs-format's "volume already known" branch, not a re-format.
        assert node1.succeed("sha256sum < /mnt/jfs/ci-probe") == probe_sum, "/mnt/jfs/ci-probe changed across the reboot"
        no_failed_units(node1)
  '';
}
