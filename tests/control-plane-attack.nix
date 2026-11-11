# VM test: a machine on the control VLAN tries to join Nomad, with each set of
# credentials an attacker could plausibly hold, against the real node1 (its machine
# module, as tests/cluster-single.nix boots it).
#
# Before Nomad had TLS and a gossip key, this attack worked end to end [RAN, the
# design's spike]: a machine on the VLAN started `nomad agent -server`, joined, was
# promoted to voter, read the ACL bootstrap token out of its own raft.db and ran a
# raw_exec job as root on node1. `rogue-baseline` is that attack, unchanged. Each
# variant after it carries more:
#
#   rogue-server-no-creds    nothing                      refused at gossip, not in raft
#   rogue-gossip-only        the gossip key               in serf, never a voter, no data
#   rogue-stolen-client-cert key + a worker's agent cert  the same: not a server's name
#   rogue-own-ca             key + its own CA, claiming   the same: not our CA
#                            server.global.nomad
#   stolen-server-cert-is-documented-limit
#                            key + a server's agent cert  a voter, with the token. This
#                            is the limit the design accepts (section 6), and why
#                            neither the key nor a server cert is on a worker.
#
# "Never a voter" is watched for as long as the documented limit takes to be promoted,
# and that case must be promoted inside the same window: so a negative result is not
# just a window too short to see anything.
#
# Then `sighup-rotates-cert`: a reissued agent certificate is served after a reload,
# without a restart.
#
# Then the scoped tokens (modules/nomad-acl.nix), from node1, which holds every role:
#
#   scoped-tokens                each role's token does its job, and is refused one
#                                thing outside its policy; none is management
#   jwt-tampered-refused         node1's own fence JWT with the role rewritten
#   jwt-wrong-audience-refused   signed by the real key, for another audience
#   jwt-unbound-role-refused     signed by the real key, a role with no binding rule
#                                (each against a freshly minted good JWT, which logs in)
#   default-namespace-cannot-run raw_exec and exec in `default`, as management
#   fence-stale-token-relogs     a fence token the cluster no longer knows: the fence
#                                logs in again by itself and completes its run
#   fence-403-is-loud            a refusal a fresh login can't cure (the login's JWT
#                                tampered too) fails its unit (UnitFailed) and leaves
#                                its metric stale (NomadFenceStale)
#   token-check-relogs           nomad-token-check gives a refused role token (avc's)
#                                a fresh login
#
# `fence-stops-nothing-on-empty` and `fence-failsafe-on-5xx` need nodes that are not the
# leader and containers Nomad placed, so they are in tests/cluster.nix, with
# `management-absent-from-deployed-secrets` (the voters); `management-absent-from-workers`
# needs a client-only worker, and is in tests/control-plane-failure.nix.
#
# And first of all, once the cluster is up, raw_exec's lockdown: what a stolen
# submit-job token (the registrar's) gets from a task on node1. Each a real Nomad job:
#
#   raw-exec-root-denied         no user (the agent's, root) or root: refused for uid 0
#   raw-exec-admin-denied        an admin account: refused for its uid
#   raw-exec-nobody-denied       nobody (65534): refused
#   raw-exec-high-uid-denied     no account exists above 65535 (or at 4096 but
#                                nomad-apps), and a task can't name one that doesn't;
#                                with -gap-is-real showing one made at run time would run
#   template-outside-sandbox     no template from outside the task, by path, by file(),
#                                or to outside it
#   artifact-file-refused        no artifact from the node's own disk
#   task-cannot-read-jfs-or-state  as nomad-apps: /mnt/jfs, /state/clients and a
#                                container root are Permission denied
#   task-has-no-network          as nomad-apps: loopback, the control VLAN and the
#                                internet all refused, where root reaches all three
#   polkit-scope                 stop of a declared container only; sshd, nomad,
#                                container@evil, restart and sudo refused
#
# Then the control mesh (modules/mesh-control-core.nix), once the attacker is on the
# VLAN. Every service but Nomad listens on a WireGuard interface, so:
#
#   vlan-only-nomad-and-wg-open  a full TCP scan of node1's control, app and storage
#                                VLAN addresses finds Nomad's three ports on the
#                                control VLAN and nothing else, SSH included; a UDP
#                                listener the firewall does not name gets nothing
#   rogue-wg-key-gets-nothing    a WireGuard peer with its own key: no handshake, 0 B
#                                back, no exporter (and with node2's key, stolen,
#                                the same attack works: the transport is open, the
#                                key is what refuses)
#   weak-host-route-refused      a route to node1's mesh address via its control IP:
#                                nothing answers, not even ping; nor from a container
#                                on br-app that declares nothing (container
#                                default-deny: only a declared app's bridge port
#                                reaches Grafana's two ports)
#   juicefs-pg-unreachable-on-vlan  PostgreSQL listens on every address, and the
#                                attacker reaches it on none
#   loki-forged-push-refused     the push that a node's own Vector makes, from the
#                                attacker: refused, and nothing lands in Loki
#   etcd-unreachable             etcd, client and peer port, either way
#
# Mutants (flake.nix legacyPackages.mutants): `nomad-no-gossip` (no key on node1:
# rogue-server-no-creds joins serf) and `nomad-no-verify-hostname` (any CA-signed
# certificate is a server: rogue-stolen-client-cert becomes a voter);
# `raw-exec-no-denied-uids` (no deny list: raw-exec-root-denied runs as root),
# `no-skuid-rule` (no output rule: task-has-no-network connects) and
# `state-clients-0755` (/mnt/jfs and /state/clients open: task-cannot-read-jfs-or-state
# reads); `no-weak-host-rule` (no weak-host drop: weak-host-route-refused answers ping,
# and only ping: the mesh accepts name wg-ctrl, so no mesh service answers either way) and
# `mesh-open-on-vlan` (the control VLAN trusted again and an exporter on it, as before
# the mesh: vlan-only-nomad-and-wg-open finds SSH and the exporter).
#
# Run: nix build .#checks.x86_64-linux.control-plane-attack -L   (needs KVM; ~6 GB RAM)
{
  pkgs,
  lib,
  clan,
  harness,
  mutant ? "",
  extraModule ? { },
}:
let
  machine = clan.config.nixosConfigurations.node1;
  inherit (machine._module.specialArgs) topology;
  net = import ../lib/net.nix { inherit lib; };
  nomadPki = import ../lib/nomad-pki.nix { inherit lib; };
  ctrl = topology.nodes.node1.controlIp;
  pki = harness.pki;
  mesh1 = net.meshIp topology topology.nodes.node1;

  # A free address on the control VLAN (the fixture's nodes are .11 to .13).
  rogueIp = "10.10.0.99";

  # The stolen client certificate is a worker's. Fails here, loudly, if the fixture
  # ever makes node2 a server, rather than testing a server cert under that name.
  stolenClient =
    assert !(net.hasTag "nomad-server" topology.nodes.node2);
    "node2";

  # What the attacker makes for itself: its own CA and a certificate from it that
  # claims to be a server. And, for sighup-rotates-cert, a reissue of node1's agent
  # certificate from the cluster CA.
  material =
    pkgs.runCommand "control-plane-attack-material"
      {
        nativeBuildInputs = [
          pkgs.openssl
          pkgs.coreutils
          pkgs.python3
        ];
      }
      ''
        set -euo pipefail
        ${nomadPki.functions}
        mkdir -p $out/own $out/rotated
        make_ca $out/own/ca.key $out/own/ca.crt 36500
        (
          pki_out=$out/own pki_ca_crt=$out/own/ca.crt pki_ca_key=$out/own/ca.key pki_days=36500
          issue agent ${nomadPki.serverName} ${
            lib.escapeShellArg (
              nomadPki.agentSans {
                isServer = true;
                controlIp = rogueIp;
              }
            )
          }
        )
        # Login JWTs: a good one, minted now with the cluster's key, and three bad ones.
        mkdir -p $out/jwt
        mint_jwt fence node1 ${nomadPki.jwtAudience} ${pki}/signing.key 36500 > $out/jwt/good
        mint_jwt fence node1 not-${nomadPki.jwtAudience} ${pki}/signing.key 36500 > $out/jwt/wrong-audience
        mint_jwt root node1 ${nomadPki.jwtAudience} ${pki}/signing.key 36500 > $out/jwt/unbound-role
        # node1's real fence JWT, its role rewritten to registrar, its signature kept.
        python3 - ${pki}/node1/jwt-fence $out/jwt/tampered <<'PY'
        import base64, json, sys
        h, p, sig = open(sys.argv[1]).read().strip().split(".")
        claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        assert claims["role"] == "fence", claims
        claims["role"] = "registrar"
        p2 = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).decode().rstrip("=")
        open(sys.argv[2], "w").write(".".join([h, p2, sig]))
        PY
        (
          pki_out=$out/rotated pki_ca_crt=${pki}/ca.crt pki_ca_key=${pki}/ca.key pki_days=36500
          issue agent ${nomadPki.serverName} ${
            lib.escapeShellArg (
              nomadPki.agentSans {
                isServer = true;
                controlIp = ctrl;
              }
            )
          }
        )
      '';

  # One agent configuration per rogue. The attacker controls its own config, so it
  # does not verify anybody's hostname and asks nothing of its own clients.
  rogueConfig =
    name: tls:
    pkgs.writeText "rogue-${name}.hcl" (
      ''
        name = "rogue-${name}"
        region = "${nomadPki.region}"
        datacenter = "${topology.datacenter}"
        data_dir = "/var/lib/rogue/${name}"
        bind_addr = "${rogueIp}"
        advertise {
          http = "${rogueIp}:4646"
          rpc = "${rogueIp}:4647"
          serf = "${rogueIp}:4648"
        }
        server {
          enabled = true
          server_join {
            retry_join = ["${ctrl}"]
          }
        }
        acl {
          enabled = true
        }
        leave_on_interrupt = true
        leave_on_terminate = true
      ''
      + lib.optionalString (tls != null) ''
        tls {
          http = true
          rpc = true
          ca_file = "${tls.ca}"
          cert_file = "${tls.cert}"
          key_file = "${tls.key}"
          verify_server_hostname = false
          verify_https_client = false
        }
      ''
    );
  stolenCert = n: {
    ca = "${pki}/ca.crt";
    cert = "${pki}/${n}/agent.crt";
    key = "${pki}/${n}/agent.key";
  };
  rogues = {
    baseline = {
      gossip = false;
      tls = null;
    };
    nocreds = {
      gossip = false;
      tls = null;
    };
    gossip = {
      gossip = true;
      tls = null;
    };
    client = {
      gossip = true;
      tls = stolenCert stolenClient;
    };
    ownca = {
      gossip = true;
      tls = {
        ca = "${material}/own/ca.crt";
        cert = "${material}/own/agent.crt";
        key = "${material}/own/agent.key";
      };
    };
    server = {
      gossip = true;
      tls = stolenCert "node1";
    };
  };
  # name -> the agent's -config arguments. The stolen gossip key is the cluster's own
  # file, as Nomad loads it.
  rogueArgs = lib.mapAttrs (
    name: r:
    "-config=${rogueConfig name r.tls}" + lib.optionalString r.gossip " -config=${pki}/gossip.hcl"
  ) rogues;

  # ── raw_exec lockdown (WS7) ─────────────────────────────────────────────────────
  inherit (import ../lib/nomad.nix) appsUser appsUid;
  # The management token's file on node1: what a template or an artifact would steal.
  mgmtTokenPath = machine.config.clan.core.vars.generators.nomad-acl.files.token.path;
  # A declared container, and one that is not: the polkit rule tells them apart.
  declaredUnit = "container@${lib.head (lib.attrNames machine.config.clusterApps)}.service";
  # Somewhere each kind of network answers, from node1: loopback (sshd), the control
  # VLAN (Nomad), and the internet (the wan VM, which answers on 443 at every address
  # it holds, node1's gateway included).
  netTargets = [
    "127.0.0.1:22"
    "${ctrl}:4646"
    "${topology.nodes.node1.publicGw4}:443"
    # And the control mesh: node1's own exporter, on its mesh address.
    "${mesh1}:${toString net.nodeExporterPort}"
  ];
  # What a task with a stolen submit-job token tries. Each script runs as the task
  # (through Nomad), and the network one also as root in the test, which is the
  # positive control: the targets answer.
  taskPath = lib.makeBinPath [
    pkgs.coreutils
    pkgs.bash
  ];
  readTask = pkgs.writeShellScript "ci-ws7-read" ''
    export PATH=${taskPath}
    id
    for f in /mnt/jfs/ci-ws7/secret /state/clients/ci-ws7/secret /var/lib/nixos-containers/ci-ws7/etc/secret; do
      if out=$(cat "$f" 2>&1); then echo "READ $f: $out"; else echo "DENIED $f: $out"; fi
    done
    for d in /mnt/jfs /state/clients /var/lib/nixos-containers; do
      if out=$(ls "$d" 2>&1); then echo "LISTED $d: $out"; else echo "DENIED $d: $out"; fi
    done
    # The task itself works: it reads what anyone may.
    cat /etc/hostname >/dev/null && echo "CONTROL read /etc/hostname"
  '';
  netTask = pkgs.writeShellScript "ci-ws7-net" ''
    export PATH=${taskPath}
    id
    for t in ${lib.escapeShellArgs netTargets}; do
      h=''${t%:*}; p=''${t##*:}
      if out=$(timeout 5 bash -c "exec 3<>/dev/tcp/$h/$p" 2>&1); then
        echo "CONNECTED $t"
      else
        echo "REFUSED $t rc=$? $out"
      fi
    done
  '';
  polkitTask = pkgs.writeShellScript "ci-ws7-polkit" ''
    export PATH=${taskPath}
    systemctl=${machine.config.systemd.package}/bin/systemctl
    id
    try() {
      if out=$("$systemctl" "$@" 2>&1); then echo "ALLOWED $*"; else echo "REFUSED $* rc=$? $out"; fi
    }
    try stop sshd.service
    try restart nomad.service
    try start container@evil.service
    try stop container@evil.service
    try restart ${declaredUnit}
    try stop ${declaredUnit}
    if out=$(/run/wrappers/bin/sudo -n true 2>&1); then echo "ALLOWED sudo"; else echo "REFUSED sudo $out"; fi
  '';

  # The baseline's last step: a batch raw_exec job that would run as root on node1.
  pwnedJob = pkgs.writeText "pwned.hcl" ''
    job "pwned" {
      type        = "batch"
      datacenters = ["${topology.datacenter}"]
      node_pool   = "ci-hold"
      group "g" {
        task "t" {
          driver = "raw_exec"
          config {
            command = "/bin/sh"
            args    = ["-c", "id > /tmp/PWNED; cat /run/secrets/shared/nomad-acl/token >> /tmp/PWNED"]
          }
        }
      }
    }
  '';
in
pkgs.testers.runNixOSTest {
  name = "control-plane-attack";

  node.pkgs = lib.mkForce null;
  node.specialArgs = removeAttrs machine._module.specialArgs [ "modulesPath" ];

  nodes = {
    wan = harness.wanNode;

    node1 = {
      imports = [
        clan.config.nixosModules."clan-machine-node1"
        (harness.nodeModule { memoryMB = 4096; })
        extraModule
      ];
      # As in tests/cluster-single.nix: every job registers, none is placed.
      services.nomad.settings.client.node_pool = "ci-hold";
    };

    # The attacker: a machine attached to the vRack, which is all "conventional
    # provider access" needs. Nomad, and the tools to read a raft log.
    attacker =
      { pkgs, ... }:
      {
        nixpkgs.config.allowUnfree = true;
        virtualisation = {
          memorySize = 1024;
          vlans = lib.mkForce [ ];
          interfaces.eth1 = {
            vlan = 2;
            assignIP = false;
          };
        };
        networking.useDHCP = false;
        networking.firewall.enable = false;
        environment.systemPackages = [
          pkgs.nomad
          pkgs.curl
          pkgs.jq
          pkgs.binutils
          pkgs.openssl
          pkgs.netcat
          # The mesh's attacks: a scan, and a WireGuard peer of its own.
          pkgs.nmap
          pkgs.wireguard-tools
          pkgs.socat
        ];
      };
  };

  testScript = ''
    import time

    ${harness.pythonHelpers}

    MUTANT = "${mutant}"
    ${builtins.readFile ./lib/control.py}

    CTRL = "${ctrl}"
    ROGUE_IP = "${rogueIp}"
    ROGUES = ${builtins.toJSON rogueArgs}
    PKI = "${pki}"
    MATERIAL = "${material}"
    PWNED_JOB = "${pwnedJob}"
    # Any registered job: the registrar plans it, the others read it.
    A_JOB = "app-${lib.head (lib.attrNames machine.config.clusterApps)}"
    METRIC = "/var/lib/prometheus-node-exporter-text/nomad_fence.prom"
    JWT_FENCE = "${machine.config.clan.core.vars.generators.nomad-login.files."jwt-fence".path}"
    UUID_RE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    # How long each negative case is watched. The documented limit must be promoted
    # inside it, which is what makes "never a voter" in the others mean something.
    WATCH = 90

    def mgmt(cmd):
        return node1.succeed(f"NOMAD_TOKEN={NOMAD_TOKEN} {cmd}")

    def raft_servers():
        return nomad_api(node1, CTRL, "/v1/operator/raft/configuration")["Servers"]

    def serf_names():
        return [m["Name"] for m in nomad_api(node1, CTRL, "/v1/agent/members")["Members"]]

    def healthy():
        leader = node1.succeed(f"curl -fsS {TLSCURL} {nomad_url(CTRL, '/v1/status/leader')}").strip().strip('"')
        voters = sorted(s["Node"] for s in raft_servers() if s["Voter"])
        return leader == f"{CTRL}:4647" and voters == ["node1.global"], f"leader={leader} voters={voters}"

    def raft_db(name):
        return f"/var/lib/rogue/{name}/server/raft/raft.db"

    def token_count(name):
        return int(attacker.succeed(f"strings {raft_db(name)} 2>/dev/null | grep -c {NOMAD_TOKEN} || true").strip() or "0")

    def start_rogue(name):
        attacker.succeed(f"systemd-run --unit=rogue-{name} --property=KillSignal=SIGINT $(command -v nomad) agent {ROGUES[name]}")
        # It is up and trying: its HTTP listener answers (plain or TLS).
        attacker.wait_until_succeeds(f"nc -z -w2 {ROGUE_IP} 4646", timeout=60)

    def rogue_alive(name):
        return attacker.execute(f"systemctl is-active --quiet rogue-{name}.service")[0] == 0

    def observe(name, seconds=WATCH, until_voter=False):
        """What node1 sees of the rogue over `seconds`: ever in serf, ever in raft,
        ever a voter, and when it became one."""
        member = peer = voter = False
        promoted_after = None
        start = time.monotonic()
        while time.monotonic() - start < seconds:
            node = f"rogue-{name}.global"
            member = member or node in serf_names()
            mine = [s for s in raft_servers() if s["Node"] == node]
            peer = peer or bool(mine)
            if any(s["Voter"] for s in mine) and not voter:
                voter = True
                promoted_after = round(time.monotonic() - start)
                if until_voter:
                    break
            time.sleep(3)
        return member, peer, voter, promoted_after

    def evict(name):
        """Take the rogue out of raft and serf, and confirm node1 is alone again."""
        for s in raft_servers():
            if s["Node"] == f"rogue-{name}.global":
                # While the rogue is still up: as a voter it is half the quorum.
                mgmt(f"nomad operator raft remove-peer -peer-id={s['ID']}")
        attacker.execute(f"systemctl stop rogue-{name}.service")
        node1.execute(f"NOMAD_TOKEN={NOMAD_TOKEN} nomad server force-leave -prune rogue-{name}.global")
        def alone(_):
            for s in raft_servers():
                if s["Node"].startswith("rogue-"):
                    node1.execute(f"NOMAD_TOKEN={NOMAD_TOKEN} nomad operator raft remove-peer -peer-id={s['ID']}")
            return not any(s["Node"].startswith("rogue-") for s in raft_servers()) and healthy()[0]
        retry(alone, timeout_seconds=120)

    def negative(name):
        """A rogue that must get no further than serf, if that. Returns the facts."""
        start_rogue(name)
        member, peer, voter, _ = observe(name)
        tokens = token_count(name)
        alive = rogue_alive(name)
        ok, why = healthy()
        detail = (f"serf={member} raft={peer} voter={voter} tokens-in-raft.db={tokens}"
                  f" rogue-alive={alive} cluster: {why}")
        print(f"rogue-{name}: {detail}")
        evict(name)
        return member, voter, tokens, alive, ok, detail

    # ── raw_exec lockdown (WS7) ─────────────────────────────────────────────────
    DC = "${topology.datacenter}"
    ALLOC_DIR = "${machine.config.services.nomad.settings.data_dir}/alloc"
    APPS_USER = "${appsUser}"
    APPS_UID = ${toString appsUid}
    MGMT_TOKEN_PATH = "${mgmtTokenPath}"
    DECLARED = "${declaredUnit}"
    NET_TARGETS = ${builtins.toJSON netTargets}
    READ_TASK = "${readTask}"
    NET_TASK = "${netTask}"
    POLKIT_TASK = "${polkitTask}"
    # Nomad's text for each refusal [RAN against a local agent, 1.11.3].
    POLKIT_REFUSED = ("Access denied", "Interactive authentication required")

    def task_run(jid, task):
        """A batch raw_exec job in `apps`, submitted with the registrar's token: the
        stolen submit-job. It lands on node1 (pool ci-hold), is never restarted or
        rescheduled, and is purged afterwards. Returns the submit's HTTP status and
        body, the allocation's client status, every task event's text, and what the
        task wrote to stdout and stderr."""
        t = {"Name": "t", "Driver": "raw_exec"}
        t.update(task)
        spec = json.dumps({"Job": {
            "ID": jid, "Name": jid, "Namespace": NS, "Type": "batch",
            "Datacenters": [DC], "NodePool": "ci-hold",
            "TaskGroups": [{"Name": "g",
                            "RestartPolicy": {"Attempts": 0, "Mode": "fail"},
                            "ReschedulePolicy": {"Attempts": 0, "Unlimited": False},
                            "Tasks": [t]}],
        }})
        code, body = as_token(node1, CTRL, role_token(node1, "registrar"), "/v1/jobs", "POST", spec)
        if code != 200:
            return code, body, None, [], ""
        def allocs():
            return nomad_api(node1, CTRL, f"/v1/job/{jid}/allocations?namespace={NS}")
        retry(lambda _: bool(allocs()) and all(a["ClientStatus"] in ("complete", "failed", "lost") for a in allocs()),
              timeout_seconds=180)
        status: list = []
        events: list = []
        out = ""
        for al in allocs():
            a = nomad_api(node1, CTRL, f"/v1/allocation/{al['ID']}?namespace={NS}")
            status.append(a["ClientStatus"])
            events += [" | ".join(str(e.get(k) or "") for k in ("Type", "DisplayMessage", "DriverError", "SetupError", "DownloadError"))
                       for ts in (a.get("TaskStates") or {}).values() for e in (ts.get("Events") or [])]
            logs = f"{ALLOC_DIR}/{al['ID']}/alloc/logs"
            out += node1.execute(f"cat {logs}/t.stdout.0 {logs}/t.stderr.0 2>/dev/null")[1]
        as_token(node1, CTRL, NOMAD_TOKEN, f"/v1/job/{jid}?namespace={NS}&purge=true", "DELETE")
        return code, body, "/".join(status), events, out

    def has(events, text):
        return any(text in e for e in events)

    def shell(script):
        return {"command": "/bin/sh", "args": ["-c", script]}

    def refused_as(name, user, uid):
        """A task as `user` (None: no user, so the agent's own, root) is refused for
        its uid before anything runs."""
        task = {"Config": shell(f"echo ran > /tmp/ci-ws7-ran-{name}")}
        if user is not None:
            task["User"] = user
        code, _, status, events, _ = task_run(f"ci-ws7-{name}", task)
        ran = node1.execute(f"test -e /tmp/ci-ws7-ran-{name}")[0] == 0
        why = f"running as uid {uid} is disallowed"
        detail = f"user={user!r} submit={code} status={status} ran={ran} refused-for-uid-{uid}={has(events, why)} events={events}"
        print(f"{name}: {detail}")
        return code == 200 and status == "failed" and has(events, why) and not ran, detail

    def ws7():
        """A stolen submit-job token (the registrar's) runs code as uid 4096, with no
        network, no data and no root. Placed first, so that a mutant of these stops
        here rather than after the rogues."""
        node1.wait_for_unit("nomad-acl-init.service")
        node1.wait_until_succeeds(f"test -s {TOKENS}/registrar", timeout=180)

        with subtest("raw-exec-root-denied: no user, or root, is refused before it starts"):
            ok_none, d_none = refused_as("nouser", None, 0)
            ok_root, d_root = refused_as("root", "root", 0)
            control("raw-exec-root-denied", ok_none and ok_root, f"no user: {d_none}; root: {d_root}")

        with subtest("raw-exec-admin-denied: an admin account is refused"):
            uid = int(node1.succeed("id -u admin").strip())
            ok, detail = refused_as("admin", "admin", uid)
            control("raw-exec-admin-denied", ok, detail)

        with subtest("raw-exec-nobody-denied: nobody is refused"):
            uid = int(node1.succeed("id -u nobody").strip())
            ok, detail = refused_as("nobody", "nobody", uid)
            control("raw-exec-nobody-denied", ok, detail)

        with subtest("raw-exec-high-uid-denied: above 65535 only an account could run, and none exists"):
            # The deny list stops at 65535 (lib/nomad.nix). Nomad runs a task only as
            # an account that exists, so the control is that none can be configured
            # there (modules/boot-security.nix, checks.security-policy), nor another
            # at nomad-apps' uid.
            high = node1.succeed("getent passwd | awk -F: '$3 >= 65536 {print $1 \":\" $3}'").split()
            at_apps = node1.succeed(f"getent passwd | awk -F: '$3 == {APPS_UID} {{print $1}}'").split()
            results: dict = {}
            for name, user in (("high-name", "ci-high-uid"), ("high-number", "70000")):
                code, _, status, events, _ = task_run(f"ci-ws7-{name}", {"User": user, "Config": shell(f"echo ran > /tmp/ci-ws7-ran-{name}")})
                ran = node1.execute(f"test -e /tmp/ci-ws7-ran-{name}")[0] == 0
                results[name] = (code == 200 and status == "failed" and has(events, f'failed to identify user "{user}"') and not ran,
                                 f"user={user} status={status} ran={ran} events={events}")
            print(f"raw-exec-high-uid-denied: accounts >= 65536: {high}; at {APPS_UID}: {at_apps}; {results}")
            control("raw-exec-high-uid-denied",
                    high == [] and at_apps == [APPS_USER] and all(ok for ok, _ in results.values()),
                    f"accounts >= 65536: {high}; at {APPS_UID}: {at_apps}; {results}")
            # Why that is the control, not Nomad: an account made at run time (which the
            # assertion keeps out of every configuration) does run. Documented, and
            # removed again at once. A name never looked up before: the node's name service
            # cache remembers the refusal above for ci-high-uid [RAN: reusing it, Nomad
            # still said "unknown user" after useradd].
            node1.succeed("useradd --system --uid 70000 --no-create-home --shell /run/current-system/sw/bin/nologin ci-gap-uid")
            node1.wait_until_succeeds("getent passwd ci-gap-uid | grep -q :70000:", timeout=30)
            code, _, status, events, out = task_run("ci-ws7-high-gap", {"User": "ci-gap-uid", "Config": shell("/run/current-system/sw/bin/id")})
            node1.succeed("userdel ci-gap-uid")
            print(f"raw-exec-high-uid-gap-is-real: status={status} out={out.strip()!r} events={events}")
            control("raw-exec-high-uid-gap-is-real", status == "complete" and "uid=70000" in out,
                    f"status={status} out={out.strip()!r} events={events}")

        with subtest("template-outside-sandbox: the agent renders as root, from inside the task only"):
            show = {"User": APPS_USER, "Config": shell("cat local/out 2>&1; echo end")}
            src = task_run("ci-ws7-tpl-src", {**show, "Templates": [{"SourcePath": MGMT_TOKEN_PATH, "DestPath": "local/out"}]})
            fn = task_run("ci-ws7-tpl-file", {**show, "Templates": [{"EmbeddedTmpl": '{{ file "%s" }}' % MGMT_TOKEN_PATH, "DestPath": "local/out"}]})
            dst = task_run("ci-ws7-tpl-dest", {**show, "Templates": [{"EmbeddedTmpl": "x", "DestPath": "../../../../../../../../../../etc/ci-ws7-template"}]})
            leaked = any(NOMAD_TOKEN in r[4] for r in (src, fn, dst))
            written = node1.execute("test -e /etc/ci-ws7-template")[0] == 0
            detail = (f"source: status={src[2]} events={src[3]}; file(): status={fn[2]} events={fn[3]};"
                      f" destination: HTTP {dst[0]} {dst[1].strip()[:200]}; token leaked={leaked} written={written}")
            print(f"template-outside-sandbox: {detail}")
            control("template-outside-sandbox",
                    src[2] == "failed" and has(src[3], "template source path escapes alloc directory")
                    and fn[2] == "failed" and has(fn[3], "is outside of sandbox")
                    and dst[0] != 200 and "destination escapes allocation directory" in dst[1]
                    and not leaked and not written,
                    detail)

        with subtest("artifact-file-refused: the getter fetches nothing from the node's own disk"):
            runs: dict = {}
            for name, source in (("url", f"file://{MGMT_TOKEN_PATH}"), ("path", MGMT_TOKEN_PATH)):
                runs[name] = task_run(f"ci-ws7-artifact-{name}", {
                    "User": APPS_USER, "Config": shell("cat local/* 2>&1; echo end"),
                    "Artifacts": [{"GetterSource": source, "RelativeDest": "local/"}],
                })
            copied = node1.execute(f"grep -rlsF {NOMAD_TOKEN} {ALLOC_DIR}")[1].strip()
            detail = "; ".join(f"{n}: status={r[2]} events={r[3]}" for n, r in runs.items()) + f"; copies in {ALLOC_DIR}: {copied!r}"
            print(f"artifact-file-refused: {detail}")
            control("artifact-file-refused",
                    all(r[2] == "failed" and has(r[3], "download not supported for scheme 'file'") and NOMAD_TOKEN not in r[4]
                        for r in runs.values()) and copied == "",
                    detail)

        with subtest("task-cannot-read-jfs-or-state: a real task as nomad-apps, and inside a container root"):
            node1.wait_for_unit("jfs-health.service", timeout=300)
            # World-readable files, so only the top directory's mode stands between.
            node1.succeed(
                "for d in /mnt/jfs/ci-ws7 /state/clients/ci-ws7 /var/lib/nixos-containers/ci-ws7/etc; do"
                "  mkdir -p $d && chmod 0755 $d && echo ci-ws7-secret > $d/secret && chmod 0644 $d/secret; done"
            )
            modes = node1.succeed("stat -c '%n %a %U:%G' /mnt/jfs /state/clients /var/lib/nixos-containers").strip()
            code, _, status, events, out = task_run("ci-ws7-read", {"User": APPS_USER, "Config": {"command": READ_TASK}})
            lines = out.splitlines()
            denied = [l for l in lines if l.startswith("DENIED ") and "Permission denied" in l]
            got = [l for l in lines if l.startswith(("READ ", "LISTED "))]
            detail = f"modes: {modes}; status={status}; task said: {lines}; events={events}"
            print(f"task-cannot-read-jfs-or-state: {detail}")
            control("task-cannot-read-jfs-or-state",
                    status == "complete" and f"uid={APPS_UID}({APPS_USER})" in out
                    and "CONTROL read /etc/hostname" in out and len(denied) == 6 and got == [],
                    detail)

        with subtest("task-has-no-network: a real task under the skuid rule, not setpriv"):
            # The positive control: as root the same script reaches every target.
            as_root = node1.succeed(f"{NET_TASK}")
            code, _, status, events, out = task_run("ci-ws7-net", {"User": APPS_USER, "Config": {"command": NET_TASK}})
            reached = [t for t in NET_TARGETS if f"CONNECTED {t}" in out]
            refused = [t for t in NET_TARGETS if f"REFUSED {t} " in out]
            detail = f"as root: {as_root.splitlines()}; as the task: status={status} {out.splitlines()} events={events}"
            print(f"task-has-no-network: {detail}")
            control("task-has-no-network-root-reaches",
                    all(f"CONNECTED {t}" in as_root for t in NET_TARGETS), detail)
            control("task-has-no-network",
                    status == "complete" and f"uid={APPS_UID}({APPS_USER})" in out
                    and reached == [] and refused == NET_TARGETS,
                    detail)

        with subtest("polkit-scope: start and stop of declared containers, nothing else"):
            nomad_pid = node1.succeed("systemctl show -p MainPID --value nomad.service").strip()
            code, _, status, events, out = task_run("ci-ws7-polkit", {"User": APPS_USER, "Config": {"command": POLKIT_TASK}})
            lines = out.splitlines()
            def said(prefix, what):
                return [l for l in lines if l.startswith(f"{prefix} {what}")]
            def refused_by_polkit(what):
                return any(any(r in line for r in POLKIT_REFUSED) for line in said("REFUSED", what))
            want_refused = ["stop sshd.service", "restart nomad.service", "start container@evil.service",
                            "stop container@evil.service", f"restart {DECLARED}"]
            sshd_up = node1.execute("systemctl is-active --quiet sshd.service")[0] == 0
            same_nomad = node1.succeed("systemctl show -p MainPID --value nomad.service").strip() == nomad_pid
            evil_up = node1.execute("systemctl is-active --quiet container@evil.service")[0] == 0
            detail = (f"status={status} task said: {lines}; sshd active={sshd_up} nomad same pid={same_nomad}"
                      f" container@evil active={evil_up} events={events}")
            print(f"polkit-scope: {detail}")
            control("polkit-scope",
                    status == "complete" and f"uid={APPS_UID}({APPS_USER})" in out
                    and all(refused_by_polkit(w) for w in want_refused)
                    and said("ALLOWED", f"stop {DECLARED}") != []
                    and said("REFUSED", "sudo") != [] and said("ALLOWED", "sudo") == []
                    and sshd_up and same_nomad and not evil_up,
                    detail)

        node1.succeed("rm -rf /mnt/jfs/ci-ws7 /state/clients/ci-ws7 /var/lib/nixos-containers/ci-ws7 /tmp/ci-ws7-*")

    # ── the control mesh (WS8) ──────────────────────────────────────────────────
    M1 = "${mesh1}"
    MESH_PORT = ${toString (net.meshPort topology)}
    MESH_SUBNET = "${topology.mesh.subnet}"
    NODE1_PUB = "${harness.wg.node1.public}"
    NODE2_PRIV = "${harness.wg.node2.private}"
    # node1's addresses on the other two VLANs, and the attacker's there.
    APP_IP = "${net.appTransitIp topology.nodes.node1}"
    STG_IP = "${topology.nodes.node1.storageIp}"
    # What node1 serves on the mesh: exporters and Vector, Loki and Prometheus,
    # etcd, the JuiceFS metadata engine (lib/net.nix meshPortsFor).
    MESH_PORTS = ${builtins.toJSON (net.meshPortsFor topology.nodes.node1)}
    WG = "${pkgs.wireguard-tools}/bin/wg"

    def open_tcp(ip):
        """Every TCP port the attacker finds open on `ip`, scanning all 65535."""
        out = attacker.succeed(
            f"nmap -n -Pn -sS -p- --min-rate 2000 --max-retries 2 -oG - {ip} 2>&1"
        )
        import re
        return sorted(int(p) for p in re.findall(r"(\d+)/open/tcp", out))

    def reaches(cmd, seconds=8):
        """True if the attacker's command succeeds within `seconds`."""
        return attacker.execute(f"timeout {seconds} {cmd}")[0] == 0

    def ws8():
        """The services on the control mesh, from a machine on the VLANs with no key."""
        with subtest("vlan-only-nomad-and-wg-open: Nomad's three ports, and nothing else on any VLAN"):
            attacker.succeed(
                "ip link add link eth1 name eth1.20 type vlan id ${toString topology.vlans.app.id}"
                " && ip addr add 10.20.0.99/24 dev eth1.20 && ip link set eth1.20 up"
                " && ip link add link eth1 name eth1.30 type vlan id ${toString topology.vlans.storage.id}"
                " && ip addr add 10.30.0.99/24 dev eth1.30 && ip link set eth1.30 up"
            )
            attacker.wait_until_succeeds(f"ping -c1 -W2 {APP_IP} && ping -c1 -W2 {STG_IP}", timeout=60)
            scans = {ip: open_tcp(ip) for ip in (CTRL, APP_IP, STG_IP)}
            # What node1 listens on, any address: the firewall is what keeps it off the VLANs.
            listening = sorted({int(l.split()[3].rsplit(":", 1)[1]) for l in node1.succeed("ss -Htln").splitlines()})
            # A UDP listener the firewall does not name, on every address, which echoes:
            # node1 itself gets the echo, the attacker gets nothing.
            node1.succeed("systemd-run --unit=ci-udp-echo ${pkgs.socat}/bin/socat UDP4-RECVFROM:5999,fork EXEC:${pkgs.coreutils}/bin/cat")
            node1.wait_until_succeeds(f"echo local | timeout 3 ${pkgs.socat}/bin/socat - UDP4:{CTRL}:5999 | grep -q local", timeout=30)
            udp_echo = attacker.execute(f"echo attacker | timeout 5 socat - UDP4:{CTRL}:5999")[1].strip()
            node1.succeed("systemctl stop ci-udp-echo.service")
            ssh_listening = 22 in listening
            detail = (f"open: control {CTRL}: {scans[CTRL]}, app {APP_IP}: {scans[APP_IP]}, storage {STG_IP}: {scans[STG_IP]};"
                      f" node1 listens on TCP {listening}; a UDP echo on 5999 answered the attacker: {udp_echo!r}")
            print(f"vlan-only-nomad-and-wg-open: {detail}")
            control("vlan-only-nomad-and-wg-open",
                    scans[CTRL] == [4646, 4647, 4648] and scans[APP_IP] == [] and scans[STG_IP] == []
                    and ssh_listening and udp_echo == "",
                    detail)

        with subtest("rogue-wg-key-gets-nothing: a WireGuard peer node1 does not list gets no handshake, no byte"):
            def wg_attack(name, private, src):
                """A WireGuard interface on the attacker aimed at node1, with `private`
                and the mesh address `src`. Returns (handshake, rx bytes, tx bytes, the
                exporter reached, ping answered)."""
                attacker.succeed(
                    f"umask 077; echo {private} > /tmp/{name}.key"
                    f" && ip link add {name} type wireguard"
                    f" && {WG} set {name} private-key /tmp/{name}.key"
                    f"    peer {NODE1_PUB} endpoint {CTRL}:{MESH_PORT} allowed-ips {MESH_SUBNET} persistent-keepalive 1"
                    f" && ip addr add {src}/24 dev {name} && ip link set {name} up"
                )
                exporter = reaches(f"curl -fsS -o /dev/null http://{M1}:9100/metrics", 15)
                pinged = reaches(f"ping -c2 -W2 {M1}", 10)
                time.sleep(3)
                hs = attacker.succeed(f"{WG} show {name} latest-handshakes").split()
                rx, tx = attacker.succeed(f"{WG} show {name} transfer").split()[1:3]
                attacker.succeed(f"ip link del {name}")
                return int(hs[1]) > 0, int(rx), int(tx), exporter, pinged
            # Its own key, at an unused mesh address.
            hs, rx, tx, exporter, pinged = wg_attack("wg-rogue", attacker.succeed(f"{WG} genkey").strip(), "${
              net.meshIp topology { index = 99; }
            }")
            # The positive control: node2's key, stolen, at node2's mesh address. node1 lists
            # it, so the transport is open from the VLAN and only the key decides.
            s_hs, s_rx, s_tx, s_exporter, s_pinged = wg_attack("wg-stolen", NODE2_PRIV, MESH["node2"])
            detail = (f"own key: handshake={hs} rx={rx}B tx={tx}B exporter={exporter} ping={pinged};"
                      f" node2's stolen key: handshake={s_hs} rx={s_rx}B exporter={s_exporter} ping={s_pinged}")
            print(f"rogue-wg-key-gets-nothing: {detail}")
            control("rogue-wg-key-gets-nothing-stolen-key-works", s_hs and s_rx > 0 and s_exporter, detail)
            control("rogue-wg-key-gets-nothing",
                    not hs and rx == 0 and tx > 0 and not exporter and not pinged,
                    detail)

        with subtest("weak-host-route-refused: a route to the mesh address through the control IP gets nothing"):
            attacker.succeed(f"ip route add {M1}/32 via {CTRL} dev eth1.10")
            via_vlan = {p: reaches(f"nc -z -w5 {M1} {p}") for p in MESH_PORTS}
            pinged = reaches(f"ping -c2 -W2 {M1}", 10)
            exporter = reaches(f"curl -fsS -o /dev/null http://{M1}:9100/metrics", 15)
            # The same from a container on node1's br-app: a veth there is bridged like
            # an nspawn container's (50-veth). It is no declared app's port, so nothing
            # answers it, Grafana's two ports included (checks.container-isolation has the
            # declared app's side).
            node1.succeed(
                "ip netns add ciws8"
                " && ip link add ve-ciws8 type veth peer name eth0 netns ciws8"
                " && ip -n ciws8 addr add ${lib.removeSuffix ".1" topology.nodes.node1.appBridgeIp}.250/24 dev eth0"
                " && ip -n ciws8 link set lo up && ip -n ciws8 link set eth0 up"
                " && ip -n ciws8 route add default via ${topology.nodes.node1.appBridgeIp}"
            )
            node1.wait_until_succeeds("ip -d link show ve-ciws8 | grep -q 'master br-app'", timeout=60)
            node1.wait_until_succeeds("ip netns exec ciws8 ping -c1 -W2 ${topology.nodes.node1.appBridgeIp}", timeout=60)
            def from_container(p):
                return node1.execute(f"ip netns exec ciws8 timeout 8 bash -c 'exec 3<>/dev/tcp/{M1}/{p}'")[0] == 0
            from_ctr = {p: from_container(p) for p in MESH_PORTS}
            granted: list = []
            # The positive control: node1 itself reaches every one of them.
            local = {p: node1.execute(f"timeout 8 bash -c 'exec 3<>/dev/tcp/{M1}/{p}'")[0] == 0 for p in MESH_PORTS}
            node1.succeed("ip netns del ciws8")
            detail = (f"from the VLAN with a route: ports {via_vlan} ping={pinged} exporter={exporter};"
                      f" from a container on br-app: {from_ctr} (expected open: {granted}); node1 itself: {local}")
            print(f"weak-host-route-refused: {detail}")
            control("weak-host-route-refused-node-reaches", all(local.values()), detail)
            control("weak-host-route-refused",
                    not any(via_vlan.values()) and not pinged and not exporter
                    and all(v == (p in granted) for p, v in from_ctr.items()),
                    detail)

        with subtest("juicefs-pg-unreachable-on-vlan: PostgreSQL listens everywhere, the attacker reaches it nowhere"):
            everywhere = node1.execute("ss -Htln 'sport = :5432' | grep -qE '(0\\.0\\.0\\.0|\\*):5432'")[0] == 0
            local = all(node1.execute(f"timeout 8 bash -c 'exec 3<>/dev/tcp/{ip}/5432'")[0] == 0 for ip in (CTRL, M1))
            reached = {ip: reaches(f"nc -z -w5 {ip} 5432") for ip in (CTRL, M1, APP_IP, STG_IP)}
            detail = f"listens on every address={everywhere}; node1 itself connects={local}; attacker reached {reached}"
            print(f"juicefs-pg-unreachable-on-vlan: {detail}")
            control("juicefs-pg-unreachable-on-vlan", everywhere and local and not any(reached.values()), detail)

        with subtest("loki-forged-push-refused: the push a node's Vector makes, from the attacker"):
            def push(n, url, marker):
                body = json.dumps({"streams": [{"stream": {"node": "node1", "app": "platform"},
                                                "values": [[str(time.time_ns()), marker]]}]})
                n.succeed(f"cat > /tmp/push.json <<'EOF'\n{body}\nEOF")
                rc, out = n.execute(
                    f"timeout 15 curl -sS -o /dev/null -w '%{{http_code}}' -H 'Content-Type: application/json'"
                    f" --data-binary @/tmp/push.json {url}/loki/api/v1/push"
                )
                return rc, out.strip()
            forged = {ip: push(attacker, f"http://{ip}:3100", f"ci-forged-{ip}") for ip in (CTRL, M1)}
            genuine = push(node1, f"http://{M1}:3100", "ci-genuine-push")
            def landed(marker):
                out = node1.succeed(
                    f"curl -fsS -G http://{M1}:3100/loki/api/v1/query_range"
                    f" --data-urlencode 'query={{node=\"node1\"}} |= \"{marker}\"' | jq '.data.result | length'"
                )
                return int(out.strip()) > 0
            node1.wait_until_succeeds(
                f"curl -fsS -G http://{M1}:3100/loki/api/v1/query_range"
                " --data-urlencode 'query={node=\"node1\"} |= \"ci-genuine-push\"' | jq -e '.data.result | length > 0'",
                timeout=60,
            )
            stored = {ip: landed(f"ci-forged-{ip}") for ip in forged}
            detail = f"attacker: {forged} stored={stored}; node1's own push: {genuine}"
            print(f"loki-forged-push-refused: {detail}")
            control("loki-forged-push-refused",
                    genuine == (0, "204") and all(rc != 0 or code != "204" for rc, code in forged.values())
                    and not any(stored.values()),
                    detail)

        with subtest("etcd-unreachable: client and peer ports, on the control IP or through a route to the mesh"):
            node1.succeed(f"etcdctl --endpoints=http://{M1}:2379 put ci-ws8 positive-control")
            local = "positive-control" in node1.succeed(f"etcdctl --endpoints=http://{M1}:2379 get ci-ws8")
            reached = {f"{ip}:{p}": reaches(f"curl -sS -o /dev/null http://{ip}:{p}/version")
                       for ip in (CTRL, M1) for p in (2379, 2380)}
            attacker.succeed(f"ip route del {M1}/32")
            detail = f"node1 put and got it back={local}; attacker reached {reached}"
            print(f"etcd-unreachable: {detail}")
            control("etcd-unreachable", local and not any(reached.values()), detail)

    def main():
        wan.start()
        wan.wait_for_unit("s3.service")
        node1.start()
        attacker.start()

        with subtest("the cluster is up, its ACLs bootstrapped with the fixture token"):
            node1.wait_for_unit("nomad.service")
            node1.wait_until_succeeds(f"curl -fsS {TLSCURL} {nomad_url(CTRL, '/v1/status/leader')} | grep -q :", timeout=300)
            node1.wait_for_unit("nomad-bootstrap.service", timeout=600)
            node1.wait_until_succeeds(
                f"curl -fsS {TLSCURL} -H 'X-Nomad-Token: {NOMAD_TOKEN}' {nomad_url(CTRL, '/v1/acl/token/self')} | grep -q management",
                timeout=120,
            )
            ok, why = healthy()
            assert ok, why

        ws7()

        with subtest("the attacker is on the control VLAN and reaches every Nomad port"):
            attacker.succeed(
                "ip link set eth1 up"
                " && ip link add link eth1 name eth1.10 type vlan id 10"
                f" && ip addr add {ROGUE_IP}/24 dev eth1.10 && ip link set eth1.10 up"
            )
            attacker.wait_until_succeeds(f"ping -c1 -W2 {CTRL}", timeout=60)
            for port in (4646, 4647, 4648):
                attacker.succeed(f"nc -z -w5 {CTRL} {port}")

        ws8()

        with subtest("nomad reloads, not restarts, when its certificate is reissued"):
            # The unit carries the ciphertext's hash (modules/cluster-common.nix), so a
            # switch that brings a new certificate sends SIGHUP.
            node1.succeed("grep -q '^X-Reload-Triggers=' /etc/systemd/system/nomad.service")

        with subtest("rogue-baseline: the spike's attack, unchanged"):
            start_rogue("baseline")
            _, _, voter, _ = observe("baseline")
            uuids = attacker.succeed(
                f"strings {raft_db('baseline')} 2>/dev/null | grep -oE '{UUID_RE}' | sort -u || true"
            ).split()
            working = []
            for u in uuids + [""]:
                for url in (f"https://{CTRL}:4646", f"http://{ROGUE_IP}:4646"):
                    rc, out = attacker.execute(
                        f"curl -sk --max-time 5 -H 'X-Nomad-Token: {u}' {url}/v1/acl/token/self"
                    )
                    if rc == 0 and "management" in out:
                        working.append((u, url))
                # The job, through the rogue and straight at node1.
                for addr in (f"http://{ROGUE_IP}:4646", f"https://{CTRL}:4646"):
                    attacker.execute(
                        f"NOMAD_TOKEN={u} NOMAD_SKIP_VERIFY=1 timeout 20 nomad job run -detach -address={addr} {PWNED_JOB}"
                    )
            time.sleep(20)
            pwned = node1.execute("test -e /tmp/PWNED")[0] == 0
            alive = rogue_alive("baseline")
            ok, why = healthy()
            evict("baseline")
            control(
                "rogue-baseline",
                alive and not voter and not working and not pwned and ok,
                f"voter={voter} uuids={len(uuids)} working-tokens={working} /tmp/PWNED={pwned}"
                f" rogue-alive={alive} cluster: {why}",
            )

        with subtest("rogue-server-no-creds: refused at gossip, never in raft"):
            member, voter, tokens, alive, ok, detail = negative("nocreds")
            control("rogue-server-no-creds", alive and not member and not voter and tokens == 0 and ok, detail)

        with subtest("rogue-gossip-only: in serf, never a voter, no data"):
            member, voter, tokens, alive, ok, detail = negative("gossip")
            # The key got it into serf, so what stops it is TLS, not a wrong key.
            control("rogue-gossip-only-passed-gossip", member, detail)
            control("rogue-gossip-only", alive and not voter and tokens == 0 and ok, detail)

        with subtest("rogue-stolen-client-cert: a worker's certificate is not a server's"):
            member, voter, tokens, alive, ok, detail = negative("client")
            control("rogue-stolen-client-cert-passed-gossip", member, detail)
            control("rogue-stolen-client-cert", alive and not voter and tokens == 0 and ok, detail)

        with subtest("rogue-own-ca: a server name from another CA"):
            member, voter, tokens, alive, ok, detail = negative("ownca")
            control("rogue-own-ca-passed-gossip", member, detail)
            control("rogue-own-ca", alive and not voter and tokens == 0 and ok, detail)

        with subtest("stolen-server-cert-is-documented-limit: the gossip key and a server cert make a voter"):
            start_rogue("server")
            member, peer, voter, after = observe("server", until_voter=True)
            # The log reaches it as replication, which can trail the promotion.
            tokens = 0
            for _ in range(30):
                tokens = token_count("server")
                if tokens > 0 or not voter:
                    break
                time.sleep(2)
            # The token from the rogue's own raft.db, used on node1 with the stolen cert.
            cert = f"--cacert {PKI}/ca.crt --cert {PKI}/node1/agent.crt --key {PKI}/node1/agent.key"
            rc, out = attacker.execute(
                f"curl -fsS --max-time 10 {cert} -H 'X-Nomad-Token: {NOMAD_TOKEN}' https://{CTRL}:4646/v1/acl/token/self"
            )
            management = rc == 0 and "management" in out
            print(f"DOCUMENTED LIMIT: promoted to voter after {after}s (watch window {WATCH}s),"
                  f" token in raft.db {tokens} times, management on node1: {management}")
            evict("server")
            control(
                "stolen-server-cert-is-documented-limit",
                voter and after is not None and after < WATCH and tokens > 0 and management,
                f"serf={member} raft={peer} voter={voter} after={after}s tokens={tokens} management={management}",
            )

        with subtest("sighup-rotates-cert: a reissued agent certificate is served after a reload"):
            served = (f"${pkgs.openssl}/bin/openssl s_client -connect {CTRL}:4646 -CAfile \"$NOMAD_CACERT\""
                      " -cert \"$NOMAD_CLIENT_CERT\" -key \"$NOMAD_CLIENT_KEY\" </dev/null 2>/dev/null"
                      " | ${pkgs.openssl}/bin/openssl x509 -noout -fingerprint -sha256")
            old = node1.succeed(served).strip()
            new = node1.succeed(f"${pkgs.openssl}/bin/openssl x509 -noout -fingerprint -sha256 -in {MATERIAL}/rotated/agent.crt").strip()
            pid = node1.succeed("systemctl show -p MainPID --value nomad.service").strip()
            d = "/run/secrets/per-machine/node1/nomad-tls"
            node1.succeed(
                f"install -m 0400 {MATERIAL}/rotated/agent.crt {d}/agent.crt"
                f" && install -m 0400 {MATERIAL}/rotated/agent.key {d}/agent.key"
            )
            node1.succeed("systemctl reload nomad.service")
            # The reload reopens the HTTPS listener, and a connection in between is refused
            # (the same gap control-plane-failure waits out): that is "not yet", not a
            # failure. The verdict below still needs the new certificate served.
            def rotated(_):
                rc, out = node1.execute(served)
                return rc == 0 and out.strip() == new
            try:
                retry(rotated, timeout_seconds=60)
            except Exception:
                pass
            now = node1.succeed(served).strip()
            same_pid = node1.succeed("systemctl show -p MainPID --value nomad.service").strip() == pid
            ok, why = healthy()
            control(
                "sighup-rotates-cert",
                now == new and new != old and same_pid and ok,
                f"before={old} want={new} served={now} same-process={same_pid} cluster: {why}",
            )

        with subtest("scoped-tokens: each role does its job, and is refused one thing outside it"):
            node1.wait_for_unit("nomad-acl-init.service")
            for role in ("fence", "node-meta", "registrar", "autoscaler", "avc"):
                node1.wait_until_succeeds(f"test -s {TOKENS}/{role}", timeout=180)
            node1.wait_for_unit("nomad-bootstrap.service")
            job = json.dumps({"Job": nomad_api(node1, CTRL, f"/v1/job/{A_JOB}?namespace={NS}")})
            plan = ("POST", f"/v1/job/{A_JOB}/plan?namespace={NS}", job)
            jobs = ("GET", f"/v1/jobs?namespace={NS}", None)
            nodes = ("GET", "/v1/nodes", None)
            # operator:read. (The raft configuration wants management.)
            operator = ("GET", "/v1/operator/scheduler/configuration", None)
            # role: (policy, what it must be able to do, one thing it must be refused)
            SCOPE = {
                "fence": ("fence", [("GET", f"/v1/allocations?namespace={NS}", None), ("GET", "/v1/agent/self", None)], jobs),
                "node-meta": ("node-meta", [nodes], jobs),
                "registrar": ("registrar", [jobs, ("GET", f"/v1/job/{A_JOB}?namespace={NS}", None), plan], nodes),
                "autoscaler": ("autoscaler", [jobs, nodes, operator], plan),
                "avc": ("operator-read", [jobs, ("GET", f"/v1/job/{A_JOB}?namespace={NS}", None), nodes, operator], plan),
            }
            results: dict = {}
            ok = True
            for role, (policy, can, cannot) in SCOPE.items():
                tok = role_token(node1, role)
                me = json.loads(as_token(node1, CTRL, tok, "/v1/acl/token/self")[1])
                got_can = [as_token(node1, CTRL, tok, p, m, d)[0] for m, p, d in can]
                got_cannot = as_token(node1, CTRL, tok, cannot[1], cannot[0], cannot[2])[0]
                # Nothing a scoped token reaches is management's: the token list.
                got_acl = as_token(node1, CTRL, tok, "/v1/acl/tokens")[0]
                fine = (me["Type"] == "client" and me["Policies"] == [policy]
                        and me["Name"] == f"clan-node1-{role}"
                        and all(c == 200 for c in got_can) and got_cannot == 403 and got_acl == 403)
                ok = ok and fine
                results[role] = f"{me['Type']}/{me['Policies']}/{me['Name']} can={got_can} cannot={got_cannot} acl={got_acl}"
            # node-meta's job is a write: it sets this node's meta, and then takes it back.
            meta_tok = role_token(node1, "node-meta")
            rc_set = node1.execute(f"NOMAD_TOKEN={meta_tok} nomad node meta apply ci_scoped=1")[0]
            [n1] = nomad_api(node1, CTRL, "/v1/nodes")
            # The client batches meta to the servers (up to 10 s).
            meta_set = False
            for _ in range(15):
                meta_set = nomad_api(node1, CTRL, f"/v1/node/{n1['ID']}")["Meta"].get("ci_scoped") == "1"
                if meta_set:
                    break
                time.sleep(2)
            rc_unset = node1.execute(f"NOMAD_TOKEN={meta_tok} nomad node meta apply -unset ci_scoped")[0]
            results["node-meta-write"] = f"set rc={rc_set} seen={meta_set} unset rc={rc_unset}"
            ok = ok and rc_set == 0 and meta_set and rc_unset == 0
            print(json.dumps(results, indent=1))
            control("scoped-tokens", ok, json.dumps(results))

        def login(path):
            """(HTTP status, body) of a login with the JWT in `path`, as nomad-login@ does it."""
            node1.succeed(
                f"jq -n --rawfile t {path} '{{AuthMethodName: \"clan\", LoginToken: ($t | rtrimstr(\"\\n\"))}}'"
                " > /tmp/login.json"
            )
            out = node1.succeed(
                f"curl -sS {TLSCURL} -o /tmp/login.out -w '%{{http_code}}' -X POST"
                f" --data-binary @/tmp/login.json {nomad_url(CTRL, '/v1/acl/login')} || true; echo; cat /tmp/login.out"
            )
            code, _, body = out.partition("\n")
            return int(code or 0), body

        with subtest("jwt-*: a forged, misaddressed or unbound JWT buys no token"):
            code, body = login(f"{MATERIAL}/jwt/good")
            good = code == 200 and json.loads(body)["Policies"] == ["fence"]
            control("jwt-login-positive", good, f"a freshly minted fence JWT: HTTP {code} {body[:200]}")
            for name, path, why in [
                ("jwt-tampered-refused", "tampered", "no known key successfully validated"),
                ("jwt-wrong-audience-refused", "wrong-audience", "invalid audience"),
                ("jwt-unbound-role-refused", "unbound-role", "no role or policy bindings matched"),
            ]:
                code, body = login(f"{MATERIAL}/jwt/{path}")
                print(f"{name}: HTTP {code}: {body[:200]}")
                control(name, code in (400, 401, 403) and why in body and "SecretID" not in body,
                        f"HTTP {code}: {body[:300]}")

        with subtest("default-namespace-cannot-run: raw_exec and exec, even as management"):
            out: dict = {}
            for driver in ("raw_exec", "exec"):
                spec = json.dumps({"Job": {
                    "ID": f"ci-default-{driver}", "Name": f"ci-default-{driver}", "Namespace": "default",
                    "Type": "batch", "Datacenters": ["${topology.datacenter}"], "NodePool": "ci-hold",
                    "TaskGroups": [{"Name": "g", "Tasks": [{"Name": "t", "Driver": driver,
                                                            "Config": {"command": "/bin/sh", "args": ["-c", "id > /tmp/RAN-IN-DEFAULT"]}}]}],
                }})
                out[driver] = as_token(node1, CTRL, NOMAD_TOKEN, "/v1/jobs", "POST", spec)
            registered = nomad_api(node1, CTRL, "/v1/jobs?namespace=default")
            ran = node1.execute("test -e /tmp/RAN-IN-DEFAULT")[0] == 0
            print(f"default-namespace-cannot-run: { {d: (c, b.strip()[:160]) for d, (c, b) in out.items()} } registered={registered} ran={ran}")
            control(
                "default-namespace-cannot-run",
                all(code != 200 and f'used task driver "{d}" is not allowed in namespace "default"' in body
                    for d, (code, body) in out.items())
                and registered == [] and not ran,
                f"{ {d: (c, b[:200]) for d, (c, b) in out.items()} } registered={registered} ran={ran}",
            )

        with subtest("fence-403-is-loud: a token the cluster forgot heals; a refusal that persists fails the unit"):
            def fence_ts():
                out = node1.execute(f"awk '/^cluster_fence_last_success_timestamp_seconds/ {{print $2}}' {METRIC}")[1].strip()
                return int(float(out or 0))
            def unit_failed_metric():
                node1.succeed(f"curl -fsS -o /tmp/ne http://{M1}:9100/metrics")
                return node1.execute(
                    """grep -qE 'node_systemd_unit_state[{]name="nomad-fence.service",state="failed"[^}]*[}] 1' /tmp/ne"""
                )[0] == 0
            bogus = "00000000-0000-4000-8000-000000000000"
            node1.wait_until_succeeds(f"test -s {TOKENS}/fence", timeout=180)
            node1.succeed("systemctl start nomad-fence.service")
            healthy_ts = fence_ts()
            # 1. A token the cluster does not know (its ACL state rebuilt, say): the fence
            #    logs in again by itself and completes its run.
            node1.succeed(f"printf %s {bogus} > {TOKENS}/fence")
            since = node1.succeed("date +%s").strip()
            time.sleep(1.1)
            rc1 = node1.execute("systemctl start nomad-fence.service")[0]
            log1 = node1.succeed(f"journalctl -u nomad-fence.service --since=@{since} --no-pager -o cat")
            healed_ts = fence_ts()
            new_tok = node1.succeed(f"cat {TOKENS}/fence").strip()
            detail1 = (f"start rc={rc1}, logged the refusal and the fresh login={'refused (HTTP 403' in log1 and 'logging in again' in log1};"
                       f" metric {healthy_ts} -> {healed_ts}; token replaced={new_tok != bogus}")
            print(f"fence-stale-token-relogs: {detail1}")
            control("fence-stale-token-relogs",
                    rc1 == 0 and "refused (HTTP 403" in log1 and "logging in again" in log1
                    and healed_ts > healthy_ts and new_tok not in ("", bogus),
                    detail1)
            # 2. A refusal the login can't cure: the token bogus again, and the login's own
            #    JWT replaced by a tampered one (refused, jwt-tampered-refused). Loud.
            node1.succeed(f"cp {JWT_FENCE} /tmp/jwt-fence.good && cp {MATERIAL}/jwt/tampered {JWT_FENCE}")
            node1.succeed(f"printf %s {bogus} > {TOKENS}/fence")
            time.sleep(1.1)
            rc = node1.execute("systemctl start nomad-fence.service")[0]
            failed = node1.execute("systemctl is-failed --quiet nomad-fence.service")[0] == 0
            said = node1.execute("journalctl -u nomad-fence.service --no-pager | grep -q 'still refused after a fresh login'")[0] == 0
            stale_ts = fence_ts()
            # What UnitFailed reads (lib/alert-rules.nix), from node1's own exporter.
            exported = False
            for _ in range(20):
                exported = unit_failed_metric()
                if exported:
                    break
                time.sleep(3)
            print(f"fence-403-is-loud: start rc={rc} failed={failed} logged={said} metric {healed_ts} -> {stale_ts} exporter={exported}")
            control(
                "fence-403-is-loud",
                rc != 0 and failed and said and stale_ts == healed_ts > 0 and exported,
                f"start rc={rc} unit failed={failed} logged the refusal={said}"
                f" metric {healed_ts} -> {stale_ts} exporter shows failed={exported}",
            )
            # And it recovers by itself at the next login.
            node1.succeed(f"cp /tmp/jwt-fence.good {JWT_FENCE}")
            node1.succeed("systemctl restart nomad-login@fence.service")
            node1.succeed("systemctl start nomad-fence.service")
            control("fence-403-recovers", fence_ts() > stale_ts and node1.execute("systemctl is-failed --quiet nomad-fence.service")[0] != 0,
                    f"metric now {fence_ts()}")

        with subtest("token-check-relogs: a role's token the cluster refuses gets a fresh login within one check"):
            node1.wait_until_succeeds(f"test -s {TOKENS}/avc", timeout=180)
            node1.succeed(f"printf %s 00000000-0000-4000-8000-000000000000 > {TOKENS}/avc")
            node1.succeed("systemctl start nomad-token-check.service")
            node1.wait_until_succeeds(f"test \"$(cat {TOKENS}/avc)\" != 00000000-0000-4000-8000-000000000000", timeout=60)
            code, body = as_token(node1, CTRL, role_token(node1, "avc"), "/v1/acl/token/self")
            said = node1.execute("journalctl -u nomad-token-check.service --no-pager | grep -q 'the avc token is refused'")[0] == 0
            detail = f"after the check: avc token HTTP {code} {body[:120]}; logged={said}"
            print(f"token-check-relogs: {detail}")
            control("token-check-relogs", code == 200 and said, detail)

    run_main(main)
  '';
}
