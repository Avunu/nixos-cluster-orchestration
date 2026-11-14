# VM test: an app's local state follows the app, for real, on three nodes with ZFS.
#
# Runs the REAL modules/app-state.nix (and so modules/app-state.py) with a stand-in for
# the app: `container@demo` is an ordinary unit that appends to a file in its state, so
# what the module adds to it (acquire before, release after) is what is under test, and
# starting the unit on a node is what Nomad placing the app there comes to. The pool is
# on a disk of its own and legacy-mounted at /state, as rpool/state is. The replication timer is
# off until the end, so each step says which node snapshots and which pulls.
#
# What it proves:
#   - a first start, with every node answering and none holding state, makes the dataset;
#   - the others receive it, unmounted and read-only, and then only what changed;
#   - a start on another node while the first is up stops the app there, takes its last
#     write, and loses nothing: a move;
#   - with the holder dead, a start elsewhere waits out the fence, then takes the newest
#     copy ANY reachable node has, not merely its own;
#   - the dead node, back, has its copy set aside whole (the write only it had is in the
#     orphan) and receives the app's new history; nothing deletes the orphan unasked;
#   - a replica that a clone hangs off (a preview) keeps receiving;
#   - a directory from before datasets is adopted where it is, and refused elsewhere;
#   - a new app is not started empty while a node that might hold it is silent;
#   - the timer does all of it by itself.
#
# Run: nix build .#checks.x86_64-linux.app-state -L   (needs KVM)
{ pkgs, lib }:
let
  clusterLib = import ../lib { inherit lib; };

  # The test network's own addresses stand in for the mesh: <subnet>.<index>.
  topology = {
    mesh.subnet = "192.168.1.0/24";
    nodes = {
      a.index = 1;
      b.index = 2;
      c.index = 3;
    };
  };

  stubClusterApps =
    { lib, ... }:
    {
      options.clusterApps = lib.mkOption {
        default = { };
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              localState = lib.mkOption {
                type = lib.types.attrsOf lib.types.str;
                default = { };
              };
              nomad.killTimeoutSeconds = lib.mkOption {
                type = lib.types.int;
                default = 5;
              };
            };
          }
        );
      };
    };

  app = name: {
    description = "stand-in for the ${name} container";
    serviceConfig.ExecStart = pkgs.writeShellScript "app-${name}" ''
      mkdir -p /state/clients/${name}/data
      while true; do
        ${pkgs.coreutils}/bin/date +%s.%N >> /state/clients/${name}/data/log
        ${pkgs.coreutils}/bin/sleep 0.2
      done
    '';
  };

  node = name: {
    imports = [
      stubClusterApps
      ../modules/app-state.nix
    ];
    _module.args = {
      inherit topology clusterLib;
      nodeName = name;
    };
    virtualisation.memorySize = 1536;
    # The pool's disk: one that is still there after the VM is killed.
    virtualisation.emptyDiskImages = [ 2048 ];
    boot.supportedFilesystems = [ "zfs" ];
    networking.hostId = "8425e34${toString topology.nodes.${name}.index}";
    networking.firewall.allowedTCPPorts = [ clusterLib.net.statePort ];
    # `container@demo` is this test's own unit, not a template instance.
    boot.enableContainers = false;

    clusterApps.demo.localState."/var/lib/demo" = "/state/clients/demo/data";
    clusterApps.old.localState."/var/lib/old" = "/state/clients/old/data";
    clusterApps.fresh.localState."/var/lib/fresh" = "/state/clients/fresh/data";
    systemd.services."container@demo" = app "demo";
    systemd.services."container@old" = app "old";
    systemd.services."container@fresh" = app "fresh";

    systemd.timers.cluster-state-replicate.wantedBy = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.jq ];
  };
in
pkgs.testers.runNixOSTest {
  name = "cluster-app-state";

  nodes.a = node "a";
  nodes.b = node "b";
  nodes.c = node "c";

  testScript = ''
    import time

    DS = "tank/state/apps/demo"
    nodes = {"a": a, "b": b, "c": c}

    def pool(m, create):
        if create:
            m.succeed("zpool create tank /dev/vdb && zfs create -o mountpoint=legacy tank/state")
        else:
            m.succeed("zpool import tank")
        m.succeed("mkdir -p /state && mount -t zfs tank/state /state && mkdir -p /state/clients")

    def replicate(*ms):
        for m in ms:
            m.succeed("systemctl start cluster-state-replicate.service")

    def head(m, ds=DS):
        return m.succeed(f"zfs list -H -t snapshot -d 1 -o guid -s createtxg {ds} | tail -1").strip()

    def prop(m, key, ds=DS):
        return m.succeed(f"zfs get -H -o value {key} {ds}").strip()

    def write(m, name):
        m.succeed(f"echo {name} > /state/clients/demo/data/{name} && sync")

    start_all()
    for m in nodes.values():
        m.wait_for_unit("multi-user.target")
        m.wait_for_unit("cluster-state.socket")
        pool(m, create=True)

    with subtest("a first start, with every node asked and none holding it, makes the dataset"):
        a.succeed("systemctl start container@demo.service")
        a.wait_until_succeeds("test -s /state/clients/demo/data/log")
        assert a.succeed("findmnt -n -o SOURCE /state/clients/demo").strip() == DS
        assert prop(a, "cluster:holder") == "a"
        assert prop(a, "readonly") == "off"

    with subtest("the others receive it: unmounted, read-only, the same snapshot"):
        write(a, "first")
        replicate(a, b, c)
        for m in (b, c):
            assert head(m) == head(a), m.name
            assert prop(m, "mounted") == "no" and prop(m, "readonly") == "on", m.name
            assert prop(m, "cluster:holder") == "-", m.name
            m.fail("test -e /state/clients/demo/data")
        # Then only what changed: the second pull is an incremental stream.
        write(a, "second")
        replicate(a, b)
        assert head(b) == head(a)
        assert int(b.succeed(f"zfs list -H -t snapshot -d 1 -o name {DS} | wc -l")) >= 2
        metrics = a.succeed("cat /var/lib/prometheus-node-exporter-text/cluster_state.prom")
        assert 'cluster_state_holder{app="demo"} 1' in metrics, metrics
        assert 'cluster_state_replica_lag_seconds{app="demo"} 0' in b.succeed("cat /var/lib/prometheus-node-exporter-text/cluster_state.prom")

    with subtest("a clone hanging off a replica's snapshot (a preview) does not stop the next one arriving"):
        snap = c.succeed(f"zfs list -H -t snapshot -d 1 -o name -s createtxg {DS} | grep @repl- | tail -1").strip()
        c.succeed(f"zfs create -o mountpoint=none tank/preview && zfs clone -o mountpoint=/pv -o readonly=off {snap} tank/preview/demo-pv1")
        c.succeed("grep -qx first /pv/data/first && echo mine > /pv/data/preview")
        write(a, "third")
        replicate(a, c)
        assert head(c) == head(a)

    with subtest("a move: started on b while a is up, it is stopped on a and nothing is lost"):
        write(a, "unsnapshotted")
        b.succeed("systemctl start container@demo.service")
        a.succeed("test \"$(systemctl is-active container@demo.service)\" = inactive")
        assert prop(a, "cluster:holder") == "released" and prop(a, "readonly") == "on"
        assert prop(a, "mounted") == "no"
        b.succeed("grep -qx unsnapshotted /state/clients/demo/data/unsnapshotted")
        b.fail("journalctl -u container@demo.service | grep -q 'not from a clean stop'")
        assert prop(b, "cluster:holder") == "b"
        # The log a wrote until it was stopped is the log b goes on with.
        b.succeed("test \"$(wc -l < /state/clients/demo/data/log)\" -gt 5")
        assert b.succeed("cluster-state where demo").strip() == ""
        assert a.succeed("cluster-state where demo").strip() == "b"
        # a is a replica now, from the snapshot it handed over.
        write(b, "on-b")
        replicate(b, a, c)
        assert head(a) == head(b) == head(c)
        assert prop(a, "cluster:holder") == "-"
        assert a.succeed("cluster-state orphans").strip() == ""

    with subtest("the holder dies: a start elsewhere waits out the fence, then takes the newest copy any node has"):
        write(b, "c-has-it")
        replicate(b, c)  # c is ahead of a now
        write(b, "only-on-b")  # in no snapshot: what a death loses
        b.crash()
        began = time.time()
        a.succeed("systemctl start container@demo.service")
        waited = time.time() - began
        # 60 s after a cut-off node's last heartbeat it stops its apps, in up to 5 s here.
        assert waited > 60, f"started after {waited:.0f}s, without waiting for b to have stopped"
        a.succeed("journalctl -u container@demo.service | grep -q 'b not answering; waiting'")
        a.succeed("journalctl -u container@demo.service | grep -q 'taking its state from c'")
        # And says that this start is not a handover, for whoever archives the database.
        a.succeed("journalctl -u container@demo.service | grep -q 'not from a clean stop'")
        a.succeed("grep -qx c-has-it /state/clients/demo/data/c-has-it")
        a.fail("test -e /state/clients/demo/data/only-on-b")

    with subtest("the dead node, back: its copy is set aside whole, and it receives the new history"):
        write(a, "after-failover")
        replicate(a)
        b.start()
        b.wait_for_unit("multi-user.target")
        pool(b, create=False)
        assert prop(b, "cluster:holder") == "b" and prop(b, "mounted") == "no"
        replicate(b)
        assert head(b) == head(a) and prop(b, "cluster:holder") == "-"
        orphans = b.succeed("cluster-state orphans").strip().splitlines()
        assert len(orphans) == 1 and orphans[0].startswith("tank/state/orphans/demo-"), orphans
        orphan = orphans[0].split()[0]
        b.succeed(f"zfs set mountpoint=/orphan {orphan} && zfs mount {orphan} && grep -qx only-on-b /orphan/data/only-on-b")
        b.succeed(f"zfs unmount {orphan}")
        assert "cluster_state_orphans 1" in b.succeed("cat /var/lib/prometheus-node-exporter-text/cluster_state.prom")
        # Nothing deletes it unasked.
        b.succeed(f"cluster-state drop-orphan {orphan} | grep -q 'add --yes'")
        b.succeed(f"zfs list {orphan}")
        b.succeed(f"cluster-state drop-orphan {orphan} --yes")
        b.fail(f"zfs list {orphan}")
        # And b can take the app back, with everything a wrote.
        b.succeed("systemctl start container@demo.service")
        b.succeed("grep -qx after-failover /state/clients/demo/data/after-failover")
        a.succeed("test \"$(systemctl is-active container@demo.service)\" = inactive")

    with subtest("a directory from before datasets is adopted where it is, and refused elsewhere"):
        c.succeed("mkdir -p /state/clients/old/data && echo legacy > /state/clients/old/data/row")
        a.fail("systemctl start container@old.service")
        a.succeed("journalctl -u container@old.service | grep -q \"is a directory on c\"")
        a.fail("zfs list tank/state/apps/old")
        c.succeed("systemctl start container@old.service")
        assert c.succeed("findmnt -n -o SOURCE /state/clients/old").strip() == "tank/state/apps/old"
        c.succeed("grep -qx legacy /state/clients/old/data/row")
        c.succeed("grep -qx legacy /state/clients/.old.before-datasets/data/row")
        # From then on it moves like any other.
        a.succeed("systemctl start container@old.service")
        a.succeed("grep -qx legacy /state/clients/old/data/row")

    with subtest("a new app is not started empty while a node that might hold it is silent"):
        c.crash()
        a.fail("systemctl start container@fresh.service")
        a.succeed("journalctl -u container@fresh.service | grep -q 'c cannot be asked for one'")
        a.fail("zfs list tank/state/apps/fresh")
        # Said by a person, it is.
        a.succeed("cluster-state init fresh && systemctl start container@fresh.service")
        a.wait_until_succeeds("test -s /state/clients/fresh/data/log")
        c.start()
        c.wait_for_unit("multi-user.target")
        pool(c, create=False)

    with subtest("the timer does all of it by itself"):
        since = int(b.succeed("date +%s"))
        write(b, "by-the-timer")
        for m in nodes.values():
            m.succeed("systemctl start cluster-state-replicate.timer")
        # A snapshot b made after the write, on the nodes that only receive.
        for m in (a, c):
            m.wait_until_succeeds(
                f"test \"$(zfs list -Hp -t snapshot -d 1 -o creation -s createtxg {DS} | tail -1)\" -gt {since}", timeout=300
            )
        print(a.succeed("cluster-state status"))
        out = a.succeed("cluster-state status")
        assert "running" in out and "replica" in out, out
  '';
}
