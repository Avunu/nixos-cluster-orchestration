# The fixture topology: what this repository's checks and VM tests run against.
#
# Every public address is documentation-only (RFC 5737, RFC 3849) and every name
# is under example.com / example.net, so nothing here can reach anything real.
# The private VLAN, app and private-service ranges are RFC 1918, because the
# documentation ranges have no /16 to carve per-node app subnets from.
#
# node1 is the real node and carries every role. node2 and node3 are placeholders,
# which tests/cluster.nix promotes to voters.
#
# Every node opts out of boot security, explicitly: these are VM tests with no real
# data, and a VM here has neither the disks nor the TPM for it. tests/fixtures/secure
# is this same topology with node1 not opted out, for the tests that need that.
#
# See README.md "Topology schema" for what each field means.
{
  datacenter = "dc1";
  region = "fixture-1";

  internalDomain = "svc.cluster.local";

  # node1 alone carries `etcd`, which modules/storage-etcd.nix refuses for a real site
  # (a one-member etcd can never grow: it would split when two more are tagged). The
  # single-node VM tests still need an etcd to run against, so the fixture says so.
  # tests/cluster.nix and tests/voter-growth.nix tag three, or none.
  insecureSingleMemberEtcd = "fixture: single-node VM tests need an etcd";

  # Every node here opts out of boot security, and each would then hold the fleet's
  # shared keys on a plaintext disk (modules/boot-security.nix). There are no real keys.
  insecureFleetKeysOnPlaintextDisk = "fixture: VM tests, placeholder keys only";

  # Stays at 1500, unlike the template. The VDE switch these tests run on silently
  # drops anything larger, so at 9000 Nomad, etcd and JuiceFS would hang rather than
  # fail. Jumbo frames get their own test, on a link that really carries them.
  vlans = {
    control = {
      id = 10;
      subnet = "10.10.0.0/24";
      mtu = 1500;
    };
    app = {
      id = 20;
      subnet = "10.20.0.0/16";
      mtu = 1500;
    };
    storage = {
      id = 30;
      subnet = "10.30.0.0/24";
      mtu = 1500;
    };
  };

  privateServices = "10.21.0.0/24";

  # WireGuard control mesh. A node takes <subnet base>.<index>.
  mesh = {
    subnet = "10.25.0.0/24";
    port = 51820;
    mtu = 1420;
  };

  # Read by a node that does not opt out (tests/fixtures/secure).
  security = {
    initrdSshPort = 2222;
    nomadTlsRotation = 0;
  };

  deploy = {
    flakeUrl = "github:example/cluster";
    pullInterval = "*:0/10";
  };

  # The VM tests' `wan` machine answers for these hostnames.
  objectStorage = {
    endpoint = "https://s3.example.net";
    region = "fixture-1";
    juicefsBucket = "fixture-juicefs";
  };

  logging.retention = "720h";

  alerting = {
    cloudflareAccountId = "00000000000000000000000000000000";
    from = "alerts@example.com";
    to = [ "ops@example.com" ];
    heartbeatUrl = null;
    # The real Worker on the wan VM (tests/lib/cluster-harness.nix). Not 443: the
    # stand-in object storage holds that port on every address there.
    auditUrl = "https://audit.example.net:8443/event";
  };

  backup = {
    repoSalt = "fixture-repo-salt";
    target = {
      type = "s3";
      endpoint = "https://backup.example.net";
      bucket = "fixture-backups";
      region = "us-east-1";
    };
    schedule = "*-*-* 07:15:00";
    maintenance = "Sun *-*-* 09:00:00";
    verify = "Sun *-*-* 10:00:00";
    retention = {
      daily = 7;
      weekly = 4;
      monthly = 12;
    };
    uploadLimitKiB = 0;
  };

  nodes = {
    node1 = {
      index = 1;
      hostName = "node1";
      insecurePlaintextBoot = "fixture: VM tests, no real data";
      # Takes each new boot stack first; node2 and node3 follow it (modules/pull-deploy.nix).
      canary = true;
      fqdn = "node1.example.com";
      deployHost = "192.0.2.11";
      roleTag = "worker";
      tags = [
        "worker"
        "nomad-server"
        "etcd"
        "nomad-leader"
        "juicefs-meta"
        "metrics"
        "backup"
      ];
      hostId = "f0000001";

      publicIp4 = "192.0.2.11";
      publicGw4 = "192.0.2.254";

      # The gateway sits outside the /64 on purpose: the module's on-link route
      # is under test.
      public6Prefix = "2001:db8:0:1";
      publicIp6 = "2001:db8:0:1::1";
      publicPrefix6 = 64;
      publicGw6 = "2001:db8:0:ff::1";

      wanInterface = "eno1np0";
      vrackInterface = "enp3s0f1np1";

      controlIp = "10.10.0.11";
      storageIp = "10.30.0.11";
      appBridgeIp = "10.20.1.1";
      appSubnet = "10.20.1.0/24";
      appDhcpPoolOffset = 10;
      appDhcpPoolSize = 200;
    };

    node2 = {
      provisioned = false;
      index = 2;
      hostName = "node2";
      insecurePlaintextBoot = "fixture: VM tests, no real data";
      fqdn = "node2.example.com";
      deployHost = "203.0.113.2";
      roleTag = "worker";
      # No `nomad-server` / `etcd` until provisioned: quorum size is derived from
      # these tags, so a placeholder voter would make Nomad and etcd wait for a
      # machine that does not exist.
      tags = [ "worker" ];
      hostId = "f0000002";
      publicIp4 = "203.0.113.2";
      publicGw4 = "203.0.113.254";
      public6Prefix = "2001:db8:0:2";
      publicIp6 = "2001:db8:0:2::1";
      publicPrefix6 = 64;
      publicGw6 = "2001:db8:0:ff::1";
      wanInterface = "eno1np0";
      vrackInterface = "enp3s0f1np1";
      controlIp = "10.10.0.12";
      storageIp = "10.30.0.12";
      appBridgeIp = "10.20.2.1";
      appSubnet = "10.20.2.0/24";
      appDhcpPoolOffset = 10;
      appDhcpPoolSize = 200;
    };

    node3 = {
      provisioned = false;
      index = 3;
      hostName = "node3";
      insecurePlaintextBoot = "fixture: VM tests, no real data";
      fqdn = "node3.example.com";
      deployHost = "203.0.113.3";
      roleTag = "worker";
      tags = [ "worker" ];
      hostId = "f0000003";
      publicIp4 = "203.0.113.3";
      publicGw4 = "203.0.113.254";
      public6Prefix = "2001:db8:0:3";
      publicIp6 = "2001:db8:0:3::1";
      publicPrefix6 = 64;
      publicGw6 = "2001:db8:0:ff::1";
      wanInterface = "eno1np0";
      vrackInterface = "enp3s0f1np1";
      controlIp = "10.10.0.13";
      storageIp = "10.30.0.13";
      appBridgeIp = "10.20.3.1";
      appSubnet = "10.20.3.0/24";
      appDhcpPoolOffset = 10;
      appDhcpPoolSize = 200;
    };
  };

  stateVersion = "25.11";
}
