# The single source of truth for the cluster, as pure data. Every module derives
# its networkd units, nftables ruleset, Nomad settings, Prometheus targets and
# quorum membership from it. README.md in the library has the full schema.
#
# Replace every example value: the addresses here are documentation-only.
{
  datacenter = "dc1";
  region = "region-1";

  internalDomain = "svc.cluster.local";

  # Tagged VLANs on each node's private trunk NIC. The app VLAN's addressing is
  # fixed: nodes take 10.20.0.<index>, containers 10.20.<index>.0/24.
  #
  # Jumbo frames. The MTU has to be one value across a VLAN, which is why it lives
  # here and not per node. A private network that doesn't really carry 9000 is a
  # silent blackhole: pings, handshakes and small requests work while transfers hang.
  # So before any data, between every pair of nodes on every VLAN:
  #   ping -M do -s 8972 <peer>
  # Not every provider or server range carries it. If that fails, set all three to
  # 1500, and the mesh below follows to 1420.
  vlans = {
    control = {
      id = 10;
      subnet = "10.10.0.0/24";
      mtu = 9000;
    };
    app = {
      id = 20;
      subnet = "10.20.0.0/16";
      mtu = 9000;
    };
    storage = {
      id = 30;
      subnet = "10.30.0.0/24";
      mtu = 9000;
    };
  };

  # Addresses inside containers, reached only through their tunnel.
  privateServices = "10.21.0.0/24";

  # WireGuard control mesh: every service but Nomad runs over it. A node takes
  # <subnet base>.<index>. Must not overlap anything above.
  mesh = {
    subnet = "10.25.0.0/24";
    # port = 51820;
    # mtu = 8920;    # the default: vlans.control.mtu - 80, WireGuard's largest overhead.
  };

  # Disk encryption and unattended unlock need nothing here: each node's disks unlock
  # from its own TPM, and its boot fields are under `nodes` below.
  security = {
    # initrdSshPort = 2222;    # not 22: the initrd host key is a different key.
    # nomadTlsRotation = 0;    # bump to reissue every Nomad agent certificate.
  };

  # Every node rebuilds itself from this flake on this timer.
  deploy = {
    flakeUrl = "github:OWNER/my-cluster";
    pullInterval = "*:0/10";
    # A site with more than one node needs a canary (`canary = true` on node1 below).
    # Going without one takes a reason:
    # withoutCanary = "<reason>";
  };

  # The cluster-ci Worker, a GitHub App's endpoint (README.md in the library, "Previews
  # and continuous deployment"). With it set, every node deploys the moment this
  # repository's branch moves, and an app with `preview.slots` gets a container per
  # pull request of its project.
  # ci.url = "https://cluster-ci.example.workers.dev";

  # S3-compatible storage for JuiceFS. Credentials: `clan vars`. Loki keeps its logs
  # on the metrics node's own encrypted disk, not here.
  objectStorage = {
    endpoint = "https://s3.example.net";
    region = "region-1";
    juicefsBucket = "my-cluster-juicefs";
    # Only for apps with `archive.enable`: a bucket of its own, since each such
    # app's container holds an S3 key to it.
    # dbArchiveBucket = "my-cluster-db-archive";
  };

  logging.retention = "720h";

  # Alert emails, through the Cloudflare Email Sending API.
  alerting = {
    cloudflareAccountId = "00000000000000000000000000000000";
    from = "alerts@example.com";
    to = [ "ops@example.com" ];
    heartbeatUrl = null;
    # The watchdog Worker's /event URL, for the off-host audit trail. Only an
    # opted-out node may leave this null.
    auditUrl = "https://watchdog.example.com/event";
  };

  # One restic repository per app, on a target away from the object storage.
  backup = {
    # Salts the repository paths on the target. Not a secret, but private to the
    # site: `openssl rand -hex 16`.
    repoSalt = "REPLACE-ME";
    target = {
      type = "s3"; # s3 | rest | b2 | local
      endpoint = "https://backup.example.net";
      bucket = "my-cluster-backups";
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

  # The key is the machine name everywhere, and must equal hostName. One node
  # carries every singleton role until more exist. A single voter has no HA, and no
  # etcd: etcd is created once, from its tags, and never grows. To form a quorum, tag
  # two more nodes `nomad-server` and all three `etcd` in ONE commit, the commit that
  # fills in their real addressing (README.md, the tags under "Topology schema").
  # Nomad grows from one voter safely; etcd tagged a node at a time would split or
  # never form, and modules/storage-etcd.nix refuses any count but 0 or an odd
  # number from 3.
  nodes = {
    node1 = {
      index = 1;
      hostName = "node1";
      fqdn = "node1.example.com";
      # The canary: each new boot stack (a nixpkgs, kernel, Lanzaboote, clan or library
      # bump) activates here first, and every other node waits until this one has been
      # rebooted into it, with someone watching, and unlocked from its TPM on its own. Exactly
      # one node, a real one with boot security. README.md, "Deploying".
      canary = true;
      deployHost = "192.0.2.11"; # SSH target
      roleTag = "worker";
      tags = [
        "worker"
        "nomad-server"
        "nomad-leader"
        "juicefs-meta"
        "metrics"
      ];
      hostId = "00000000"; # ZFS: head -c4 /dev/urandom | od -A none -t x4

      publicIp4 = "192.0.2.11";
      publicGw4 = "192.0.2.254";
      # The node's routed /64. Containers take derived addresses from it.
      public6Prefix = "2001:db8:0:1";
      publicIp6 = "2001:db8:0:1::1";
      publicPrefix6 = 64;
      publicGw6 = "2001:db8:0:ff::1";

      wanInterface = "eth0";
      vrackInterface = "eth1"; # the private VLAN trunk

      # Kernel modules for the WAN NIC in the initrd. Hardware-specific and not
      # detectable at evaluation, so this node refuses to evaluate until you fill it
      # in, e.g. [ "igb" "mlx5_core" ]. `lspci -k` on the node names them.
      initrdNicModules = [ ];
      # disks = { a = "/dev/nvme0n1"; b = "/dev/nvme1n1"; };  # the default. Use
      # /dev/disk/by-id/... on hardware whose enumeration swaps.

      # There is one opt-out from disk encryption and Secure Boot, per node, and it
      # takes a reason. Such a node gets plaintext disks and warns at every
      # evaluation. Keeping apps off it is not enough: like every node it holds the
      # fleet's shared keys (the JuiceFS volume key, S3, restic, the backup target),
      # so its disk alone reads every client's data. The site must also set
      # `insecureFleetKeysOnPlaintextDisk = "<reason>";` at the top level, saying so.
      # insecurePlaintextBoot = "lab machine";

      controlIp = "10.10.0.11";
      storageIp = "10.30.0.11";
      appBridgeIp = "10.20.1.1";
      appSubnet = "10.20.1.0/24";
      appDhcpPoolOffset = 10;
      appDhcpPoolSize = 200;
    };
  };

  stateVersion = "25.11";
}
