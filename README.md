# nixos-cluster-orchestration

A NixOS module library for running application containers on a small cluster of bare-metal machines: `systemd-nspawn` containers, started and stopped by HashiCorp Nomad, sharing state through an encrypted JuiceFS volume, each reaching the internet through its own outbound Cloudflare Tunnel, on top of [clan-core](https://clan.lol). Every node's disks are encrypted and unlock unattended only into the node's own signed boot.

There is no Kubernetes, image registry or load balancer. Each node compiles its own closure locally from a flake, Nomad only turns pre-built dormant containers on and off, and no inbound port is opened for any application.

This repository holds no site's details. You keep your topology, apps and encrypted secrets in your own private flake, which calls [`lib.mkCluster`](#the-interface).

```sh
nix flake init -t github:Avunu/nixos-cluster-orchestration
```

**Contents.** [Architecture](#architecture) · [The interface](#the-interface) · [Encryption](#encryption) · [Installing a node](#installing-a-node) · [Recovery](#recovery) · [Real hardware checklist](#real-hardware-checklist) · [Residual risks](#residual-risks) · [Topology schema](#topology-schema) · [Kinds](#kinds) · [Operations](#operations) · [Upgrading a running cluster](#upgrading-a-running-cluster) · [Testing](#testing) · [Defaults awaiting a decision](#defaults-awaiting-a-decision) · [Known limitations](#known-limitations) · [License](#license)

## Architecture

- **The topology is the single source of truth.** Nodes, VLANs, addressing, object storage, the Tang server and role tags are one plain Nix attrset. Every module derives its networkd units, nftables ruleset, Nomad settings, quorum membership and Prometheus targets from it.
- **clan-core is the fleet substrate.** It owns the machine registry, role assignment, the secret lifecycle (`vars`) and bare-metal install. It has no analogue for the orchestration below, which this library owns. The clan inventory is a mechanical projection of the topology.
- **Bootstrap is push, steady state is pull.** `clan machines install` installs a node (through `avc boot install`, see [Installing a node](#installing-a-node)). After that, every node rebuilds itself from your flake on a timer (`modules/pull-deploy.nix`), so deploying means pushing a commit.
- **Every node is encrypted unless it says why not.** Both disks are LUKS2 under the ZFS mirror, the boot is signed with keys made on the node, and the disk key is released only to that signed boot with the Tang server reachable. A node that sets nothing fails to evaluate. See [Encryption](#encryption).
- **Apps are one short file each.** `apps/<name>.nix` is one `clusterApps.<name>` entry, and its [kind](#kinds) fills in the container, paths, sockets, secrets, backups and ingress. Each entry becomes a dormant container on every node, plus a Nomad job that starts and stops it.
- **Ingress is a tunnel per app, over a unix socket.** Each container runs its own `cloudflared` against a unix socket. See [Ingress](#ingress).
- **Storage has two tiers.** Local ZFS (`modules/zfs-host.nix`) holds anything latency-sensitive, such as database directories. JuiceFS over S3 (`modules/storage-juicefs.nix`) holds shared state that follows an app between nodes. The volume is encrypted, and every mount refuses one that is not.
- **Secrets are `clan vars`** on clan's plain `age` backend. Values are generated offline, committed encrypted, and decrypted on the host at activation. Containers never hold a key: the plaintext is bind-mounted in.
- **Cluster roles are tags, not positions.** Singleton services (the JuiceFS metadata engine, the Nomad job registrar, Prometheus) are assigned by `tags` through `modules/cluster-roles.nix`.
- **The private network is not trusted.** Nomad speaks mTLS with a gossip key on the control VLAN. Everything else between nodes (etcd, Loki, Prometheus and its exporters, Vector, the JuiceFS metadata database) listens only on a WireGuard mesh, `wg-ctrl`, over that VLAN. See [The control plane](#the-control-plane).

### How a container runs

1. Every node has every app pre-built in its `/nix/store`. Nothing ships a root filesystem around the network.
2. Each app's Nomad job is one `raw_exec` task in the `apps` namespace, a wrapper that runs `nixos-container start <name>`, blocks while the unit is active, and stops it cleanly on `SIGTERM`. The task runs as the unprivileged `nomad-apps` user (uid 4096) with no network, and a polkit rule lets that user start and stop the declared containers and nothing else. "Task alive" and "container running" are the same thing by construction.
3. `nomad-bootstrap.service`, on the node tagged `nomad-leader`, registers every rendered job after raft leadership, with the scoped `registrar` token. An unchanged job is a no-op.
4. `nomad-fence` runs on every node every 30 seconds and stops any managed container Nomad no longer claims. If the local API is unreachable or answers with an error, it does nothing rather than guess.
5. Moving an app is a clean stop on one node and a cold start on another. Its tunnel travels with it and its socket path does not change, so nothing moves on the Cloudflare side.
6. A deploy reaches a running container by reload, not restart. Only the guest units whose definition changed restart. What a reload cannot apply (bind mounts, network interfaces, capabilities) needs `nomad job restart app-<name>`.
7. One app's failure is not the node's. A guest that fails its reload is reported (`cluster_app_deploy_degraded`, alert `AppDeployDegraded`) instead of failing the host's switch and every other app's deploy.

### Ingress

```
Cloudflare edge ──TLS──┐
                       │ (per-app tunnel, outbound only)
  ┌────────────────────┴─────────────────────────────────┐
  │ nspawn container            no inbound reachability  │
  │                                                      │
  │  cloudflared ──unix:/run/<app>/<app>.sock──> Caddy   │
  │      ▲                                       or nginx│
  │      └── /run/secrets/cloudflared                    │
  │                                                      │
  │  wan0 ── GUA from node's /64 ──> br-wan ──> WAN NIC  │
  │  eth0 ── DHCPv4 private ───────> br-app ──> NAT      │
  └──────────────────────────────────────────────────────┘
```

The route is a socket path rather than an address, so it is correct on every node under any scheduling decision. WAN input is SSH, mosh (UDP 60000-61000) and ICMP only.

The tunnel belongs to the app, not the container. Cloudflare requires every connector on a tunnel to serve identical routes, and steers each request to the closest connector with no route awareness, so two different apps on one tunnel would silently serve each other's traffic. Each hostname therefore needs its own `CNAME` to `<tunnel-id>.cfargotunnel.com`.

### Container networking

| Interface | Bridge | Addressing | Purpose |
| --- | --- | --- | --- |
| `eth0` | `br-app` | DHCPv4, private, masqueraded | IPv4-only destinations |
| `wan0` (`vw-<iid>`) | `br-wan` | static IPv6 GUA from the node's /64, fixed MAC | IPv6 egress, not NATted |

Container addresses are derived, never assigned: a hash of the app name against the node's /64 (`lib/net.nix`). Collisions and reserved identifiers are evaluation errors.

Bridged frames do not traverse the host's IP hooks, so each container firewalls its own WAN interface, and a bridge table on the host keeps containers from spoofing each other on `br-wan` (neighbour discovery, MAC and address are pinned per port).

**Container to host and container to container are default-deny.** A container reaches the internet, its node's DHCP and DNS, and nothing else, unless its app declares it:

```nix
# apps/<name>.nix
network.hostAccess = [ 3100 ];                             # TCP ports on the metrics node's mesh address
network.peerAccess = [ { app = "wpdb"; port = 3306; } ];   # another app, one TCP port
```

- `hostAccess` is for Loki and Prometheus on the `metrics` node. The app must be pinned there (`homeNode` carrying the `metrics` tag) and its name must be at most 12 characters, because its identity is nspawn's veth `vb-<name>`. Both are asserted.
- `peerAccess` reaches another app on the same node over the bridge, or on any other node over the app VLAN, on one TCP port, and nothing comes back but replies. Both ends get an extra `br-app` veth named `vp-<iid>`, so any name length works (D23 under [Defaults awaiting a decision](#defaults-awaiting-a-decision)).
- Identity is the bridge port a frame arrives on, never the address: a container holds `CAP_NET_ADMIN` and can take any address and MAC it likes.
- A container's IPv4 egress excludes RFC 1918, CGNAT, link-local and every node's public address. An S3 endpoint on a private address would need a rule of its own.
- ICMP between containers is not allowed.
- The `grafana` kind declares its own `hostAccess`, and `wordpress` declares `peerAccess` to its `wpdb`.

Refused traffic is logged, rate-limited, with the prefixes `container-to-host-drop` and `container-forward-drop`.

### The control plane

- **Nomad** listens on the control VLAN with mutual TLS (`nomad-ca`, `nomad-tls`) and a gossip key (`nomad-gossip`, servers only), and verifies server names. ACLs are on. Apps run in the `apps` namespace; `default` can run nothing.
- **Every machine logs in with scoped tokens.** Each node holds pre-signed JWTs (`nomad-login`, signed offline by `nomad-jwt`) for its roles: `fence`, `node-meta` and `avc` everywhere, `registrar` on the `nomad-leader` node, `autoscaler` on the `metrics` node. `nomad-login@<role>` exchanges them for tokens in `/run/nomad-tokens/<role>`. The management token (`nomad-acl`) is only on the `nomad-leader` node, read only by `nomad-acl-init`. **Every voter still holds every ACL token, management included, in its raft state**, and root on a server can always mint one.
- **Everything else is on the WireGuard mesh**, `wg-ctrl`, one key per machine (`wg-ctrl`), each node at `<mesh.subnet base>.<index>`. A machine on the VLAN without a key reaches only Nomad's port and the mesh's UDP port. The mesh authenticates the machine, not the process: any process on a node can use it (D1, accepted). SSH no longer answers on the VLANs.
- **etcd** is created once, from the tags, with three or more members (see the tag table).
- **Jumbo frames.** The VLANs take `vlans.<v>.mtu` (9000 in the template) and the mesh 80 bytes less. A private network that doesn't really carry 9000 is a silent blackhole, so every node probes every peer at full size (`VrackJumboBroken`), and the [real hardware checklist](#real-hardware-checklist) tests it before any data. With the trunk at 1500 and a VLAN asking for 9000, networkd does not create the VLAN at all.

An operator shell on a node has `NOMAD_ADDR`, the CLI certificates and `NOMAD_NAMESPACE=apps` set. Bring a token:

```sh
export NOMAD_TOKEN=$(cat /run/nomad-tokens/avc)   # read, restart, logs: the everyday token
```

### Assumptions about the hardware

The network modules were written for bare-metal hosts on OVHcloud's model, and some comments still describe it: a WAN NIC with an off-subnet gateway on both address families, a routed /64 with no router advertisements, and a second NIC trunking tagged private VLANs (`vrackInterface`). Another provider fits if it offers the same shape. Each node needs two NVMe disks for the ZFS mirror (`lib/mk-disk-layout.nix`, `nodes.<n>.disks`), UEFI with Secure Boot that can enter Setup Mode, and a TPM 2.0. The Tang server is a separate small machine on a private VLAN of its own that the nodes reach only from their initrd.

## The interface

The library's flake exports `lib.mkCluster`, which returns the clan-core clan result. A consumer's flake looks like this ([`templates/cluster`](templates/cluster) is a complete one):

```nix
{
  inputs = {
    cluster.url = "github:Avunu/nixos-cluster-orchestration/<rev>";
    nixpkgs.follows = "cluster/nixpkgs";
    # Your own project flakes, which app files see as inputs.<name>.
    my-odoo-project.url = "git+https://github.com/OWNER/my-odoo-project.git?ref=main&submodules=1";
  };

  outputs = inputs@{ self, cluster, ... }:
    let
      topology = import ./topology.nix;
      clan = cluster.lib.mkCluster {
        inherit self inputs topology;
        directory = ./.;
        meta = { name = "my-cluster"; domain = "example.com"; };
        recipients = [ "age1..." ];
        admins = [ "ssh-ed25519 AAAA... me@laptop" ];
        appsDir = ./apps;
        hostsDir = ./hosts;
      };
    in
    {
      inherit (clan.config) nixosConfigurations clanInternals;
      opsIndex = cluster.lib.mkOpsIndex { inherit clan topology; };
      inherit (cluster) packages devShells;
    };
}
```

| Argument | Required | Meaning |
| --- | --- | --- |
| `self` | yes | Your flake. clan builds with `self.inputs.nixpkgs`, falling back to the library's. Use `nixpkgs.follows = "cluster/nixpkgs"` to stay on the tested revision. |
| `inputs` | no | Your flake's inputs, merged with the library's and passed to modules and app files as `inputs`. Yours win, so you can bring your own `frappe-nix`, `odoo-nix` or `wordpress-nix`. Any you don't set come from the library. |
| `directory` | yes | Where the site's clan state lives (`vars/`, `secrets/`, `inventory.json`). Use `./.`, a path, so each secret's ciphertext joins the system closure. |
| `topology` | yes | See [Topology schema](#topology-schema). |
| `meta` | yes | `{ name; domain; }`, handed to clan. `name` also signs alert emails. |
| `recipients` | yes | The operators' age public keys, plus one offline recipient (see [The offline kit](#the-offline-kit)). Anyone listed can decrypt every secret. |
| `admins` | yes | The operators' SSH public keys, for `root` and `admin` on every node, and for the initrd's SSH. Empty is an evaluation error, because it would lock you out. |
| `appsDir` | no | One file per app. `null` means no apps. |
| `hostsDir` | no | `<name>.nix` per machine, each optional. |
| `grafanaDashboards` | no | Replaces the dashboards in `configs/grafana-dashboards`. |
| `extraModules` | no | NixOS modules imported on every machine. |

Other exports:

| Output | What it is |
| --- | --- |
| `lib.mkOpsIndex { clan, topology; }` | What `avc` reads, exposed as your flake's `opsIndex`. |
| `lib.net`, `lib.juicefs`, `lib.backupTarget`, `lib.mkAppContainer`, `lib.nomad` | The pure helpers the modules use. |
| `nixosModules.*` | The modules. They read `topology`, `clusterLib` and `clusterSite` from `specialArgs`, which `mkCluster` provides. |
| `nixosModules.tangServer` | The Tang server's module, for the Tang host's own repository. Not part of `mkCluster`: it needs no topology, clan or cluster arguments. See [The Tang server](#the-tang-server). |
| `packages.avc`, `devShells.default` | The operations tool, and a shell with `avc`, `clan`, `nomad`, `juicefs`, `age` and friends. |
| `templates.default` | The consumer flake skeleton. |
| `nixosConfigurations`, `clanInternals`, `opsIndex` | The **fixture** cluster's, for this repository's checks. Yours come from your own `mkCluster` call. |

Three things are easy to get wrong:

- **`module.input = "self"` is resolved by clan against the clan's own `modules` option**, not your flake's outputs, so you don't re-export the `cluster-roles` service. `checks.mk-cluster` calls `mkCluster` with a `self` that exports nothing, to keep it that way.
- **`nix flake check --no-build` evaluates read-only.** With `directory` as a path, clan's interpolation names a store path that a read-only run never adds, so that command fails on a consumer flake whose current source no normal evaluation has copied yet. Plain `nix flake check`, `nix eval` and real builds are unaffected. This repository's fixtures pass a string to get past it, which a real site must not do: a string would keep the secrets out of the closure.
- **Flakes only see tracked files.** Run `git add` on new apps and vars before you evaluate.

## Encryption

### The threat goal

Conventional access to the hosting provider's side of a machine must not be enough to read client data: pulled drives, a rescue boot, a BIOS change, a snapshot, or another machine attached to the private VLANs. What stays out of scope is written down in [Residual risks](#residual-risks): an attacker on the hardware buses, firmware or BMC compromise, and a full takeover of the provider account that boots the real system.

### What protects what

| Where data is | How it is protected |
| --- | --- |
| Both disks | LUKS2 on each leg of the ZFS mirror (`crypt-a`, `crypt-b`); evaluation refuses a vdev that is not on dm-crypt, and `PoolVdevNotEncrypted` checks it at run time. Swap takes a random key every boot. The ESPs are plaintext and hold the signed boot files, public values, and one secret: the initrd's SSH host key, inside the initrd (see [Residual risks](#residual-risks)). |
| The disk key | Clevis, two shares of two (`sss`, t=2): the Tang server, reachable only from the initrd over a VLAN of its own, and the TPM sealed to PCR 7, which records Secure Boot's state and keys. Neither alone unlocks. |
| The boot | Secure Boot through Lanzaboote, with keys made on the node at install and never copied off it (`/var/lib/sbctl`, on the encrypted root). No Microsoft keys by default: option ROMs this boot measured are enrolled by hash. |
| A swapped volume | A per-node secret on the encrypted root whose hash is compiled into the signed initrd. The initrd checks it before it mounts anything from the pool, and halts on a mismatch, so a forged disk with copied identifiers gets nothing. |
| The emergency shell | Protected by a hashed password, and entering it first extends PCR 7 with a burn, so the TPM refuses its share for the rest of that boot. |
| The JuiceFS volume | Encrypted by JuiceFS with an RSA key (`juicefs-rsa`, `aes256gcm-rsa`). Every mount and the metadata node refuse a volume that is not encrypted (exit 3, `JuiceFSVolumeNotEncrypted`). Its automatic metadata dumps in the bucket are encrypted too. |
| Logs | Loki keeps its store on the `metrics` node's own encrypted disk (`/var/lib/loki`), not in a bucket. Core dumps are off on every node and in every container. |
| Backups | restic, with each app's repository at a salted hash of its name. |
| Between nodes | Nomad mTLS and gossip key; everything else on the WireGuard mesh. |

Unattended unlock needs no person, and never stands in one's way. A typed passphrase always works: on the console, a BMC KVM, or over SSH into the initrd (`avc boot unlock`), in parallel with Clevis. If Tang is down or the TPM refuses, the node waits at the prompt.

Two independent records watch this from outside: each node's **boot report** (`modules/boot-report.nix`: how it unlocked, Secure Boot state, PCR 7, initrd SSH logins) becomes metrics and alerts, and an **off-host audit trail** sends boots, deploys, SSH logins, Nomad ACL changes, canary hits and Tang's own key releases to a Cloudflare Worker that only appends (see [Audit trail](#audit-trail)). A Tang release with no boot report after it is an email: someone may be trying the real hardware.

### The Tang server

Tang holds the network share. It runs on a separate small machine that no node and no person uses for anything else, from its own private repository that imports `nixosModules.tangServer`:

```nix
{
  imports = [ cluster.nixosModules.tangServer ];
  cluster.tangServer = {
    privateInterface = "ens4";            # the Tang VLAN: the only interface Tang listens on
    publicInterface = "ens3";             # the only interface SSH answers on
    allowedClients = [ "10.40.0.0/28" ];  # security.tang.subnet
    pinnedThumbprints = [ ];              # empty only until `tang-keys init`
    # port = 7654;
    monitor = {
      heartbeatUrl = "https://watchdog.example.com/event";
      eventUrl = "https://watchdog.example.com/event";
      tokenFile = "/var/lib/tang-monitor/token";   # delivered out of band
    };
  };
}
```

- `tang-keys init` makes the first keys and prints the signing key's thumbprint. Pin it here and in the site's `security.tang.thumbprints`. The cluster learns only the URL and the thumbprints.
- A guard runs before every connection and refuses to answer when tangd would mint new keys by itself: an empty key directory, only hidden keys, corrupt or 0-byte key files, or a pinned key missing. Without it, `/adv` answers 200 signed by keys no node is bound to, and every node's next boot needs its passphrase.
- **Never run stock `tangd-rotate-keys` as root.** It leaves root-owned keys tangd can't read, and tangd then mints its own. Use `tang-keys rotate-begin` and `tang-keys rotate-finish` (see [Tang rotation](#tang-rotation)). `tang-keys list` shows what is there.
- A self-probe fetches `/adv` every 5 minutes, verifies its signature against the pinned thumbprints, and posts `tang_probe` to the Worker; silence for 20 minutes is an email. That proves Tang is alive, not that a node's path to it works: only a real reboot proves that, so reboot the canary node now and then.
- Each `/rec` tangd answers is posted to the Worker as `tang_rec`, so every key release is on the audit trail. The Worker's `AUDIT_TOKENS` needs the Tang host's entry: `"<its token>": {"sender": "tang", "kinds": ["tang_rec", "tang_probe"]}`.
- Don't back up Tang's keys. A provider snapshot of the Tang machine is one of the two shares, which is why there are two.

### What the private repository holds

| Thing | Where | Notes |
| --- | --- | --- |
| Topology, apps, hosts | `topology.nix`, `apps/`, `hosts/` | Including `security.tang.thumbprints`, copied from the Tang host after `tang-keys init`. |
| Vars ciphertext and public values | `secrets/`, `vars/` | See [Secrets](#secrets). `git add` and commit them before any install: flakes only see tracked files, and `avc boot preflight` refuses uncommitted vars. |
| Age recipients | `recipients` in `flake.nix` | The operators, plus one **offline** recipient that exists only on paper or sealed media. After adding a recipient, run `clan vars fix <machine>` for each machine (`avc secrets fix` does every one): partitioning secrets are encrypted to each machine's key, and that key to the recipients. |
| `secrets/policy.toml` | `avc`'s rotation policy | The template's marks `luks`, `volume-identity`, `juicefs-rsa` and `restic` never, and `nomad-ca`, `nomad-jwt`, `wg-ctrl` and `juicefs-pg` manual. `avc` refuses the never-ones in code too. |
| Nothing of Tang's | the Tang host's own repository | Tang's configuration, keys and access stay out of the site's repository entirely. |

**Name a second unlocker for each site**: a second person with their own age identity in `recipients`, an SSH key in `admins`, and access to the provider's console, who has run `avc boot unlock` once. Unattended unlock depends on Tang and the TPM; a typed passphrase depends on a person.

### The offline kit

Kept outside any repository, off the cluster, and away from the laptop that holds your age key:

- the offline age identity, whose public key is in `recipients`;
- a dated `git bundle` of the private repository (`git bundle create site-<date>.bundle --all`);
- direct copies of each node's `luks/passphrase`, of `restic/password`, and of `juicefs-rsa/rsa.pem` and `juicefs-rsa/rsa-passphrase` (the PEM is about 3.4 KB);
- `ovh-s3/{access-key,secret-key}`, `backup-target/{access-key,secret-key}`, and from the topology `objectStorage`, `backup.target` and `backup.repoSalt`.

With the bundle and the offline identity, `clan vars get` gives back every other secret: `git clone site-<date>.bundle site`, then in it `AGE_KEYFILE=<offline identity> clan vars get <node> luks/passphrase`. To let a new operator in, add their public key to `recipients`, commit, and run `clan vars fix <machine>` for each machine with the offline identity; a key not yet in `recipients` reads nothing. With the JuiceFS key, the S3 pair and the bucket alone, the volume's metadata can be rebuilt anywhere (see [Restore without a node](#restore-without-a-node)).

### Opting out

`nodes.<n>.insecurePlaintextBoot = "<reason>"` is the one switch, per node. That node gets plain disks, systemd-boot, no Secure Boot, no Clevis, no initrd SSH and no volume identity. Every evaluation warns, the node exports `cluster_boot_insecure_optout 1`, and `BootSecurityOptedOut` fires. Nothing else changes: Nomad mTLS, the mesh, the raw_exec lockdown, default-deny and the encrypted JuiceFS volume have no opt-out.

Like every node, an opted-out one holds the fleet's shared keys (`juicefs-rsa`, `ovh-s3`, `restic`, `backup-target`) beside the age key that decrypts them, so one pulled drive of it reads every client's files and backups, whatever runs on it. The site has to say it knows: `insecureFleetKeysOnPlaintextDisk = "<reason>"` at the top level, or evaluation fails. The test fixtures opt out on every node; a real site should not.

Without the opt-out, evaluation fails unless the **resulting** configuration has LUKS under the pool, Lanzaboote, Clevis, the identity check and the rest. The assertions read results, not intent: a host file that swaps the disk layout fails too.

### Never

- **Never `clan vars generate --regenerate` `luks` or `volume-identity` on an installed node.** A new passphrase opens nothing, and a new identity halts the node at its next boot. `avc secrets rotate` refuses both.
- **Never `clevis luks regen`.** It hard-codes `-y` and drops the pinned thumbprint, so it trusts whatever `/adv` serves. Rebind with `avc boot bind <node> <adv-file> --replace`.
- **Never bind in Setup Mode.** PCR 7 in Setup Mode is the same constant on every machine, so a seal taken then can be reproduced by anyone who clears the keys. `cluster-boot-seal bind` refuses.
- **Never run stock `tangd-rotate-keys` as root** on the Tang host.
- **A manual `juicefs dump` is plaintext**, file names included. The automatic dumps in the bucket are encrypted; one you take by hand is not. Keep it on an encrypted disk and delete it.

## Installing a node

The order: install in Setup Mode, first boot with the passphrase, enroll the node's own keys from the running system, reboot enforcing with the passphrase, bind Clevis with a delivered Tang advertisement, reboot unattended. Each `avc boot` command runs one step and says what comes next. The sequence ran end to end in a VM, driven by the boot test harness rather than `avc` and `clan` (`checks.boot-install`); `avc boot preflight` and `clan vars generate` ran on a site made from the template; real firmware has its own [checklist](#real-hardware-checklist).

Three rules behind the order:

- **Never bind in Setup Mode** (above).
- **Every signed generation carries the identity check and the PCR burn.** On a fresh install that is automatic: generation 1 has both, and evaluation fails without them.
- **The identity's hash is known before the first build.** `clan vars generate` makes the secret and its hash together on your machine. The hash is a public value compiled into generation 1's initrd, signed at install; the secret is written to the new root by the install before the first boot. Read the ESP and you find the hash, not the secret.

### S0. Prepare the private repository

You, at your workstation, in `nix develop`, with the Tang server already running and `tang-keys init` done. The node doesn't exist yet.

```sh
age-keygen -o ~/.config/age/identities        # once per operator
age-keygen -o /secure/offline-identity        # once; keep it offline, put its public key in `recipients`
$EDITOR topology.nix                          # security.tang.*, mesh, nodes.<n>.{tangIp,initrdNicModules,disks}
clan vars generate                            # every machine, placeholders too, so their mesh keys exist
git add vars secrets topology.nix && git commit -m "vars"
avc boot preflight <node>
```

`avc boot preflight` must pass. It evaluates the node's system and disk script, so every posture assertion fires here and not on the server, and it prints the identity hash, the initrd host key's fingerprint and the Tang thumbprints for your records.

If it fails, nothing has touched a machine: fix and repeat.

### S1. Firmware

At the provider's BMC console:

- Enable the TPM and the IOMMU. CSM off.
- Clear the Secure Boot keys, so the firmware is in Setup Mode.
- Write down the BMC version and the TPM's state. Clear the TPM if the firmware offers it. If it can't be cleared, go on and write that down.

### S2. Install

```sh
avc boot install <node> root@<rescue-address>
```

From the provider's rescue system, with SSH, outbound network, and Secure Boot not enforcing. `avc` runs the preflight again, asks you to type the node's name, and runs `clan machines install <node> --target-host root@<rescue-address> --yes`: kexec into the NixOS installer, partition and format (both disks get an ESP, swap, and a LUKS2 leg made with the node's `luks/passphrase`), write the identity secret, the initrd's SSH host key and new Secure Boot keys to the new root, install and sign generation 1 onto both ESPs, and reboot.

If it fails, run it again from rescue. It formats again; nothing is on the disks yet.

### S3. First boot: Setup Mode, not enforcing

```sh
avc boot unlock <node>        # types the passphrase over the initrd's SSH, port 2222
avc boot status <node>
```

The prompt appears within seconds, whatever Tang does. `avc boot unlock` asks you for the passphrase (`clan vars get <node> luks/passphrase`); one passphrase opens both legs. Typing it at the console works as well. `avc boot unlock` checks the initrd's host key against the repository's copy, which protects against reaching the wrong machine by accident. It does **not** authenticate the machine: the key is readable on the ESP, so anyone who has read the ESP can impersonate the initrd. A passphrase can be typed into a tampered machine.

`avc boot status` should show Setup Mode, both legs `ONLINE`, and `identity OK`.

A wrong passphrase asks again, for ever. If the node lands in emergency mode, its SSH, network and password prompts stay up: answer the prompts, then `systemctl restart zfs-import-rpool; systemctl --no-block default`. The emergency password is `clan vars get <node> emergency-access/password`.

### S4. Enroll the node's own keys

```sh
avc boot enroll <node>
ssh root@<node> systemctl reboot
```

This runs `cluster-boot-seal enroll` on the node: it refuses unless the firmware is in Setup Mode, and enrolls the node's own keys with `sbctl enroll-keys --tpm-eventlog`, which adds the option ROMs this boot measured (NIC, NVMe, RAID firmware) to the allowed list by hash, so they keep loading. Microsoft's keys are not enrolled; `cluster.boot.enrollMicrosoftKeys = true` in a host file does that instead, and then the node can't be bound at all if any of its option ROMs is Microsoft-signed (see [Residual risks](#residual-risks), D27).

If enrollment is refused or the node won't boot afterwards, put the firmware back in Setup Mode. Nothing is bound yet, so the passphrase is all you need.

### S5. Second boot: enforcing

```sh
avc boot unlock <node>
avc boot status <node>        # Secure Boot: enabled (user), PCR 7 different from S3's
```

Some firmware needs Secure Boot switched on by hand at this point.

### S6. Bind Clevis

The node's stage 2 has no route to Tang (its VLAN exists only in the initrd), so the advertisement is fetched on the Tang host and delivered:

```sh
ssh root@<tang-public-address> 'curl -fsS http://127.0.0.1:7654/adv' > adv.jws
avc boot bind <node> adv.jws
```

`avc` copies the advertisement to the node and runs `cluster-boot-seal bind`, with the passphrase on stdin from `clan vars get`. It refuses unless Secure Boot is enforcing and Setup Mode is off; if PCR 7 was burned this boot (the node went through emergency mode: reboot first); unless PCR 7's event log shows only this node's own certificate (or hash entries) as the authority that let the boot run; unless the identity secret matches the hash; and unless the advertisement's signature verifies against a key in `security.tang.thumbprints`. Then for each leg it adds a Clevis slot, `sss` with t=2 over Tang and the TPM's PCR 7, and finally checks that the TPM share decrypts. The passphrase slot is never touched.

To redo it: `avc boot bind <node> adv.jws --replace` binds a new slot first and only then removes the old one, so a bad advertisement loses nothing. Always bind from a delivered advertisement: Tang answers `/adv/<thumbprint>` for hidden, retired keys too.

### S7. Third boot: nobody types

```sh
avc boot reboot <node>
```

`avc boot reboot` refuses unless the next boot should come back by itself: the default entry's boot contract is the running one, the default entry is not on the rollback denylist ([Rolling back](#rolling-back-a-bad-closure)), an ESP is mounted, no automated hold is set, every leg has a binding whose TPM share opens and whose Tang key is still in `security.tang.thumbprints` (`cluster-boot-seal check`), the identity secret is in place (`cluster-boot-seal identity`), and the last boot unlocked every leg through Clevis. A short Clevis count is only a note in two cases. When `avc boot bind` succeeded this boot (it moves its advertisement to `/run/adv.jws` only once the bind has returned 0; `/run` clears at boot), the last unlock was the typed one from before the binding, as at S7, and only this reboot can prove the binding; `cluster-boot-seal check` must still pass. When PCR 7 was burned this boot (emergency mode), the binding only looks broken until a reboot; a leg with no binding still refuses. Then it reboots the node and waits for a new boot.

Expect stage 2 within about a minute, and Tang to see one `/rec` per leg. On the node: `cluster_boot_unlock_clevis_devices` equal to the number of legs, `cluster_boot_secure_boot_enabled 1`, `cluster_boot_setup_mode 0`, `cluster_tang_vlan_present 0`; and an email from the Worker, `[NOTICE] <site>: <node> booted (clevis)`.

If Tang is unreachable or the TPM refuses, the prompt is there: type the passphrase, then go back to S6 with `--replace` if PCR 7 changed.

### S8. Attack it, then seal it

Run the [real hardware checklist](#real-hardware-checklist) on the node with canary data only. Stop if the TPM releases the key to anything but the node's own signed boot. The node is **sealed** when the checklist passes. Only then may client data move onto it.

### The first deploy after an install

A freshly installed node runs generation 1, which has a boot contract and a boot stack, so its pull deploys proceed. The first canary node of a new site has nothing to wait for. Each later node takes the stack the canary has booted; if your repository has moved on to a newer stack since, it waits until the canary reboots into that one (see [Deploying](#deploying)).

## Recovery

### Who can do what, once sealed

| Event | What it takes |
| --- | --- |
| A kernel update, a new generation | Nothing. PCR 7 does not change. |
| Secure Boot toggled off; db or dbx changed; the TPM cleared | The signed loader still runs, PCR 7 differs, and the TPM refuses its share: type the passphrase at the next boot (`avc boot unlock <node>`), then `avc boot bind <node> <adv-file> --replace`. |
| A firmware update **cleared** the keys (the firmware is in Setup Mode) | Bind refuses in Setup Mode. `avc boot unlock <node>`, `avc boot enroll <node>`, reboot, `avc boot unlock <node>` again, then `avc boot bind <node> <adv-file> --replace`. |
| The firmware restored its **factory** keys | The node's own loader is refused (Access Denied), so no prompt appears. At the BIOS: put the firmware in Setup Mode (or turn Secure Boot off), boot with the passphrase, then `avc boot enroll <node>`, reboot, unlock, `avc boot bind <node> <adv-file> --replace`. How real firmware behaves here is on the [checklist](#real-hardware-checklist). |
| A disk died | The node boots on the other one, unattended and DEGRADED (`ZfsPoolUnhealthy`, `EspNotMounted`). See [Replacing a disk](#replacing-a-disk). |
| The Secure Boot signing keys are lost (`/var/lib/sbctl` gone, root intact) | Every new generation fails to install (`DeployActivationFailing`), but the installed ones still boot. See [Signing keys lost, or rotated on purpose](#signing-keys-lost-or-rotated-on-purpose). |
| The identity secret is damaged or missing | The node halts at boot (`volume-identity: MISMATCH`). See [Identity secret damaged](#identity-secret-damaged). `VolumeIdentityMissing` warns while the node is still running. |
| An initrd authorized key must be retired, or a fix to the boot path must stick | Rotate the Secure Boot keys and rebind: [Signing keys lost, or rotated on purpose](#signing-keys-lost-or-rotated-on-purpose). Removing the key from `admins` alone is not enough (D26). |
| The initrd's SSH host key | `avc secrets rotate` refuses it and prints the procedure: `clan vars generate <node> --generator initrd-ssh --regenerate`, then `clan vars get <node> initrd-ssh/ssh_host_ed25519_key \| ssh root@<node> install -m 0400 /dev/stdin /var/lib/initrd-ssh/ssh_host_ed25519_key`, then deploy. It takes effect at the next **new** generation; the ones already on the ESP keep the old key. |
| Tang's keys | [Tang rotation](#tang-rotation). |
| The Tang machine reinstalled | New keys, so no binding works any more: a node that reboots needs its passphrase. `tang-keys init`, replace the thumbprints in `security.tang.thumbprints` with the new one and deploy, then on each node, before it next reboots if you can, `avc boot bind <node> <adv-file> --replace`. Running nodes are unaffected until they reboot. Once the new thumbprints are deployed, a node not yet rebound shows `ClevisBoundToUnpinnedTang`, and `avc boot reboot` refuses it. |
| Everything lost | [Total loss](#total-loss). |

### Booting an older generation

The boot menu's timeout is 0, so it shows only if you press a key (hold space) at the console while the loader starts. The menu's editor is off. Three ways to pick a generation:

1. **At the console:** press a key as the loader starts, choose the generation. Any signed generation still on the ESP boots and unlocks unattended.
2. **From rescue:** mount the ESPs and set `default` in `/loader/loader.conf` on both (`default nixos-generation-<n>-*.efi`, the names are in `/EFI/Linux`). `loader.conf` is not signed.
3. **When the provider's rescue can't boot under enforcing Secure Boot:** turn Secure Boot off at the BIOS, do the above from rescue, and turn it back on. That changes PCR 7 while it is off, so expect the passphrase at the next boot and run `avc boot bind <node> <adv-file> --replace` afterwards.

### Rolling back a bad closure

A closure that builds and passes every gate but fails at a reboot has to be kept off, because the pull loop would otherwise activate it again within about 90 seconds of the node coming back. The order:

1. Hold the pull loop on every node (`avc deploy hold <node>`), so nothing else takes the bad closure.
2. Revert or pin the private repository to the last good commit. Ship it with `avc deploy ship`: the revert goes by pull request through the merge gate like every other change, about 20 minutes when it changes the lock. The holds of step 1 and the denylist of step 4 keep the nodes off the bad closure meanwhile.
3. Boot the previous generation on the broken node ([above](#booting-an-older-generation)).
4. `avc boot rollback <node>` (or `avc boot rollback --all`) adds every generation after the running one to `/var/lib/cluster-upgrade/refused`, which survives reboots. The tick refuses anything listed (`cluster_deploy_rollback_held 1`, `DeployRollbackHeld`).
5. Once `main` has the revert, release the holds (`avc deploy release <node>`). Released earlier, a node that never took the bad closure takes it.

The node does step 4 by itself too: `cluster-upgrade-rollback-guard` runs at boot, before the first tick, and refuses every generation after the booted one when the node booted something other than the profile's current generation.

**After a rollback the boot default is unchanged.** The bad closure is still the default entry, so a reboot goes back into it until a good closure deploys and becomes the default. `avc boot reboot` refuses while the default entry is on the denylist, whatever its boot contract says (a kernel or nixpkgs bump changes none). To take a closure off the list: `avc boot unrollback <node> <closure>`.

A failed bootloader install leaves the profile on the closure it failed for, with the running system and the boot entries unchanged. A node that then reboots boots the old entry, which is not the profile's current generation, so the rollback guard refuses the newer closure (`DeployRollbackHeld`) rather than retrying it. Fix what failed (a full or unmounted ESP, lost signing keys), then `avc boot unrollback <node> <closure>`. The same holds for a node that went down between setting its profile and its switch.

### Replacing a disk

On the running, DEGRADED node, with deploys held (`avc deploy hold <node>`), for a new disk in the place of `nvme0` (leg `a`, ESP `/boot`; for `nvme1` use `disk-nvme1-*`, `crypt-b` and `/boot-fallback`):

```sh
zpool status -g rpool                      # the dead leg's GUID
sgdisk -n1:0:+1G -t1:EF00 -c1:disk-nvme0-ESP -n2:0:+32G -c2:disk-nvme0-swap \
       -n3:0:0 -c3:disk-nvme0-luks /dev/disk/by-id/<new disk>
udevadm settle
mkfs.vfat -F 32 /dev/disk/by-partlabel/disk-nvme0-ESP     # before anything else: an unformatted ESP fails boot.mount
cryptsetup luksFormat --type luks2 /dev/disk/by-partlabel/disk-nvme0-luks     # the node's luks/passphrase
cryptsetup open --allow-discards /dev/disk/by-partlabel/disk-nvme0-luks crypt-a
zpool replace -f rpool <dead leg's GUID> /dev/mapper/crypt-a
zpool status rpool                         # wait for "resilvered"
mount /boot && /run/current-system/bin/switch-to-configuration boot   # signs onto both ESPs again
```

Then bind only the new leg, from a fresh advertisement: `avc boot bind <node> adv.jws /dev/disk/by-partlabel/disk-nvme0-luks`. Not a bare `bind`, which refuses because the healthy leg is bound, and not `--replace`, which would rebind the healthy leg too. Release the hold. If the new disk enumerates differently, point `nodes.<n>.disks` at `/dev/disk/by-id/...`; the disks are in the boot contract, so that deploy waits for an approval on the node.

### Identity secret damaged

The node halts at every boot until the secret is back; each attempt needs a power cycle from the BMC.

1. Boot the provider's rescue system. Under enforcing Secure Boot that may need Secure Boot off at the BIOS first; turn it back on afterwards and expect a `--replace` rebind, because PCR 7 changed.
2. Open both legs with the passphrase: `cryptsetup open /dev/disk/by-partlabel/disk-nvme0-luks crypt-a`, the same for `disk-nvme1-luks` and `crypt-b`.
3. `zpool import -f -N -d /dev/mapper rpool` (`-f`, because the pool was last used by another host ID), then `mount -t zfs rpool/root /mnt`.
4. From your workstation: `clan vars get <node> volume-identity/secret | ssh root@<rescue-address> install -m 0400 /dev/stdin /mnt/var/lib/volume-identity/secret`. `clan vars get` writes the bytes with no trailing newline, which is what the check hashes.
5. **`umount /mnt` and `zpool export rpool`** before rebooting, then `cryptsetup close crypt-a` and `crypt-b`. A rescue interrupted before the export leaves a pool the node refuses to import at its next boot: boot rescue again and finish it.

`checks.boot-degraded`'s `identity-repair-rehearsal` rehearses this sequence in a VM, including the interrupted rescue.

### Signing keys lost, or rotated on purpose

Lost keys and a deliberate rotation are the same procedure. A rotation is what retires an initrd authorized key that was removed from `admins`, or makes a fix to the boot path irreversible: every older generation signed with the old keys still passes PCR 7 if someone kept a copy and puts it back on the ESP (D26). The deploy tick says so when `admins` changes. The order matters:

1. At the BIOS, put the firmware in Setup Mode (this clears its keys).
2. Boot, and type the passphrase (`avc boot unlock <node>`).
3. On the node, move the old keys away if they still exist (`mv /var/lib/sbctl /root/sbctl.old`), then `sbctl create-keys`.
4. `avc boot enroll <node>`.
5. **Sign again before any reboot:** `/run/current-system/bin/switch-to-configuration boot`, which writes both ESPs. Rebooting first would leave a loader the new keys refuse.
6. Reboot, type the passphrase, then `avc boot bind <node> <adv-file> --replace`. Delete the old keys.

### Tang rotation

The order matters: the Tang host's guard refuses every connection while a pinned key is missing.

1. On the Tang host: `tang-keys rotate-begin`. It makes a new key pair and hides the old one (hidden keys still decrypt).
2. Pin the new thumbprint: in the Tang host's `pinnedThumbprints` (deploy it) and in the site's `security.tang.thumbprints` (ship it, `avc deploy ship`). Thumbprints are not in the boot contract, so this needs no approval.
3. Once every node has deployed the new thumbprint, rebind each from a freshly delivered advertisement: `avc boot bind <node> adv.jws --replace`. Then `avc boot reboot <node>`, one at a time, proves each.
4. Unpin the old thumbprint on the Tang host and deploy; take it out of `security.tang.thumbprints` and ship that.
5. **Before the next step, check every node.** Once a node has deployed step 4, a Clevis slot still bound to the old key fails `cluster-boot-seal check` with exit status 4, `avc boot reboot` refuses, and the boot audit raises `ClevisBoundToUnpinnedTang`. Rebind any node that shows it, as in step 3. `tang-keys rotate-finish` on the Tang host can't see the nodes, so this is the only place a node missed in step 3 shows.
6. `tang-keys rotate-finish`, which deletes the hidden keys. It refuses while a hidden key is still pinned.

Revoking Tang for every node at once: stop `tangd.socket`. For one node: rotate, rebind the others, and finish. Neither protects against the provider, who can read the Tang machine's disk.

### Total loss

All nodes gone, or a rebuild from scratch, in this order:

1. The Tang server up (`tang-keys init`).
2. The private repository from the offline kit: `git clone site-<date>.bundle site`, `AGE_KEYFILE=<offline identity>`, a new operator key added to `recipients`, and `clan vars fix <machine>` for each machine.
3. The first node installed and sealed, S0 to S8.
4. The JuiceFS metadata restored from the bucket with the PEM and its passphrase: the reinstalled `juicefs-meta` node does it by itself from a recent dump ([below](#when-the-juicefs-metadata-node-is-reinstalled)), or by hand ([Restore without a node](#restore-without-a-node)).
5. Nomad bootstraps itself on the first voter, and the leader registers every job.
6. `cluster-restore <app> --yes` per app.

`checks.jfs-encrypted`'s `total-loss-escrow-only` proves step 4 from the kit alone, and `checks.boot-install` the mechanism of step 3; the whole chain has not been rehearsed on real machines.

## Real hardware checklist

A VM can't prove these. Run each on the first real node, with canary data only, and write the answer down.

**Firmware and Secure Boot**
- How the board enters Setup Mode; whether `sbctl enroll-keys` from the running system is accepted; whether Secure Boot turns on by itself afterwards.
- **Option ROMs, before enrollment:** from rescue, `tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements` on each node: list every PCR 7 authority and every option ROM measured. Confirm that `cluster-boot-seal enroll` (`--tpm-eventlog`) enrolls them by hash, that the node boots with every device present (NICs, NVMe, any RAID controller or GPU), and that `avc boot bind` accepts. Repeat after a BIOS update: an option ROM whose hash changed is no longer allowed and won't run.
- Booting from `\EFI\BOOT\BOOTX64.EFI` with no NVRAM entry, and which ESP the firmware picks after a disk swap.
- Real PCR 7 contents and their stability across a BIOS update and a dbx update; `tpm2_eventlog` across a rescue cycle.
- The TPM's lockout state and leftover handles; whether a TPM clear is offered.
- The provider's own signed software: its rescue with Secure Boot on (netboot, iPXE). Record what happens.
- After install, read the raw disks: no canary. Rescue boot, a BIOS toggle, key changes: the TPM refuses. A volume swap, if the provider allows one.
- A kernel update and a reboot: unlocks by itself.
- `kexec` from the provider's rescue before enrollment.

**Network**
- The real NIC names and drivers in the initrd (`lspci -k`), so `initrdNicModules` is right; the Tang VLAN on the trunk.
- Whether frames from another machine attached to the private network reach the node as they would in the test switch, and whether a spoofed source address passes.
- **Jumbo frames, before any data:** between every pair of nodes, both ways, on every VLAN, `ping -M do -s 8972 <peer>` must pass; on the mesh, `ping -M do -s 8892 <peer mesh address>` must pass and `-s 8893` fail. Check `ip link` on the trunk and VLANs: a VLAN whose MTU the NIC refused is simply absent. Then a bulk transfer. If any of it fails, set `vlans.*.mtu = 1500`; the mesh follows to 1420.
- That Tang answers only on its VLAN, from outside.
- A NIC that never comes up delays Clevis, not the prompt.

**Hardware**
- The IOMMU is on: `/sys/class/iommu` is not empty (`IommuDisabled`).
- The watchdog driver loads and stays quiet at a long initrd prompt after a reset (`WatchdogDeviceMissing`).
- The real initrd's size against the 1 GiB ESP.
- A physically absent NVMe, device timeouts, and `nofail` with both ESPs on real disks.

**Install route and provider**
- `clan machines install` through kexec from the provider's rescue (`avc boot install`).
- The Worker on real Cloudflare, the R2 bucket's lock, event rates, and its cron within the 15-minute grace.
- An offline-kit drill with the real kit: from the offline identity to a machine key to `clan vars get`, including adding a recipient and `clan vars fix`. The same drill ran on a scratch site made from the template; yours proves your kit.

## Residual risks

Accepted, and written here so they are accepted knowingly.

**Out of scope.**
- **Hardware bus attacks.** Clevis's TPM unseal uses no session encryption, so the TPM's share likely crosses the bus in clear. Against someone on the bus with the node's network position, Tang is the only barrier.
- Firmware tampering, BMC compromise and memory attacks.
- A full takeover of the provider account that boots the real system: it unlocks, and still needs a login. Nothing here defends a running system with its disk key.

**Accepted with the design.**
- **An older signed generation passes PCR 7 for as long as the Secure Boot keys are the same (D26, accepted by the user).** `configurationLimit` bounds only what stays on the ESP. Anyone with the disk can copy a generation off and put it back later, and `loader.conf` is unsigned, so it can be made the default. So an initrd authorized key removed from `admins` still opens every older signed initrd anyone kept, and a fix to the boot path can be undone the same way. Retiring either needs new signing keys and a rebind ([procedure](#signing-keys-lost-or-rotated-on-purpose)). The tick says so when `admins` changes. A forward-moving seal (systemd-pcrlock, or a signed PCR 11 policy) would close this, and is not built.
- **Own Secure Boot keys only, no Microsoft keys (D27, chosen by the user).** Option ROMs are enrolled by hash from this boot's event log. An option ROM whose hash changes with a firmware update no longer runs. `bind` refuses when PCR 7 records any authority but the node's own, because anything a Microsoft-signed component lets run could replay PCR 7. `cluster.boot.enrollMicrosoftKeys = true` is a written risk acceptance: it lets the provider's Microsoft-signed rescue images run under Secure Boot, and makes binding impossible on a node with a Microsoft-signed option ROM.
- **`loader.conf` on the ESP is unsigned.** An attacker can pick any signed entry. Production closures have no specialisations; that is asserted.
- **The ESP is readable by the provider:** the initrd's SSH host key, the emergency password's hash, the identity hash and the authorized keys, though not the secret. The host key doesn't prove the machine before a passphrase is typed into it.
- **The emergency password** still opens a root shell in the initrd that can read whatever is unlocked and destroy data, even with PCR 7 burned. It is 32 random bytes and is held like the passphrase (D3).
- **A forged pool is parsed by the kernel's ZFS before the identity check.** A crafted pool could attack the kernel; that needs an exploit and is beyond conventional access.
- **An old LUKS header copy with the old passphrase stays valid** until `cryptsetup reencrypt`; changing the passphrase does not change the volume key.
- **The passphrase's ciphertext is in git for good,** decryptable with an operator's age key or the machine's. The answer to a lost operator key is `cryptsetup reencrypt`.
- **`allowDiscards`** shows which blocks are free.
- **Tang's keys are readable by the provider,** and a snapshot can bring back a deleted key. That is why Tang is one of two shares.
- **A stolen gossip key plus a server's certificate makes a Nomad voter** within about 20 seconds, with the tokens in raft state. That is why both stay off workers. Root on a server can always mint a management token.
- **A stolen client certificate can register a Nomad client,** and the scheduler can place work on it. Job specs hold only store paths and names. A machine's pre-signed login JWTs are long-lived; retiring them means a new `nomad-jwt` signing key.
- **A stolen `submit-job` token** (the `registrar`'s) runs code as uid 4096 on every node, with no network, and can start or stop declared containers. Nomad gives task processes supplementary group 0 (a Nomad bug): they can read what group root can, such as `/etc/sudoers`. `denied_host_gids` must never be set, because it would refuse every task. An account above uid 65535 made by hand at run time would run a task: the evaluation-time check covers configured accounts only.
- **The mesh authorizes nodes, not processes** (D1): any process on a node can reach etcd, Loki, Prometheus and the metadata database's port.
- **The app VLAN is not authenticated.** An attacker on it who spoofs a container's source address can reach a port an app declared on another node: for traffic arriving from the VLAN, the rule checks the source subnet and port, not identity.
- **Metadata leaks:** the bucket shows object sizes and timing; restic's key files show host names and times; metrics and alert emails carry app and host names to Cloudflare; PostgreSQL's WAL, the JuiceFS cache and backup staging hold plaintext on the encrypted disk until the next run.
- **`juicefs config --secret-key` puts the S3 secret on a command line** on the metadata node for the seconds of its storage test, after a restore, a rotation or a lost state file. JuiceFS 1.4.1 has no other way.
- **Loki's history is lost with the `metrics` node.** Backing it up would keep client-bearing logs past their retention.
- **`freeipa` keeps every capability** (`additionalCapabilities = [ "all" ]`), so a compromise of that container is host root whatever the firewall does.
- **Cloudflare sees traffic at the tunnel edge,** and the alert emails' text.
- **Lanzaboote is pinned to a commit,** not a release.

## Topology schema

The topology is pure data. [`templates/cluster/topology.nix`](templates/cluster/topology.nix) is a skeleton with every field.

| Field | Meaning |
| --- | --- |
| `datacenter` | Nomad datacenter. |
| `region` | The site's region, for reference. |
| `internalDomain` | Internal DNS domain. |
| `vlans.{control,app,storage}` | `{ id; subnet; mtu; }`, tagged on each node's trunk NIC. The app VLAN's addressing is fixed by `modules/overlay-network.nix`: nodes take `10.20.0.<index>`, containers a `10.20.<index>.0/24`. One `mtu` per VLAN for the whole site; see the jumbo frame test in the [checklist](#real-hardware-checklist). |
| `privateServices` | CIDR for addresses inside containers, reached only through their tunnel, such as FreeIPA's Kerberos and LDAP. Asserted not to overlap the VLANs or app subnets. |
| `mesh.subnet` | Required. A /24 for the WireGuard control mesh; a node takes `<subnet base>.<index>`. |
| `mesh.port` | UDP port on the control VLAN. Default 51820. |
| `mesh.mtu` | Default `vlans.control.mtu - 80`: 8920 at 9000, 1420 at 1500. Asserted to fit. |
| `security.tang.url` | `http://<ipv4>:<port>`, exactly: the initrd has no DNS. The port is the Tang host's `cluster.tangServer.port` (7654 by default). |
| `security.tang.thumbprints` | The Tang host's signing key thumbprints, from `tang-keys init`. Public. `bind` accepts only an advertisement signed by one of these. Not in the boot contract. |
| `security.tang.vlanId`, `security.tang.subnet` | The Tang VLAN, which exists only in the initrd, and its subnet, asserted not to overlap anything else. |
| `security.initrdSshPort` | The initrd's SSH port. Default 2222, deliberately not 22, so its host key never meets the running system's in `known_hosts`. |
| `security.nomadTlsRotation` | Bump to reissue every Nomad agent certificate. Default 0. |
| `deploy.flakeUrl` | What nodes rebuild from, as `github:owner/repo`. Also how `avc` finds the deploy remote. |
| `deploy.pullInterval` | systemd `OnCalendar` for the pull loop. |
| `deploy.withoutCanary` | `"<reason>"` to run a site of more than one node without a canary node (see `canary` below, and [Deploying](#deploying)). Leave it out otherwise. |
| `objectStorage` | `{ endpoint; region; juicefsBucket; }`. Credentials come from the `ovh-s3` vars generator, whichever provider you use. Loki does not use it: its store is the `metrics` node's own encrypted disk (`/var/lib/loki`), so its history stays with that node. |
| `logging.retention` | Loki retention, one number and one unit (`m`, `h`, `d`, `w`, `y`), such as `"720h"`. Older lines are deleted from the store, and a node that no longer runs Loki deletes what is left in its `/var/lib/loki` once it is this old. |
| `alerting` | `{ cloudflareAccountId; from; to; heartbeatUrl; auditUrl; }`. `heartbeatUrl` is the watchdog Worker's `/heartbeat`; `auditUrl` its `/event`, for the [audit trail](#audit-trail). Only an opted-out node may leave `auditUrl` null. |
| `backup.repoSalt` | This site's own string, at least 16 characters (`openssl rand -hex 16`). It salts each app's repository path (see [Backups and restore](#backups-and-restore)). Set it once, before the first backup, and never change it. |
| `backup.target` | `{ type; ... }`, where `type` is `s3`, `rest`, `b2` or `local` (`lib/backup-target.nix`), with `endpoint`, `bucket` and `region` for S3. Keep it away from the object storage it protects. |
| `backup.{schedule,maintenance,verify}` | systemd `OnCalendar`, in the node's clock (UTC). |
| `backup.retention` | `{ daily; weekly; monthly; }`. |
| `backup.uploadLimitKiB` | restic upload limit. `0` means unlimited. |
| `stateVersion` | `system.stateVersion` for the whole fleet. |
| `insecureFleetKeysOnPlaintextDisk` | Required, as `"<reason>"`, once any node sets `nodes.<n>.insecurePlaintextBoot`. Every node holds the fleet's shared keys (`juicefs-rsa`, `ovh-s3`, `restic`, `backup-target`) beside the age key that decrypts them, so one opted-out node's disk reads every client's files and backups, whatever runs on it. Test fixtures only. |
| `insecureSingleMemberEtcd` | Test fixtures only: `"<reason>"` lets exactly one node carry `etcd`. Such an etcd can never grow (see the tag table below). Leave it out of a real site. |
| `nodes.<name>` | One per machine. See below. |

The attribute key under `nodes` is the machine name everywhere: the clan machine, the `--flake .#<key>` target, an app's `homeNode`. It must equal `hostName`.

| Node field | Meaning |
| --- | --- |
| `index` | Small unique integer. Selects the node's app-VLAN address, app subnet and mesh address. |
| `hostName`, `fqdn` | Host name, and the name in the clan inventory. |
| `deployHost` | SSH target, and the address `avc boot unlock` reaches the initrd on. |
| `roleTag` | Nomad client `meta.role`, a scheduling label. Not a cluster role. |
| `tags` | Cluster roles, below. |
| `hostId` | ZFS machine ID, 8 hex digits. |
| `publicIp4`, `publicGw4` | Public address (configured as a /32) and its on-link gateway. The initrd uses them too. |
| `public6Prefix`, `publicIp6`, `publicPrefix6`, `publicGw6` | The node's routed IPv6 prefix, the host's address in it (never the bare `::`), and its on-link gateway. |
| `wanInterface`, `vrackInterface` | NIC names: the WAN port and the private VLAN trunk. |
| `controlIp`, `storageIp` | Addresses on the control and storage VLANs. |
| `appBridgeIp`, `appSubnet` | `br-app`'s address and the containers' subnet. |
| `appDhcpPoolOffset`, `appDhcpPoolSize` | The containers' DHCP pool. Addresses below the offset are free for static use, such as `wpdb.address`. |
| `tangIp` | The node's address on the Tang VLAN, inside `security.tang.subnet`. Initrd only. |
| `initrdNicModules` | Kernel modules for both NICs in the initrd, such as `[ "igb" "mlx5_core" ]`. Not detectable at evaluation; `lspci -k` on the node names them. Required unless opted out. |
| `disks` | `{ a; b; }`, the two disk devices. Default `/dev/nvme0n1` and `/dev/nvme1n1`. Use `/dev/disk/by-id/...` on hardware whose enumeration swaps. |
| `insecurePlaintextBoot` | `"<reason>"`: the one opt-out from disk encryption and Secure Boot. See [Opting out](#opting-out). |
| `provisioned` | `false` for a placeholder: not scraped or alerted on. Delete the line when the machine exists. |
| `canary` | `true` on exactly one real node once the site has more than one: it takes each new boot stack first, and the others wait until it has rebooted into it (see [Deploying](#deploying)). Not a placeholder, and not an opted-out node while any node has boot security. |

What an unlock depends on (the node's `initrdNicModules`, `wanInterface`, `vrackInterface`, `publicIp4`, `publicGw4`, `tangIp`, the Tang URL and VLAN, the disks and required mounts, the initrd SSH port, and a hash of `admins`) is the node's **boot contract**. A change to any of them waits for approval on each node (see [Deploying](#deploying)).

| Tag | What it does |
| --- | --- |
| `worker` | Runs application containers (Nomad client). |
| `nomad-server` | Votes in the Nomad raft. `bootstrap_expect` is asserted to be the number of nodes with this tag. Holds the gossip key and every ACL token in raft state. |
| `etcd` | Votes in the etcd raft. |
| `nomad-leader` | Registers rendered jobspecs, and holds the management token. Singleton. |
| `juicefs-meta` | Hosts the JuiceFS metadata PostgreSQL. Singleton: two would mean two metadata engines over one bucket. |
| `metrics` | Hosts Prometheus, Loki, Alertmanager and the Nomad autoscaler. Singleton. Moving the tag starts an empty Loki. |
| `backup` | Owns backing up shared state. Local state is backed up on an app's `homeNode`. |

Quorum size is derived from the tags, so a placeholder listed as a voter makes Nomad and etcd wait for a machine that does not exist. Add `nomad-server` and `etcd` in the same commit that fills in a node's real addressing. A cluster with fewer than three voters has no HA.

### Growing to three voters

Go from one voter to three in a single commit: `nomad-server` on the two new nodes, and `etcd` on all three. etcd has no member add. It is created once, from the tags, so it is either absent or has an odd number of at least three members, and evaluation refuses anything else. A one-member etcd can't grow: its data directory makes it ignore the new member list, and the two new members would form a second cluster of their own. Nomad tolerates one voter growing, but two voters means no leader while either is down, so don't stop at two.

The switch is safe for the running voter: Nomad ignores `bootstrap_expect` once it has raft state, and its allocations keep running. `checks.voter-growth` covers both orders (the first voter switching before or after the new ones start, a worker promoted, a fresh voter).

**Before reinstalling a server that died, remove it from raft and wait.** Autopilot removes a failed server by itself a moment after serf marks it failed; a reinstall seconds later can be pulled back into the old cluster under its old identity. And never reinstall a node from a topology commit in which it is the only voter while the others still run: it would bootstrap a cluster of its own.

## Kinds

An app is one file in `appsDir`, named after the app. It is a function of `{ inputs, lib, pkgs, name }`, or JSON for what tooling writes. A `.nix` and a `.json` of the same name merge. The file holds only what differs:

```nix
# apps/shop.nix
{ inputs, ... }:
{
  homeNode = "node1";
  odoo = {
    package = inputs.my-odoo-project.packages.x86_64-linux.default;
    hostname = "shop.example.com";
    workers = 4;
  };
  tunnel.id = "<tunnel uuid>";
  resources = { cpu = 2000; memoryMB = 4096; };
}
```

| Kind | Parameters | What it derives |
| --- | --- | --- |
| `odoo` | `package`, `hostname`, `workers`, `maxCronThreads`, `serverWideModules` | Odoo and nginx on a socket, local PostgreSQL, the filestore on JuiceFS, an admin password var. |
| `frappe` | `package`, `site`, `webThreads`, `settings` | A bench, local MariaDB and Redis, the site directory on JuiceFS, its secrets. |
| `freeipa` | `hostname`, `domain`, `realm`, `privateIp4`, `image`, `authelia` | The upstream FreeIPA image under podman, a private address reachable only over WARP, optional Authelia as an OIDC provider, nightly upgrades. |
| `grafana` | `hostname`, `loginName`, `adminGroup`, `editorGroup`, with `oidc.idp` | Grafana on the metrics node, signed in through an identity provider's Authelia, reaching Loki and Prometheus through `network.hostAccess`. |
| `wpdb` | `address`, `port`, `clientHosts`, `bufferPoolSize` | The one MariaDB every WordPress site shares, with databases and grants per site. |
| `wordpress` | The `wordpress` section, usually written by a tool as JSON | One file, two containers: `<name>` (read-only public face) and `<name>-admin` (writable admin face), each reaching `wpdb` through `network.peerAccess`. |

The payload modules come from [wordpress-nix](https://github.com/Avunu/wordpress), [frappe-nix](https://github.com/Avunu/frappe-nix) and [odoo-nix](https://github.com/Avunu/odoo-nix). Your project flake supplies the `package`. To pin its payload module to the library's, use `inputs.odoo-nix.follows = "cluster/odoo-nix"`.

Beside the kind, every generic `clusterApps` option stays available (`modules/app-container.nix`): `homeNode`, `tunnel.id`, `resources`, `startTimeout`, `network` ([Container networking](#container-networking)), `module` for extra guest config, and so on. `oidc = { idp = "<a FreeIPA app>"; }` makes any app a client of that provider's Authelia. `enable = false;` keeps a file without deploying it.

### Adding an app

1. Add its flake input if it has one.
2. Write `apps/<name>.nix`, run `clan vars generate <node>` for the kind's generated secrets, and ship it (`avc deploy ship`). Nomad starts it. With no `tunnel.id` it has no ingress yet.
3. Wire the tunnel:
   ```sh
   cloudflared tunnel create <name>
   # set tunnel.id in the file; the var exists once the id is set
   clan vars set <node> <name>-cf/cloudflared < ~/.cloudflared/<id>.json
   cloudflared tunnel route dns <name> <hostname>
   ```
4. Ship the id and the var together (`avc deploy ship`), then run `nomad job restart app-<name>`, because the credentials are a new bind mount.

Odoo and Frappe databases are not initialised for you. Restore or create one after the first start. Deploys then migrate it.

## Operations

`nix run .#avc` is the guided entrypoint for status, apps, secrets, deploys, boot and audit, and every menu entry is also a subcommand: `avc status show`, `avc app restart <app>`, `avc secrets rotate <generator>`, `avc deploy now`, `avc boot status <node>`, and so on (`avc --help`, `avc <group> --help`). `avc site ...` delegates to an optional provisioning tool that this library doesn't include. Pass one with `packages.avc.override { siteProvisioner = ...; }`. Without it, those commands say so and everything else works.

### First install

Minimum before the first node: the Tang server running with its thumbprints, an operator age identity and the offline one in `recipients`, the topology filled in, and the `ovh-s3` and `github-token` generators. Then [Installing a node](#installing-a-node), S0 to S8:

```sh
nix develop
age-keygen -o ~/.config/age/identities     # once per operator; add the public key to `recipients`
clan vars generate                         # prompts for what third parties issue
git add vars secrets && git commit -m vars
avc boot preflight node1
avc boot install node1 root@<rescue-address>
```

Then, after S5 (`avc boot unlock` and `avc boot enroll`) and before S6 and S7 (`avc boot bind`, `avc boot reboot`), deploy the [watchdog Worker](#dead-man), set `alerting.heartbeatUrl` and `alerting.auditUrl`, and push `AUDIT_TOKENS` with the Tang host's entry. S7's boot report, its Tang release and the `booted (clevis)` email that says S7 worked all go there.

### Secrets

Generators run offline, so anything a third party issues is a `prompt`, filled once and stored. "Per machine" means one value per node; the rest are one value for the fleet.

| Generator | Consumer | Origin |
| --- | --- | --- |
| `luks/passphrase` | The disks' LUKS passphrase, per machine. Used at install, then only by people: the typed fallback and `avc boot bind`. **Never regenerate it** on an installed node | Generated |
| `volume-identity/{secret,hash}` | The volume identity, per machine. The secret goes on the root at install; the hash is compiled into the signed initrd. **Never regenerate it** on an installed node | Generated |
| `initrd-ssh/ssh_host_ed25519_key` | The initrd's SSH host key, per machine. Placed at install; the public half is what `avc boot unlock` expects. Rotation by hand (see [Recovery](#recovery)) | Generated |
| `emergency-access/{password,hash}` | The initrd emergency shell, per machine. The password never leaves the repository; the hash is in every signed initrd | Generated |
| `ovh-s3/{access-key,secret-key}` | JuiceFS on all nodes. The volume keeps its own copy in its settings, which every mount reads; the metadata node puts a new pair there when the vars change, and running mounts pick it up | Prompt, from your S3 provider |
| `juicefs-rsa/{rsa.pem,rsa-passphrase}` | The JuiceFS volume's encryption key. Never regenerate it: the volume's data can't be read without it, and `avc` refuses to rotate it | Generated |
| `juicefs-pg/password` | The JuiceFS metadata engine. Manual: every mount and the metadata role change together | Generated |
| `nomad-acl/token` | Nomad's management token: the ACL bootstrap and `nomad-acl-init`, on the `nomad-leader` node only | Generated |
| `nomad-jwt/{signing.key,signing.pub}` | Signs each machine's login JWTs; the key never leaves the operator's machine | Generated |
| `nomad-login/jwt-<role>` | Each machine's scoped Nomad logins (`fence`, `node-meta`, `avc`, plus `registrar` and `autoscaler` where those run), per machine | Generated, signed by `nomad-jwt` |
| `nomad-gossip/gossip.hcl` | Nomad's serf encryption key, servers only | Generated |
| `nomad-ca/{ca.key,ca.crt}` | Nomad's CA; the key never leaves the operator's machine | Generated |
| `nomad-tls/{agent,cli}.{key,crt}` | Each machine's Nomad certificates (per machine) | Generated, signed by `nomad-ca` |
| `wg-ctrl/{private,public}` | Each machine's mesh key (per machine); every peer reads the public half | Generated |
| `audit/token` | Each machine's token for the audit trail (per machine), listed in the Worker's `AUDIT_TOKENS` | Generated |
| `canary/value` | The string the [canary scan](#canary-scan) plants and looks for | Generated |
| `github-token/{nix.conf,netrc}` | Pull loop access to private flakes | Prompt, a fine-grained PAT with read access to contents |
| `restic/password` | Every app's backup repository. Never regenerate it: a new one opens none of them, and `avc` refuses to rotate it | Generated |
| `backup-target/{access-key,secret-key}` | The backup target | Prompt |
| `alerting/cf-email-token` | Alert emails | Prompt, a Cloudflare token with Email Sending only |
| `alerting-watchdog/token` | The dead-man heartbeat | Generated |
| `cloudflare/provision-token` | The operator's own Cloudflare token for site provisioning; never deployed to a node | Prompt |
| `<app>-cf/cloudflared` | Each app's tunnel | Prompt, from `cloudflared tunnel create` |

Each kind declares its own, from its entry in `apps/`. A secret an app mounts but that was never generated is a build error, not an empty file.

```sh
clan vars list node1
clan vars generate node1
clan vars generate node1 --generator ovh-s3 --regenerate   # rotate one
clan vars get node1 <generator>/<file>
```

`avc secrets inventory` shows every secret's age, consumers and rotation policy; `avc secrets rotate <generator>` regenerates one, ships it and restarts what reads it. It refuses `luks`, `volume-identity`, `juicefs-rsa` and `restic` in code, refuses `initrd-ssh` and `emergency-access` with their manual procedures, and follows `secrets/policy.toml` for the rest. Per-machine vars are named `<machine>:<generator>/<file>` in `avc secrets set` and `avc secrets reveal`.

Rotation notes:

- **`nomad-gossip`:** Nomad copies the key into `<data_dir>/server/serf.keyring` on first start, so a new `gossip.hcl` changes nothing on a running server. Rotate with `nomad operator gossip keyring` (install, use, remove), then regenerate the var to match.
- **`nomad-ca`:** regenerating reissues every machine's certificates: a hard cut, every node at once. `security.nomadTlsRotation` reissues the agent certificates alone. `NomadTlsCertExpiring` and `NomadTlsCaExpiring` warn first.
- **`nomad-jwt`:** regenerating reissues every node's logins, and the leader's `nomad-acl-init` updates the auth method on its next switch. Manual in the policy.
- **`wg-ctrl`:** both ends of a link must switch: a node with a new key is cut off from each peer until that peer lists the new public key, and back within seconds after. Manual in the policy. A node with no mesh key still boots, and its mesh services retry.
- **`audit`:** a new token must reach the Worker (`avc audit tokens | wrangler secret put AUDIT_TOKENS`, with the Tang entry added), or that node's events are refused (`AuditEventRejected`).
- **`canary`:** harmless to regenerate; the next scan plants the new value.

### Deploying

A change reaches the nodes by merging into `main`, and it merges by pull request. `avc deploy ship` does all of it: it commits on a branch of its own (`avc/...`), pushes that branch, opens the pull request and asks for auto-merge, waits for the site's merge gate to merge it, and then waits for the nodes. It never pushes to `main`, so `main` can be protected with no bypass for anyone (see "Merging safely" in [`templates/cluster/README.md`](templates/cluster/README.md)). It needs the GitHub CLI logged in once (`gh auth login`); without it, it pushes the branch and tells you to open the pull request yourself. Within `deploy.pullInterval` of the merge, every node converges. Watch one with `journalctl -fu cluster-upgrade` (`avc deploy watch <node>`), or force it with `systemctl start cluster-upgrade` (`avc deploy now` for the fleet).

What a tick does (`lib/cluster-upgrade.nix`), in order:

1. Builds the node's closure from the flake.
2. Refuses a closure on the rollback list, `/var/lib/cluster-upgrade/refused` ([Rolling back](#rolling-back-a-bad-closure)).
3. **Refuses a closure whose boot contract differs from the running one** until `/run/cluster-upgrade.approve` on that node lists the closure's basename: nothing activated, profile untouched, `cluster_deploy_contract_blocked 1`, `DeployBlockedByBootContract`. The tick's log names the fields that differ. A topology edit to anything an unlock depends on would otherwise activate, become the default entry, and fail at the next reboot. Approve per node, after reading the diff:
   ```sh
   journalctl -u cluster-upgrade | grep -A3 REFUSING          # the closure and what differs
   echo <closure basename> >> /run/cluster-upgrade.approve    # /run: clears at reboot
   systemctl start cluster-upgrade
   ```
4. Waits for the canary on a new boot stack (below).
5. Activates with `switch`, at most three attempts per closure, then waits for a new commit (`DeployActivationFailing`). `avc deploy retry <node>` clears the attempts by hand. A closure that activated during an outage and was counted as failed is marked good once its own units are healthy.

Pull deploys never reboot. A node running a closure it has not booted shows `cluster_reboot_pending 1`, and `RebootPendingTooLong` after two weeks. Reboot one node at a time, with `avc boot reboot <node>`.

`clan machines update` is break-glass only (`avc deploy break-glass <node>`). It builds from your working tree, so the next pull would silently revert it, and it bypasses every gate above. Hold the loop first:

```sh
ssh root@node1 touch /run/cluster-upgrade.hold     # or: avc deploy hold node1
clan machines update node1
# get the same change merged into main (avc deploy ship), and only then:
ssh root@node1 rm /run/cluster-upgrade.hold          # or: avc deploy release node1
```

The hold lives in `/run`, so a forgotten one clears on reboot. Automated holds (a backup dumping a database, a restore) use one file each in `/run/cluster-upgrade.hold.d/`, so they cannot release each other, and `avc boot reboot` refuses while any is set. Keep a console open for changes to `br-wan` or the WAN stanza: on a remote machine a mistake there is a lockout.

**New boot stacks go to the canary first.** What a boot is built from and every node shares, the nixpkgs source, the kernel, clan-core, Lanzaboote, disko and this library's `modules/` and `lib/`, is written into each closure as `boot-stack`, each named by its lock's narHash or a content-addressed store path, so every node renders the same file whichever Nix it evaluates with, lazy trees or not. A bump of any of them changes no boot contract, reaches every node within the pull interval, and first runs at the next reboot, on all of them. So the node with `canary = true` activates a new boot stack at once, like any closure, and every other node builds it and waits: nothing activated, its profile and boot entry left on the old stack, `cluster_deploy_canary_wait 1` (`DeployWaitingForCanary` after a day). Reboot the canary, `avc boot reboot <canary>`, and watch it. Once that boot has unlocked by Clevis on every leg, and the boot report says so, it writes `/mnt/jfs/.cluster-deploy/canary-booted/<sha256 of boot-stack>`, and the others activate the stack at their next tick. A switch is not a boot, and a boot someone had to type the passphrase for proves nothing (`CanaryBootUnproven`), so neither publishes. App releases and topology edits on the same stack never wait. If the canary cannot be rebooted, list the closure's basename in `/run/cluster-upgrade.skip-canary` on each node you accept it on; it clears at reboot. `clan machines update` bypasses this, as it bypasses the pull loop.

Bump `clan-core` alone, as one reviewable commit. It tracks clan's unstable channel, and `checks.clan-coexist` is what catches an upstream change to host configuration. A site's private repository should merge library and lock bumps only through its merge gate: see "Merging safely" in [`templates/cluster/README.md`](templates/cluster/README.md).

### Backups and restore

Each app is backed up on its `homeNode` into its own restic repository, `<target>/apps/<sha256 of repoSalt and the app's name>`. The two are joined with nothing between them, so from a machine that isn't a node, `printf %s "$salt$app" | sha256sum` gives the directory name. `cluster-backup-list <app>` prints it on a node, and is the only map from hash to app. A snapshot holds a logical database dump, taken inside the container with its own tools, and the app's JuiceFS paths, so a restore brings back a database and the files it refers to together. `backup.localSnapshot = true` adds an app's local state, read from a ZFS snapshot, for apps no dump covers.

```sh
cluster-backup [<app>]                     # back up now
cluster-backup-list <app>                  # its snapshots
cluster-restore <app>                      # print the plan (dry run)
cluster-restore <app> --yes                # restore the latest snapshot
cluster-restore <app> --snapshot <id> --yes
cluster-restore <app> --db-only --yes      # or --files-only
cluster-restore <app> --to-scratch /var/tmp/r
```

A weekly rehearsal restores each app's backup to prove it works. If you lose a node, set the app's `homeNode` to a survivor, ship it (`avc deploy ship`), and run `cluster-restore <app> --yes` there. Keep your age key somewhere other than your laptop, because backups can't be decrypted without it.

The staging, verify and restore directories (`/var/lib/cluster-backup/{staging,verify,restore}`) hold plaintext dumps until the next run, on the node's encrypted root.

For an S3 target, use a bucket with versioning and a user that cannot delete object versions, so a compromised cluster can hide objects but cannot destroy history.

#### When the JuiceFS metadata node is reinstalled

`juicefs-format` restores the newest metadata dump on its own if it is at most 6 hours old. The mounts write one every 2 hours, encrypted, to `<bucket>/appfs/meta/`. An older one means the dumps stopped, and restoring it would lose every file written since, so the unit refuses with exit 5 and says why. To restore that dump anyway, name it on the node: `echo <dump name> > /var/lib/juicefs-format/restore-stale-dump`, then `systemctl restart juicefs-format`. Exit 4 is an outage (the database or the object storage unreachable). The unit retries it every 30 seconds, and `UnitRestartLoop` fires if it goes on for 15 minutes. Exit 3 is a volume that is not encrypted, which is refused for good.

The JuiceFS metadata engine is deliberately not backed up by restic, because restoring a stale dump against a live bucket produces a filesystem that lies about its contents. Its recovery path is JuiceFS's own metadata dump in the bucket, which `juicefs-format.service` restores when a reinstalled metadata node comes up.

#### Restore without a node

From the [offline kit](#the-offline-kit) alone, on any machine with `juicefs` (`nix develop`) and a local metadata engine:

```sh
export JFS_RSA_PASSPHRASE="$(cat rsa-passphrase)"
# the newest <bucket>/appfs/meta/dump-<date>.json.gz, downloaded with the S3 pair
juicefs load sqlite3://meta.db dump-<date>.json.gz --encrypt-rsa-key rsa.pem --encrypt-algo aes256gcm-rsa
juicefs config sqlite3://meta.db --access-key <access-key> --secret-key <secret-key> --yes   # a dump does not carry the S3 secret
juicefs mount -d sqlite3://meta.db /mnt/rescue --read-only
```

Without the passphrase, with the wrong one, or with the wrong PEM, the load or the mount fails rather than reading garbage. For the backups: `restic -r <target>/apps/<hash> snapshots` with `restic/password` and the target's credentials.

### Monitoring and alerting

Every node runs node_exporter, `smartctl_exporter`, a JuiceFS write probe, the boot report and audit, the canary scan and a jumbo-frame probe of every peer, and ships its journal and every container's journal to Loki through Vector over the mesh. The node tagged `metrics` adds Prometheus, Loki, Alertmanager and blackbox probes of every app's public hostname.

```
Prometheus (lib/alert-rules.nix) -> Alertmanager -> alert-email-bridge
  -> send-notification-email (lib/notify-email.nix) -> Cloudflare Email Sending API
```

Setup, once:

1. Onboard the sender's domain (`alerting.from`) to Cloudflare Email Sending, including SPF and DKIM.
2. Create an API token with the Email Sending permission only, and run `clan vars set <node> alerting/cf-email-token`.
3. After the deploy, run `cluster-alert-test` on the metrics node. It fires a real alert through the whole path, which resolves by itself after 5 minutes.

A weekly report emails each app's last backup, rehearsal and repository check. It is a positive signal: if it stops arriving, that tells you something.

| Alert | Severity | Means |
| --- | --- | --- |
| `BootUnlockedByPassphrase` | critical | The last boot was unlocked by a typed passphrase, not by Clevis. Expected only after an attended recovery. |
| `UnlockTpmShareFailing` | critical | Clevis did not unlock every leg on the last boot: fix the binding before the next reboot. |
| `ClevisBindingMissing` | critical | A leg has no Clevis binding (after a disk replacement, until `avc boot bind ... <device>`). |
| `ClevisBoundToUnpinnedTang` | critical | A Clevis slot is bound to a Tang key no longer in `security.tang.thumbprints`: a node not rebound after a [Tang rotation](#tang-rotation) or reinstall. Rebind before `tang-keys rotate-finish`. |
| `SecureBootOff` | critical | The node booted without Secure Boot enforcing. |
| `Pcr7Changed` | critical | PCR 7 changed within the last day: firmware, keys or Secure Boot state changed. |
| `VolumeIdentityMissing` | critical | The identity secret is missing or wrong: the next boot would halt. |
| `PoolVdevNotEncrypted` | critical | A vdev of `rpool` is not on dm-crypt. |
| `TangVlanPresent` | critical | The Tang VLAN is still up in stage 2. |
| `BootReportMissing` | critical | The node has not reported on its boot. |
| `BootSecurityOptedOut` | critical | The node runs with `insecurePlaintextBoot`, holding the fleet's keys on a plaintext disk. |
| `EspNotMounted` | warning | An ESP is not mounted: that disk's boot files are going stale. |
| `CoreDumpsNotOff` | warning | `kernel.core_pattern` is not the pipe to nowhere. |
| `IommuDisabled` | warning | No IOMMU groups. |
| `WatchdogDeviceMissing` | warning | No hardware watchdog. |
| `NodeRebooted` | warning | The node rebooted recently. |
| `RebootPendingTooLong` | warning | The node has run a closure it has not booted for two weeks. |
| `DeployActivationFailing` | critical | The deployed closure cannot be activated (three attempts, then waiting for a new commit). |
| `DeployBlockedByBootContract` | critical | A closure changes what an unlock depends on, and waits for `/run/cluster-upgrade.approve`. |
| `DeployRollbackHeld` | warning | A closure on the rollback list is being held back, or the node booted a non-default generation. |
| `DeployWaitingForCanary` | warning | A new boot stack has waited a day for the canary's reboot. |
| `CanaryBootUnproven` | warning | The canary booted without a clean Clevis unlock, so it vouches for nothing. |
| `CanaryFound` | critical | The canary turned up in plaintext somewhere it must never be: find the writer. |
| `CanaryScanStale` | warning | The canary scan has not run for 8 days. |
| `JuiceFSVolumeNotEncrypted` | critical | A node refused a JuiceFS volume that is not encrypted. |
| `JuiceFSUnwritable` | critical | `/mnt/jfs` is not writable. |
| `JuiceFSProbeStale` | warning | The JuiceFS probe has not run. |
| `JuiceFSMetaDumpStale` | warning | The newest metadata dump in the bucket is old. |
| `AuditDeliveryStale` | warning | Audit events are held on the node, undelivered. |
| `AuditProducerStale` | warning | An audit producer (sender, journal follower, Nomad stream) has stopped working. |
| `AuditNomadStreamRefused` | warning | Nomad's ACL event stream refuses the audit follower. |
| `AuditEventRejected` | warning | The Worker refused audit events from the node (a token or schema mismatch). |
| `NomadFenceStale` | critical | The fence has not completed a run. |
| `NomadTlsCertExpiring` | critical | A node's Nomad agent certificate expires soon. |
| `NomadTlsCaExpiring` | critical | The Nomad CA expires soon. |
| `VrackJumboBroken` | critical | Full-size frames to a peer are lost while small ones pass. |
| `NodeDown` | critical | The node is not reporting metrics. |
| `UnitFailed` | warning | A host unit failed. |
| `UnitRestartLoop` | warning | An audit, JuiceFS mount or format unit keeps restarting. |
| `AppUnitFailed` | critical | An app's unit failed. |
| `AppDeployDegraded` | critical | The last deploy did not apply inside an app's container. |
| `AppDown` | critical | An app's public hostname is unreachable. |
| `AppLogCritical` | warning | An app logged at critical level or above. |
| `AppErrorBurst` | warning | An app logged over 100 errors in 10 minutes. |
| `AppMigrationFailed` | warning | A database migration failed. |
| `BackupStale` | critical | No successful backup recently. |
| `BackupPartial` | warning | The last backup could not read some files. |
| `BackupVerifyStale` | warning | Backups not proven restorable recently. |
| `BackupCheckStale` | warning | A repository not pruned or checked recently. |
| `BackupNeverRan` | critical | An app has never been backed up. |
| `BackupNeverVerified` | warning | An app's backups have never passed a restore rehearsal. |
| `BackupTargetDown` | warning | The backup target is unreachable. |
| `ZfsPoolUnhealthy` | critical | A ZFS pool is DEGRADED or worse. |
| `FilesystemFull` | critical | A filesystem is nearly full. |
| `FilesystemFilling` | warning | A filesystem is filling. |
| `DiskUnhealthy` | critical | A disk fails its SMART health check. |
| `FreeIPADown` | critical | FreeIPA is not running. |
| `FreeIPAUnhealthy` | warning | `ipa-healthcheck` reports errors. |
| `FreeIPARestartPending` | warning | A deployed FreeIPA change has not been applied for a day. |
| `FreeIPAHealthStale` | warning | The FreeIPA health check has not run. |
| `FreeIPAHealthNeverRan` | warning | The FreeIPA health check has never reported. |
| `LokiDown` | warning | Loki is down: logs are queueing on every node. |
| `LogShipperDown` | warning | A node's log shipper is down. |
| `LogShippingFailing` | warning | A node has been failing to push logs. |
| `Watchdog` | none | Always firing: the heartbeat the dead-man Worker listens for. |

#### Dead-man

Alerting runs on the cluster, so it can't report the cluster's own death. `workers/cluster-watchdog` is a Cloudflare Worker that receives Alertmanager's always-firing `Watchdog` as a heartbeat, and emails you if heartbeats stop for 20 minutes. To deploy it, first fill in `CLUSTER_NAME`, `ACCOUNT_ID`, `ALERT_FROM` and `ALERT_TO` and the R2 bucket's name in `wrangler.toml`, then:

```sh
cd workers/cluster-watchdog
wrangler kv namespace create WATCHDOG          # put the printed id in wrangler.toml
wrangler r2 bucket create <bucket_name in wrangler.toml>   # the audit trail; add a bucket lock rule
clan vars get <metrics node> alerting-watchdog/token | wrangler secret put WATCHDOG_TOKEN
wrangler secret put CF_EMAIL_TOKEN             # the Email-Sending-only token
avc audit tokens                               # add the Tang host's entry, then:
wrangler secret put AUDIT_TOKENS               # paste the JSON
avc audit tang-clients | wrangler secret put TANG_CLIENTS
wrangler deploy
```

Then set `alerting.heartbeatUrl` to its `/heartbeat` URL and `alerting.auditUrl` to its `/event` URL, and ship it.

#### Audit trail

Each node sends events to the Worker's `/event`, with its own `audit/token`, from a spool on the node that survives outages: `boot` (the boot report: unlock method, devices, initrd SSH logins, Secure Boot, PCR 7, generation), `deploy` (each tick's result), `ssh_login`, `nomad_acl` (token and policy changes, from the leader) and `canary` (a hit). The Tang host sends `tang_rec` (each key release) and `tang_probe` (its heartbeat). The Worker accepts only the fields each kind's schema names, each required, from a token allowed that kind, and stores each event in the R2 bucket before it emails: it can append, never read or delete. It emails each boot (`[NOTICE]` for a clean Clevis boot, `[FIRING]` otherwise), each refused `/rec`, a Tang release with no boot report after it within 15 minutes, and a silent Tang probe.

Lock the R2 bucket against deletion with a bucket lock rule, so a stolen Cloudflare token cannot rewrite history either. How long to keep events is the site's decision ([Defaults awaiting a decision](#defaults-awaiting-a-decision)); until a rule says otherwise, they are kept. The sender is strict about TLS: a private CA in front of the Worker needs proper CA extensions.

#### Canary scan

A weekly scan plants the `canary` value in a file on the JuiceFS volume (`/mnt/jfs/.canary/<node>`), as client data is stored, and then looks for it where client data must never be in plaintext. Each place is a class, reported as `cluster_canary_hits{path_class=...}`: `tmp`, `coredump` (any core file at all), `journal` (read through journalctl, because journald compresses fields), `swap` (the raw devices under the random-key mapping), `esp`, `s3` (the exact objects JuiceFS stored the file in, as the provider stores them), and with `cluster.canary.rawDisks = true` in a host file, `raw` (every byte of both disks). A hit is `CanaryFound`, and a `canary` audit event. A class that cannot look fails the unit instead of reporting 0. Opted-out nodes scan too: their swap and disks are plaintext, so a hit there is real.

### Logs

Grafana queries Loki with labels `node`, `app`, `site`, `service` and `level`. The payload flakes supply the application fields. A label contract is pinned at build time: `modules/logging.nix` runs its VRL program over sample entries with `vector vrl`, and a program that stops emitting a label fails the system's build. Loki's store is on the `metrics` node's own encrypted disk, in its own dataset (`rpool/loki`, 50 GB quota): moving the `metrics` tag starts an empty Loki.

## Upgrading a running cluster

This version is written for fresh installs. A cluster running an earlier version of this library can't take it as an ordinary deploy, because several changes are hard cuts:

- **Disk encryption needs a reinstall.** A running plaintext node can only stay as it is with `insecurePlaintextBoot` (and the site's `insecureFleetKeysOnPlaintextDisk`), or be reinstalled through [Installing a node](#installing-a-node).
- **The first deploy of this code waits on every node.** The running closures have no boot contract, so the contract gate refuses until `/run/cluster-upgrade.approve` lists the new closure, node by node. And they have no boot stack, so every node but the canary also waits until the canary has rebooted into it.
- **Nomad TLS and the gossip key.** Rolled out node by node by the pull loop, servers with and without the key can't gossip, and plaintext and TLS RPC can't talk. All servers must switch together.
- **Scoped tokens.** The leader's `nomad-acl-init` has to run before any other node's logins succeed; until then those retry every 10 seconds, and a non-leader's deploy may report an activation failure once and then recover.
- **The mesh.** etcd's peer addresses move from the control VLAN to the mesh, and etcd reads its member list only on a new data directory, so an existing member keeps advertising its old addresses: an in-place move needs `etcdctl member update` per member, or a fresh etcd. Not tested. SSH over the VLANs stops.
- **JuiceFS encryption.** A volume formatted before is plaintext, and every mount and the metadata node now refuse it (exit 3). Moving to an encrypted volume is a migration (a new volume, copy, cut over), not a switch.
- **Loki's dataset.** A node installed before has no `rpool/loki`, and disko creates datasets only at install. Create it first on the `metrics` node: `zfs create -o mountpoint=legacy -o quota=50G -o com.sun:auto-snapshot=false rpool/loki`. Required mounts are in the boot contract, so the closure waits for approval anyway; create the dataset before approving. The old Loki bucket is no longer used.
- **Hashed backup paths.** Apps with repositories at `apps/<app>` get new, empty ones at the hashed path; the old ones stay untouched. Deploy before the first backup, or `restic copy` each app across.
- **Every container restarts once.** Each job now runs as `nomad-apps` with a new wrapper, so each allocation is replaced. Containers with `peerAccess` get a new veth, which a reload cannot apply: `nomad job restart app-<name>`. Containers' WAN MACs become fixed (`02:76:77:<node index>:<iid>`); if your provider pins MACs per port or address, check before rollout.

## Testing

Everything runs against the **fixture cluster** in [`tests/fixtures`](tests/fixtures), which is built through `mkCluster` the way a consumer's is. Its public addresses are documentation-only (RFC 5737, RFC 3849) and its names are under `example.com` and `example.net`. Its internal VLANs are RFC 1918, because the documentation ranges have no /16 to split into per-node subnets. It has `node1` with every role, placeholders `node2` and `node3`, and neutral apps of every kind, with stub packages for Odoo and Frappe. Every fixture node opts out of boot security, because a VM test of a cluster has no TPM; the `boot-*` checks install and boot the encrypted layout themselves, and `tests/fixtures/secure` is node1 with boot security on, evaluated by `security-policy` and `boot-closure`.

No secret is committed. `tests/fixtures/secrets` holds placeholders that are not ciphertext, because `lib/mk-app-container.nix` asserts that every secret an app mounts exists. `tests/fixtures/update-secrets.sh` regenerates them after you add a fixture app or change a generator.

```sh
nix build -L .#checks.x86_64-linux.<name>        # one check
nix flake check --no-build --option eval-cores 1 # evaluate everything (see the RAM note)
nix run .#checks.x86_64-linux.cluster.driverInteractive   # a shell into the VMs
tests/run-mutants.sh <name> ...                  # prove named mutants
```

**Evaluating every check takes about 14 to 32 GB of RAM, single-threaded.** `nix flake check --no-build --option eval-cores 1` peaked between 13.6 and 31.7 GB in the nix client over the nine runs measured (median about 22 GB; the latest two, on this tree, 13.6 and 23.4 GB, about 5 minutes each; Determinate Nix 3.24.2, nix 2.35.3), before anything builds. With Determinate Nix's parallel evaluation (its default) it peaked at 52.9 GB, so pass `--option eval-cores 1` on a smaller machine. Each check is wrapped in `detach` (`tests/lib/detached-check.nix`), so once its `.drv` path is known its systems are garbage, and `checks.eval-memory` refuses a check or mutant written without it. What remains is the fixture's own `nixosConfigurations`, which the flake exports, the check being evaluated, and whatever the evaluator's conservative garbage collector has not yet let go of from the ones before, which is why the figure varies from run to run. A `nix build .#x` also keeps its evaluator's heap for as long as a VM test runs, so on a smaller machine evaluate first and build the `.drv`, which holds almost nothing:

```sh
nix build --no-link "$(nix eval --raw .#checks.x86_64-linux.<name>.drvPath)^*"
```

`tests/run-mutants.sh` works this way. With no names it evaluates every mutant in one go, which peaked at 25 to 41 GB. One check at a time is much cheaper: most evaluate in 0.2 to 5 GB, the largest are `container-isolation` (8.6 GB), `security-policy-fixture` (8.4 GB) and `control-plane-failure` (6.2 GB), and `nix run .#checks.x86_64-linux.<test>.driverInteractive` evaluates that test again. All the checks one after another take about two hours of VM time; the boot tests are the long ones.

**Mutants** (`legacyPackages.x86_64-linux.mutants`) are the proofs that the security checks can fail: each removes or weakens one control, and must fail its check's named subtest with `##MUTATION-PROVEN##`, for the reason it names. They are not checks, so `nix flake check` does not build them. Run them all before a release (`tests/run-mutants.sh` with no names, about four hours), and a changed control's own mutants with it. `nix eval .#legacyPackages.x86_64-linux.mutants --apply builtins.attrNames` lists them.

| Check | What it proves |
| --- | --- |
| `avc` | The operations tool's own tests: policy gate, ship ordering, registry, boot, secrets and audit flows. |
| `mk-cluster` | The consumer interface, with a `self` that exports nothing, and the template's own flake outputs, including that the template as shipped refuses to evaluate until its boot fields are filled in. |
| `docs` | This README against the code: every check has a row here, every `avc`, `cluster-boot-seal` and `tang-keys` command it names exists, every topology field, alert and generator is documented, and no address or email is outside the reserved ranges. |
| `security-policy` | The boot security posture and its one opt-out: what evaluates, what is refused and for the reason it claims; the boot contract's fields, the boot stack, the canary's topology rules; and that `clan vars generate` can read every generator of a new site. Evaluation only. |
| `security-policy-fixture` | The posture checks that need a whole fixture system per node. |
| `boot-closure` | What can be proven about an encrypted closure without booting it: the ESP budget, the initrd's contents (a stock Clevis fails the build), and when the boot contract moves (not on a kernel bump; on every field an unlock depends on). |
| `boot-install` | An encrypted node installed with the real disko script, under Secure Boot with keys made on the node: unattended unlock through Tang and the TPM, bind refused in Setup Mode and for a wrong thumbprint, the Tang VLAN gone in stage 2, a second kernel and generation on both ESPs. |
| `boot-fallback` | Tang refused, silent or dropped: the prompt within seconds, typing on serial, tty0 and SSH; wrong passphrases ask again; one leg waiting does not import the pool degraded; the boot report counts the passphrase. |
| `boot-degraded` | A dead, absent or corrupt disk boots unattended and DEGRADED; each ESP boots alone; a full or unmounted ESP refuses a new generation without writing to the root; a disk replacement onto a new LUKS leg; signing keys lost and recovered; the identity repair from rescue; no plain vdev. |
| `boot-attack` | A swapped volume with forged identifiers halts before it can steal anything (and steals the keys with the check removed); the emergency shell burns PCR 7; a tampered initrd or unsigned loader is refused; Secure Boot off, a db certificate added, keys cleared, another signed loader or a cleared TPM all withhold the TPM share; a foreign authority in PCR 7 refuses bind. |
| `tang-server` | The Tang host: Tang only on its private NIC and to its clients, SSH only on the public one; the key guard refuses where stock tangd would mint keys; rotation with a t=2 Clevis client; the verified probe and `/rec` events reach the real Worker. |
| `deploy-safety` | What a pull deploy does with a closure that fails, one whose boot contract changed, a refused one after a rollback (by hand and at boot), a held node, and a frozen PID 1 under the hardware watchdog. |
| `canary-gate` | The staged rollout, with two VMs and the real tick and publisher: a follower waits for a new boot stack and takes an app release on the same stack at once; the canary takes the stack first; a switch and a passphrase boot publish nothing; a clean reboot publishes it and the follower then activates it; `/run/cluster-upgrade.skip-canary` is per closure; an unmounted store proves nothing either way. |
| `nomad-pki` | Nomad's PKI without booting anything: the real generators' certificates, names, chain and validity, the gossip file, and a minted login JWT. |
| `control-plane-attack` | A machine on the control VLAN with each credential an attacker could hold: what mTLS and the gossip key refuse, and the documented limit; what a stolen `submit-job` token can and cannot do through `raw_exec`; what a machine on the VLANs reaches without a mesh key. |
| `control-plane-failure` | The control plane's own failures: the mesh cut, a key rotated on one side, a node booted without its mesh key, every Nomad certificate expired, and recovery from each. |
| `jumbo-mtu` | MTU 9000 on the VLANs and 8920 on the mesh, on a link that carries it and on one that silently doesn't (`VrackJumboBroken`). |
| `container-isolation` | Container to host and container to container: default-deny, the holes an app declares by bridge port, spoofed identities refused, the WAN segment's pinned MACs and neighbour discovery. |
| `voter-growth` | One Nomad voter to three: the first voter's switch, a worker promoted, a fresh voter, etcd formed once three nodes carry it, and the `bootstrap_expect` trap. |
| `jfs-encrypted` | The JuiceFS volume is encrypted; a plaintext one is refused at format and at mount; restore works with the key, only with the key, and from the offline kit alone; stale dumps, interrupted loads, S3 key rotation. |
| `canary-scan` | Per class: plant the canary, scan, found; remove it, scan, not found. Swap plain against dm-crypt, a plaintext bucket against an encrypted one, a real compressed core a grep can't see into. |
| `container-tunnel` | The generated container, tunnel and firewall wiring. |
| `clan-coexist` | clan-core is not overriding the host configuration it must not touch. Run it on every clan bump. |
| `backup` | What the fixture apps generate: engine detection, units, salted repository paths, target URLs. |
| `freeipa` | FreeIPA's wiring, and Authelia's own `validate-config` over its generated config. |
| `alert-rules` | Every alert rule fires when it should and stays quiet when it should not (promtool). |
| `alerting` | An alert travels Prometheus, Alertmanager and the bridge to a stub of the Cloudflare API, in a VM. |
| `cluster-watchdog` | The dead-man's logic, and the audit Worker's schemas, tokens and emails. |
| `logging` | A journal entry reaches Loki with the label contract, in a VM. Loki keeps its store on local disk with no credentials, retention deletes old lines, and a crash leaves no core dump on the host or in a container. |
| `backup-roundtrip` | Backup, damage and restore against an S3 server, for PostgreSQL and MariaDB, in a VM. |
| `install-boot` | The plain disk layout installs into a VM, reboots, and comes back. |
| `cluster-single` | `node1`'s real machine module boots and walks the whole cold start, twice: secrets, networking, the mesh, etcd, encrypted JuiceFS on S3, Nomad with TLS and scoped tokens, every app's job, monitoring, the audit producers. Jobs register but aren't placed. About 5 GB of RAM. |
| `cluster` | Three voters form quorums, share one JuiceFS volume, and run probe containers with cross-node reachability, pinning and fencing. About 9 GB of RAM. |
| `ci-workflows` | The workflows in `.github/` and the template's pass actionlint, keep the properties the merge gates rest on (one evaluation per check, never `nix flake check`, a gate that fails on anything but success), and `tools/ci` fails loudly, against a stub `nix`. |
| `eval-memory` | Every check and mutant is detached, so `nix flake check` does not keep every evaluation to the end, and detaching keeps the same `.drv` and the interactive driver. |

The VM tests take the real machine modules and change only what a VM cannot have (`tests/lib/cluster-harness.nix`, `tests/lib/boot-harness.nix`): fixture values are written to the paths clan's age backend would decrypt to, NICs carry the topology's names, a `wan` VM holds the nodes' gateways and answers for the object-storage hostnames, and the pull timer is unhooked. The test network has no route out. The boot tests run OVMF with Secure Boot and a software TPM, and a `tang` VM on the Tang VLAN.

### Continuous integration

`.github/workflows/ci.yml` is the merge gate: every check in `checks.x86_64-linux`, the `boot-*` VM tests included, each in its own job. Make **`ci-gate`** the required status check on `main`; it fails unless every job succeeded, a skipped one included. `mutants.yml` builds every named mutant, each in its own job, by hand before a release (about four hours of VM time).

It needs a self-hosted runner, labelled `self-hosted, linux, x64, kvm`, because the boot tests boot VMs from encrypted disks under OVMF and hosted runners cannot fit them: Nix with flakes, `/dev/kvm` writable by the runner (nested virtualisation, if the runner is a VM), `system-features = kvm nixos-test`, at least 16 GB of RAM, and about 100 GB of disk. `tools/ci/preflight.sh` runs at the start of every job that builds, on whichever runner took it, and refuses a runner without Nix, a read-write `/dev/kvm`, both system-features, 16 GB of `MemTotal` or 50 GB free under `/nix/store`. All the checks one after another take about two hours on one runner; more runners take jobs in parallel.

It never runs `nix flake check`. Each job evaluates one check in its own `nix` process and builds the `.drv` it printed (`tools/ci/build.sh`), so no evaluation needs more than about 9 GB, against 14 to 53 GB for the whole flake.

A self-hosted runner runs a pull request's code. On a public repository set "Require approval for all external contributors" (Settings, Actions) and approve only what you have read: a fork can edit the workflow, so the workflow's own check that a pull request comes from this repository stops accidents, not attackers. That check also means **a pull request from a fork never passes `ci-gate`**, approved or not: its jobs are skipped, and a skipped job fails the gate. To gate a contribution, read it, push it to a branch of this repository, and open the pull request from there. Approval only decides whether a fork's run starts at all, which matters when the fork has edited the workflow.

A site's private repository gates its own merges the same way, at its own `flake.lock`, which is what its nodes run: see "Merging safely" in [`templates/cluster/README.md`](templates/cluster/README.md).

## Defaults awaiting a decision

Each of these is built with a default and is easy to reverse. They are choices for whoever runs a site to confirm. The D-numbers are the labels these decisions carry in the code's comments.

| Choice | Default | To reverse |
| --- | --- | --- |
| The initrd emergency shell (D3) | Kept, behind a hashed random password, with a PCR 7 burn before it starts. The only way in if the initrd's network fails. | No shell at all: `emergencyAccess = false` in `modules/boot-security-core.nix` and its assertion in `modules/boot-security.nix`. SSH recovery still works. |
| The Nomad management token (D6) | Kept on the `nomad-leader` node, read only by `nomad-acl-init`. Deleting it adds little: root on a server can mint one. | Delete it after `nomad-acl-init` and make policy changes through `acl-bootstrap-reset`. |
| The Nomad autoscaler (D11) | Runs on the `metrics` node with a scoped token, and does nothing until a job has a scaling policy. | Remove the service and the `autoscaler` login role. |
| Deploy judgement calls (D15) | Three activation attempts per closure; no automatic live rollback; contract changes approved per closure on the node; boot counting off; `RebootPendingTooLong` after 14 days; attended reboots, one node at a time. | `MAX=3` in `lib/cluster-upgrade.nix`; an approved digest in the private repository instead of per-node approval; Lanzaboote's boot counting. |
| Hashed restic paths (D17) | `apps/<sha256(salt + app)>`, so app names don't reach the backup provider. | Delete the `cluster.backup.repoPathFor` line and the salt assertion in `modules/backup.nix`. |
| CI merge gate and canary (D22) | Public CI on a self-hosted KVM runner; the site's merges gated on `boot-install` and `boot-fallback` at its own lock; one canary node required on any site of more than one node. Every new boot stack holds the other nodes' deploys until the canary reboots. | `deploy.withoutCanary = "<reason>"`; per closure, `/run/cluster-upgrade.skip-canary`. |
| Same-node `peerAccess` identity (D23) | A deterministic extra veth, `vp-<iid>`, per peer app. | Forbid long names on `peerAccess` apps instead, which would force renames. |
| FreeIPA's capabilities | `additionalCapabilities = [ "all" ]` kept, which includes loading kernel modules: a compromised FreeIPA container is host root. | Drop capabilities in `modules/kinds/freeipa.nix`, after testing a real FreeIPA, which no VM here can run. |
| Audit retention | Nothing chosen: events are kept until someone deletes them. | An R2 lifecycle or bucket lock rule with the period the risk analysis chooses; no code depends on it. |
| The mesh interface's name | `wg-ctrl`. | `meshIf` in `lib/net.nix`, one line. |
| Fixed container WAN MACs | `02:76:77:<node index>:<iid>`, so the bridge can pin them. | Drop `linkConfig.MACAddress` in `lib/mk-app-container.nix` and the per-app rules in `modules/overlay-network.nix`. |
| Microsoft keys (D27) | Not enrolled; option ROMs by hash. Chosen by the user. | `cluster.boot.enrollMicrosoftKeys = true` per node, with the risk above. |
| Old signed generations (D26) | Bootable until the Secure Boot keys rotate. Accepted by the user. | A forward-moving seal (systemd-pcrlock or a signed PCR 11 policy), not built. |

## Known limitations

These are accepted deliberately.

1. **No origin health checking.** Cloudflare fails over between connectors, not origins. A live connector in front of a dead container returns 502.
2. **Replicas do not load-balance.** Steering is to the closest connector.
3. **Request body cap.** Cloudflare's limit (100 MB on Free and Pro) applies to everything proxied, tunnel included.
4. **Config changes bounce the connector.** A container restart drops its tunnel briefly.
5. **`br-wan` puts containers on the public L2 segment.** Their inbound filtering is the container's own firewall, with the host pinning each port's MAC and addresses.
6. **Backups are nightly, not point-in-time.** Local ZFS snapshots narrow that to 15 minutes, but only for losses on the node itself.
7. **The JuiceFS metadata engine is a single point of failure.** If the `juicefs-meta` node dies, every node's `/mnt/jfs` is stranded until it returns.
8. **x86_64-linux only.** The machine platform is fixed in `lib/mk-cluster.nix`.
9. **A reboot needs Tang or a person.** If the Tang server is down, every rebooting node waits at its prompt.
10. **Nothing here has run on real firmware.** Every boot path is proven in VMs (OVMF, a software TPM); the [checklist](#real-hardware-checklist) is what proves a real node.

## License

MIT. See [LICENSE](LICENSE).
