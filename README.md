# nixos-cluster-orchestration

A NixOS module library for running application containers on a small cluster of bare-metal machines: `systemd-nspawn` containers, started and stopped by HashiCorp Nomad, sharing state through an encrypted JuiceFS volume, each reaching the internet through its own outbound Cloudflare Tunnel. Every node's disks are encrypted and unlock unattended only into the node's own signed boot.

There is no Kubernetes, image registry or load balancer. Each node compiles its own closure locally from a flake, Nomad only turns pre-built dormant containers on and off, and no inbound port is opened for any application.

This repository holds no site's details. You keep your topology, apps and encrypted secrets in your own private flake, which calls [`lib.mkCluster`](#the-interface).

```sh
nix flake init -t github:Avunu/nixos-cluster-orchestration
```

**Contents.** [Architecture](#architecture) · [The interface](#the-interface) · [Encryption](#encryption) · [Installing a node](#installing-a-node) · [Recovery](#recovery) · [Real hardware checklist](#real-hardware-checklist) · [Residual risks](#residual-risks) · [Topology schema](#topology-schema) · [Kinds](#kinds) · [Operations](#operations) · [Upgrading a running cluster](#upgrading-a-running-cluster) · [Testing](#testing) · [Defaults awaiting a decision](#defaults-awaiting-a-decision) · [Known limitations](#known-limitations) · [License](#license)

## Architecture

- **The topology is the single source of truth.** Nodes, VLANs, addressing, object storage and role tags are one plain Nix attrset. Every module derives its networkd units, nftables ruleset, Nomad settings, quorum membership and Prometheus targets from it.
- **Bootstrap is push, steady state is pull.** `avc boot install` installs a node from its provider's rescue system, with [nixos-install-helper](https://github.com/Avunu/nixos-install-helper) and nixos-anywhere underneath (see [Installing a node](#installing-a-node)). After that, every node rebuilds itself from your flake on a timer (`modules/pull-deploy.nix`), so deploying means pushing a commit.
- **Every node is encrypted unless it says why not.** Both disks are LUKS2 under the ZFS mirror, the boot is signed with keys made on the node, and the TPM releases the disk key only to that signed boot. A node that sets nothing fails to evaluate. See [Encryption](#encryption).
- **Apps are one short file each.** `apps/<name>.nix` is one `clusterApps.<name>` entry, and its [kind](#kinds) fills in the container, paths, sockets, secrets, backups and ingress. Each entry becomes a dormant container on every node, plus a Nomad job that starts and stops it. No entry names a node: Nomad places every app, and an app's data is where Nomad puts it ([Where an app runs](#where-an-app-runs)).
- **Ingress is a tunnel per app, over a unix socket.** Each container runs its own `cloudflared` against a unix socket. See [Ingress](#ingress).
- **Storage has two tiers, and both follow the app.** Local ZFS (`modules/zfs-host.nix`) holds anything latency-sensitive, such as database directories: each app's is a dataset of its own, replicated to every node (`modules/app-state.nix`). JuiceFS over S3 (`modules/storage-juicefs.nix`) holds files: each app has a volume of its own, in a bucket of its own, mounted on the node the app runs on ([An app's files](#an-apps-files)). Its metadata is a PostgreSQL database with a member on every node, which survives the loss of the node holding its primary ([The JuiceFS metadata database](#the-juicefs-metadata-database)). The volume is encrypted, and every mount refuses one that is not.
- **Secrets are age files, rekeyed per node.** Each is committed encrypted to the operators' master identities (YubiKeys), and [agenix-rekey](https://github.com/oddlama/agenix-rekey) re-encrypts what a node reads to that node's own recipient, whose private half is in the node's TPM. The rekeyed files are committed too, so a node decrypts at activation from its own closure, with no operator and no operator key. A node whose secrets did not all decrypt does not start Nomad, and says so (`SecretsMissing`). Containers never hold a key: the plaintext is bind-mounted in. See [Secrets](#secrets).
- **No service belongs to one node.** A tag says what a node votes in (`nomad-server`, `etcd`) or that it runs apps (`worker`). Everything else, the JuiceFS metadata database, job registration, Prometheus, Alertmanager and Loki included, runs on every node or every Nomad server.
- **The private network is not trusted.** Nomad speaks mTLS with a gossip key on the control VLAN. Everything else between nodes (etcd, Loki, Prometheus and its exporters, Vector, the JuiceFS metadata database) listens only on a WireGuard mesh, `wg-ctrl`, over that VLAN. See [The control plane](#the-control-plane).

### How a container runs

1. Every node has every app pre-built in its `/nix/store`. Nothing ships a root filesystem around the network.
2. Each app's Nomad job is one `raw_exec` task in the `apps` namespace, a wrapper that runs `nixos-container start <name>`, blocks while the unit is active, and stops it cleanly on `SIGTERM`. The task runs as the unprivileged `nomad-apps` user (uid 4096) with no network, and a polkit rule lets that user start and stop the declared containers and nothing else. "Task alive" and "container running" are the same thing by construction.
3. `nomad-bootstrap.service`, on every Nomad server, registers every rendered job after raft leadership, with the scoped `registrar` token. An unchanged job is a no-op, so the first server to switch to a generation registers its jobs and the others change nothing. A server registers a generation once: restarted on the same generation, it registers only a job the cluster no longer has or has dead, so a server still on an older generation does not put its jobspecs back at each boot.
4. `nomad-fence` runs on every node every 30 seconds and stops any managed container Nomad no longer claims. If the local API is unreachable or answers with an error, it does nothing rather than guess.
5. Moving an app is a clean stop on one node and a cold start on another, with its local state handed over in between. Its tunnel travels with it and its socket path does not change, so nothing moves on the Cloudflare side.
6. A deploy reaches a running container by reload, not restart. Only the guest units whose definition changed restart. What a reload cannot apply (bind mounts, network interfaces, capabilities) needs `nomad job restart app-<name>`.
7. One app's failure is not the node's. A guest that fails its reload is reported (`cluster_app_deploy_degraded`, alert `AppDeployDegraded`) instead of failing the host's switch and every other app's deploy.

### Where an app runs

Nomad decides, each time an app starts: the emptiest node that can run it (`scheduler_algorithm = "spread"`), by the `resources` its entry declares. Nothing in an entry names a node, and two things only narrow the choice. An app with files on JuiceFS needs a node whose mount is ready. And `wpdb` runs on the node whose app subnet its `address` is in, because an address does not move between subnets. `nomad.constraints` takes anything else in Nomad's own terms.

An app with local state (a database directory, FreeIPA's data) runs as one allocation, and its state goes where it goes:

- **A dataset per app.** `<pool>/state/apps/<app>`, mounted at `/state/clients/<app>` on the node running the app and kept unmounted and read-only on every other node.
- **Replicated every minute.** The node running the app snapshots the dataset if anything was written (`cluster.state.intervalSeconds`, 60), and every other node pulls what it lacks, incrementally, over the mesh. Each node thins its own copy by its own clock: every snapshot for four hours, then one an hour for a day, then one a day for a week (`cluster.state.keep`). A replica never drops history because the running node did, so that node, taken over, cannot erase what the others hold; asked to, a replica sets its copy aside like an orphan.
- **A move loses nothing.** When Nomad starts the app on another node while the first is reachable (a drain, a job restart that lands elsewhere), the new node stops it on the old one, takes a last snapshot of the stopped database, receives it, and starts.
- **A node's death loses at most the interval.** Nomad marks the node down and starts the app on another, from the newest snapshot any surviving node holds. The new node first waits until the dead one, if it is only cut off, has stopped its own copy: a node that cannot reach a Nomad server stops its stateful apps 60 seconds after its last heartbeat (Nomad's `disconnect.stop_on_client_after`). An unplanned failover therefore takes about three minutes, and what the dead node wrote after its last replicated snapshot is not in the app any more.
- **Those writes are kept, on the node that made them.** When it returns, its copy is renamed to `<pool>/state/orphans/<app>-<time>`, whole, and it receives the app's new history as a replica. `StateOrphaned` fires. Nothing deletes an orphan: mount it, take what is needed, and remove it yourself.

```sh
cluster-state status                      # per app: which node runs it, each replica's age, orphans
cluster-state orphans                     # copies set aside on this node
zfs set mountpoint=/mnt/orphan <orphan> && zfs mount <orphan>   # read one
cluster-state drop-orphan <orphan> --yes  # delete it
cluster-state init <app>                  # a new app's empty dataset, when a node cannot be asked
```

A new app's first start makes its dataset, once every node has answered that none holds one. With a node silent, the start is refused instead of beginning an empty database beside one that may exist; `cluster-state init <app>` says it is new.

What this does not do. Replication is asynchronous, so a failover is to a slightly earlier database, never to the same one. Every node holds a copy of every app's local state, so the pool is sized for all of them, not for a share. Nomad places an app when it starts and does not move a running one to even out load: `nomad node drain` and `nomad job restart` are how load is moved by hand. And the fence above relies on the cut-off node's Nomad agent running: a node whose agent is dead while its containers live, and which no peer can reach on the mesh, would keep writing to a copy that is then orphaned.

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
network.hostAccess = [ 3100 ];                             # TCP ports on the mesh address of the node it runs on
network.peerAccess = [ { app = "wpdb"; port = 3306; } ];   # another app, one TCP port
```

- `hostAccess` is for Loki and Prometheus, which every node runs: the app reaches them on the node Nomad put it on. Its name must be at most 12 characters, because its identity is nspawn's veth `vb-<name>` (asserted).
- `peerAccess` reaches another app on the same node over the bridge, or on any other node over the app VLAN, on one TCP port, and nothing comes back but replies. Both ends get an extra `br-app` veth named `vp-<iid>`, so any name length works (D23 under [Defaults awaiting a decision](#defaults-awaiting-a-decision)).
- Identity is the bridge port a frame arrives on, never the address: a container holds `CAP_NET_ADMIN` and can take any address and MAC it likes.
- A container's IPv4 egress excludes RFC 1918, CGNAT, link-local and every node's public address. An S3 endpoint on a private address would need a rule of its own.
- ICMP between containers is not allowed.
- The `grafana` kind declares its own `hostAccess`, and `wordpress` declares `peerAccess` to its `wpdb`.

Refused traffic is logged, rate-limited, with the prefixes `container-to-host-drop` and `container-forward-drop`.

### The control plane

- **Nomad** listens on the control VLAN with mutual TLS (`nomad-ca`, `nomad-tls`) and a gossip key (`nomad-gossip`, servers only), and verifies server names. ACLs are on. Apps run in the `apps` namespace; `default` can run nothing.
- **Every machine logs in with scoped tokens.** Each node holds pre-signed JWTs (`nomad-login`, signed offline by `nomad-jwt`) for its roles: `fence`, `node-meta` and `avc` everywhere, `registrar` on the Nomad servers. `nomad-login@<role>` exchanges them for tokens in `/run/nomad-tokens/<role>`. The management token (`nomad-acl`) is on the Nomad servers and on no worker, read only by `nomad-acl-init` and the audit trail's ACL stream. **Every voter still holds every ACL token, management included, in its raft state**, and root on a server can always mint one.
- **Everything else is on the WireGuard mesh**, `wg-ctrl`, one key per machine (`wg-ctrl`), each node at `<mesh.subnet base>.<index>`. A machine on the VLAN without a key reaches only Nomad's port and the mesh's UDP port. The mesh authenticates the machine, not the process: any process on a node can use it (D1, accepted). SSH no longer answers on the VLANs.
- **etcd** is created once, from the tags, with three or more members (see the tag table).
- **Jumbo frames.** The VLANs take `vlans.<v>.mtu` (9000 in the template) and the mesh 80 bytes less. A private network that doesn't really carry 9000 is a silent blackhole, so every node probes every peer at full size (`VrackJumboBroken`), and the [real hardware checklist](#real-hardware-checklist) tests it before any data. With the trunk at 1500 and a VLAN asking for 9000, networkd does not create the VLAN at all.

An operator shell on a node has `NOMAD_ADDR`, the CLI certificates and `NOMAD_NAMESPACE=apps` set. Bring a token:

```sh
export NOMAD_TOKEN=$(cat /run/nomad-tokens/avc)   # read, restart, logs: the everyday token
```

### Assumptions about the hardware

The network modules were written for bare-metal hosts on OVHcloud's model, and some comments still describe it: a WAN NIC with an off-subnet gateway on both address families, a routed /64 with no router advertisements, and a second NIC trunking tagged private VLANs (`vrackInterface`). Another provider fits if it offers the same shape. Each node needs two NVMe disks for the ZFS mirror (`lib/mk-disk-layout.nix`, `nodes.<n>.disks`), UEFI with Secure Boot that can enter Setup Mode, and a TPM 2.0.

## The interface

The library's flake exports `lib.mkCluster`, which returns the site's machines and what `agenix rekey` reads. A consumer's flake looks like this ([`templates/cluster`](templates/cluster) is a complete one):

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
      site = cluster.lib.mkCluster {
        inherit self inputs topology;
        directory = ./.;
        meta.name = "my-cluster";
        masterIdentities = [ ./secrets/master/yubikey-1.pub ];
        extraRecipients = [ "age1..." ];
        admins = [ "ssh-ed25519 AAAA... me@laptop" ];
        appsDir = ./apps;
        hostsDir = ./hosts;
      };
    in
    {
      inherit (site) nixosConfigurations agenix-rekey apps;
      clusterSecrets = site.secrets;
      opsIndex = cluster.lib.mkOpsIndex { inherit site topology; };
      inherit (cluster) packages devShells;
    };
}
```

| Argument | Required | Meaning |
| --- | --- | --- |
| `self` | yes | Your flake. The machines are built with `self.inputs.nixpkgs`, falling back to the library's. Use `nixpkgs.follows = "cluster/nixpkgs"` to stay on the tested revision. `agenix rekey` writes below its root. |
| `inputs` | no | Your flake's inputs, merged with the library's and passed to modules and app files as `inputs`. Yours win, so you can bring your own `frappe-nix`, `odoo-nix` or `wordpress-nix`. Any you don't set come from the library. |
| `directory` | yes | Where the site's secrets live, under `secrets/` (see [Secrets](#secrets)). Use `./.`, a path at your flake's root: `agenix rekey` finds where each node's rekeyed files go by it. |
| `topology` | yes | See [Topology schema](#topology-schema). |
| `meta` | yes | `{ name; }`. The name signs alert emails and names the binary cache's signing key. Other attributes are ignored. |
| `masterIdentities` | yes | The operators' age identities, as agenix-rekey's `age.rekey.masterIdentities` takes them: a path to an identity file, or `{ identity; pubkey; }`. Every secret in the repository is encrypted to all of them, and `agenix rekey` decrypts with any one. For a YubiKey, the file `age-plugin-yubikey --identity` prints, which holds no private key and is committed. Anyone holding one can decrypt every secret. |
| `extraRecipients` | no | age recipients every secret is also encrypted to and that nothing decrypts with day to day: the offline one (see [The offline kit](#the-offline-kit)). |
| `admins` | yes | The operators' SSH public keys, for `root` and `admin` on every node, and for the initrd's SSH. Empty is an evaluation error, because it would lock you out. |
| `appsDir` | no | One file per app. `null` means no apps. |
| `hostsDir` | no | `<name>.nix` per machine, each optional. |
| `grafanaDashboards` | no | Replaces the dashboards in `configs/grafana-dashboards`. |
| `extraModules` | no | NixOS modules imported on every machine. |

Other exports:

| Output | What it is |
| --- | --- |
| `lib.mkOpsIndex { site, topology; }` | What `avc` reads, exposed as your flake's `opsIndex`. `site` is what `mkCluster` returned. |
| `lib.net`, `lib.juicefs`, `lib.backupTarget`, `lib.mkAppContainer`, `lib.nomad` | The pure helpers the modules use. |
| `nixosModules.*` | The modules. They read `topology`, `clusterLib` and `clusterSite` from `specialArgs`, which `mkCluster` provides. |
| `packages.avc`, `packages.agenix`, `devShells.default` | The operations tool; agenix-rekey's command (`nix run .#agenix -- rekey`, `edit`, `view`), which reads the flake it is run in; and a shell with both, `nomad`, `juicefs`, `age` and its YubiKey and TPM plugins. |
| `templates.default` | The consumer flake skeleton. |
| `nixosConfigurations`, `agenix-rekey`, `clusterSecrets`, `opsIndex` | The **fixture** cluster's, for this repository's checks. Yours come from your own `mkCluster` call. |

`mkCluster` returns:

| Attribute | What it is |
| --- | --- |
| `nixosConfigurations` | One NixOS system per key of `topology.nodes`. |
| `agenix-rekey` | What `agenix rekey`, `edit` and `view` read. Export it under that name. |
| `secrets` | Every machine's secret generators as data (script, prompts, dependencies, and where each file is kept), for the tool that runs them. `nix eval --json .#clusterSecrets.<node>`. |
| `machineModules` | Each machine as a NixOS module, which the VM tests boot. |
| `apps` | `apps.x86_64-linux.install-<node>` for each node: its installer, which `avc boot install` runs. Export it as your flake's `apps`. |
| `installers` | The same per node as the whole [nixos-install-helper](https://github.com/Avunu/nixos-install-helper) project (`mkProject`'s result), for a site that wants more of it than the `deploy` app. |

Three things are easy to get wrong:

- **`nix flake check --no-build` evaluates read-only.** agenix-rekey reads a node's rekeyed files through a copy of their directory in the store, which a read-only run never makes (`error: path '/nix/store/…' is not valid`), so that command fails on a flake whose rekeyed files no normal evaluation has copied yet. Plain `nix flake check`, `nix eval` and real builds are unaffected. This repository's fixtures have no recipients and pass `directory` as a string to stay clear of it; `checks.secrets-tpm` and `checks.secrets` read a site that does have them.
- **Flakes only see tracked files.** Run `git add` on new apps, secrets and rekeyed files before you evaluate.
- **A rekeyed file that is missing stops the build.** A node with a recipient whose secret was added or changed and not rekeyed fails to evaluate, with agenix-rekey's "please run `agenix rekey`". A node with no recipient yet evaluates with placeholders that decrypt nowhere, and a warning.

## Encryption

### The threat goal

Conventional access to the hosting provider's side of a machine must not be enough to read client data: pulled drives, a rescue boot, a BIOS change, a snapshot, or another machine attached to the private VLANs. What stays out of scope is written down in [Residual risks](#residual-risks): an attacker on the hardware buses, firmware or BMC compromise, and a full takeover of the provider account that boots the real system.

### What protects what

| Where data is | How it is protected |
| --- | --- |
| Both disks | LUKS2 on each leg of the ZFS mirror (`crypt-a`, `crypt-b`); evaluation refuses a vdev that is not on dm-crypt, and `PoolVdevNotEncrypted` checks it at run time. Swap takes a random key every boot. The ESPs are plaintext and hold the signed boot files, public values, and one secret: the initrd's SSH host key, inside the initrd (see [Residual risks](#residual-risks)). |
| The disk key | Each leg's header holds two key slots and no more. One is a TPM2 slot (`systemd-cryptenroll`), made at install bound to no PCR and replaced by `avc boot bind`, once Secure Boot enforces the node's own keys, with one sealed to PCR 7, which records Secure Boot's state and keys. The other is the node's **recovery key**, which exists as ciphertext in the private repository, encrypted to the operators' YubiKeys, and nowhere else. The key a leg is formatted with is made in the installer's memory and has no slot once the install is over. The TPM is the one unattended factor: see [Residual risks](#residual-risks). |
| The boot | Secure Boot through Lanzaboote, with keys made on the node at install and never copied off it (`/var/lib/sbctl`, on the encrypted root). No Microsoft keys by default: option ROMs this boot measured are enrolled by hash. |
| A swapped volume | A per-node secret on the encrypted root whose hash is compiled into the signed initrd. The initrd checks it before it mounts anything from the pool, and halts on a mismatch, so a forged disk with copied identifiers gets nothing. |
| The emergency shell | Protected by a hashed password, and entering it first extends PCR 7 with a burn, so the TPM refuses the disk key for the rest of that boot. |
| The JuiceFS volume | Encrypted by JuiceFS with an RSA key (`juicefs-rsa`, `aes256gcm-rsa`). Every mount, and `juicefs-format` on every node, refuse a volume that is not encrypted (exit 3, `JuiceFSVolumeNotEncrypted`). Its automatic metadata dumps in the bucket are encrypted too. |
| Logs | Each node's Loki keeps its store on that node's own encrypted disk (`/var/lib/loki`), not in a bucket. Core dumps are off on every node and in every container. |
| Backups | restic, with each app's repository at a salted hash of its name. |
| The state backup | Restic, like the nightly backup and under the same password, at a salted hash of the app's name that is not the nightly repository's. See [Backups and restore](#backups-and-restore). |
| Between nodes | Nomad mTLS and gossip key; everything else on the WireGuard mesh. |
| A node's secrets | In its closure and in the repository, each encrypted to an age identity whose private half is in that node's TPM. The identity file that names the key to the TPM is on the node's encrypted disk and not in the repository: the TPM key is bound to no boot state, so the disk is what keeps a rescue boot from using it. In memory once decrypted, on a tmpfs that never swaps. |

Unattended unlock needs no person and no network, and never stands in a person's way. The recovery key, typed, always works: on the console, a BMC KVM, or over SSH into the initrd (`avc boot unlock`). If the TPM refuses, the node waits at the prompt.

Two records watch this: each node's **boot report** (`modules/boot-report.nix`: how it unlocked, Secure Boot state, PCR 7, initrd SSH logins) becomes metrics and alerts, and an **off-host audit trail** sends boots, deploys, SSH logins, Nomad ACL changes and canary hits to a Cloudflare Worker that only appends (see [Audit trail](#audit-trail)). Both are the node's own account. Nothing off the node sees a disk key released, so a machine that boots where it reaches neither leaves no record: see [A node left your control](#a-node-left-your-control).

### What the private repository holds

| Thing | Where | Notes |
| --- | --- | --- |
| Topology, apps, hosts | `topology.nix`, `apps/`, `hosts/` | The site's description, in plain Nix. |
| Secrets and public values | `secrets/shared/`, `secrets/per-machine/<node>/` | One file per generator file: `<generator>/<file>.age`, encrypted to the master identities, or `<generator>/<file>` in the clear for a public value. No node can read a `.age` file here. See [Secrets](#secrets). |
| What each node reads | `secrets/rekeyed/<node>/` | `agenix rekey`'s output: each secret the node is given, re-encrypted to that node's recipient. These are the files in a node's closure. Commit them with the secret they came from. |
| Each node's recipient | `secrets/recipients/<node>.pub` | The public half of the node's age identity (age-plugin-tpm), whose private half never leaves its TPM. `avc boot install` writes it, from the node's TPM, before the node's system is built. A node without one is given placeholders. |
| Each node's identity file | `secrets/identities/<node>.age` | What `age-plugin-tpm --generate` wrote on that node: a handle to the key in its TPM, useless on any other machine. Encrypted to the master identities like every secret. The node's own copy is on its encrypted disk; this one is what a reinstall on the same machine puts back, so that nothing has to be rekeyed. |
| Master identities | `masterIdentities` and `extraRecipients` in `flake.nix` | The operators' YubiKey identities: two, so that losing one loses nothing. `extraRecipients` is for an **offline** recipient that exists only on paper or sealed media; a site whose recovery keys are to be readable by the YubiKeys alone names none, because every secret is encrypted to it too. After changing them, `avc secrets fix` re-encrypts every secret to the new set and rekeys (`agenix update-masterkeys` would skip the ones no node is given). `secrets/.master-recipients` records the set the files are encrypted to. |
| `secrets/policy.toml` | `avc`'s rotation policy | The template's marks `luks`, `volume-identity`, `juicefs-rsa` and `restic` never, and `nomad-ca`, `nomad-jwt`, `wg-ctrl` and `juicefs-pg` manual. `avc` refuses the never-ones in code too. |

**Name a second unlocker for each site**: a second person with their own YubiKey in `masterIdentities`, an SSH key in `admins`, and access to the provider's console, who has run `avc boot unlock` once. Unattended unlock depends on the TPM and an unchanged PCR 7; the recovery key depends on a person with a YubiKey.

### The offline kit

Kept outside any repository, off the cluster, and away from the laptop you work on:

- the second YubiKey, when one operator holds both, and the offline age identity if `extraRecipients` names one;
- a dated `git bundle` of the private repository (`git bundle create site-<date>.bundle --all`);
- direct copies of `restic/password`, and of `juicefs-rsa/rsa.pem` and `juicefs-rsa/rsa-passphrase` (the PEM is about 3.4 KB), and the same two files of every `<app>-jfs`: each app's volume has its own key;
- `cloud-state/passphrase`, with `cloud`: without it OpenTofu's state is unreadable, and what it made has to be imported again by hand;
- `ovh-s3/{access-key,secret-key}`, `backup-target/{access-key,secret-key}` and `backup-state-target/{access-key,secret-key}`, and from the topology `objectStorage`, `backup.target`, `backup.state.target` and `backup.repoSalt`.

**No disk secret goes in the kit.** A node's recovery key (`luks/passphrase`) and its volume identity secret exist as ciphertext in the repository and nowhere else: the bundle carries them, and a master identity reads them. A copy in the clear, on paper or on a stick, would be a second way into every disk that nothing watches.

With the bundle and one master identity, `avc` gives back every secret: `git clone site-<date>.bundle site`, `nix develop` in it, plug in a YubiKey, and `avc secrets reveal <node>:luks/passphrase`. With the offline identity instead: `AVC_AGE_IDENTITY=<offline identity file> avc secrets reveal …`. To let a new operator in, add their YubiKey's identity to `masterIdentities`, commit, and run `avc secrets fix` with a key that already reads: it re-encrypts every secret, the nodes' identity files included, to the new set and rekeys. A key not yet in `masterIdentities` reads nothing. With the JuiceFS key, the S3 pair and the bucket alone, the volume's metadata can be rebuilt anywhere (see [Restore without a node](#restore-without-a-node)).

### Opting out

`nodes.<n>.insecurePlaintextBoot = "<reason>"` is the one switch, per node. That node gets plain disks, systemd-boot, no Secure Boot, no TPM binding, no initrd SSH and no volume identity. Every evaluation warns, the node exports `cluster_boot_insecure_optout 1`, and `BootSecurityOptedOut` fires. Nothing else changes: Nomad mTLS, the mesh, the raw_exec lockdown, default-deny and the encrypted JuiceFS volume have no opt-out.

Like every node, an opted-out one holds the fleet's shared keys (`juicefs-rsa`, `ovh-s3`, `restic`, `backup-target`) as ciphertext on its plaintext disk, and its TPM decrypts them for whatever is booted on the machine: the node's age identity is bound to the TPM, not to a boot state. So a rescue boot of it reads every client's files and backups, whatever runs on it. The site has to say it knows: `insecureFleetKeysOnPlaintextDisk = "<reason>"` at the top level, or evaluation fails. The test fixtures opt out on every node; a real site should not.

Without the opt-out, evaluation fails unless the **resulting** configuration has LUKS under the pool, Lanzaboote, the TPM option on every leg, the identity check and the rest. The assertions read results, not intent: a host file that swaps the disk layout fails too.

### Never

- **Never regenerate `luks` or `volume-identity` on an installed node.** A new recovery key opens nothing, and a new identity halts the node at its next boot. `avc secrets rotate` refuses both, and `avc secrets provision` makes neither anew on a node that has a recipient.
- **Never copy a recovery key out of the repository.** It is read in two places: typed at a prompt (`avc boot unlock`, which names the command that prints it), and sent on stdin by `avc boot bind --recovery-key`. Nothing else needs it, and the kit does not hold it.
- **Never enroll a TPM slot by hand.** A bare `systemd-cryptenroll` runs none of `cluster-boot-seal bind`'s checks (Setup Mode, the burn, a foreign authority, the identity), so it can seal to a PCR 7 that someone else can reproduce. Rebind with `avc boot bind <node> --replace`.
- **Never bind in Setup Mode.** PCR 7 in Setup Mode is the same constant on every machine, so a seal taken then can be reproduced by anyone who clears the keys. `cluster-boot-seal bind` refuses.
- **Never leave a node between its install and its bind.** The install's TPM slot is bound to no PCR: until `avc boot bind`, anything booted on the machine, the provider's rescue system included, can have its TPM open the disks. `TpmBindingUnsealed` fires after six hours of it, and no client data belongs on the node before S8.
- **Never clear a node's TPM once it is installed**, unless you mean to: the disk key's slot and the node's age key are both in it. The recovery key gets you back in, and `avc boot identity` and a rebind put both back ([Recovery](#recovery)).
- **A manual `juicefs dump` is plaintext**, file names included. The automatic dumps in the bucket are encrypted; one you take by hand is not. Keep it on an encrypted disk and delete it.

## Installing a node

The order: install in Setup Mode, a first boot nobody types into, enroll the node's own keys from the running system, reboot enforcing, bind the TPM slot to PCR 7, reboot. Nobody types a disk key at any step: the install leaves each leg a TPM slot that opens on this machine's TPM, and the bind seals it. Each `avc boot` command runs one step and says what comes next. The sequence ran end to end in VMs: the install through the real installer, with a software TPM, in `checks.install-node`, and S3 to S7 on the real seal tool in `checks.boot-install`. Real firmware, a real TPM and YubiKeys have their own [checklist](#real-hardware-checklist).

Four rules behind the order:

- **Never bind in Setup Mode** (above).
- **The bind follows the install by hours, not days.** Between them the TPM gives the disk key to any boot of the machine (above).
- **Every signed generation carries the identity check and the PCR burn.** On a fresh install that is automatic: generation 1 has both, and evaluation fails without them.
- **The identity's hash is known before the first build.** `avc secrets provision` makes the secret and its hash together on your machine. The hash is a public value compiled into generation 1's initrd, signed at install; the secret is written to the new root by the install before the first boot. Read the ESP and you find the hash, not the secret.

Where each secret is, step by step:

| Secret | Before the install | During it | Afterwards |
| --- | --- | --- | --- |
| The key each leg is formatted with | Does not exist | Made by the disk layout's hook in the installer's memory (`/run/cluster-install`), one per leg | Its slot is removed and the file deleted before the install goes on; the installer's reboot forgets the memory |
| The disk key's TPM slot | Does not exist | Enrolled by the same hook, bound to this TPM and to no PCR | In each leg's header. Replaced at S6 by one sealed to PCR 7 |
| The recovery key (`luks/passphrase`) | Ciphertext in the repository, encrypted to the YubiKeys | Decrypted on your machine into a tmpfs, sent over SSH into the installer's `/run`, given a slot on each leg | Ciphertext in the repository. The tmpfs copy is removed when the installer ends, the other at the reboot |
| The volume identity secret, the initrd's SSH host key | As the recovery key | As the recovery key, then written to the new root by the layout's hook | On the node's encrypted root (the host key also inside the initrd, on the ESP), and ciphertext in the repository |
| The node's age key | Does not exist | Made in the machine's TPM by `age-plugin-tpm`, in the installer | In the TPM. It never leaves it |
| The node's identity file (a handle to that key) | Does not exist | Read from the installer, staged for the new root, encrypted to the YubiKeys into `secrets/identities/<node>.age` | On the node's encrypted root (`/var/lib/cluster-secrets/identity.txt`), and ciphertext in the repository |
| What the node reads (its services' secrets) | Ciphertext to the YubiKeys | Rekeyed on your machine to the node's new recipient, before its system is built | In the node's closure and in `secrets/rekeyed/<node>/`, encrypted to its TPM's key |
| The Secure Boot signing keys | Do not exist | Made on the new root by the layout's hook | On the node's encrypted root (`/var/lib/sbctl`), and nowhere else |

### S0. Prepare the private repository

You, at your workstation, in `nix develop`. The node doesn't exist yet.

```sh
age-plugin-yubikey --generate                 # once per YubiKey: a key in a PIV slot
age-plugin-yubikey --identity > secrets/master/yubikey-1.pub   # its identity file: no private key, committed
$EDITOR flake.nix                             # masterIdentities (both YubiKeys), admins
$EDITOR topology.nix                          # mesh, nodes.<n>.{initrdNicModules,disks}
git add -A                                    # flakes only see tracked files
avc secrets provision                         # every machine, placeholders too, so their mesh keys exist
avc secrets check
avc boot preflight <node>
```

`avc secrets provision` commits `secrets/` on a branch and opens the pull request; nothing is rekeyed yet, because no node has a recipient. `avc boot preflight` must pass. It evaluates the node's system and disk script, so every posture assertion fires here and not on the server, and it prints the identity hash and the initrd host key's fingerprint for your records.

If it fails, nothing has touched a machine: fix and repeat.

### S1. Firmware

At the provider's BMC console:

- Enable the TPM and the IOMMU. CSM off.
- Clear the Secure Boot keys, so the firmware is in Setup Mode.
- Write down the BMC version and the TPM's state. Clear the TPM if the firmware offers it. If it can't be cleared, go on and write that down. This is the last time it may be cleared: from S2 on it holds the node's keys.

### S2. Install

```sh
avc boot install <node> root@<rescue-address>
```

From the provider's rescue system, booted with your SSH key, with outbound network and Secure Boot not enforcing, **and with the server's console open** (OVH: the IPMI/KVM of the server, in the Manager): the first thing `avc` asks is something only the console can answer.

`avc` runs the preflight again, verifies the rescue system's SSH host key, asks you to type the node's name, and runs the site's installer for the node, `nix run .#install-<node>`: [nixos-install-helper](https://github.com/Avunu/nixos-install-helper)'s network install, which is nixos-anywhere in two runs with a step of `avc`'s between them.

0. **The host key.** A rescue system has an SSH host key nobody has seen before, and this install sends that address the node's recovery key and takes from it the recipient every secret the node reads is encrypted to. So `avc` reads the key the address presents, prints its fingerprint, and asks whether the console shows the same one. At the console, logged in to the rescue system:

   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Compare the whole `SHA256:…` string, and answer yes only if it is the same. Or read it at the console first and give it up front, and nothing is asked: `avc boot install <node> root@<rescue-address> --host-key-fingerprint SHA256:…`. A fingerprint that does not match is refused, `-y` does not answer the question, and without a terminal the option is the only way. Up to here nothing has been sent to the address.

   The key is then pinned for the run: a `known_hosts` file of this install's own, in memory, that every connection is checked against, strictly, and no other. That covers `avc`'s connections and nixos-anywhere's: nixos-anywhere asks ssh for no host key checking at all, so the installer is run with an `ssh` of `avc`'s first on its PATH, which puts the pinned options in front of nixos-anywhere's, where ssh keeps them. Over the first connection so authenticated, `avc` reads the host keys in the rescue system's `/etc/ssh` (and makes an ed25519 one there if there is none) and pins those too: they are the ones the installer will answer with.
1. **kexec.** The rescue system is replaced, in memory, by the NixOS installer (nixos-anywhere downloads nixos-images' release; `AVC_INSTALL_ARGS="--kexec <tarball>"` gives it one instead). The installer keeps the rescue system's host keys: nixos-images' kexec script copies `/etc/ssh/ssh_host_*` into the installer's initrd, and the installer puts them back before its sshd starts. So the check simply goes on across the kexec, with no second comparison. Nothing on the disks has changed.
2. **`avc boot stage`**, on your machine, against the installer:
   - it copies `age` and `age-plugin-tpm` into the installer and makes the node's age identity on the machine's TPM. If the repository already holds an identity for this node and this TPM still answers for it (a reinstall), that one is kept, nothing is rekeyed, and nothing is asked;
   - a **new** recipient is shown, and you are asked whether to encrypt everything the node reads to it, the fleet's shared keys included. Like the host key, this is a person's answer: `-y` does not give it, and without a terminal it is refused. Nothing has been rekeyed or written to the repository before it;
   - it writes the recipient to `secrets/recipients/<node>.pub` and the identity file, encrypted to the YubiKeys, to `secrets/identities/<node>.age`, and rekeys everything the node reads to the new recipient (`secrets/rekeyed/<node>/`);
   - it stages the identity file for the new root, and decrypts the three partitioning secrets (the recovery key, the volume identity secret, the initrd's host key) into a tmpfs.

   Your YubiKey is asked for one touch per file it decrypts: the three partitioning secrets, and each secret rekeyed to the node. The identity is made in the installer rather than in the provider's rescue system because that is the kernel and the TPM driver that enroll the disk's TPM slot a moment later, and it has Nix, so the plugin is the one this library pins and no static build has to be kept for a rescue system that may have no TPM driver at all.
3. **Partition, install, reboot.** Only now is the node's system built, so the closure that is installed already holds the secrets its TPM decrypts. nixos-anywhere sends the partitioning secrets into the installer's `/run` and runs the disk layout: both disks get an ESP, swap, and a LUKS2 leg. Each leg is formatted with a key made on the spot, in memory; that key enrolls a TPM2 slot bound to no PCR and adds a slot for the recovery key, and is then removed and deleted. The layout's hook writes the identity secret, the initrd's SSH host key and new Secure Boot keys to the new root, the system is installed and generation 1 signed onto both ESPs, and the machine reboots.

Then `avc` ships what the step wrote under `secrets/` (the recipient, the identity file, the rekeyed files) by pull request, like every change.

If it fails before the partitioning, nothing on the disks has changed. After it, run it again from rescue: it formats again, and keeps the identity it made the first time. An installer without a TPM, or without the recovery key, refuses before it formats anything: the first node could never unlock itself and the second could never be recovered.

If the address ever answers with a host key that is not a pinned one (someone else on the address after the kexec, say), ssh refuses that connection before anything is sent over it, `avc` stops the installer (nixos-anywhere would retry for ever), and says how far the install had come: before `avc boot stage` nothing was partitioned, rekeyed or sent; after it, what had been sent went to the verified machine, and the install is run again from rescue.

What the pin protects against is someone between you and the server, or answering on its address: without the machine's own host key they are refused, and are sent nothing. What it does not protect against is in [Residual risks](#residual-risks): a console that lies, and a rescue system that is not what it seems.

### S3. First boot: Setup Mode, and nobody types

```sh
avc boot status <node>
```

The node comes up by itself, within about a minute of the installer's reboot: the install's TPM slot opens both legs, and its secrets decrypt with the identity made at S2. `avc boot status` should show Setup Mode, both legs `ONLINE`, `identity OK`, and for each leg `1 TPM slot(s), 0 sealed to PCR 7`.

That last line is the state to leave quickly. The slot is bound to this TPM and to nothing else, so any boot of this machine can ask the TPM for the disk key (`cluster_boot_tpm_unsealed_tokens`, `TpmBindingUnsealed` after six hours). It cannot be sealed yet: PCR 7 in Setup Mode is the same on every machine.

If the node waits at a prompt instead (a TPM cleared since S2, say), the recovery key opens it: `avc boot unlock <node>` types over the initrd's SSH, port 2222, and names the command that prints the key; one answer opens both legs. `avc boot unlock` checks the initrd's host key against the repository's copy, which protects against reaching the wrong machine by accident. It does **not** authenticate the machine: the key is readable on the ESP, so anyone who has read the ESP can impersonate the initrd. A recovery key can be typed into a tampered machine. Then S6 needs `--recovery-key`.

A wrong key asks again, for ever. If the node lands in emergency mode, its SSH, network and password prompts stay up: answer the prompts, then `systemctl restart zfs-import-rpool; systemctl --no-block default`. The emergency password is `avc secrets reveal <node>:emergency-access/password`.

### S4. Enroll the node's own keys

```sh
avc boot enroll <node>
avc boot reboot <node>
```

This runs `cluster-boot-seal enroll` on the node: it refuses unless the firmware is in Setup Mode, and enrolls the node's own keys with `sbctl enroll-keys --tpm-eventlog`, which adds the option ROMs this boot measured (NIC, NVMe, RAID firmware) to the allowed list by hash, so they keep loading. Microsoft's keys are not enrolled; `cluster.boot.enrollMicrosoftKeys = true` in a host file does that instead, and then the node can't be bound at all if any of its option ROMs is Microsoft-signed (see [Residual risks](#residual-risks), D27).

If enrollment is refused or the node won't boot afterwards, put the firmware back in Setup Mode. The install's slot still opens the disks, and the recovery key does whatever happens.

### S5. Second boot: enforcing

```sh
avc boot status <node>        # Secure Boot: enabled (user), PCR 7 different from S3's
```

Again nobody types: the install's slot is bound to no PCR, so the change of PCR 7 does not matter to it. Some firmware needs Secure Boot switched on by hand at this point.

### S6. Bind the TPM

```sh
avc boot bind <node>
```

`avc` runs `cluster-boot-seal bind` on the node and sends it nothing. It refuses unless Secure Boot is enforcing and Setup Mode is off; if PCR 7 was burned this boot (the node went through emergency mode: reboot first); unless PCR 7's event log shows only this node's own certificate (or hash entries) as the authority that let the boot run; unless the identity secret matches the hash; and if a leg already has a slot sealed to PCR 7. Then for each leg it enrolls a TPM2 key slot sealed to PCR 7 with `systemd-cryptenroll`, authorised by the leg's own TPM slot, which must open now; removes the install's slot once the new one is written; and checks that each slot opens and that none is left unsealed. The recovery key's slot is never touched, and the recovery key never leaves the repository.

A leg with no TPM slot that opens (the node was unlocked by hand at S3 or S5, a disk was replaced, PCR 7 has changed since a bind) has nothing on the node to authorise a new slot: `avc boot bind <node> --recovery-key` decrypts the recovery key with your YubiKey and sends it on stdin, to the node and nowhere that prints.

To redo it: `avc boot bind <node> --replace` enrolls the new slot first and only then removes the leg's older TPM slots, so a failure loses nothing.

### S7. Third boot: nobody types

```sh
avc boot reboot <node>
```

`avc boot reboot` refuses unless the next boot should come back by itself: the default entry's boot contract is the running one, the default entry is not on the rollback denylist ([Rolling back](#rolling-back-a-bad-closure)), an ESP is mounted, no automated hold is set, every leg has a TPM slot that opens now (`cluster-boot-seal check`), the identity secret is in place (`cluster-boot-seal identity`), and the last boot unlocked every leg from the TPM. It says so when a leg's slot is still the install's. A short TPM count is only a note in two cases. When `avc boot bind` succeeded this boot (it writes `/run/avc-boot-bound` only once the bind has returned 0; `/run` clears at boot), the last unlock was a typed one from before the binding, and only this reboot can prove the binding; `cluster-boot-seal check` must still pass. When PCR 7 was burned this boot (emergency mode), no TPM slot can be tried, so the check says nothing about the binding and only the reboot shows it. Then it reboots the node and waits for a new boot.

Expect stage 2 within about a minute. On the node: `cluster_boot_unlock_tpm_devices` equal to the number of legs, `cluster_boot_secure_boot_enabled 1`, `cluster_boot_setup_mode 0`, `cluster_boot_tpm_unsealed_tokens 0` for each leg; and an email from the Worker, `[NOTICE] <site>: <node> booted (tpm)`.

If the TPM refuses, the prompt is there: `avc boot unlock <node>` with the recovery key, then back to S6 with `--replace --recovery-key`.

### S8. Attack it, then seal it

Run the [real hardware checklist](#real-hardware-checklist) on the node with canary data only. Stop if the TPM releases the key to anything but the node's own signed boot. The node is **sealed** when the checklist passes. Only then may client data move onto it.

### The first deploy after an install

A freshly installed node runs generation 1, built from your working tree with the recipient the install had just written, so it holds its secrets from its first boot. It has a boot contract and a boot stack, so its pull deploys proceed once the install's pull request has merged. The first canary node of a new site has nothing to wait for. Each later node takes the stack the canary has booted; if your repository has moved on to a newer stack since, it waits until the canary reboots into that one (see [Deploying](#deploying)).

## Recovery

### Who can do what, once sealed

| Event | What it takes |
| --- | --- |
| A kernel update, a new generation | Nothing. PCR 7 does not change. |
| Secure Boot toggled off; db or dbx changed | The signed loader still runs, but PCR 7 differs and the TPM refuses the disk key: type the recovery key at the next boot (`avc boot unlock <node>`), then `avc boot bind <node> --replace --recovery-key`. The key is needed because no TPM slot on the node opens any more. |
| The TPM was cleared | As above, and the node's age key went with the seal: it boots on the recovery key and decrypts none of its secrets (`SecretsMissing`, and Nomad's agent is held). `avc boot unlock <node>`, `avc boot identity <node>`, `avc deploy break-glass <node>`, then `avc boot bind <node> --replace --recovery-key`. See [The node's age key is gone](#the-nodes-age-key-is-gone). |
| A firmware update **cleared** the keys (the firmware is in Setup Mode) | Bind refuses in Setup Mode. `avc boot unlock <node>`, `avc boot enroll <node>`, reboot, `avc boot unlock <node>` again, then `avc boot bind <node> --replace --recovery-key`. |
| The firmware restored its **factory** keys | The node's own loader is refused (Access Denied), so no prompt appears. At the BIOS: put the firmware in Setup Mode (or turn Secure Boot off), boot with the recovery key, then `avc boot enroll <node>`, reboot, unlock, `avc boot bind <node> --replace --recovery-key`. How real firmware behaves here is on the [checklist](#real-hardware-checklist). |
| A disk died | The node boots on the other one, unattended and DEGRADED (`ZfsPoolUnhealthy`, `EspNotMounted`). See [Replacing a disk](#replacing-a-disk). |
| The Secure Boot signing keys are lost (`/var/lib/sbctl` gone, root intact) | Every new generation fails to install (`DeployActivationFailing`), but the installed ones still boot. See [Signing keys lost, or rotated on purpose](#signing-keys-lost-or-rotated-on-purpose). |
| The identity secret is damaged or missing | The node halts at boot (`volume-identity: MISMATCH`). See [Identity secret damaged](#identity-secret-damaged). `VolumeIdentityMissing` warns while the node is still running. |
| An initrd authorized key must be retired, or a fix to the boot path must stick | Rotate the Secure Boot keys and rebind: [Signing keys lost, or rotated on purpose](#signing-keys-lost-or-rotated-on-purpose). Removing the key from `admins` alone is not enough (D26). |
| The initrd's SSH host key | `avc secrets rotate` refuses it and prints the procedure: a new pair from `ssh-keygen -t ed25519`, each half stored with `avc secrets set <node>:initrd-ssh/ssh_host_ed25519_key` (and `.pub`), then `avc -y secrets reveal <node>:initrd-ssh/ssh_host_ed25519_key \| ssh root@<node> install -m 0400 /dev/stdin /var/lib/initrd-ssh/ssh_host_ed25519_key`, then deploy. It takes effect at the next **new** generation; the ones already on the ESP keep the old key. |
| The mainboard, or its TPM, was replaced | The new TPM holds no seal and no age key, and the firmware none of the node's keys. At the BIOS: Setup Mode. Boot with the recovery key (`avc boot unlock <node>`), `avc boot identity <node>` and `avc deploy break-glass <node>` ([The node's age key is gone](#the-nodes-age-key-is-gone)), `avc boot enroll <node>` (the signing keys are on the encrypted root), reboot, unlock, `avc boot bind <node> --replace --recovery-key`. `checks.install-node` shows the first step, the disks behind another TPM asking for the recovery key and holding their secrets shut; the rest is not rehearsed as one sequence. |
| The machine is going back to the provider, or being retired | [Returning hardware](#returning-hardware), before it leaves. |
| The machine left your control: stolen, seized, returned unwiped, or booted where you can't account for it | [A node left your control](#a-node-left-your-control). |
| Everything lost | [Total loss](#total-loss). |

### Booting an older generation

The boot menu's timeout is 0, so it shows only if you press a key (hold space) at the console while the loader starts. The menu's editor is off. Three ways to pick a generation:

1. **At the console:** press a key as the loader starts, choose the generation. Any signed generation still on the ESP boots and unlocks unattended.
2. **From rescue:** mount the ESPs and set `default` in `/loader/loader.conf` on both (`default nixos-generation-<n>-*.efi`, the names are in `/EFI/Linux`). `loader.conf` is not signed.
3. **When the provider's rescue can't boot under enforcing Secure Boot:** turn Secure Boot off at the BIOS, do the above from rescue, and turn it back on. That changes PCR 7 while it is off, so expect the prompt at the next boot (`avc boot unlock <node>`) and run `avc boot bind <node> --replace --recovery-key` afterwards.

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
```

The new leg is formatted with the node's recovery key, sent from your workstation on stdin, so that it is never on the node's disk or in its shell history (one YubiKey touch each):

```sh
avc -y secrets reveal <node>:luks/passphrase | ssh root@<node> \
  cryptsetup -q luksFormat --type luks2 --key-file - /dev/disk/by-partlabel/disk-nvme0-luks
avc -y secrets reveal <node>:luks/passphrase | ssh root@<node> \
  cryptsetup open --allow-discards --key-file - /dev/disk/by-partlabel/disk-nvme0-luks crypt-a
```

Back on the node:

```sh
zpool replace -f rpool <dead leg's GUID> /dev/mapper/crypt-a
zpool status rpool                         # wait for "resilvered"
mount /boot && /run/current-system/bin/switch-to-configuration boot   # signs onto both ESPs again
```

Then bind only the new leg: `avc boot bind <node> --device /dev/disk/by-partlabel/disk-nvme0-luks --recovery-key`. The key, because the new leg has no TPM slot yet to authorise one. Not a bare `bind`, which refuses because the healthy leg is bound, and not `--replace`, which would rebind the healthy leg too. Release the hold. If the new disk enumerates differently, point `nodes.<n>.disks` at `/dev/disk/by-id/...`; the disks are in the boot contract, so that deploy waits for an approval on the node.

### Identity secret damaged

The node halts at every boot until the secret is back; each attempt needs a power cycle from the BMC.

1. Boot the provider's rescue system. Under enforcing Secure Boot that may need Secure Boot off at the BIOS first; turn it back on afterwards and expect a `--replace` rebind, because PCR 7 changed.
2. Open both legs with the recovery key, from your workstation: `avc -y secrets reveal <node>:luks/passphrase | ssh root@<rescue-address> cryptsetup open --key-file - /dev/disk/by-partlabel/disk-nvme0-luks crypt-a`, the same for `disk-nvme1-luks` and `crypt-b`. A rescue boot can't ask the TPM: its PCR 7 is not the node's.
3. `zpool import -f -N -d /dev/mapper rpool` (`-f`, because the pool was last used by another host ID), then `mount -t zfs rpool/root /mnt`.
4. From your workstation: `avc -y secrets reveal <node>:volume-identity/secret | ssh root@<rescue-address> install -m 0400 /dev/stdin /mnt/var/lib/volume-identity/secret`. Into a pipe, `avc secrets reveal` writes the bytes with no trailing newline, which is what the check hashes.
5. **`umount /mnt` and `zpool export rpool`** before rebooting, then `cryptsetup close crypt-a` and `crypt-b`. A rescue interrupted before the export leaves a pool the node refuses to import at its next boot: boot rescue again and finish it.

`checks.boot-degraded`'s `identity-repair-rehearsal` rehearses this sequence in a VM, including the interrupted rescue.

### The node's age key is gone

The TPM was cleared or replaced, or `/var/lib/cluster-secrets/identity.txt` was lost from the disk. The node boots (on its TPM slot if the TPM is the same, on the recovery key if not) and decrypts none of its secrets: `cluster-secrets.service` fails, `SecretsMissing` fires, Nomad's agent is held, and the pull loop can't fetch a private repository without its token. SSH still works.

```sh
avc boot identity <node>
avc deploy break-glass <node>
```

`avc boot identity` does on the running node what the install does in the installer, over your ordinary SSH to the node: the host key is checked against your own `known_hosts`, and a node that is not in it, or whose key changed, is refused. A new recipient is shown and confirmed as at an install, before the node, the repository or a secret is touched (`-y` does not answer; no terminal, no new identity). If the TPM still holds the key the repository's identity file names, it puts that file back and nothing else changes: the secrets decrypt at the next activation. Otherwise it makes a new identity on the TPM, writes it to the node, commits the recipient and the encrypted identity file, rekeys everything the node reads (one YubiKey touch per secret) and opens the pull request. The node holds no secret until a closure built from that tree is on it, and can't pull one, so `avc deploy break-glass <node>` builds on your machine and switches the node over SSH. If the TPM changed, the disk's TPM slot went with it: `avc boot bind <node> --replace --recovery-key`.

The old recipient's rekeyed files stay in the repository's history. They are encrypted to a key that no longer exists.

### Signing keys lost, or rotated on purpose

Lost keys and a deliberate rotation are the same procedure. A rotation is what retires an initrd authorized key that was removed from `admins`, or makes a fix to the boot path irreversible: every older generation signed with the old keys still passes PCR 7 if someone kept a copy and puts it back on the ESP (D26). The deploy tick says so when `admins` changes. The order matters:

1. At the BIOS, put the firmware in Setup Mode (this clears its keys).
2. Boot, and type the recovery key (`avc boot unlock <node>`).
3. On the node, move the old keys away if they still exist (`mv /var/lib/sbctl /root/sbctl.old`), then `sbctl create-keys`.
4. `avc boot enroll <node>`.
5. **Sign again before any reboot:** `/run/current-system/bin/switch-to-configuration boot`, which writes both ESPs. Rebooting first would leave a loader the new keys refuse.
6. Reboot, type the recovery key, then `avc boot bind <node> --replace --recovery-key`. Delete the old keys.

### A node left your control

A whole machine that powers on unlocks itself: the TPM asks nobody. So when a node is stolen, seized, kept by the provider, returned without [its headers wiped](#returning-hardware), or booted somewhere you can't account for, assume it booted, and count everything on it as read. What stood in the way was the running system's logins and the attacks this design leaves [out of scope](#residual-risks), and nothing will tell you whether they held: a machine with no route to the Worker sends no boot report. Drives that left without their mainboard are a different case. They stay closed without the recovery key, which is in no place they could have come from, and nothing here is needed for them.

What the node held, and what replaces it:

| On the node | How it is replaced |
| --- | --- |
| Client data: every app's local state, since each node holds a copy of each app's ([Where an app runs](#where-an-app-runs)), and through its mount every file on the JuiceFS volume | Nothing replaces it. It is disclosed, and whom to tell is your decision and your clients'. |
| The machine's age identity (the key in its TPM, and the identity file on its disk), which decrypts everything rekeyed to that machine at every commit in the repository's history | Nothing fixes history, so each value below gets a new value. Re-encrypting the old one changes nothing. |
| `ci` (the machine's own), and what it held for GitHub | Push `AGENT_TOKENS` again without the node (`avc ci tokens`, after it is out of `nodes`): the Worker then answers it nothing. The GitHub tokens it held read the site's repositories, ciphertext included, and nothing else; they expire within the hour and cannot be renewed without the Worker. No GitHub credential that lasts was on the node. |
| `ovh-s3`, `backup-target`, `backup-state-target` | New pairs from the provider, `avc secrets rotate ovh-s3`, `avc secrets rotate backup-target` and `avc secrets rotate backup-state-target`, then delete the old pairs at the provider. |
| `wg-ctrl`, `audit`, `nomad-tls`, `nomad-login` (the machine's own) | Take the node out of `nodes` and ship it, so every peer drops its mesh key, and push `AUDIT_TOKENS` again without it. Nomad can't revoke one certificate or one login JWT: regenerate `nomad-ca` (a hard cut, every node at once) and `nomad-jwt`, by their rotation notes in [Secrets](#secrets). |
| `nomad-gossip` on a server, `nomad-acl` on a server, the alerting tokens on every node | The gossip key by its rotation note. The alerting tokens with `avc secrets rotate`. The library has no procedure for replacing the management token. Nomad's own is an ACL bootstrap reset on the servers, which is not rehearsed here. |
| `juicefs-pg`, `juicefs-patroni` | By hand, in a window: every mount, every member and the roles change together. |
| Each app's own secrets, its tunnel credentials included (every app is a dormant container on every node) | `avc secrets rotate <generator>` for each, and a new tunnel credential from Cloudflare. |
| `juicefs-rsa`, every `<app>-jfs`, `restic` | Bound to data. New volumes and new repositories: below. |
| every `<app>-jfs-s3` | As `ovh-s3`: a new pair from the provider (`avc cloud apply` after removing the old key there), then delete the old one. |
| `luks`, `volume-identity`, `initrd-ssh`, `emergency-access`, the node's identity file and the Secure Boot keys | The lost machine's own, and they open nothing else. With the node out of `nodes`, `git rm -r` its `secrets/per-machine/<node>`, `secrets/rekeyed/<node>`, `secrets/recipients/<node>.pub` and `secrets/identities/<node>.age`. Its replacement is a new install, S0 to S8, under new values. |

The order: the node's token out of the Worker's `AGENT_TOKENS` and the S3 pairs first, because they are what reaches the data and the repository from outside. Then the node out of `nodes`, then Nomad, then the two data-bound keys, which need a window.

**The data-bound keys.** `avc secrets rotate` and `avc secrets provision` refuse `juicefs-rsa`, every `<app>-jfs` and `restic`, and go on refusing: a new value opens nothing that exists. Here that is the purpose, and it has one command of its own, `avc secrets replace <generator>`. It takes only these generators, says what must already be true, and makes the new value only when you type `replace <generator>` back: `-y` does not answer it. It generates and rekeys and ships nothing: the new key belongs in one commit with the bucket or the salt it goes with, below. Before either procedure, compare the [offline kit](#the-offline-kit)'s `juicefs-rsa/rsa.pem`, `juicefs-rsa/rsa-passphrase` and `restic/password` with the repository's (`avc secrets reveal juicefs-rsa/rsa.pem`, and so on). The old volume and the old repositories open with those and with nothing else, and after a replacement the repository holds them only in its history.

**A new JuiceFS volume.** A volume's key can't be changed, so this is a deliberate loss of the storage tier: a new, empty volume in a new bucket, and every app back from its backup.

1. `cluster-backup` on a node, for each app running there (`avc app backup <app>` finds the node), and look at the result (`cluster-backup-list <app>`). These snapshots are what comes back.
2. Hold every node (`avc deploy hold <node>`), and stop the apps (`nomad job stop app-<name>`) and then `juicefs-mount` on every node.
3. Create a new, empty bucket. In one commit: its name in `objectStorage.juicefsBucket`, and a new key from `avc secrets replace juicefs-rsa`. Ship it (`avc deploy ship`). An app's own volume is the same with its `<app>-jfs` and its bucket.
4. On the node holding the metadata database's primary (`patronictl list` names it), empty the database (as `postgres`: `dropdb -p 5433 juicefs`, then `createdb -p 5433 -O juicefs juicefs`). This is the step that makes the volume new. With the old metadata still there, `juicefs-format` finds a volume it knows and keeps it, old bucket and old key.
5. Release the nodes (`avc deploy release <node>`). The first `juicefs-format` to run finds no metadata and an empty bucket, which is a first bring-up: it formats an encrypted volume with the new key, and the others find it formatted.
6. With each app's container running on the new volume, `cluster-restore <app> --yes` on the node it is running on (`avc app restore <app>`).
7. When every app has been checked, delete the old bucket. Until then the old volume can be read from the kit ([Restore without a node](#restore-without-a-node)).

**New restic repositories**, after the restores above, which read the old ones. `restic key add` and `restic key remove` change a repository's password but not its master key, and the old password has already given that away. In one commit: a new `backup.repoSalt`, and a new password from `avc secrets replace restic`, shipped with `avc deploy ship`. A repository's path is a hash of the salt and the app's name, so every app moves to a new, empty repository, and the first backup creates it under the new password. Run `cluster-backup` for every app at once, and check each. The old repositories stay where they were, readable with the old password, until you delete them.

Afterwards, put the new key, password, pairs, bucket and salt in the offline kit, with a new bundle.

Two limits. A new key protects what is written from then on: whoever copied the old bucket or the old repositories while holding the old key can read that copy for good. And each step above follows from what the code does in that state (`checks.jfs-encrypted` proves `juicefs-format`'s states one at a time, `checks.backup-roundtrip` a restore, `checks.avc` that `replace` makes a key for its name typed back and for nothing else), but neither migration has been rehearsed as a sequence, in a VM or on machines. Rehearse it on a scratch site before you need it.

### Returning hardware

Before a machine goes back to the provider or is retired, while it is still yours. Done in this order, nothing in [A node left your control](#a-node-left-your-control) is needed afterwards.

1. Move its work away: `nomad node drain -enable -yes <node>`. Each app stops there and starts on another node with its state, losing nothing ([Where an app runs](#where-an-app-runs)); `cluster-state status` shows when none is left. `wpdb`, which its address ties to one node, needs a new `address` in another node's subnet first. Its role tags go to another node first.
2. **Wipe both LUKS headers**, on the running node, before any step that can fail or be interrupted:

   ```sh
   cryptsetup erase /dev/disk/by-partlabel/disk-nvme0-luks
   cryptsetup erase /dev/disk/by-partlabel/disk-nvme1-luks
   cryptsetup luksDump /dev/disk/by-partlabel/disk-nvme0-luks   # no key slot is left
   ```

   `erase` destroys every key slot, the recovery key's and the TPM's, so from here no key and no TPM opens these disks. The running system still has the volume key in memory.
3. Power it off. It can't unlock again.
4. At the firmware, clear the TPM and the Secure Boot keys. A copy of a header made before step 2 still carries a TPM slot, which opens only on this TPM with this PCR 7. Clearing ends that, and leaves such a copy the recovery key alone. It also destroys the node's age key, so what was rekeyed to it, at any commit, decrypts nowhere.
5. From the provider's rescue, discard both whole disks (`blkdiscard /dev/nvme0n1`, then `nvme1n1`). The ESPs are plaintext and hold the initrd's SSH host key and the emergency password's hash.
6. Take the node out of `nodes`, `git rm -r` its `secrets/per-machine/<node>`, `secrets/rekeyed/<node>`, `secrets/recipients/<node>.pub` and `secrets/identities/<node>.age`, ship it, and push `AUDIT_TOKENS` again without it.

`checks.boot-attack` shows that a cleared TPM withholds the disk key. The header wipe is `cryptsetup`'s own and is not in the VM tests.

### Total loss

All nodes gone, or a rebuild from scratch, in this order:

1. The private repository from the offline kit: `git clone site-<date>.bundle site`, and a master identity that reads it: a YubiKey, or the offline identity (`AVC_AGE_IDENTITY=<offline identity file>`). A new operator's YubiKey goes into `masterIdentities`, and `avc secrets fix` re-encrypts everything to the new set. The old nodes' recipients, identity files and rekeyed files name TPMs that are gone: `git rm -r secrets/recipients secrets/identities secrets/rekeyed`, so that every node is a node not yet installed.
2. The first node installed and sealed, S0 to S8.
3. The JuiceFS metadata restored from the bucket with the PEM and its passphrase: the first node does it from a recent dump once you tell it to start an empty database ([below](#when-every-copy-of-the-juicefs-metadata-is-lost)), or by hand ([Restore without a node](#restore-without-a-node)).
4. Nomad bootstraps itself on the first voter, which registers every job.
5. `cluster-restore <app> --yes` per app.

`checks.jfs-encrypted`'s `total-loss-escrow-only` proves step 3 from the kit alone, and `checks.install-node` and `checks.boot-install` the mechanism of step 2; the whole chain has not been rehearsed on real machines.

## Real hardware checklist

A VM can't prove these. Run each on the first real node, with canary data only, and write the answer down.

**Firmware and Secure Boot**
- How the board enters Setup Mode; whether `sbctl enroll-keys` from the running system is accepted; whether Secure Boot turns on by itself afterwards.
- **Option ROMs, before enrollment:** from rescue, `tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements` on each node: list every PCR 7 authority and every option ROM measured. Confirm that `cluster-boot-seal enroll` (`--tpm-eventlog`) enrolls them by hash, that the node boots with every device present (NICs, NVMe, any RAID controller or GPU), and that `avc boot bind` accepts. Repeat after a BIOS update: an option ROM whose hash changed is no longer allowed and won't run.
- Booting from `\EFI\BOOT\BOOTX64.EFI` with no NVRAM entry, and which ESP the firmware picks after a disk swap.
- Real PCR 7 contents and their stability across a BIOS update and a dbx update; `tpm2_eventlog` across a rescue cycle.
- The TPM's lockout state and leftover handles; whether a TPM clear is offered. Whether the TPM is a discrete chip or part of the firmware, from the board's documentation: it decides what a [bus attack](#residual-risks) can reach.
- The provider's own signed software: its rescue with Secure Boot on (netboot, iPXE). Record what happens.
- After install, read the raw disks: no canary. Rescue boot, a BIOS toggle, key changes: the TPM refuses. A volume swap, if the provider allows one.
- **Between S3 and S6, on purpose:** boot the provider's rescue system and ask the TPM for a leg (`cryptsetup open --test-passphrase --token-only`). It opens: that is the window the install leaves, and what `avc boot bind` closes. Repeat after S6: it must not.
- A kernel update and a reboot: unlocks by itself.
- `kexec` from the provider's rescue before enrollment.

**The TPM, at the install**
- In the kexec'd installer: `/dev/tpmrm0` is there (the driver the nixos-images release carries, `tpm_crb` or `tpm_tis`, binds to this board's TPM), and `age-plugin-tpm --generate` and `systemd-cryptenroll --tpm2-device=auto` both work on it. `avc boot install` refuses a machine without one before it formats anything.
- The identity made in the installer decrypts on the installed node: the same TPM, reached by another kernel. `avc boot stage` checks a round trip in the installer; the first boot's `cluster-secrets.service` is the other half.
- A second `avc boot install` on the same machine keeps the identity; one after a TPM clear makes a new one and rekeys.
- The installer's ZFS (the release's kernel module) accepts the pool the node's own `zpool` creates there.

**YubiKeys**
- `age-plugin-yubikey` with each of the two keys: `avc secrets provision`, `avc secrets reveal`, and an install with the other operator's key plugged in (`AGENIX_REKEY_PRIMARY_IDENTITY` names the one that is). Count the touches an install asks for, and whether the PIN policy asks once or every time.
- SSH with the operators' `ed25519-sk` keys: to the rescue system (nixos-anywhere copies a temporary key of its own after the first connection), to a node, and to the initrd (`avc boot unlock`). The initrd's sshd accepts such a key in a VM (`checks.boot-fallback`, with OpenSSH's software authenticator); a real key adds the touch.

**Network**
- The WAN NIC's real name and driver in the initrd (`lspci -k`), so `initrdNicModules` is right and `avc boot unlock` reaches the prompt.
- Whether frames from another machine attached to the private network reach the node as they would in the test switch, and whether a spoofed source address passes.
- **Jumbo frames, before any data:** between every pair of nodes, both ways, on every VLAN, `ping -M do -s 8972 <peer>` must pass; on the mesh, `ping -M do -s 8892 <peer mesh address>` must pass and `-s 8893` fail. Check `ip link` on the trunk and VLANs: a VLAN whose MTU the NIC refused is simply absent. Then a bulk transfer. If any of it fails, set `vlans.*.mtu = 1500`; the mesh follows to 1420.
- With every cable out, the node still unlocks by itself. With the TPM refusing, the prompt still appears on the console.

**Hardware**
- The IOMMU is on: `/sys/class/iommu` is not empty (`IommuDisabled`).
- The watchdog driver loads and stays quiet at a long initrd prompt after a reset (`WatchdogDeviceMissing`).
- The real initrd's size against the 1 GiB ESP.
- A physically absent NVMe, device timeouts, and `nofail` with both ESPs on real disks.

**Install route and provider**
- `avc boot install` through kexec from the provider's rescue: a Debian-based system, where the VM test's is NixOS. That root logs in with your key there, that the kexec keeps the address and the key, and how long the provider leaves a rescue system up.
- **The host key step, on the provider's rescue.** Where the fingerprint is read: on OVH, the server's IPMI/KVM console in the Manager, logged in to the rescue system, `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Record whether the rescue system has that file at all (if its sshd keeps its key elsewhere, `avc` shows the fingerprint of the key it presents and names the file by its type: find where that key is and compare there), and whether the fingerprint `avc` prints is the console's. Then that the install goes through without another question: the release's installer answers with the key from the rescue system's `/etc/ssh`. If it stops after the kexec with a refused host key instead, the installer did not keep the key: write down what `/etc/ssh` held in the rescue system, and whether `/etc/ssh` is writable there.
- The same step with `--host-key-fingerprint`, and once with a wrong fingerprint: refused, the rescue system's `/root/.ssh/authorized_keys` and disks as they were.
- The Worker on real Cloudflare, the R2 bucket's lock, event rates, and its cron within the 15-minute grace.
- An offline-kit drill with the real kit: from the bundle and the second YubiKey (or the offline identity) to `avc secrets reveal <node>:luks/passphrase`, including adding an operator to `masterIdentities` and `avc secrets fix`. Then the recovery key itself: type it at a node's prompt.

## Residual risks

Accepted, and written here so they are accepted knowingly.

**Out of scope.**
- **Hardware bus attacks.** Nothing stands behind the TPM. `systemd-cryptsetup` unseals over an encrypted session, which should defeat a passive tap on a discrete TPM's bus; that was not tested here. There is no PIN, so someone who can reset a discrete TPM and replay the boot's measurements into it gets the disk key. A firmware TPM has no such bus, and falls with the firmware.
- Firmware tampering, BMC compromise and memory attacks.
- A full takeover of the provider account that boots the real system: it unlocks, and still needs a login. Nothing here defends a running system with its disk key.

**Accepted with the design.**
- **The TPM is the only unattended factor.** A whole machine, powered on anywhere, unlocks itself. Nothing on a network has to agree, and nothing off the machine sees it happen. Whoever holds it then faces the running system: its logins, and the attacks above. Drives pulled without the mainboard stay closed. So a machine that leaves your control counts as read ([A node left your control](#a-node-left-your-control)), and one that goes back gets its headers wiped first ([Returning hardware](#returning-hardware)).
- **An older signed generation passes PCR 7 for as long as the Secure Boot keys are the same (D26, accepted by the user).** `configurationLimit` bounds only what stays on the ESP. Anyone with the disk can copy a generation off and put it back later, and `loader.conf` is unsigned, so it can be made the default. So an initrd authorized key removed from `admins` still opens every older signed initrd anyone kept, and a fix to the boot path can be undone the same way. Retiring either needs new signing keys and a rebind ([procedure](#signing-keys-lost-or-rotated-on-purpose)). The tick says so when `admins` changes. A forward-moving seal (systemd-pcrlock, or a signed PCR 11 policy) would close this, and is not built.
- **Own Secure Boot keys only, no Microsoft keys (D27, chosen by the user).** Option ROMs are enrolled by hash from this boot's event log. An option ROM whose hash changes with a firmware update no longer runs. `bind` refuses when PCR 7 records any authority but the node's own, because anything a Microsoft-signed component lets run could replay PCR 7. `cluster.boot.enrollMicrosoftKeys = true` is a written risk acceptance: it lets the provider's Microsoft-signed rescue images run under Secure Boot, and makes binding impossible on a node with a Microsoft-signed option ROM.
- **`loader.conf` on the ESP is unsigned.** An attacker can pick any signed entry. Production closures have no specialisations; that is asserted.
- **The ESP is readable by the provider:** the initrd's SSH host key, the emergency password's hash, the identity hash and the authorized keys, though not the secret. The host key doesn't prove the machine before a recovery key is typed into it.
- **The emergency password** still opens a root shell in the initrd that can read whatever is unlocked and destroy data, even with PCR 7 burned. It is 32 random bytes and is held like the recovery key (D3).
- **A forged pool is parsed by the kernel's ZFS before the identity check.** A crafted pool could attack the kernel; that needs an exploit and is beyond conventional access.
- **Between the install and the bind, the TPM answers any boot of the machine.** The install's TPM slot is bound to no PCR, because no PCR 7 worth sealing to exists before the node's own Secure Boot keys are enrolled. For those hours a rescue boot of the machine, by you or by the provider, opens the disks; the emergency shell's burn of PCR 7 protects nothing either. The node holds its secrets from its first boot, and no client data until S8. `cluster-boot-seal status` and `check` say when a slot is not sealed, `avc boot reboot` notes it, and `TpmBindingUnsealed` fires after six hours.
- **An install trusts the console, and the rescue system.** `avc boot install` pins the rescue system's SSH host key to the fingerprint you compared at the server's console, and every connection of the install is held to it, so someone on the network path or on the machine's address is refused and is sent nothing. Two things are outside that. Whoever controls the console as well (the provider, or its BMC) can show you the fingerprint of a machine of their own. And the rescue system is the provider's image, booted by the provider: it holds the host key's private half, it is what downloads and starts the installer (nixos-images' release, over HTTPS from GitHub, unchecked beyond that), and a tampered one can read everything the install sends, the recovery key first. Both are the provider acting against you with more than conventional access, which this design does not claim to stop; `AVC_INSTALL_ARGS="--kexec <tarball>"` at least makes the installer one you built.
- **An old LUKS header copy with the old recovery key stays valid** until `cryptsetup reencrypt`; changing the recovery key does not change the volume key.
- **The recovery key's ciphertext is in git for good,** decryptable with an operator's master identity (or the offline one, where a site names one); it is rekeyed to no machine. The answer to a lost YubiKey is to take it out of `masterIdentities` and `avc secrets fix`, and `cryptsetup reencrypt` with a new recovery key if the lost one could be used.
- **A node's identity file is on its disk and in the repository.** It is a handle: only the machine's TPM can use the key, and the TPM puts no condition on that use. So whatever boots on the machine and has the file decrypts the node's secrets. The disk keeps the file from a rescue boot, which is one more reason the bind must follow the install.
- **`allowDiscards`** shows which blocks are free.
- **A stolen gossip key plus a server's certificate makes a Nomad voter** within about 20 seconds, with the tokens in raft state. That is why both stay off workers. Root on a server can always mint a management token.
- **A stolen client certificate can register a Nomad client,** and the scheduler can place work on it. Job specs hold only store paths and names. A machine's pre-signed login JWTs are long-lived; retiring them means a new `nomad-jwt` signing key.
- **A stolen `submit-job` token** (the `registrar`'s) runs code as uid 4096 on every node, with no network, and can start or stop declared containers. Nomad gives task processes supplementary group 0 (a Nomad bug): they can read what group root can, such as `/etc/sudoers`. `denied_host_gids` must never be set, because it would refuse every task. An account above uid 65535 made by hand at run time would run a task: the evaluation-time check covers configured accounts only.
- **The mesh authorizes nodes, not processes** (D1): any process on a node can reach etcd, Loki, Prometheus and the metadata database's port.
- **The app VLAN is not authenticated.** An attacker on it who spoofs a container's source address can reach a port an app declared on another node: for traffic arriving from the VLAN, the rule checks the source subnet and port, not identity.
- **Metadata leaks:** the bucket shows object sizes and timing; restic's key files show host names and times; metrics and alert emails carry app and host names to Cloudflare; PostgreSQL's WAL, the JuiceFS cache and backup staging hold plaintext on the encrypted disk until the next run.
- **`juicefs config --secret-key` puts the S3 secret on a command line** on a node for the seconds of its storage test, after a restore or a rotation, and once on each node after its install. JuiceFS 1.4.1 has no other way.
- **Logs are kept on the nodes only.** Every node's Loki holds the whole cluster's lines, so they survive any node but not all of them. Backing them up would keep client-bearing logs past their retention.
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
| `security.initrdSshPort` | The initrd's SSH port. Default 2222, deliberately not 22, so its host key never meets the running system's in `known_hosts`. |
| `security.nomadTlsRotation` | Bump to reissue every Nomad agent certificate. Default 0. |
| `deploy.flakeUrl` | What nodes rebuild from, as `github:owner/repo`. Also how `avc` finds the deploy remote. |
| `deploy.pullInterval` | systemd `OnCalendar` for the pull loop. |
| `deploy.withoutCanary` | `"<reason>"` to run a site of more than one node without a canary node (see `canary` below, and [Deploying](#deploying)). Leave it out otherwise. |
| `ci.url` | The cluster-ci Worker's URL. Set, every node asks it for read access to the site's GitHub repositories (short-lived tokens; without it a node reads public repositories only) and runs the pipeline's agent: deploys the moment the deploy branch moves, and previews for apps with `preview.slots` ([Previews and continuous deployment](#previews-and-continuous-deployment)). Leave it out for none of that. |
| `cloud` | Optional: what `avc cloud` makes at the providers ([Providers](#providers)). `cloud.ovh` is `{ endpoint; project; region; noncurrentDays; }`: the API endpoint (`ovh-us`, `ovh-eu`, `ovh-ca`), the Public Cloud project's id, the region its buckets are made in, and how long a hidden object version is kept (30). `cloud.cloudflare` is `{ accountId; zones; auditBucket; auditLockDays; }`: `zones` maps a zone's name to its id (`zones."example.com" = "<zone id>"`), and only hostnames in one of them get a DNS record; `auditBucket` is the audit trail's R2 bucket, locked for `auditLockDays` (365). Leave a provider out and nothing of its is touched. |
| `objectStorage` | `{ endpoint; region; juicefsBucket; appBucketPrefix; }`. `juicefsBucket` is the cluster's own volume; each app's bucket is `<appBucketPrefix>-<app>`, and the prefix is `juicefsBucket` unless set. Credentials come from the `ovh-s3` vars generator, whichever provider you use. Loki does not use it: each node's store is its own encrypted disk (`/var/lib/loki`). |
| `logging.retention` | Loki retention, one number and one unit (`m`, `h`, `d`, `w`, `y`), such as `"720h"`. Older lines are deleted from the store, and a node that no longer runs Loki deletes what is left in its `/var/lib/loki` once it is this old. |
| `alerting` | `{ cloudflareAccountId; from; to; heartbeatUrl; auditUrl; }`. `heartbeatUrl` is the watchdog Worker's `/heartbeat`; `auditUrl` its `/event`, for the [audit trail](#audit-trail). Only an opted-out node may leave `auditUrl` null. |
| `backup.repoSalt` | This site's own string, at least 16 characters (`openssl rand -hex 16`). It salts each app's repository path (see [Backups and restore](#backups-and-restore)). Set it once, before the first backup, and never change it: a new salt moves every app to a new, empty repository, which is wanted only in [A node left your control](#a-node-left-your-control). |
| `backup.target` | `{ type; ... }`, where `type` is `s3`, `rest`, `b2` or `local` (`lib/backup-target.nix`), with `endpoint`, `bucket` and `region` for S3. The nightly backup's: the long history. Keep it away from the object storage it protects, and from the nodes. |
| `backup.state` | Optional: `{ target; schedule; retention; staleHours; }`, a second, frequent backup of each app's local state to a second target, which must not be `backup.target` ([Backups and restore](#backups-and-restore)). `target` is `{ type; endpoint; bucket; region; }` as above, with credentials from `backup-state-target`; `schedule` is `hourly` unless set; `retention` is `{ hourly = 48; daily = 14; }`; `staleHours` (4) is when `StateBackupStale` fires. |
| `backup.{schedule,maintenance,verify}` | systemd `OnCalendar`, in the node's clock (UTC). |
| `backup.retention` | `{ daily; weekly; monthly; }`. |
| `backup.uploadLimitKiB` | restic upload limit. `0` means unlimited. |
| `stateVersion` | `system.stateVersion` for the whole fleet. |
| `insecureFleetKeysOnPlaintextDisk` | Required, as `"<reason>"`, once any node sets `nodes.<n>.insecurePlaintextBoot`. Every node holds the fleet's shared keys (`juicefs-rsa`, `ovh-s3`, `restic`, `backup-target`) as ciphertext its TPM decrypts for whatever is booted on the machine, so a rescue boot of one opted-out node reads every client's files and backups, whatever runs on it. Test fixtures only. |
| `insecureSingleMemberEtcd` | Test fixtures only: `"<reason>"` lets exactly one node carry `etcd`. Such an etcd can never grow (see the tag table below). Leave it out of a real site. |
| `nodes.<name>` | One per machine. See below. |

The attribute key under `nodes` is the machine name everywhere: the directory its secrets are kept under, the `--flake .#<key>` target, the name Nomad knows the node by. It must equal `hostName`.

| Node field | Meaning |
| --- | --- |
| `index` | Small unique integer. Selects the node's app-VLAN address, app subnet and mesh address. |
| `hostName`, `fqdn` | Host name (equal to the key under `nodes`), and the fully qualified name. |
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
| `initrdNicModules` | Kernel modules for the WAN NIC in the initrd, such as `[ "igb" ]`, so the recovery key can be typed over SSH. Not detectable at evaluation; `lspci -k` on the node names them. Required unless opted out. |
| `disks` | `{ a; b; }`, the two disk devices. Default `/dev/nvme0n1` and `/dev/nvme1n1`. Use `/dev/disk/by-id/...` on hardware whose enumeration swaps. |
| `swapPerDiskGiB` | The swap partition on each disk, in GiB; the node's swap is twice this. Default 32. Fixed at install: a new value takes a reinstall. |
| `insecurePlaintextBoot` | `"<reason>"`: the one opt-out from disk encryption and Secure Boot. See [Opting out](#opting-out). |
| `provisioned` | `false` for a placeholder: not scraped or alerted on. Delete the line when the machine exists. |
| `canary` | `true` on exactly one real node once the site has more than one: it takes each new boot stack first, and the others wait until it has rebooted into it (see [Deploying](#deploying)). Not a placeholder, and not an opted-out node while any node has boot security. |

What an unlock depends on (the node's `initrdNicModules`, `wanInterface`, `publicIp4`, `publicGw4`, the disks, how each leg is opened (its unlock options and the initrd's TPM support), the required mounts, the initrd SSH port, and a hash of `admins`) is the node's **boot contract**. A change to any of them waits for approval on each node (see [Deploying](#deploying)).

| Tag | What it does |
| --- | --- |
| `worker` | Runs application containers (Nomad client). |
| `nomad-server` | Votes in the Nomad raft. `bootstrap_expect` is asserted to be the number of nodes with this tag. Holds the gossip key, the management token, and every ACL token in raft state. Registers the rendered jobspecs and applies the ACL policies; every server does, so none of them has to be up for either. |
| `etcd` | Votes in the etcd raft, which is also where the JuiceFS metadata database elects its primary. |

Quorum size is derived from the tags, so a placeholder listed as a voter makes Nomad and etcd wait for a machine that does not exist. Add `nomad-server` and `etcd` in the same commit that fills in a node's real addressing. A cluster with fewer than three voters has no HA.

### Growing to three voters

Go from one voter to three in a single commit: `nomad-server` on the two new nodes, and `etcd` on all three. etcd has no member add. It is created once, from the tags, so it is either absent or has an odd number of at least three members, and evaluation refuses anything else. A one-member etcd can't grow: its data directory makes it ignore the new member list, and the two new members would form a second cluster of their own. Nomad tolerates one voter growing, but two voters means no leader while either is down, so don't stop at two.

The switch is safe for the running voter: Nomad ignores `bootstrap_expect` once it has raft state, and its allocations keep running. The JuiceFS metadata database changes hands in the same commit, from the one server's PostgreSQL to a member on every node that starts from that server's data, and `/mnt/jfs` is stalled from the moment the first node switches until etcd has formed and the old server's member is up. `checks.voter-growth` covers both orders (the first voter switching before or after the new ones start, a worker promoted, a fresh voter).

**Before reinstalling a server that died, remove it from raft and wait.** Autopilot removes a failed server by itself a moment after serf marks it failed; a reinstall seconds later can be pulled back into the old cluster under its old identity. And never reinstall a node from a topology commit in which it is the only voter while the others still run: it would bootstrap a cluster of its own.

## Kinds

An app is one file in `appsDir`, named after the app. It is a function of `{ inputs, lib, pkgs, name }`, or JSON for what tooling writes. A `.nix` and a `.json` of the same name merge. The file holds only what differs:

```nix
# apps/shop.nix
{ inputs, ... }:
{
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
| `grafana` | `hostname`, `loginName`, `adminGroup`, `editorGroup`, with `oidc.idp` | Grafana on whichever node Nomad picks, signed in through an identity provider's Authelia, reaching Loki and Prometheus through `network.hostAccess`. |
| `attic` | `bucket`, `public`, `hostname`, `retentionDays`, `cache`, `hostOctet` | The cluster's binary cache ([The binary cache](#the-binary-cache)): an Attic server on whichever node Nomad picks, its NARs in a bucket of its own, its index in the app's dataset, and on every node the substituter, the push after each switch, and the proxy that finds it. One per cluster. |
| `wpdb` | `address`, `port`, `clientHosts`, `bufferPoolSize` | The one MariaDB every WordPress site shares, with databases and grants per site. Runs on the node whose app subnet holds `address`. |
| `wordpress` | The `wordpress` section, usually written by a tool as JSON | One file, two containers: `<name>` (read-only public face) and `<name>-admin` (writable admin face), each reaching `wpdb` through `network.peerAccess`. |

The payload modules come from [wordpress-nix](https://github.com/Avunu/wordpress), [frappe-nix](https://github.com/Avunu/frappe-nix) and [odoo-nix](https://github.com/Avunu/odoo-nix). Your project flake supplies the `package`. To pin its payload module to the library's, use `inputs.odoo-nix.follows = "cluster/odoo-nix"`.

Beside the kind, every generic `clusterApps` option stays available (`modules/app-container.nix`): `tunnel.id`, `resources`, `startTimeout`, `network` ([Container networking](#container-networking)), `module` for extra guest config, and so on. `oidc = { idp = "<a FreeIPA app>"; }` makes any app a client of that provider's Authelia. `enable = false;` keeps a file without deploying it.

### An app's files

An app with `juicefsPaths` has a JuiceFS volume of its own: a bucket (`<appBucketPrefix>-<app>`), an S3 pair that opens that bucket and no other, an encryption key, and a database and role of its own in the [metadata database](#the-juicefs-metadata-database). Nothing of one app's files is in another's bucket or database.

- **Mounted where the app runs.** The app's container starts its mount (`juicefs-mount-<app>`, at `/mnt/jfs-app/<app>`) and the mount goes when the container does. The first start anywhere formats the volume; every later one finds it formatted. A mount that dies takes its container with it, and Nomad starts the app again.
- **A new app needs its bucket first.** `avc cloud apply` makes the bucket and writes the S3 pair into the site's secrets ([Providers](#providers)); without `topology.cloud`, make the bucket and its key by hand and `avc secrets provision` prompts for them. The key and role password are generated. Until the bucket exists the app's start fails and Nomad retries it.
- **A preview's files are a clone inside the app's volume** (`previews/<slot>` beside `data`), so a preview needs no bucket and shares none of its writes with production.
- **Two apps can share one volume** by naming it (`juicefsVolume`): a WordPress site's two faces do.
- **Removing an app** leaves its bucket and database. The bucket carries `prevent_destroy`, so `avc cloud plan` fails on it and names it; delete it by hand once you are sure, and its database with `dropdb -p 5433 jfs_<app>` on the primary.
- **Every node still holds every app's keys**, because any node may be the one an app runs on. A volume per app bounds a leaked S3 key, a mistake and a restore to one app; it does not bound a lost node.

The cluster keeps one small volume for itself (`/mnt/jfs`, on every node): the deploy's canary marker, the write probe and the canary scan. No app's files are in it.

Not watched per app: the age of a volume's metadata dump. `JuiceFSMetaDumpStale` is about the cluster's own volume. An app's dumps are written while it is mounted, and matter only if every copy of the metadata database is lost.

### The JuiceFS metadata database

JuiceFS keeps file names, sizes and the map from files to objects in PostgreSQL. On a site with an etcd, every node runs a member of one PostgreSQL cluster (`modules/storage-juicefs-pg.nix`), and Patroni keeps one of them the primary by a lock in etcd.

- **Every member has the data as it is written.** The replicas stream from the primary, and a commit is not acknowledged until one of them has it (`synchronous_mode: quorum`). A node that dies takes no acknowledged write with it.
- **The primary's node can die.** Its lock runs out after 20 seconds, a replica that holds every acknowledged write is promoted, and the mounts on the other nodes carry on: 23 to 27 seconds from the kill to the next write in `checks.cluster`. Acknowledged writes are not lost. A file operation in flight at that moment can come back to the app as an I/O error; the ones after it stall until there is a primary. A member is given up only after about ten seconds without an answer, so a shorter hiccup of the mesh is a stall and nothing else.
- **No node is named.** Each mount asks its own node's loopback (`127.0.0.1:5432`), where HAProxy asks every member's Patroni which one is the primary and passes the connection there. A member that stops being the primary has its connections cut.
- **A reinstalled node's member copies the database back** from the primary, by itself.
- **A primary left alone keeps writing.** With every replica gone, the primary carries on without waiting for one (Patroni records that, and promotes nobody who missed those writes). The other choice would stop every app on a three-node site that is down to one node.
- **It needs etcd's quorum.** With etcd down to a minority there is no primary, by design: that is what keeps two sides of a partition from both writing.

`patronictl list` on any node shows the members (`Leader`, `Quorum Standby`), and `patronictl switchover` moves the primary by hand, before planned work on its node. Patroni's settings are in `modules/storage-juicefs-pg.nix`; each node applies them, so don't `patronictl edit-config`.

A site with one Nomad server and no `etcd` tag has one PostgreSQL, on that server, in the same place and with the same roles. [Growing to three voters](#growing-to-three-voters) turns it into the first member.

**Moving a site from the `juicefs-meta` tag.** The node that carried the tag has the database, and its member starts the cluster from it; the others, with nothing, wait until it has (a member with no data creates no database while the bucket holds a volume). Remove the tag in the same commit. This path is the one `checks.voter-growth` covers for a one-server site; on a site that already had an etcd it has not been run.

### Adding an app

1. Add its flake input if it has one.
2. Write `apps/<name>.nix`, `git add` it, and run `avc secrets provision` for the kind's generated secrets: it generates them, rekeys them for the nodes and ships the lot. Nomad starts the app. With no `tunnel.id` it has no ingress yet.
3. Wire the tunnel:
   ```sh
   cloudflared tunnel create <name>
   # set tunnel.id in the file and `git add` it; the secret exists once the id is set
   avc secrets set <name>-cf/cloudflared      # "A file": ~/.cloudflared/<id>.json
   cloudflared tunnel route dns <name> <hostname>
   ```
4. `avc secrets set` ships the id and the credentials together and restarts the app, because the credentials are a new bind mount. With `topology.cloud`, `avc cloud apply` does steps 3 and 4.

Odoo and Frappe databases are not initialised for you. Restore or create one after the first start. Deploys then migrate it.

## Operations

`nix run .#avc` is the guided entrypoint for status, apps, secrets, deploys, boot and audit, and every menu entry is also a subcommand: `avc status show`, `avc app restart <app>`, `avc secrets rotate <generator>`, `avc deploy now`, `avc boot status <node>`, and so on (`avc --help`, `avc <group> --help`). `avc site ...` delegates to an optional provisioning tool that this library doesn't include. Pass one with `packages.avc.override { siteProvisioner = ...; }`. Without it, those commands say so and everything else works.

### First install

Minimum before the first node: both operators' YubiKey identities in `masterIdentities`, your SSH keys in `admins`, the topology filled in, and the `ovh-s3` generator. A site whose repository or inputs are private also needs the cluster-ci Worker and its GitHub App before the first node pulls ([Previews and continuous deployment](#previews-and-continuous-deployment), steps 1 to 4): the install itself is pushed, but the node's pull loop reads GitHub with tokens that Worker hands it. Then [Installing a node](#installing-a-node), S0 to S8:

```sh
nix develop
age-plugin-yubikey --identity > secrets/master/yubikey-1.pub   # once per YubiKey; name it in `masterIdentities`
git add -A
avc secrets provision                      # prompts for what third parties issue; commits and opens the pull request
avc boot preflight node1
avc boot install node1 root@<rescue-address>   # asks for the host key at the console; then the TPM identity, the disks, the first closure
avc boot status node1                      # up by itself, in Setup Mode
avc boot enroll node1
avc boot reboot node1                      # enforcing, still on the install's TPM slot
```

Then, before S6 and S7 (`avc boot bind`, `avc boot reboot`), deploy the [watchdog Worker](#dead-man), set `alerting.heartbeatUrl` and `alerting.auditUrl`, and push `AUDIT_TOKENS`. S7's boot report and the `booted (tpm)` email that says S7 worked both go there. Do not let that take the day: until the bind, the node's TPM opens its disks for any boot of the machine.

### Secrets

Generators run offline, so anything a third party issues is a `prompt`, filled once and stored. "Per machine" means one value per node; the rest are one value for the fleet.

| Generator | Consumer | Origin |
| --- | --- | --- |
| `luks/passphrase` | The node's recovery key, per machine: the one thing besides its TPM that opens its disks. Given a slot on each leg at install, then read only to recover: typed at a prompt, or sent by `avc boot bind --recovery-key`. Rekeyed to no node and kept nowhere but here. **Never regenerate it** on an installed node | Generated |
| `volume-identity/{secret,hash}` | The volume identity, per machine. The secret goes on the root at install; the hash is compiled into the signed initrd. **Never regenerate it** on an installed node | Generated |
| `initrd-ssh/ssh_host_ed25519_key` | The initrd's SSH host key, per machine. Placed at install; the public half is what `avc boot unlock` expects. Rotation by hand (see [Recovery](#recovery)) | Generated |
| `emergency-access/{password,hash}` | The initrd emergency shell, per machine. The password never leaves the repository; the hash is in every signed initrd | Generated |
| `ovh-s3/{access-key,secret-key}` | JuiceFS on all nodes. The volume keeps its own copy in its settings, which every mount reads; `juicefs-format` puts a new pair there when the secrets change, and running mounts pick it up | Prompt, from your S3 provider |
| `juicefs-rsa/{rsa.pem,rsa-passphrase}` | The cluster's own JuiceFS volume's encryption key. Never regenerate it: the volume's data can't be read without it, and `avc` refuses to rotate it | Generated |
| `<app>-jfs/{rsa.pem,rsa-passphrase,pg-password}` | One app's JuiceFS volume: its encryption key and its metadata role's password. Never regenerate it, as above, for that app's files | Generated |
| `<app>-jfs-s3/{access-key,secret-key}` | The S3 pair that opens that app's bucket and no other | Prompt, or written by `avc cloud apply` |
| `juicefs-pg/password` | The JuiceFS metadata database's role for the mounts. Manual: every mount and the role change together | Generated |
| `juicefs-patroni/{superuser,replication,restapi}` | The metadata database's own: its superuser, the role its members replicate as, and what Patroni's API wants for anything that changes the cluster. Manual: restart `patroni` on each node afterwards, replicas first | Generated |
| `nomad-acl/token` | Nomad's management token: the ACL bootstrap and `nomad-acl-init`, on the Nomad servers only | Generated |
| `nomad-jwt/{signing.key,signing.pub}` | Signs each machine's login JWTs; the key never leaves the operator's machine | Generated |
| `nomad-login/jwt-<role>` | Each machine's scoped Nomad logins (`fence`, `node-meta`, `avc`, plus `registrar` where jobs are registered), per machine | Generated, signed by `nomad-jwt` |
| `nomad-gossip/gossip.hcl` | Nomad's serf encryption key, servers only | Generated |
| `nomad-ca/{ca.key,ca.crt}` | Nomad's CA; the key never leaves the operator's machine | Generated |
| `nomad-tls/{agent,cli}.{key,crt}` | Each machine's Nomad certificates (per machine) | Generated, signed by `nomad-ca` |
| `wg-ctrl/{private,public}` | Each machine's mesh key (per machine); every peer reads the public half | Generated |
| `audit/token` | Each machine's token for the audit trail (per machine), listed in the Worker's `AUDIT_TOKENS` | Generated |
| `ci/token` | Each machine's token for the cluster-ci Worker (per machine), listed in the Worker's `AGENT_TOKENS`: what the pipeline's agent and the node's GitHub token refresh sign in with. Only with `ci.url` | Generated |
| `canary/value` | The string the [canary scan](#canary-scan) plants and looks for | Generated |
| `github-app/{app-id,private-key,webhook-secret}` | The site's GitHub App, for the cluster-ci Worker and for `avc ci installations`; never deployed to a node. `avc ci app <value>` prints one for `wrangler secret put`. Only with `ci.url` | Prompt for the id and the private key, from the App's settings; the webhook secret is generated |
| `restic/password` | Every app's backup repositories, nightly and state. Never regenerate it: a new one opens none of them, and `avc` refuses to rotate it | Generated |
| `backup-target/{access-key,secret-key}` | The backup target | Prompt |
| `backup-state-target/{access-key,secret-key}` | The state backup's target, only with `backup.state` | Prompt |
| `cache-s3/{access-key,secret-key}` | The binary cache's bucket, only with an `attic` app. In the cache's container, on the node it runs on | `avc cloud apply`, or prompt |
| `cache-token/rs256.pem` | What the cache checks every token with, and what makes them. In the cache's container. Regenerating it revokes every token: regenerate `cache-push` with it | Generated |
| `cache-push/token` | Every node's token for the cache: pull and push on the one cache, nothing else. Made from `cache-token`, good for ten years | Generated |
| `cache-signing/{secret,public}` | The key the cache signs with. The secret half in the cache's container; the public half is not a secret, is in the repository, and is what every node's `nix.conf` trusts. A new one orphans nothing: the cache signs again as paths are fetched | Generated |
| `alerting/cf-email-token` | Alert emails | Prompt, a Cloudflare token with Email Sending only |
| `alerting-watchdog/token` | The dead-man heartbeat | Generated |
| `cloudflare/provision-token` | The operator's own Cloudflare token, for site provisioning and for `avc cloud`; never deployed to a node | Prompt |
| `cloud-ovh/{application-key,application-secret,consumer-key}` | The operator's OVH API application, for `avc cloud`, only with `cloud.ovh`; never deployed to a node | Prompt |
| `cloud-state/passphrase` | What `cloud/terraform.tfstate` is encrypted with, only with `cloud`; never deployed to a node. Never regenerate it: a new one reads none of the state | Generated |
| `<app>-cf/cloudflared` | Each app's tunnel | Prompt, from `cloudflared tunnel create` |

Each kind declares its own, from its entry in `apps/`. A secret an app mounts but that was never generated is a build error, not an empty file.

**How a secret reaches a node.** A generator's file that is secret, deployed and read by services is an agenix secret on every node that declares it, at `/run/secrets/shared/<generator>/<file>` or `/run/secrets/per-machine/<node>/<generator>/<file>`. Its source in the repository is encrypted to the master identities; `agenix rekey` re-encrypts it to each such node's recipient under `secrets/rekeyed/<node>/`, and activation decrypts that with the node's TPM into a tmpfs that never swaps. A file marked never deployed (an operator's secret, or one only another generator reads) and a file read only at install (`luks`, `volume-identity`, `initrd-ssh`) are rekeyed to no node and are in no closure.

**When it does not.** agenix carries on past a file it cannot decrypt, so the boot completes without it. `cluster-secrets.service` then fails, Nomad and the units that wait for it are not started on that boot (`cluster.secrets.gate`), and `cluster_secrets_missing` counts the files (`SecretsMissing`); SSH, the network and the pull loop are untouched, so the node can be reached and can pull the commit that repairs it. A check every minute keeps the count current on a running node, where a failed switch removes the previous values too.

**The commands.** `avc secrets` is the one way a secret is made, read or changed. Each command that writes ends by rekeying and shipping (a commit on a branch, a pull request, the deploy, a restart of the apps that read the value).

```sh
avc secrets provision                   # generate what is missing or outdated, on every machine; asks for prompted values
avc secrets inventory                   # every generator: scope, consumers, age, rotation policy, state
avc secrets rotate <generator>          # regenerate one, and everything that reads its files
avc secrets set <generator>/<file>      # store a value by hand (an issued token), typed or from a file
avc -y secrets reveal <generator>/<file>   # print a value; without -y it asks first
avc secrets fix                         # after masterIdentities or extraRecipients changed: re-encrypt every source
avc secrets rekey                       # after a source changed outside avc (an install rekeys by itself)
avc secrets replace <generator>         # a new juicefs-rsa, <app>-jfs or restic, after a node left your control; typed back
avc secrets check                       # would a deploy of this tree give every node its secrets? `avc secrets check <node>` for one
```

A per-machine value is named `<machine>:<generator>/<file>` in `avc secrets set` and `avc secrets reveal`. `avc secrets inventory` shows every secret's age, consumers and rotation policy; `avc secrets rotate <generator>` regenerates one, ships it and restarts what reads it. It refuses `luks`, `volume-identity`, `juicefs-rsa`, `restic` and every `<app>-jfs` in code, refuses `initrd-ssh` and `emergency-access` with their manual procedures, and follows `secrets/policy.toml` for the rest. `avc secrets provision` makes none of those anew for an installed node (one with a recipient) either: a file of theirs that went missing comes back from git.

**How a generator runs** (`tools/avc/avc/core/secretstore.py`). `avc` reads the generators from the flake (`clusterSecrets`), orders them by their dependencies, and runs one when a declared file is missing or its `validation` changed, along with every generator that reads its files. A shared generator runs once for the fleet, a per-machine one once per node. Each script runs under bubblewrap with no network, an empty environment and nothing of your machine but the Nix store, in a directory of its own (mode 0700) on a tmpfs, `$XDG_RUNTIME_DIR` or else `/dev/shm`, which is removed when the script ends, however it ends; a machine with no tmpfs is refused. `$in` holds the files of the generators it depends on, `$prompts` what you were asked, and it must write every declared file to `$out` and nothing else. Only when every generator of the run has done so is anything written: each secret encrypted to the master recipients, each public file as it is, each by rename. A run that fails, at a script or at a prompt, leaves the repository as it was. Plaintext is never written to a disk.

Beside a generator's files, `secrets/<scope>/<generator>/.validation-hash` records the `validationHash` they were made from; when the flake's is another, or there is no record, the generator is outdated and `avc secrets provision` runs it again. `AVC_SANDBOX=none` runs the scripts without bubblewrap, for a machine that cannot make a user namespace.

**Rekeying.** A node is given the files under `secrets/rekeyed/<node>/` and nothing else, so a value that was generated and not rekeyed is a value no node has: the node builds, switches, and runs short of it. Every `avc secrets` command that writes a source therefore writes the rekeyed files for it, from the plaintext it already holds, removes the ones nothing names any more, and then runs the flake's own `agenix rekey -a`, which is the authority and finds nothing left to do. A node with no recipient is skipped. `avc secrets check` fails when a declared secret is not generated, was made from other inputs than it declares now, or has no current rekeyed file for a node that has a recipient; `avc deploy ship` and `avc deploy break-glass` run it first and refuse.

**YubiKey touches.** Reading a secret is one `age -d` with a master identity, which age-plugin-yubikey answers after a touch (and the PIN, as the key's PIN policy asks). `avc` decrypts a file at most once per run, and never one that the same run made or wrote. Set `AGENIX_REKEY_PRIMARY_IDENTITY` to the recipient of the key that is plugged in, and age asks for that one first.

| Operation | Decryptions (touches) |
| --- | --- |
| `avc secrets provision` on a new site | None: every input was made in the run |
| `avc secrets provision`, `avc secrets rotate` | One per stored secret that a generator being run reads through `$in`, however many generators read it; none when there is none |
| `avc secrets set` | None |
| The rekey after any of the above | None |
| `avc secrets reveal`, `avc boot bind --recovery-key`, `avc audit tokens`, `avc ci tokens` | One per value read (one per node for the tokens) |
| `avc boot bind` | None: the node's own TPM slot authorises the new one |
| `avc boot install` | Three for the partitioning secrets, and one per secret the new node is given (none of those when the machine's TPM still holds the identity in the repository, and they are already rekeyed) |
| `avc boot identity` | One for the identity file in the repository, and one per secret the node is given when a new identity is made |
| `avc cloud plan`, `avc cloud apply`, `avc cloud tofu` | One per credential: the state's passphrase, and up to four for the providers |
| `avc secrets rekey` | One per secret a node lacks; a source that several nodes lack is decrypted once for all of them. An install rekeys by itself |
| `avc secrets fix` | One per secret in the repository |
| `avc secrets check`, `avc secrets inventory` | None |

`agenix rekey` run by hand decrypts once per secret per node instead, which is why `avc secrets rekey` fills in the files first. `AVC_AGE_IDENTITY=<file>` puts an identity file before the flake's master identities, for a key the flake names only as a recipient: the offline one.

agenix-rekey's own commands still work on a source, and none of them knows about generators or policy; follow one that writes with `avc secrets rekey`:

```sh
nix run .#agenix -- rekey -a               # what `avc secrets rekey` ends with
nix run .#agenix -- edit secrets/shared/<generator>/<file>.age
nix run .#agenix -- view secrets/shared/<generator>/<file>.age
```

Rotation notes:

- **`nomad-gossip`:** Nomad copies the key into `<data_dir>/server/serf.keyring` on first start, so a new `gossip.hcl` changes nothing on a running server. Rotate with `nomad operator gossip keyring` (install, use, remove), then regenerate the secret to match (`avc secrets rotate nomad-gossip`).
- **`nomad-ca`:** regenerating reissues every machine's certificates: a hard cut, every node at once. `security.nomadTlsRotation` reissues the agent certificates alone. `NomadTlsCertExpiring` and `NomadTlsCaExpiring` warn first.
- **`nomad-jwt`:** regenerating reissues every node's logins, and each server's `nomad-acl-init` updates the auth method on its next switch. Manual in the policy.
- **`wg-ctrl`:** both ends of a link must switch: a node with a new key is cut off from each peer until that peer lists the new public key, and back within seconds after. Manual in the policy. A node with no mesh key still boots and stays reachable, and its mesh services retry; like any node short of a secret it starts no Nomad on that boot ([Secrets](#secrets)).
- **`audit`:** a new token must reach the Worker (`avc audit tokens | wrangler secret put AUDIT_TOKENS`), or that node's events are refused (`AuditEventRejected`).
- **`ci`:** a new token must reach the Worker (`avc ci tokens | wrangler secret put AGENT_TOKENS`), or that node's agent is refused: it then deploys on the timer alone, and its previews stand still.
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

A push is break-glass only (`avc deploy break-glass <node>`): `nixos-rebuild switch --target-host` builds the node from your working tree on your machine and switches it over SSH. The next pull would silently revert it, and it bypasses every gate above. The node needs nothing from your machine but the closure: its secrets are the rekeyed files in it, so `avc deploy break-glass` runs `avc secrets check <node>` first. Hold the loop first:

```sh
ssh root@node1 touch /run/cluster-upgrade.hold     # or: avc deploy hold node1
nixos-rebuild switch --flake .#node1 --target-host root@<node1's address>
# get the same change merged into main (avc deploy ship), and only then:
ssh root@node1 rm /run/cluster-upgrade.hold          # or: avc deploy release node1
```

The hold lives in `/run`, so a forgotten one clears on reboot. Automated holds (a backup dumping a database, a restore) use one file each in `/run/cluster-upgrade.hold.d/`, so they cannot release each other, and `avc boot reboot` refuses while any is set. Keep a console open for changes to `br-wan` or the WAN stanza: on a remote machine a mistake there is a lockout.

**New boot stacks go to the canary first.** What a boot is built from and every node shares, the nixpkgs source, the kernel, agenix, agenix-rekey, Lanzaboote, disko and this library's `modules/` and `lib/`, is written into each closure as `boot-stack`, each named by its lock's narHash or a content-addressed store path, so every node renders the same file whichever Nix it evaluates with, lazy trees or not. A bump of any of them changes no boot contract, reaches every node within the pull interval, and first runs at the next reboot, on all of them. So the node with `canary = true` activates a new boot stack at once, like any closure, and every other node builds it and waits: nothing activated, its profile and boot entry left on the old stack, `cluster_deploy_canary_wait 1` (`DeployWaitingForCanary` after a day). Reboot the canary, `avc boot reboot <canary>`, and watch it. Once that boot has unlocked from the TPM on every leg, and the boot report says so, it writes `/mnt/jfs/.cluster-deploy/canary-booted/<sha256 of boot-stack>`, and the others activate the stack at their next tick. A switch is not a boot, and a boot someone had to type the passphrase for proves nothing (`CanaryBootUnproven`), so neither publishes. App releases and topology edits on the same stack never wait. If the canary cannot be rebooted, list the closure's basename in `/run/cluster-upgrade.skip-canary` on each node you accept it on; it clears at reboot. A pushed `nixos-rebuild` bypasses this, as it bypasses the pull loop.

Bump `agenix` and `agenix-rekey` alone, each as one reviewable commit: they decide what every node decrypts at activation, and `checks.secrets-tpm` is what runs them for real. A site's private repository should merge library and lock bumps only through its merge gate: see "Merging safely" in [`templates/cluster/README.md`](templates/cluster/README.md).

### Previews and continuous deployment

All of a cluster's GitHub access is one GitHub App. It is how the nodes read the site's repository and its private inputs ([GitHub access](#github-access), below), and it closes the two gaps the pull loop leaves: the wait between a merge and the nodes' next tick, and having nowhere to look at a pull request before it merges. Its endpoint is a Cloudflare Worker, [`workers/cluster-ci`](workers/cluster-ci), because a node accepts nothing inbound. Every node runs an agent (`modules/ci-agent.nix`, on once `ci.url` is set) that asks the Worker what to do, with a token of its own, and the Worker holds each request until it has an answer.

**A merge deploys at once.** Three pushes matter, and GitHub tells the Worker of each:

1. A push to a branch one of your flake inputs follows (a project's `main`). The Worker reads your site's `flake.lock`, finds the inputs that follow that branch, and starts the site's `flake-update.yml` for those inputs alone. Updating a lock takes Nix, so the workflow does it, on a branch, as a pull request with auto-merge: the [merge gate](templates/cluster/README.md) still decides.
2. The merge of that pull request, or of any other, into the branch `deploy.flakeUrl` names. The Worker answers every node's held request, and each starts `cluster-upgrade.service`: the same tick as the timer's, with every gate above.
3. Nothing else. The timer stays, so a push the Worker never heard of deploys within `deploy.pullInterval` as before.

**A pull request gets a container.** `preview.slots` on an app declares that many more containers, `<app>-pv1` to `<app>-pvN`, of the same kind with the same parameters:

```nix
# apps/shop.nix
preview = {
  slots = 2;                       # branches previewed at once
  input = "my-odoo-project";       # the flake input its package comes from
  repo = "OWNER/my-odoo-project";  # whose pull requests get previews
};
```

A slot is dormant like every container, and everything the host decides about one (mounts, memory limit, addresses, firewall) is fixed at evaluation and merged like the rest of the site. What a pull request supplies is what runs inside. When one opens on a branch of `repo`, and at each push to it:

1. The Worker makes the branch a tunnel and a hostname of its own, `<branch>-<app>.<PREVIEW_DOMAIN>`, and gives the preview to the node with the fewest previews. Every node can take one, since each holds a copy of the app's data.
2. The agent builds your site's flake with `input` at the pull request's commit, for one free slot's container.
3. The first time, it gives the slot a copy of production: a ZFS clone of the node's copy of the app's dataset, at its newest snapshot (the app's own of the last minute, or a replica's), so the database comes up as after a power cut, and a `juicefs clone` of the app's files. Neither copies a block until one side writes, so the size of the database does not matter.
4. It starts the container on that closure. The kind's own units migrate the copy before the app starts, exactly as a deploy migrates production. A later push keeps the copy and migrates it again.
5. It asks the hostname for the kind's health path, and the Worker writes the result as one comment on the pull request, edited in place, and as the commit status `preview/<app>`, which a branch ruleset can require.

One preview per app and branch, whatever the number of pull requests on the branch. It goes when the last of them closes or the branch is deleted: container stopped, clone destroyed, files removed, then tunnel and DNS record deleted. `/preview reset` in a comment on the pull request, from someone with write access, starts again from a fresh copy. With every slot taken, a new branch waits and says so.

**What a preview is trusted with.** A copy of the app's data and the app's own secrets, running code that has not been reviewed. So:

- **Forks get nothing.** Only a pull request from a branch of the repository itself is previewed, which takes write access to push. That is in the Worker's code, not its configuration.
- **A copy does not act as production.** An `odoo` slot runs Odoo's `neutralize` on its copy before anything else, which turns off its mail servers, scheduled actions and payment providers, and does not start if that fails (Odoo 16 and later). A `frappe` slot sets `mute_emails` and `pause_scheduler`, and is not given the app's `cloud-storage` settings: the bucket is production's, so a preview's attachments are missing rather than writable.
- **The preview's own sign-in is all that guards it.** It is production's data at a hostname anyone can ask for. Put the preview zone behind Cloudflare Access.
- **Use a zone that serves nothing else** for `PREVIEW_DOMAIN`: unreviewed code at a subdomain of a production zone can set cookies for it.
- **A slot is not backed up**, is no Nomad job, and stays on the node that seeded it, where its clone is. Its logs are with every app's, under its slot's name. A build's last lines and the names of failed units go to the pull request; a guest's log never does, since it is a copy of production speaking.

Setting it up, once per site:

1. Create **one** GitHub App, under the account that owns the site's repository, from [`workers/cluster-ci/app-manifest.json`](workers/cluster-ci/app-manifest.json): repository permissions contents read, metadata read, pull requests write, commit statuses write, actions write; events pull request, push, delete, issue comment. Make it **public** ("Any account" may install it): GitHub lets a private App be installed on its owner's account only, and an app whose project belongs to another organization is onboarded by that organization installing this App. Being public gives nobody anything: see [GitHub access](#github-access). Generate a private key and note the App ID.
2. Set `ci.url` in `topology.nix` to where the Worker will answer, and run `avc secrets provision`: it asks for the App ID and the private key (paste the `.pem`), generates the webhook secret and each node's `ci/token`, and ships them. The key is then in the repository, encrypted to the operators, and on no node.
3. Fill in `wrangler.toml` (`PREVIEW_DOMAIN`, `CF_ACCOUNT_ID`, `CF_ZONE_ID`, `GITHUB_APP_ID`, and `SITE_FLAKE`, the same value as `deploy.flakeUrl`), then:
   ```sh
   cd workers/cluster-ci
   wrangler deploy
   avc ci app private-key    | wrangler secret put GITHUB_APP_PRIVATE_KEY   # one YubiKey touch
   avc ci app webhook-secret | wrangler secret put GITHUB_WEBHOOK_SECRET    # one touch
   avc ci tokens             | wrangler secret put AGENT_TOKENS             # one touch per node
   wrangler secret put CF_API_TOKEN          # Cloudflare Tunnel: Edit, and DNS: Edit on the preview zone
   ```
   In the App's settings, point its webhook at the Worker's `/webhook/github` and paste the webhook secret (`avc ci app webhook-secret`).
4. Install the App on the site's repository and on each private repository the site uses, then `avc ci installations`: it lists who has installed the App and, for every repository the site uses, whether an installation covers it (one touch: it signs in as the App with the private key, on your machine, and only reads).
5. Add `preview` to an app and ship it. The slots exist once the nodes have deployed.

The agent exports `cluster_ci_last_sync_timestamp_seconds` and `cluster_ci_previews` by `state`; no alert rule reads those yet. The token refresh exports `cluster_github_token_last_success_timestamp_seconds`, `cluster_github_token_expiry_timestamp_seconds`, `cluster_github_token_repositories` and `cluster_github_token_uncovered_repositories`, and `GitHubTokenStale` reads the first.

#### GitHub access

No node holds a GitHub credential that lasts, and no personal access token exists anywhere. The App's private key is in two places: the Worker, and the site's repository, encrypted to the operators (`github-app`). A node asks the Worker, with its own `ci/token`, and is handed installation tokens that GitHub itself has narrowed:

- **read-only:** contents and metadata, whatever else the App is permitted;
- **the site's repositories only:** one token per owner, naming each repository;
- **one hour:** the Worker hands out nothing with under half an hour left, and a node asks every ten minutes and before each pull.

**Which repositories is never the node's to say.** The Worker reads it from the site's repository, at the branch the nodes deploy (`SITE_FLAKE`): that repository itself, every github.com input in its `flake.lock`, and `github-repos.json` at its root, for what no lock names (a WordPress site's content repository, an app's `preview.repo`, and whatever a site adds to `cluster.github.repositories`, such as a project's private submodules). That file is not written by hand: `avc ci repos` writes it from the flake, and the template's merge gate fails when the committed file differs (`checks.github-repos`), so the list changes by a merge, like the lock. A repository of the set that no installation covers is named in the Worker's answer and in the node's log (`journalctl -u cluster-github-token`): a public one needs no token, a private one is waiting for its owner to install the App.

On the node, `cluster-github-token.service` (`modules/github-access.nix`) writes two files under `/run/cluster-github`, root's alone, each replaced whole: a `nix.conf` fragment with `access-tokens` per repository, which Nix's `github:` fetcher reads, and the tokens for git's credential helper, which answers `git+https://` inputs and `builtins.fetchGit` with the token of the repository git names, or with nothing. A refresh that fails keeps every token that is still good.

**The Worker is therefore required** for the pull loop of a site with private repositories. `GitHubTokenStale` fires after 25 minutes without an answer, while the tokens a node holds are still good. A site with only public repositories and no `ci.url` runs with no tokens at all. A site with private repositories and no `ci.url` evaluates (whether a repository is private cannot be known at evaluation) and fails at the fetch, in `cluster-upgrade`'s log, with GitHub's "not found".

**The App is public, and that gives nobody anything.** Anyone can install it on their own repositories; what that does is nothing. The Worker's site is its own configuration, not what installs the App and not what a node reports; a webhook about a repository outside the site's set makes no preview, starts no workflow and moves no deploy; and no token is ever made for a repository outside the set, since GitHub is asked for each by name.

| Who is compromised | What they reach at GitHub |
| --- | --- |
| A node | Read access to the repositories the site uses, for at most an hour after its `ci/token` is taken out of `AGENT_TOKENS`. That is what the node could already read: the site's repository holds every secret as ciphertext, and the node's own as files it can decrypt. No write, no other repository of the same owner, and nothing that renews without the Worker. |
| The Worker (its secrets, or the Cloudflare account) | The App itself: on every repository of every installation, read contents, write pull requests and commit statuses, start workflows (`actions: write`). Not push: the App holds no `contents: write`, so nothing merges that the merge gate did not pass, though a workflow it starts runs with that repository's own secrets. Also the preview tunnels, and each node's `ci/token`. Replace the App's private key at GitHub, then `avc secrets rotate github-app` and the `wrangler secret put` lines again. |
| An operator's YubiKey | Everything in the repository, the App's key included. See [A node left your control](#a-node-left-your-control) for the rest. |

#### Onboarding an app from another organization

A customer's project stays in the customer's organization. What the cluster needs is to read it, and to comment on its pull requests if it gets previews:

1. **The customer installs the App** on that repository: its public page, `https://github.com/apps/<app>/installations/new`, "Only select repositories". Nothing happens yet: the site does not name the repository, so the Worker gives it nothing.
2. **Add it to the site:** the project as a flake input, the app in `apps/` (with `preview.repo` if it gets previews), then `avc ci repos`, which rewrites `github-repos.json` when the app fetches something the lock does not name. `avc ci installations` should show the repository as covered.
3. **Ship it** (`avc deploy ship`). Your own workstation and the merge gate's runner need their own read access to the customer's repository to lock and build it; the nodes do not use yours.
4. **After the merge** the Worker reads the new lock and file from the deploy branch, and its next answer to each node includes a token for the customer's organization that names that repository and no other. From then on a push to the branch the input follows starts the lock update, and a pull request gets its preview.

If the customer removes the installation, the nodes' tokens for it are not renewed, the next pull that has to fetch the repository fails, and the running system stays as it is.

**What is proven.** `checks.cluster-ci` runs the Worker's decisions (which webhook makes, moves, resets or removes a preview, what a node's report does to the pull request, which push deploys and which updates a lock) with GitHub and Cloudflare stood in for. It also runs what a node is handed for GitHub: that only a node's bearer token is answered, that GitHub is asked for read-only tokens naming the site's repositories, where that set comes from, what a stranger's installation causes (nothing), and when a token is replaced. `checks.github-access` runs the node's refresh against a stand-in Worker (files whole and root's alone, a failed refresh keeping what is still good) and asks git itself what the credential helper answers for each repository. `checks.ci-agent` runs the agent as a process against a stand-in Worker and stand-in `nix`, `zfs`, `juicefs` and `systemd`, and holds it to what it asks of them and in which order. A slot's container and its host evaluate on the fixture cluster. Nothing here has met GitHub, Cloudflare or a node: no installation token has been narrowed by the real API, no Nix on a node has fetched with one, no slot has been started, no clone taken, no copy migrated. The first preview on a real site is that test.

### Providers

What the site needs from OVH and Cloudflare is made by [OpenTofu](https://opentofu.org), from a configuration nobody writes: `lib/cloud.nix` derives it from the topology and the apps, as the flake's `cloud` output. `avc cloud` runs it on your machine. No node holds a provider's API credentials or runs OpenTofu.

```sh
avc cloud plan                 # what would change; nothing done
avc cloud apply                # done, written back, and shipped as a pull request
avc cloud apply --destroy <address>[,<address>]
avc cloud tofu "state list"    # OpenTofu itself, same configuration, state and credentials
```

| Provider | What is made | From |
| --- | --- | --- |
| OVH | A bucket, a user of its own, that user's S3 key pair, and a policy that reaches that bucket and no other | `objectStorage.juicefsBucket`; one for each app with `juicefsPaths`; `backup.state.target.bucket` when it is on the same endpoint |
| OVH | The same for the binary cache's bucket, unversioned | an app of kind `attic`, its `attic.bucket` |
| OVH | Versioning on the state backup's bucket, and hidden versions expired after `noncurrentDays` | `backup.state.target.bucket` |
| Cloudflare | A tunnel per app, locally configured | every app with a hostname whose `tunnel.accountId` is unset or `cloud.cloudflare.accountId` |
| Cloudflare | A proxied CNAME per hostname, to the app's tunnel | hostnames in a zone of `cloud.cloudflare.zones` |
| Cloudflare | The private route to a FreeIPA server's address | `freeipa.privateIp4` |
| Cloudflare | The audit trail's R2 bucket, with a lock rule | `cloud.cloudflare.auditBucket` |

No user may delete an object version, so on the versioned bucket a node that is taken over can hide backups and not destroy them.

**What comes back goes where the site reads it.** An S3 key pair into its var (`ovh-s3`, `<app>-jfs-s3`, `backup-state-target`, `cache-s3`), written only when it differs. A new tunnel's id into `apps/<app>.json`, which merges with the app's `.nix`, and its credentials file into the app's `<app>-cf/cloudflared`. So a new app with a hostname needs no `cloudflared tunnel create` and no `tunnel.id`: `avc cloud apply` makes the tunnel and writes both. The apply ends in the same pull request every change does.

**A tunnel made by hand is adopted.** An app that already has a `tunnel.id` gets an import of it, and its secret and its name stay as they are. A DNS record made by hand is not known to the topology by any id: delete it first, or `avc cloud tofu "import cloudflare_dns_record.<name> <zone id>/<record id>"`. A bucket made by hand likewise (`import ovh_cloud_project_storage.juicefs <project>/<region>/<name>`); its old user and key are then yours to remove once the new pair is deployed.

**A tunnel in another account is left alone.** An app whose `tunnel.accountId` names another Cloudflare account than `cloud.cloudflare.accountId` has its tunnel and its DNS records made there, outside OpenTofu: a client's zone in the client's own account, where a CNAME to `<id>.cfargotunnel.com` resolves only to a tunnel in that same account. `wordpress-nix edge provision` makes such a tunnel and prints its id and credentials, which go into the app's file and `<app>-cf/cloudflared` as for a tunnel made by hand. `avc cloud` makes no tunnel, import or record for the app, and names its hostnames as someone else's. None of them may be in a zone of `cloud.cloudflare.zones`, or the node fails to evaluate: two owners of one record would undo each other's changes (`checks.cloud-accounts`, `checks.container-tunnel`).

**Nothing is destroyed by accident.** Buckets and tunnels carry `prevent_destroy`, so a plan that would delete one fails in OpenTofu. Anything else a plan would delete or replace, `avc cloud apply` refuses until each address is named with `--destroy`. A replaced key pair is one a node is using: name it, apply, and let the ship reach the nodes.

**The state** is `cloud/terraform.tfstate` in your repository, committed with each apply. It holds every key the providers issued, so OpenTofu encrypts it (and every saved plan) with `cloud-state/passphrase`, enforced: without the passphrase it refuses to read the state, and it never writes one in the clear. Put the passphrase in the [offline kit](#the-offline-kit). Two operators applying at once would each commit a state; the pull request of the second conflicts, which is the lock.

To turn it on: `cloud` in the topology; `avc secrets provision` for `cloud-state` (it leaves the key pairs `avc cloud apply` issues, such as `ovh-s3`, to that command while they are missing), and for `cloud-ovh` an API application of your own (`https://<endpoint>/createToken`, with GET, POST, PUT and DELETE on `/cloud/project/<project>/*`); `cloudflare/provision-token` needs Cloudflare Tunnel, DNS and R2 write. Then `avc cloud plan`.

Not made here: the Workers' own code and secrets (`wrangler deploy`), API tokens, Access applications and their policies, a WordPress site's R2 bucket (the site provisioner's), the nightly backup's target (which is meant to be elsewhere), and the servers themselves.

### The binary cache

One app of kind `attic` gives the cluster a binary cache, an [Attic](https://github.com/zhaofengli/attic) server:

```nix
# apps/cache.nix
{
  attic.bucket = "example-cluster-cache";
}
```

Then `avc cloud apply` (the bucket and its key) and `avc secrets provision` (`cache-token`, `cache-signing`, `cache-push`), which ships. The nodes ask the cache once `cache-signing/public` is in the repository, which generating the secrets puts there.

- **What goes in.** Each node pushes the closure of the system it runs after every switch and once a day (`cluster-cache-push`), and that closure holds every app container the node was built with. The CI agent pushes each preview it builds. Attic leaves out what cache.nixos.org already signed, so the bucket holds what the cluster built and nothing else. With pull-deploy the canary node builds first and pushes; the others fetch.
- **What comes out.** Every node has the cache as a substituter at its own loopback (port 8732). HAProxy there passes the request over the mesh (port 8733) to whichever node has the container, found by health check. The container takes a fixed address in the app subnet of the node it starts on (`attic.hostOctet`, 9), so no node has to be told where it went.
- **It is never needed.** A push that fails is the `CachePushStale` alert, and fails nothing. With the cache on no node the loopback port refuses connections, Nix leaves the substituter alone for a minute at a time and builds. That is also how a new cluster's first deploy goes, and the cache's own.
- **Who may write.** Reading needs no token. Writing needs `cache-push/token`, which every node holds and which can push and pull on this one cache and nothing else.
- **Retention.** A path nobody pushed or fetched for `attic.retentionDays` (90) is dropped, and chunks no path uses are deleted from the bucket, every twelve hours. What a node runs is pushed daily, so it stays.
- **What is not backed up.** The bucket. The index (a SQLite file) is the app's local state, replicated and snapshotted like any app's; lose both and the nodes fill a new cache as they deploy.

**`attic.public = true` serves it to anyone**, at `attic.hostname` on the app's tunnel, read-only: an nginx in the container passes `GET` and `HEAD` and refuses Attic's API, so nothing is pushed or configured from outside whatever token is presented. It is off by default, because of what it gives away:

- **Every store path the cluster built**, to anyone who knows or can compute its name. That includes each node's whole system closure: the rendered configuration of every service and every app, which is your private repository's `apps/` and topology in built form (hostnames, addresses, firewall rules, job specifications, package versions).
- **Your apps' own code**, as built packages, if the projects are private.
- **Not the secrets in the clear.** A node's rekeyed files are in its closure, encrypted to the key in its TPM; what is decrypted goes to `/run/secrets` and is never part of a store path. That holds for what this library writes; a value you put in an app's `module` as a string is in the store, and so in the cache.

Attic does not list a cache's contents, and a store path's name starts with a hash of everything it was built from, so a path is fetched by someone who has its name: from a deployed system's closure, or by evaluating the same flake. Treat that as slowing a reader down, not stopping one. If other people should have the apps' packages and not your cluster's configuration, a public cache is the wrong tool as it stands: it pushes whole system closures.

### Backups and restore

There are two backups, to two places, on two schedules.

**The nightly one** is the long history, and goes to `backup.target`: somewhere that is neither the nodes nor their provider. Each app is backed up, by whichever node is running it when the timer fires, into its own restic repository, `<target>/apps/<sha256 of repoSalt and the app's name>`. The two are joined with nothing between them, so from a machine that isn't a node, `printf %s "$salt$app" | sha256sum` gives the directory name. `cluster-backup-list <app>` prints it on a node, and is the only map from hash to app. A snapshot holds a logical database dump, taken inside the container with its own tools, and the app's JuiceFS paths, so a restore brings back a database and the files it refers to together. `backup.localSnapshot = true` adds an app's local state, read from a ZFS snapshot, for apps no dump covers.

**The state backup** is the recent past off the nodes, and exists once the topology has `backup.state`, with a target of its own: the nodes' own object storage is the natural one, since an hourly upload wants to be near and the nightly copy is the one that is far. Every hour (`backup.state.schedule`), each app's local state, as its newest replicated snapshot has it, goes into a second repository of the app's, `<state target>/state/<another hash>`: the database's directory itself, crash-consistent, which a database recovers from as from a power cut. One node does it per app, a replica, so reading a whole database costs the running app nothing. 48 hourly and 14 daily snapshots are kept (`backup.state.retention`). It is a physical copy: it restores to the same database version, and not the app's JuiceFS files, which are in object storage already.

```sh
cluster-state-backup [<app>]               # now; does nothing on a node that is not the one to
cluster-state-backup-list <app>            # its snapshots, dated as the data is
cluster-state-restore <app>                # print the plan
cluster-state-restore <app> --snapshot <id> --yes   # the app stopped first: nomad job stop app-<name>
```

A state restore replaces the whole dataset on the node it runs on, after a ZFS snapshot of what was there, and every other node receives the result; then `nomad job start app-<name>`. Which to reach for: a node died, nothing, the app has moved already. A mistake in the last day, a replicated snapshot on any node (`zfs list -t snapshot <pool>/state/apps/<app>`, and `zfs clone` to read one). The nodes are gone, or the mistake is older: the state backup for the last two weeks to the hour, the nightly one beyond that or across a database version.

The nightly backup's commands:

```sh
cluster-backup [<app>]                     # back up now
cluster-backup-list <app>                  # its snapshots
cluster-restore <app>                      # print the plan (dry run)
cluster-restore <app> --yes                # restore the latest snapshot
cluster-restore <app> --snapshot <id> --yes
cluster-restore <app> --db-only --yes      # or --files-only
cluster-restore <app> --to-scratch /var/tmp/r
```

A weekly rehearsal restores each app's backup to prove it works. If you lose a node, its apps start on the others by themselves, from their replicated state ([Where an app runs](#where-an-app-runs)); the backup is for losing more than that, or for going further back. `cluster-restore` runs on the node the app is running on, or on any node while it runs on none. Keep your age key somewhere other than your laptop, because backups can't be decrypted without it.

The staging, verify and restore directories (`/var/lib/cluster-backup/{staging,verify,restore}`) hold plaintext dumps until the next run, on the node's encrypted root.

For an S3 target, use a bucket with versioning and a user that cannot delete object versions, so a compromised cluster can hide objects but cannot destroy history.

#### When every copy of the JuiceFS metadata is lost

One reinstalled node is not this case: its member copies the database from the primary and nothing is restored. This is every member's data gone at once (or the one node of a one-node site), with the bucket intact.

On a site with an etcd, every member then waits, because none of them may start an empty database while the bucket holds a volume: `patroni` restarts every 10 seconds and says so, and `JuiceFSMetaNoPrimary` fires. Pick one node and `touch /var/lib/patroni/found-new-cluster` there. That member starts empty, the others join it, and `juicefs-format` restores the newest dump. Remove the file afterwards. A one-node site needs no such step.

`juicefs-format` restores the newest metadata dump on its own if it is at most 6 hours old. The mounts write one every 2 hours, encrypted, to `<bucket>/appfs/meta/`. An older one means the dumps stopped, and restoring it would lose every file written since, so the unit refuses with exit 5 and says why. To restore that dump anyway, name it on the node: `echo <dump name> > /var/lib/juicefs-format/restore-stale-dump`, then `systemctl restart juicefs-format`. Exit 4 is an outage (the database or the object storage unreachable). The unit retries it every 30 seconds, and `UnitRestartLoop` fires if it goes on for 15 minutes. Exit 3 is a volume that is not encrypted, which is refused for good.

The metadata database is deliberately not backed up by restic, because restoring a stale dump against a live bucket produces a filesystem that lies about its contents. Its protection is its replicas, and behind them JuiceFS's own metadata dump in the bucket.

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

Every node runs node_exporter, `smartctl_exporter`, a JuiceFS write probe, the boot report and audit, the canary scan and a jumbo-frame probe of every peer, and ships its journal and every container's journal through Vector over the mesh. Every node also runs the whole of monitoring: a Prometheus that scrapes every node, a Loki that every node ships to, an Alertmanager, and blackbox probes of every app's public hostname.

No node is the monitoring node, and nothing about monitoring is placed or elected: it does not depend on the scheduler it watches.

- **One alert is one email.** Each Prometheus evaluates the same rules and tells its own Alertmanager; the Alertmanagers gossip on the mesh (port 9094) about what has been sent.
- **Every node has every log line.** Each node's Vector feeds its own Loki from the journal, and every other node's through a 512 MiB buffer on disk. A node down for longer than its peers' buffers hold has a gap in its own copy when it returns; the other copies are whole.
- **Grafana asks the node it is on,** wherever Nomad puts it, so a graph may show a gap for the time that node was down which another node's history does not have.
- **The weekly report is sent once,** by the node whose address sorts first among those its Prometheus sees up.
- **What it costs:** the stack once per node, in memory and in disk (each Loki has its 50 GB dataset).

```
Prometheus (lib/alert-rules.nix) -> Alertmanager -> alert-email-bridge
  -> send-notification-email (lib/notify-email.nix) -> Cloudflare Email Sending API
```

Setup, once:

1. Onboard the sender's domain (`alerting.from`) to Cloudflare Email Sending, including SPF and DKIM.
2. Create an API token with the Email Sending permission only, and run `avc secrets set alerting/cf-email-token`.
3. After the deploy, run `cluster-alert-test` on any node. It fires a real alert through the whole path, which resolves by itself after 5 minutes.

A weekly report emails each app's last backup, rehearsal and repository check. It is a positive signal: if it stops arriving, that tells you something.

| Alert | Severity | Means |
| --- | --- | --- |
| `BootUnlockedByPassphrase` | critical | The last boot was unlocked by the typed recovery key, not from the TPM. Expected only after an attended recovery. |
| `UnlockTpmFailing` | critical | The TPM did not unlock every leg on the last boot: fix the binding before the next reboot. |
| `TpmBindingMissing` | critical | A leg has no TPM binding (after a disk replacement, until `avc boot bind <node> --device <device> --recovery-key`). |
| `TpmBindingUnsealed` | critical | A leg's TPM slot has been the install's, bound to no PCR, for six hours: any boot of the machine can open the disks. Finish the install (`avc boot enroll`, reboot, `avc boot bind`). |
| `SecureBootOff` | critical | The node booted without Secure Boot enforcing. |
| `Pcr7Changed` | critical | PCR 7 changed within the last day: firmware, keys or Secure Boot state changed. |
| `VolumeIdentityMissing` | critical | The identity secret is missing or wrong: the next boot would halt. |
| `PoolVdevNotEncrypted` | critical | A vdev of `rpool` is not on dm-crypt. |
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
| `CanaryBootUnproven` | warning | The canary booted without a clean TPM unlock, so it vouches for nothing. |
| `CanaryFound` | critical | The canary turned up in plaintext somewhere it must never be: find the writer. |
| `CanaryScanStale` | warning | The canary scan has not run for 8 days. |
| `JuiceFSVolumeNotEncrypted` | critical | A node refused a JuiceFS volume that is not encrypted. |
| `GitHubTokenStale` | warning | A node has had no GitHub tokens from the cluster-ci Worker for 25 minutes. The ones it holds last up to an hour; after that its pull loop reads public repositories only. Only with `ci.url`. |
| `SecretsMissing` | critical | Secrets the node was given did not decrypt: its TPM does not hold the identity they were rekeyed to. A boot that began this way did not start Nomad. |
| `JuiceFSUnwritable` | critical | `/mnt/jfs` is not writable. |
| `JuiceFSProbeStale` | warning | The JuiceFS probe has not run. |
| `JuiceFSMetaDumpStale` | warning | The newest metadata dump in the bucket is old, or a volume has gone that long without writing its first. |
| `JuiceFSMetaNoPrimary` | critical | The metadata database has had no primary for 3 minutes: every `/mnt/jfs` is stalled. |
| `JuiceFSMetaMemberDown` | warning | A node's member of the metadata database is down or unreachable. |
| `JuiceFSMetaReplicaNotStreaming` | warning | A replica of the metadata database is not following the primary. |
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
| `BackupStale` | critical | No successful backup recently, on any node. |
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
| `StateBackupStale` | warning | An app's state has not reached the state backup target for 4 hours (`backup.state.staleHours`). |
| `StateBackupNeverRan` | warning | An app's state has never reached the state backup target. |
| `StateReplicaLagging` | warning | A node's copy of an app's local state is over 10 minutes behind the running one. |
| `StateReplicationStale` | warning | A node has not snapshotted or pulled app state for 15 minutes. |
| `StateReplicationFailing` | warning | Replicating some app's state fails on a node. |
| `StateOrphaned` | warning | A node holds a copy of app state set aside after a failover, with writes no other node has. |
| `CacheDown` | warning | The binary cache answers no node. Deploys build what they would have fetched. |
| `CachePushStale` | warning | A node has pushed nothing to the binary cache for three days. |
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
avc -y secrets reveal alerting-watchdog/token | wrangler secret put WATCHDOG_TOKEN
wrangler secret put CF_EMAIL_TOKEN             # the Email-Sending-only token
avc audit tokens | wrangler secret put AUDIT_TOKENS
wrangler deploy
```

Then set `alerting.heartbeatUrl` to its `/heartbeat` URL and `alerting.auditUrl` to its `/event` URL, and ship it.

#### Audit trail

Each node sends events to the Worker's `/event`, with its own `audit/token`, from a spool on the node that survives outages: `boot` (the boot report: unlock method, devices, initrd SSH logins, Secure Boot, PCR 7, generation), `deploy` (each tick's result), `ssh_login`, `nomad_acl` (token and policy changes, from every Nomad server: each sends what its own event stream showed, so one change is in the trail once per server, under each one's name, and no one server can keep it out) and `canary` (a hit). The Worker accepts only the fields each kind's schema names, each required, from a token allowed that kind, and stores each event in the R2 bucket before it emails: it can append, never read or delete. It emails each boot: `[NOTICE]` when the report says every leg unlocked from the TPM under enforcing Secure Boot, `[FIRING]` otherwise. The report is the node's own account, so a clean one is a notice to read, not proof.

Lock the R2 bucket against deletion with a bucket lock rule, so a stolen Cloudflare token cannot rewrite history either. How long to keep events is the site's decision ([Defaults awaiting a decision](#defaults-awaiting-a-decision)); until a rule says otherwise, they are kept. The sender is strict about TLS: a private CA in front of the Worker needs proper CA extensions.

#### Canary scan

A weekly scan plants the `canary` value in a file on the JuiceFS volume (`/mnt/jfs/.canary/<node>`), as client data is stored, and then looks for it where client data must never be in plaintext. Each place is a class, reported as `cluster_canary_hits{path_class=...}`: `tmp`, `coredump` (any core file at all), `journal` (read through journalctl, because journald compresses fields), `swap` (the raw devices under the random-key mapping), `esp`, `s3` (the exact objects JuiceFS stored the file in, as the provider stores them), and with `cluster.canary.rawDisks = true` in a host file, `raw` (every byte of both disks). A hit is `CanaryFound`, and a `canary` audit event. A class that cannot look fails the unit instead of reporting 0. Opted-out nodes scan too: their swap and disks are plaintext, so a hit there is real.

### Logs

Grafana queries Loki with labels `node`, `app`, `site`, `service` and `level`. The payload flakes supply the application fields. A label contract is pinned at build time: `modules/logging.nix` runs its VRL program over sample entries with `vector vrl`, and a program that stops emitting a label fails the system's build. Each node's Loki has its store on that node's own encrypted disk, in its own dataset (`rpool/loki`, 50 GB quota).

## Upgrading a running cluster

This version is written for fresh installs. A cluster running an earlier version of this library can't take it as an ordinary deploy, because several changes are hard cuts:

- **Disk encryption needs a reinstall.** A running plaintext node can only stay as it is with `insecurePlaintextBoot` (and the site's `insecureFleetKeysOnPlaintextDisk`), or be reinstalled through [Installing a node](#installing-a-node).
- **A node's secrets are its TPM's.** A node installed before has no age identity: `avc boot identity <node>` makes one on its TPM, commits the recipient and rekeys, and `avc deploy break-glass <node>` puts the first closure that carries them on it ([The node's age key is gone](#the-nodes-age-key-is-gone) is the same state). Its disks need nothing: the passphrase they were formatted with is the `luks/passphrase` that is now called the recovery key, and a TPM slot an earlier `avc boot bind` sealed to PCR 7 is what this version's makes. Not rehearsed on a node installed by an earlier version.
- **The first deploy of this code waits on every node.** The running closures have no boot contract, so the contract gate refuses until `/run/cluster-upgrade.approve` lists the new closure, node by node. And they have no boot stack, so every node but the canary also waits until the canary has rebooted into it.
- **Nomad TLS and the gossip key.** Rolled out node by node by the pull loop, servers with and without the key can't gossip, and plaintext and TLS RPC can't talk. All servers must switch together.
- **Scoped tokens.** One server's `nomad-acl-init` has to run before any other node's logins succeed; until then those retry every 10 seconds, and a non-leader's deploy may report an activation failure once and then recover.
- **The mesh.** etcd's peer addresses move from the control VLAN to the mesh, and etcd reads its member list only on a new data directory, so an existing member keeps advertising its old addresses: an in-place move needs `etcdctl member update` per member, or a fresh etcd. Not tested. SSH over the VLANs stops.
- **JuiceFS encryption.** A volume formatted before is plaintext, and every mount and `juicefs-format` now refuse it (exit 3). Moving to an encrypted volume is a migration (a new volume, copy, cut over), not a switch.
- **Loki's dataset.** A node installed before has no `rpool/loki`, and disko creates datasets only at install. Create it first, on every node: `zfs create -o mountpoint=legacy -o quota=50G -o com.sun:auto-snapshot=false rpool/loki`. Required mounts are in the boot contract, so the closure waits for approval anyway; create the dataset before approving. The old Loki bucket is no longer used.
- **Hashed backup paths.** Apps with repositories at `apps/<app>` get new, empty ones at the hashed path; the old ones stay untouched. Deploy before the first backup, or `restic copy` each app across.
- **Every container restarts once.** Each job now runs as `nomad-apps` with a new wrapper, so each allocation is replaced. Containers with `peerAccess` get a new veth, which a reload cannot apply: `nomad job restart app-<name>`. Containers' WAN MACs become fixed (`02:76:77:<node index>:<iid>`); if your provider pins MACs per port or address, check before rollout.
- **The `nomad-leader` tag is gone.** Remove it from the node that had it (evaluation warns while it is there). Every `nomad-server` node now holds `nomad-acl` and a `registrar` login: `avc secrets provision` makes them for each server that did not have them, and add `nomad_acl` to those servers' kinds in the watchdog Worker's `AUDIT_TOKENS` (`avc audit tokens` prints the new value), or the Worker refuses their ACL events and they stay in the spool.
- **`homeNode` is gone, and local state moves into datasets.** Remove `homeNode` from every app (evaluation refuses it). An app's database is then a plain directory on the node it was pinned to, and the app has to start there once more: that start copies the directory into `<pool>/state/apps/<app>` (as long as the copy takes, inside `startTimeout`) and keeps the original as `/state/clients/.<app>.before-datasets`, to remove by hand. Started on any other node first, it refuses and Nomad tries again elsewhere, so an app may take a few attempts to land. To choose instead of waiting: `nomad node eligibility -disable` the other nodes, `nomad job restart app-<name>`, and enable them again. Each other node then receives a whole copy, which needs the disk. `/state` must be ZFS, as the installer makes it. Not rehearsed on a site with data.
- **The scheduler algorithm.** New clusters spread apps over nodes. One bootstrapped before keeps Nomad's packing until told, once, on a server: `nomad operator scheduler set-config -scheduler-algorithm=spread`.
- **The `github-token` secret is gone.** A node no longer holds a personal access token: it asks the cluster-ci Worker for short-lived, read-only ones ([GitHub access](#github-access)). The closure that removes the token is the last one a node fetches with it, so everything the next pull needs must be there before that closure merges: the App created and installed on the site's repository and every private input, the Worker deployed with `SITE_FLAKE`, the App's key and `AGENT_TOKENS`, and `ci.url` set with every node's `ci/token` shipped. `avc ci installations` shows each of the site's repositories as covered, and `curl -sS -X POST -H "Authorization: Bearer <a node's ci/token>" <ci.url>/agent/token` answers with tokens. Then merge the library bump with `secrets/shared/github-token` and its rekeyed files removed, watch `journalctl -u cluster-github-token -u cluster-upgrade` on the canary, and revoke the old token at GitHub once every node has pulled without it. A node that cannot get tokens after the switch is reached with `avc deploy break-glass <node>`.
- **The `backup` tag does nothing now.** Each app is backed up by the node running it. Leave the tag or remove it.
- **The database archive is gone.** `archive.*` on an app, `objectStorage.dbArchiveBucket` and the `<app>-db-archive*` vars no longer exist: remove them, and the archive bucket and its keys at the provider when its last week is no longer wanted. What replaces it is replication between the nodes and, off them, `backup.state`.
- **The `metrics` tag does nothing now, and the autoscaler is gone.** Every node runs Prometheus, Loki and Alertmanager. The node that had the tag keeps its history; the others start empty and fill from then on, and each needs `rpool/loki` (above). Remove the tag or leave it. The Nomad autoscaler ran on that node and never acted, since no job carries a scaling policy; its `autoscaler` login role went with it, so `avc secrets provision` reissues each node's `nomad-login`.

## Testing

Everything runs against the **fixture cluster** in [`tests/fixtures`](tests/fixtures), which is built through `mkCluster` the way a consumer's is. Its public addresses are documentation-only (RFC 5737, RFC 3849) and its names are under `example.com` and `example.net`. Its internal VLANs are RFC 1918, because the documentation ranges have no /16 to split into per-node subnets. It has `node1` with every role, placeholders `node2` and `node3`, and neutral apps of every kind, with stub packages for Odoo and Frappe. Every fixture node opts out of boot security, because a VM test of a cluster has no TPM; the `boot-*` checks install and boot the encrypted layout themselves, and `tests/fixtures/secure` is node1 with boot security on, evaluated by `security-policy` and `boot-closure`.

No secret is committed. `tests/fixtures/secrets` holds placeholders that are not ciphertext, because a secret with no file is not given to a node and `lib/mk-app-container.nix` asserts that every secret an app mounts exists. `tests/fixtures/agenix` is the exception that proves nothing: real ciphertext for `checks.secrets-tpm`, with its master key and its software TPM's state beside it in the clear. `tests/fixtures/update-secrets.sh` regenerates them after you add a fixture app or change a generator.

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
| `avc` | The operations tool's own tests: policy gate, ship ordering, registry, boot, secrets, audit and pipeline flows. And the generator runner for real, with a plain age key where a site has a YubiKey: order and `$in`, prompts, shared and per-machine, a changed `validation`, a failing script leaving nothing, no plaintext in the repository or off the tmpfs, the sandbox, one decryption per source, rekeyed files under agenix-rekey's names, and `avc secrets check` refusing what is ungenerated or not rekeyed. |
| `cluster-ci` | The pipeline's Worker: a pull request becomes one preview per app and branch with its own tunnel and hostname, a fork gets nothing, a node's report reaches the pull request only for the commit it is about, a preview's tunnel is deleted only after its node let go of it, and which push deploys and which updates the site's lock. And a node's GitHub tokens: only a node's bearer token is answered, GitHub is asked for read-only tokens naming the site's repositories, the set comes from the site's repository and never from a node, a stranger's installation of the public App causes nothing, a token is minted once and replaced with half an hour left, and an uncovered repository is named. |
| `ci-agent` | The pipeline's agent as a process, against stand-in commands: build with the input overridden and fresh GitHub tokens asked for first, clone before start, a push that does not seed again, a reset that does, a full app that says so, a release that leaves nothing, a failure that names units and no log line, and a deploy started once per push, across a restart. |
| `github-access` | A node's GitHub token refresh as a process, against a stand-in Worker: both files replaced by rename, mode 0600 in a 0700 directory, one `access-tokens` entry per repository that the nodes' Nix parses, a missing include ignored, a failed refresh keeping the tokens still good and dropping the expired, an answer that is not tokens and names refused. And git's credential helper, asked by git: the token of the repository named, nothing for an unknown owner, another repository of a known owner, an expiring token or another host. |
| `mk-cluster` | The consumer interface, with a `self` that exports nothing, and the template's own flake outputs, including that the template as shipped refuses to evaluate until its boot fields are filled in. |
| `docs` | This README against the code: every check has a row here, every `avc` and `cluster-boot-seal` command it names exists, every topology field, alert and generator is documented, and no address or email is outside the reserved ranges. |
| `security-policy` | The boot security posture and its one opt-out: what evaluates, what is refused and for the reason it claims; the boot contract's fields, the boot stack, the canary's topology rules; and that every generator of a new site can be read. Evaluation only. |
| `security-policy-fixture` | The posture checks that need a whole fixture system per node. |
| `boot-closure` | What can be proven about an encrypted closure without booting it: the ESP budget, the initrd's contents (one without TPM support fails the build), and when the boot contract moves (not on a kernel bump; on every field an unlock depends on). |
| `boot-install` | An encrypted node installed with the real disko script on its own TPM, under Secure Boot with keys made on the node: each leg left with a TPM slot bound to no PCR and the recovery key's, and nothing else; unattended unlock on that slot in Setup Mode and enforcing; bind refused in Setup Mode; the bind sealing to PCR 7 with nothing sent to the node, and refused on a leg with no slot that opens unless the recovery key comes; unattended unlock on both legs, with and without a network; one leg rebound; a second kernel and generation. |
| `install-node` | A node installed the way `avc boot install` does it, in VMs with a software TPM: the rescue system's SSH host key pinned to the fingerprint read on it, a wrong fingerprint refused and a far end with another key refused to nixos-anywhere's own connections, both with the machine, its disks and the site untouched; then nixos-install-helper's `deploy` and nixos-anywhere's kexec from a rescue system under that pin, the installer answering with the rescue system's key, `avc`'s step between the kexec and the partitioning making the age identity on the machine's TPM, the recipient and the encrypted identity file in the site, the secret the node reads rekeyed to it, the partitioning secrets through a tmpfs into the installer's memory. Then the node boots unattended, decrypts with that identity, and holds no install-time secret; the same disks behind another TPM ask for the recovery key and decrypt nothing; and a rescue boot opens them with the recovery key from the site and not with its TPM. |
| `boot-fallback` | The TPM refuses: the prompt within seconds, typing on serial, tty0 and SSH; the initrd's sshd accepts an operator's FIDO2 (`ed25519-sk`) key and refuses another's; wrong keys ask again; one leg waiting does not import the pool degraded; the boot report counts the typed unlock. |
| `boot-degraded` | A dead, absent or corrupt disk boots unattended and DEGRADED; each ESP boots alone; a full or unmounted ESP refuses a new generation without writing to the root; a disk replacement onto a new LUKS leg; signing keys lost and recovered; the identity repair from rescue; no plain vdev. |
| `boot-attack` | A swapped volume with forged identifiers halts before it can steal anything (and steals the keys with the check removed); the emergency shell burns PCR 7; a tampered initrd or unsigned loader is refused; Secure Boot off, a db certificate added, keys cleared, another signed loader or a cleared TPM all withhold the disk key; a foreign authority in PCR 7 refuses bind. |
| `deploy-safety` | What a pull deploy does with a closure that fails, one whose boot contract changed, a refused one after a rollback (by hand and at boot), a held node, and a frozen PID 1 under the hardware watchdog. |
| `canary-gate` | The staged rollout, with two VMs and the real tick and publisher: a follower waits for a new boot stack and takes an app release on the same stack at once; the canary takes the stack first; a switch and a passphrase boot publish nothing; a clean reboot publishes it and the follower then activates it; `/run/cluster-upgrade.skip-canary` is per closure; an unmounted store proves nothing either way. |
| `nomad-pki` | Nomad's PKI without booting anything: the real generators' certificates, names, chain and validity, the gossip file, and a minted login JWT. |
| `control-plane-attack` | A machine on the control VLAN with each credential an attacker could hold: what mTLS and the gossip key refuse, and the documented limit; what a stolen `submit-job` token can and cannot do through `raw_exec`; what a machine on the VLANs reaches without a mesh key. |
| `control-plane-failure` | The control plane's own failures: the mesh cut, a key rotated on one side, a node booted without its mesh key, every Nomad certificate expired, and recovery from each. |
| `jumbo-mtu` | MTU 9000 on the VLANs and 8920 on the mesh, on a link that carries it and on one that silently doesn't (`VrackJumboBroken`). |
| `container-isolation` | Container to host and container to container: default-deny, the holes an app declares by bridge port, spoofed identities refused, the WAN segment's pinned MACs and neighbour discovery. |
| `voter-growth` | One Nomad voter to three: the first voter's switch, a worker promoted, a fresh voter, etcd formed once three nodes carry it, the metadata database growing from the one server's to three members with its data, and the `bootstrap_expect` trap. |
| `jfs-encrypted` | The JuiceFS volume is encrypted; a plaintext one is refused at format and at mount; restore works with the key, only with the key, and from the offline kit alone; stale dumps, interrupted loads, S3 key rotation. |
| `canary-scan` | Per class: plant the canary, scan, found; remove it, scan, not found. Swap plain against dm-crypt, a plaintext bucket against an encrypted one, a real compressed core a grep can't see into. |
| `container-tunnel` | The generated container, tunnel and firewall wiring. |
| `secrets` | What a node is given of the site's secrets and what it is not (an operator's, an install-time one), each at the path the modules read; what the gate holds and what it must not; a node with a recipient and an unrekeyed secret does not evaluate. Evaluation only. |
| `secrets-tpm` | The real path, in VMs with a software TPM: agenix-rekey's own app rekeys two master-encrypted secrets to a node's TPM recipient, the node decrypts them at boot at their paths and with their owners, what `avc`'s runner rekeyed from the same site's `clusterSecrets` has the same names and decrypts on that TPM too, a secret removed on the running node is counted and comes back with an activation, and the same system on another TPM decrypts nothing, fails `cluster-secrets`, starts no Nomad and says so in its metric, with SSH up. |
| `backup` | What the fixture apps generate: engine detection, units, salted repository paths, target URLs. |
| `freeipa` | FreeIPA's wiring, and Authelia's own `validate-config` over its generated config. |
| `alert-rules` | Every alert rule fires when it should and stays quiet when it should not (promtool). |
| `alerting` | An alert travels Prometheus, Alertmanager and the bridge to a stub of the Cloudflare API, in a VM. |
| `cluster-watchdog` | The dead-man's logic, and the audit Worker's schemas, tokens and emails. |
| `logging` | A journal entry reaches Loki with the label contract, in a VM. Loki keeps its store on local disk with no credentials, retention deletes old lines, and a crash leaves no core dump on the host or in a container. |
| `cloud-accounts` | `tunnel.accountId`: a tunnel in the cluster's Cloudflare account, by default or by name, is made with its records and imported where the app names it; one in another account gets no tunnel, import, record, output or write-back, and its hostnames are reported as someone else's. |
| `cloud` | The fixture's OpenTofu configuration validated against the OVH and Cloudflare providers' own schemas, with the OpenTofu `avc` runs: a bucket, user, key pair and one-bucket policy per bucket, none able to delete a version; a tunnel per app, adopted where the app names one; proxied CNAMEs, FreeIPA's private route, the locked audit bucket; and where each output is written back. No provider is contacted. |
| `backup-roundtrip` | Backup, damage and restore against an S3 server, for PostgreSQL and MariaDB, in a VM. |
| `attic` | The binary cache on the fixture node, placed by Nomad: made with the site's signing key and unchanged by a second run; reached at the node's loopback through the mesh port; a pushed path deleted and substituted back, which takes the trusted signature; no configuring or pushing without a token, no configuring with a node's; the public face serving reads and refusing every write and the API; and with the cache stopped, a refused port, a build that goes ahead, a push that fails nothing, and a probe that says down. The fixture keeps NARs in a directory: S3 is not exercised. |
| `app-state` | An app's local state following it between three VMs with real ZFS: replicas received whole and then incrementally, a move that loses nothing, a dead holder waited out and replaced from the newest copy any node has, its return with its own writes set aside, a legacy directory adopted where it is, and a new app not started empty while a node is silent. Also: a replica keeping its history when the running node destroys its own, the state backup taken by one replica, and its restore reaching every node. |
| `install-boot` | The plain disk layout installs into a VM, reboots, and comes back. |
| `cluster-single` | `node1`'s real machine module boots and walks the whole cold start, twice: secrets, networking, the mesh, etcd, encrypted JuiceFS on S3, Nomad with TLS and scoped tokens, every app's job, monitoring, the audit producers. Jobs register but aren't placed. About 5 GB of RAM. |
| `cluster` | Three voters form quorums, share the cluster's JuiceFS volume whose metadata database loses its primary and a replica's disk and carries on, give an app its own volume (bucket, database, role), and run probe containers with cross-node reachability, an app held to one node by a constraint, and fencing. About 9 GB of RAM. |
| `ci-workflows` | The workflows in `.github/` and the template's pass actionlint, keep the properties the merge gates rest on (one evaluation per check, never `nix flake check`, a gate that fails on anything but success), and `tools/ci` fails loudly, against a stub `nix`. |
| `eval-memory` | Every check and mutant is detached, so `nix flake check` does not keep every evaluation to the end, and detaching keeps the same `.drv` and the interactive driver. |

The VM tests take the real machine modules and change only what a VM cannot have (`tests/lib/cluster-harness.nix`, `tests/lib/boot-harness.nix`): fixture values are written to the paths agenix would decrypt to (`checks.secrets-tpm` is the one test that decrypts), NICs carry the topology's names, a `wan` VM holds the nodes' gateways and answers for the object-storage hostnames, and the pull timer is unhooked. The test network has no route out. The boot tests run OVMF with Secure Boot and a software TPM, and a `peer` VM that types the passphrase over SSH.

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
| The Nomad management token (D6) | Kept on every Nomad server, read only by `nomad-acl-init` and the audit trail's ACL stream. Keeping it to one server, or deleting it, adds little: every server has working management tokens in its raft state, and root on one can mint another. | Delete it after `nomad-acl-init` and make policy changes through `acl-bootstrap-reset`. |
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
6. **No restore is to the second.** An app's state can be had back to the minute for the last four hours and to the hour for the last day, from any node's snapshots ([Where an app runs](#where-an-app-runs)); from off the nodes, to the hour with `backup.state` and to the night without. The continuous database archive an earlier version had is gone: it was the only thing here that reached a second, nothing restored from it, and replication took over what it was for.
7. **The JuiceFS metadata database needs etcd's quorum.** It survives a node, its primary's included, but with etcd down to a minority it has no primary and every `/mnt/jfs` stalls until the quorum is back. A site with one Nomad server and no etcd has one copy, on that server.
8. **x86_64-linux only.** The machine platform is fixed in `lib/mk-cluster.nix`.
9. **A preview is the pipeline's first real run.** [Previews and continuous deployment](#previews-and-continuous-deployment) is proven with GitHub, Cloudflare and the node's tools stood in for, and by evaluation.
10. **Nothing here has run on real firmware.** Every boot path is proven in VMs (OVMF, a software TPM); the [checklist](#real-hardware-checklist) is what proves a real node.
11. **State replication has run in VMs only.** `checks.app-state` proves the moves, the failover and the orphan with real ZFS on three VMs, with a stand-in for the container; no check yet has Nomad itself move a stateful app, and nothing has timed a large database's first replica or a failover on real disks. `wpdb` cannot move at all, and FreeIPA's move is the generic one, untried with a real FreeIPA.
12. **`avc cloud` has met no provider.** Its configuration is validated against the providers' published schemas and its state encryption against OpenTofu itself, but no plan has been made against a real OVH or Cloudflare account. Unverified there: that OVH's policy language keeps `s3:DeleteObjectVersion` from a user that has `s3:DeleteObject`, the import ids, and the `ovh-us` endpoint's coverage of each resource. Read the first plan before applying it.

## License

MIT. See [LICENSE](LICENSE).
