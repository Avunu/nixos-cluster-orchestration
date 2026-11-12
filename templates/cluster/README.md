# My cluster

A private flake on top of [nixos-cluster-orchestration](https://github.com/Avunu/nixos-cluster-orchestration). The library holds the modules; everything specific to this site lives here.

## What goes where

| Path | What it holds |
| --- | --- |
| `flake.nix` | The pinned library, your project flakes, and the `mkCluster` call with the operators' keys |
| `topology.nix` | Nodes, roles, VLANs, object storage, backup target, alert addresses |
| `apps/<name>.nix` or `.json` | One file per app |
| `hosts/<node>.nix` | Optional per-node hardware quirks |
| `vars/`, `secrets/` | Written by `clan vars generate` and committed. Secrets are age-encrypted |
| `inventory.json` | Written by clan when it installs a machine |

Keep this repository private: it names your addresses and customers, and it holds your encrypted secrets.

## First steps

1. Set the `cluster` input in `flake.nix` to a real commit of the library, then run `nix flake lock`.
2. Run `age-keygen -o ~/.config/age/identities` once per operator, and put the public keys in `recipients` in `flake.nix`. Make one more identity for the offline kit (`age-keygen -o <offline media>/identity`) and add its public key too.
3. Put your SSH public keys in `admins` in `flake.nix`.
4. Replace every example value in `topology.nix`: `deploy.flakeUrl` to this repository's URL, `backup.repoSalt` (`openssl rand -hex 16`), and per node `initrdNicModules`. A node refuses to evaluate until its boot fields are real.
5. `nix develop`, generate the secrets, commit them, and install the first node with the library's README, "Installing a node" (S0 to S8), as far as its Secure Boot keys:

   ```sh
   git add -A                       # flakes only see tracked files
   clan vars generate               # every machine; prompts for what third parties issue
   git add -A && git commit -m "vars"
   avc boot preflight node1
   avc boot install node1 root@<rescue-address>
   avc boot unlock node1            # first boot, Setup Mode: type the passphrase
   avc boot enroll node1            # own Secure Boot keys; then reboot and unlock once more
   ```

6. Deploy the watchdog Worker, set `alerting.heartbeatUrl` and `alerting.auditUrl` in `topology.nix`, and push its `AUDIT_TOKENS` (`avc audit tokens`). The first unattended boot is next, and its boot report and the `booted (tpm)` email that says S7 worked both go there.
7. Bind and reboot, with nobody typing (S6, S7):

   ```sh
   avc boot bind node1              # a TPM slot on each leg, sealed to PCR 7
   avc boot reboot node1            # nobody types; expect the Worker's email
   ```

After that, every node rebuilds itself from `main` on a timer. `avc` is the guided way to do day-to-day operations. It never pushes to `main`: it puts each change on a branch of its own, opens a pull request and waits for it to merge (see "Merging safely"). Run `gh auth login` once so that it can.

## Keep an offline kit

Off the cluster and away from your laptop: the offline age identity, a dated `git bundle create site-<date>.bundle --all` of this repository, and copies of each node's `luks/passphrase`, `restic/password`, `juicefs-rsa/rsa.pem` and `juicefs-rsa/rsa-passphrase`, `<app>-db-archive/key` for each app that archives its database, the S3 and backup-target keys, and `backup.repoSalt`. The library's README, "The offline kit", says what each restores. Refresh the bundle whenever `vars/` or `secrets/` change. Name a second person who can unlock a node.

## Secrets policy

`secrets/policy.toml` tells `avc secrets rotate` which secrets it may regenerate. The ones bound to disks or data (`luks`, `volume-identity`, `juicefs-rsa`, `restic`) are refused whatever it says, and each app's database archive key (`<app>-db-archive`) is marked never; the ones whose rotation needs both sides of something at once (`nomad-ca`, `nomad-jwt`, `wg-ctrl`, `juicefs-pg`) are manual. Never `clan vars generate --regenerate` `luks` or `volume-identity` for an installed node.

## Nodes that already run an earlier library

The first deploy of a library version with boot security waits on every such node: its running closure has no boot contract, so the deploy is refused until `/run/cluster-upgrade.approve` on that node lists the new closure's basename (`journalctl -u cluster-upgrade` names it). It has no boot stack either, so every node but the canary also waits until the canary has rebooted into the new closure. Read "Upgrading a running cluster" in the library's README before you deploy it to a live fleet: several changes there are hard cuts.

## Adding an app

Write `apps/<name>.nix`, run `clan vars generate <node>`, and ship it (`avc deploy ship`). To give it ingress, create its Cloudflare tunnel and set `tunnel.id`. The library's README has the full steps and the list of kinds.

## Updating the library

Change the `cluster` input's revision and bump nothing else in the same commit. It goes by pull request like every other change (`avc deploy ship` opens one), because nodes apply `main` within minutes: the merge gate below has to pass on it first.

## Merging safely

Every node rebuilds itself from `main` and first runs a new kernel and initrd at its next reboot. So a lock that cannot boot an encrypted node would pass every build, reach every node, and stop them all at their next reboots. Two things stop that: a merge gate, and a canary node.

**The merge gate.** `.github/workflows/merge-gate.yml` builds, at this repository's own `flake.lock`, which is what the nodes run: the library's `boot-install` and `boot-fallback` VM tests (re-exported as `checks.x86_64-linux` in `flake.nix`), a check that this flake's nixpkgs is the library's, and every node's system. It needs a self-hosted runner with KVM: Nix with flakes, `/dev/kvm` writable by the runner, `system-features = kvm nixos-test`, and 16 GB of RAM. The two boot tests take about 6 and 17 minutes.

Set a ruleset (or branch protection) on `main`, in the repository's settings:

- Require a pull request before merging.
- Require status checks to pass, and require these: `merge-gate`, `boot-install`, `boot-fallback`. `merge-gate` fails unless every job in the workflow succeeded; naming the boot tests as well keeps them required if someone edits it.
- Require branches to be up to date before merging, so the checks ran on the lock that merges.
- Block force pushes and deletion.
- **Bypass list: empty.** Not the operators, not the account behind `FLAKE_UPDATE_TOKEN`, not an app, and not "Repository admin" as a role that anyone with admin rights inherits.

Under "Require a pull request", ask for no approvals unless you want a second person on every operation: nobody can approve their own pull request, and `avc` waits until someone else has.

Nothing needs a bypass, because `avc` has no push to `main`. Everything it ships (vars and secrets after a provision or a rotation, `topology.nix`, apps, a break-glass fix, a rollback's revert, a lock or library bump) is committed on a branch named `avc/<time>-<subject>`, pushed, and opened as a pull request with auto-merge asked for. It does that as the operator, through the GitHub CLI: run `gh auth login` once, and have write access to the repository. Then it waits for the merge, deploys, and only after that runs its post-actions (restarts, revoking an old credential). If a check fails, the wait is interrupted (Ctrl-C, or an hour without a merge) or `gh` is not there, nothing has reached `main` and the post-actions are kept: `avc deploy ship` picks up from wherever it stopped, whether the pull request is still open or has merged since. Without `gh` it pushes the branch and asks you to open the pull request yourself.

In the repository's settings, turn on "Allow auto-merge" and allow squash merging. `avc` and `flake-update.yml` both ask for a squash.

What that costs: every operation waits for the gate. The two boot tests are built from the lock and the library, not from your vars or apps, so on a runner that keeps its Nix store a pull request that leaves `flake.lock` alone finds them already built and waits for the evaluation and each node's system. One that changes the lock waits for the boot tests too, about 20 minutes. And while the runner is down nothing merges at all. For a fix that cannot wait for that, `avc deploy break-glass <node>` applies the working tree to one node and holds the node there until the pull request has merged. That hold does not survive a reboot.

With those rules auto-merge is safe: GitHub merges a pull request only once the required checks pass, and never on a red or skipped run. `.github/workflows/flake-update.yml` updates the lock on a branch, opens a pull request and asks for auto-merge. It needs a `FLAKE_UPDATE_TOKEN` secret (contents and pull-requests write), not the built-in token, whose pull requests start no workflows; and "Allow auto-merge" turned on. If your project flakes are private, put a read token in a `NIX_ACCESS_TOKENS` secret as `access-tokens = github.com=<token>`. An auto-merge that pushes to `main` itself, or merges without these checks, is exactly the gap this closes: replace it.

**The canary.** One node, `canary = true` in `topology.nix`, takes each new boot stack first: a nixpkgs, kernel, Lanzaboote, clan or library bump. The others build it and wait (`DeployWaitingForCanary` after a day) until the canary has been rebooted into it and unlocked from the TPM on its own. Reboot it with `avc boot reboot <canary>` and watch the console; if it fails to come back, nothing else has the bad stack as its boot entry. If the canary cannot be rebooted, list the closure in `/run/cluster-upgrade.skip-canary` on each node you accept it on. A site of one node needs no canary; a site of more needs one, or `deploy.withoutCanary = "<reason>"`.
