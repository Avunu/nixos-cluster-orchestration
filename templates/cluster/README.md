# My cluster

A private flake on top of [nixos-cluster-orchestration](https://github.com/Avunu/nixos-cluster-orchestration). The library holds the modules; everything specific to this site lives here.

## What goes where

| Path | What it holds |
| --- | --- |
| `flake.nix` | The pinned library, your project flakes, and the `mkCluster` call with the operators' keys |
| `topology.nix` | Nodes, roles, VLANs, object storage, backup target, alert addresses |
| `apps/<name>.nix` or `.json` | One file per app |
| `hosts/<node>.nix` | Optional per-node hardware quirks |
| `secrets/shared/`, `secrets/per-machine/<node>/` | One file per secret, age-encrypted to the operators' master identities, and public values in the clear. Committed |
| `secrets/rekeyed/<node>/` | What `nix run .#agenix -- rekey` made of them for each node: the files a node decrypts with its TPM. Committed with the secret they came from |
| `secrets/recipients/<node>.pub` | Each node's age recipient, from its TPM. `avc boot install` writes it |
| `github-repos.json` | The GitHub repositories this site fetches that `flake.lock` does not name. Written by `avc ci repos`, held to the flake by the merge gate, read by the cluster-ci Worker. Absent when there are none |
| `secrets/identities/<node>.age` | Each node's identity file, a handle to the key in its TPM, encrypted to the operators. A reinstall on the same machine puts it back |

Keep this repository private: it names your addresses and customers, and it holds your encrypted secrets.

## First steps

1. Set the `cluster` input in `flake.nix` to a real commit of the library, then run `nix flake lock`.
2. The operators' keys are two YubiKeys. On each: `age-plugin-yubikey --generate` once, then `age-plugin-yubikey --identity > secrets/master/yubikey-<n>.pub`. That file holds no private key and is committed. Name both in `masterIdentities` in `flake.nix`: every secret is encrypted to both, and either reads them.
3. Put your SSH public keys in `admins` in `flake.nix`. `ed25519-sk` keys (on the same YubiKeys) work everywhere, the initrd included.
4. Replace every example value in `topology.nix`: `deploy.flakeUrl` to this repository's URL, `backup.repoSalt` (`openssl rand -hex 16`), and per node `initrdNicModules`. A node refuses to evaluate until its boot fields are real.
5. `nix develop`, generate the secrets, and install the first node with the library's README, "Installing a node" (S0 to S8), as far as its Secure Boot keys. Nobody types a disk key at any step:

   ```sh
   git add -A                       # flakes only see tracked files
   avc secrets provision            # every machine; prompts for what third parties issue, then
                                    # commits secrets/ on a branch and opens the pull request
   avc secrets check                # every declared secret is generated; nothing is rekeyed yet:
                                    # a node has a recipient once it is installed
   avc boot preflight node1
   avc boot install node1 root@<rescue-address>
                                    # from the provider's rescue system: makes node1's age identity on
                                    # its TPM, rekeys its secrets to it, formats and installs. Each disk
                                    # gets a TPM slot and a slot for the recovery key, which stays in
                                    # this repository as ciphertext. Ships what it wrote under secrets/
   avc boot status node1            # first boot, by itself: Setup Mode, TPM slots not sealed yet
   avc boot enroll node1            # own Secure Boot keys
   avc boot reboot node1            # enforcing, still by itself
   ```

6. Deploy the watchdog Worker, set `alerting.heartbeatUrl` and `alerting.auditUrl` in `topology.nix`, and push its `AUDIT_TOKENS` (`avc audit tokens`). The first sealed boot is next, and its boot report and the `booted (tpm)` email that says S7 worked both go there. Do it the same day: until the bind below, the node's TPM opens its disks for any boot of the machine.
7. Bind and reboot (S6, S7):

   ```sh
   avc boot bind node1              # each leg's TPM slot replaced by one sealed to PCR 7
   avc boot reboot node1            # nobody types; expect the Worker's email
   ```

After that, every node rebuilds itself from `main` on a timer. `avc` is the guided way to do day-to-day operations. It never pushes to `main`: it puts each change on a branch of its own, opens a pull request and waits for it to merge (see "Merging safely"). Run `gh auth login` once so that it can.

## Keep an offline kit

Off the cluster and away from your laptop: the second YubiKey (and the offline age identity, if `extraRecipients` names one), a dated `git bundle create site-<date>.bundle --all` of this repository, and copies of `restic/password`, `juicefs-rsa/rsa.pem` and `juicefs-rsa/rsa-passphrase`, the S3 and backup-target keys (and the state backup target's), and `backup.repoSalt`. No disk secret goes in it: a node's recovery key (`luks/passphrase`) is in the bundle as ciphertext, and `avc secrets reveal <node>:luks/passphrase` with a YubiKey reads it. The library's README, "The offline kit", says what each restores. Refresh the bundle whenever `secrets/` changes. Name a second person who can unlock a node.

## Secrets policy

`secrets/policy.toml` tells `avc secrets rotate` which secrets it may regenerate. The ones bound to disks or data (`luks`, `volume-identity`, `juicefs-rsa`, `restic`) are refused whatever it says (`avc secrets replace` is the one way to a new `juicefs-rsa` or `restic`, after a node left your control: the library's README, Recovery); the ones whose rotation needs both sides of something at once (`nomad-ca`, `nomad-jwt`, `wg-ctrl`, `juicefs-pg`, `juicefs-patroni`) are manual. Never regenerate `luks` or `volume-identity` for an installed node: `avc secrets rotate` and `avc secrets provision` both refuse to. `avc secrets check` says whether a deploy would give every node its secrets, and `avc deploy ship` asks it first.

## Nodes that already run an earlier library

The first deploy of a library version with boot security waits on every such node: its running closure has no boot contract, so the deploy is refused until `/run/cluster-upgrade.approve` on that node lists the new closure's basename (`journalctl -u cluster-upgrade` names it). It has no boot stack either, so every node but the canary also waits until the canary has rebooted into the new closure. Read "Upgrading a running cluster" in the library's README before you deploy it to a live fleet: several changes there are hard cuts.

## Adding an app

Write `apps/<name>.nix`, `git add` it, and run `avc secrets provision`: it generates the app's secrets, rekeys them for the nodes and ships the lot. To give it ingress, create its Cloudflare tunnel and set `tunnel.id`. The library's README has the full steps and the list of kinds.

## GitHub access, deploying on merge, and previews

One GitHub App and its Worker (`workers/cluster-ci` in the library) are all of this site's GitHub access. Set `ci.url` in `topology.nix`; the library's README, "Previews and continuous deployment", has the setup, the security model and what a preview is trusted with.

- **The nodes read this repository through it.** No node holds a GitHub credential that lasts: each asks the Worker and is handed read-only tokens, good for an hour, for this repository, the github.com inputs in `flake.lock` and what `github-repos.json` names. If this repository or any input is private, the Worker has to be up before the first node pulls, and stay up: `GitHubTokenStale` says when a node stops getting answers. `avc ci installations` shows which repositories the App's installations cover.
- **A merge deploys at once**, where without the Worker it waits for the nodes' next timer, and a project's new commits reach this repository's lock when they are pushed, not once a week. `.github/workflows/flake-update.yml` is what the Worker starts when a project's branch moves, so keep its file name, or set the Worker's `FLAKE_UPDATE_WORKFLOW`.
- **A pull request of a project gets a container** of its own on a copy of production: `preview` on an app.

**An app whose project belongs to another organization:** that organization installs the App on the repository, you add the input and the app here and run `avc ci repos`, and after the merge the Worker gives the nodes a token for that repository and no other of theirs. The library's README, "Onboarding an app from another organization".

## Updating the library

Change the `cluster` input's revision and bump nothing else in the same commit. It goes by pull request like every other change (`avc deploy ship` opens one), because nodes apply `main` within minutes: the merge gate below has to pass on it first.

## Merging safely

Every node rebuilds itself from `main` and first runs a new kernel and initrd at its next reboot. So a lock that cannot boot an encrypted node would pass every build, reach every node, and stop them all at their next reboots. Two things stop that: a merge gate, and a canary node.

**The merge gate.** `.github/workflows/merge-gate.yml` builds, at this repository's own `flake.lock`, which is what the nodes run: the library's `boot-install` and `boot-fallback` VM tests (re-exported as `checks.x86_64-linux` in `flake.nix`), a check that this flake's nixpkgs is the library's, a check that `github-repos.json` names what the site fetches from GitHub outside the lock (`avc ci repos` writes it), and every node's system. It needs a self-hosted runner with KVM: Nix with flakes, `/dev/kvm` writable by the runner, `system-features = kvm nixos-test`, and 16 GB of RAM. The two boot tests take about 6 and 17 minutes.

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

With those rules auto-merge is safe: GitHub merges a pull request only once the required checks pass, and never on a red or skipped run. `.github/workflows/flake-update.yml` updates the lock on a branch, opens a pull request and asks for auto-merge. It needs a `FLAKE_UPDATE_TOKEN` secret (contents and pull-requests write), not the built-in token, whose pull requests start no workflows; and "Allow auto-merge" turned on. If your project flakes are private, the runner needs its own read access to them: a `NIX_ACCESS_TOKENS` secret, as `access-tokens = github.com=<token>`. That is the runner's, not a node's; the nodes get theirs from the Worker. An auto-merge that pushes to `main` itself, or merges without these checks, is exactly the gap this closes: replace it.

Every run of `flake-update.yml` moves every input that follows a branch, except those listed in `.github/flake-update-hold` (one per line, with a comment saying why), so a burst of the Worker's dispatches loses no bump. One broken project must not hold up the rest: when `merge-gate` fails on `flake-auto-update`, the workflow opens one pull request per input that moved (`flake-update/<input>`), and each merges on its own gate. An input that fails alone gets an issue, "flake input `<name>` fails the merge gate", and a pull request adding it to the hold file, which a person merges. Remove the line once the input is fixed. The token needs issues write for that.

**The canary.** One node, `canary = true` in `topology.nix`, takes each new boot stack first: a nixpkgs, kernel, Lanzaboote, agenix or library bump. The others build it and wait (`DeployWaitingForCanary` after a day) until the canary has been rebooted into it and unlocked from the TPM on its own. Reboot it with `avc boot reboot <canary>` and watch the console; if it fails to come back, nothing else has the bad stack as its boot entry. If the canary cannot be rebooted, list the closure in `/run/cluster-upgrade.skip-canary` on each node you accept it on. A site of one node needs no canary; a site of more needs one, or `deploy.withoutCanary = "<reason>"`.
