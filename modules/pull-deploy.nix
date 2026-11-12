# modules/pull-deploy.nix — GitOps pull deployment (steady state).
#
# The "pull" paradigm (rebuild from a GitHub flake ref), run frequently, and applies with `switch` (live) rather than
# `boot`. Each node rebuilds ITSELF from <flakeUrl>#<hostName> on a timer.
#
# Bootstrap is still push (`clan machines install`); this takes over once a node
# is up. Private-repo access (this flake + private flake inputs) comes from a
# github token kept OUT of the Nix store (a nix.conf `!include`).
#
# This loop is why the whole secrets design has to work with NO clan CLI on the
# node: plain `age` decrypts vars in an activation script using the node's existing
# SSH host key (modules/vars.nix), so a switch here needs nothing uploaded.
#
# What a tick does is lib/cluster-upgrade.nix: a closure gets three attempts and then
# waits for a new commit, a closure whose boot contract differs from the running one
# waits for an approval on the node, and it never reboots. The state and the two hand
# controls, both per closure basename, one a line:
#
#   /var/lib/cluster-upgrade/{good,target,attempts}   what the tick last saw
#   /var/lib/cluster-upgrade/refused                  never activate these, across reboots
#   /run/cluster-upgrade.approve                      activate these despite the contract
#
# A node's kernel and initrd are first used at the next reboot, which a human does. So
# the gate is what stands between a topology edit and a node that cannot unlock.
#
# The staged rollout (design D22) is the same problem for what every node shares: a
# nixpkgs, kernel, Lanzaboote, clan or library bump changes no contract, reaches every
# node within the pull interval, and first runs at the next reboot, on all of them. So
# one node, `topology.nodes.<n>.canary = true`, takes each new boot stack first and is
# rebooted into it with someone watching; when that boot unlocked cleanly it publishes
# the stack on /mnt/jfs, and only then do the others activate it. Their profile and
# default boot entry stay on the old stack until then. By hand, per closure and node:
#
#   /run/cluster-upgrade.skip-canary                 activate these without the canary
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  ...
}:
let
  d = topology.deploy;
  host = node.hostName;
  toplevel = "${d.flakeUrl}#nixosConfigurations.${host}.config.system.build.toplevel";

  boot = config.cluster.boot;

  # Every mount a boot waits for (no nofail, no noauto): a new one whose dataset or device
  # the node does not have halts the node at its next reboot (local-fs.target fails, and
  # on a sealed node the emergency shell burns PCR 7), while the closure itself activates
  # and passes every check. disko creates datasets only at install, so a dataset added to
  # the layout later (rpool/loki, WS12) is exactly that. Listed in the contract, so such a
  # closure waits for an approval on each node, after the dataset has been created there.
  requiredMounts = lib.sort lib.lessThan (
    lib.mapAttrsToList (_: fs: "${fs.mountPoint} ${toString fs.device} ${fs.fsType}") (
      lib.filterAttrs (
        _: fs: !(lib.elem "nofail" fs.options) && !(lib.elem "noauto" fs.options)
      ) config.fileSystems
    )
  );

  # ── the staged rollout ─────────────────────────────────────────────────────
  canaries = lib.attrNames (lib.filterAttrs (_: n: n.canary or false) topology.nodes);
  provisioned = lib.attrNames (lib.filterAttrs (_: n: n.provisioned or true) topology.nodes);
  optedOut = n: (topology.nodes.${n}.insecurePlaintextBoot or null) != null;
  withoutCanary = d.withoutCanary or null;
  isReason = r: builtins.isString r && lib.trim r != "";
  role =
    if canaries == [ ] then
      "none"
    else if lib.elem nodeName canaries then
      "canary"
    else
      "follower";
in
{
  imports = [ ./pull-deploy-core.nix ];

  assertions = [
    {
      assertion = lib.length canaries <= 1;
      message = "topology: at most one node may set canary = true; these do: ${toString canaries}.";
    }
    {
      assertion = lib.all (n: lib.elem n provisioned) canaries;
      message = "topology: the canary (${toString canaries}) is a placeholder (provisioned = false). Every other node would wait for a boot that never happens; make a real node the canary.";
    }
    {
      assertion = lib.length provisioned <= 1 || canaries != [ ] || isReason withoutCanary;
      message =
        "topology: a site with more than one node needs a canary. Set `canary = true` on one node: "
        + "it takes each new boot stack (nixpkgs, kernel, Lanzaboote, clan, this library) first, and the others "
        + "activate it only once that node has rebooted into it with a clean unlock (modules/pull-deploy.nix). "
        + "Without one, a bump that cannot boot reaches every node at once. To go without, set "
        + "deploy.withoutCanary = \"<reason>\".";
    }
    {
      assertion = withoutCanary == null || (isReason withoutCanary && canaries == [ ]);
      message = "topology: deploy.withoutCanary must be a non-empty reason, and only on a site with no canary node.";
    }
    {
      # An opted-out canary's boot has no unlock to prove, so it would vouch for a stack whose
      # TPM unlock it never ran.
      assertion = canaries == [ ] || !optedOut (lib.head canaries) || lib.all optedOut provisioned;
      message = "topology: the canary (${toString canaries}) opted out of boot security (insecurePlaintextBoot) while other nodes did not. Its boots cannot prove a TPM unlock; make a node with boot security the canary.";
    }
  ];

  # What a boot is built from, besides the library inputs lib/mk-cluster.nix adds. The
  # nixpkgs this node really evaluates (clan takes the site's, not the library's) and its
  # kernel, which a host file or a site-wide setting can change without any bump. Store
  # paths as plain strings: they name, they do not pull anything into the closure.
  #
  # Each must be the same on every evaluation (lib/mk-cluster.nix says why). `pkgs.path`
  # is not: with lazy trees it can be a virtual store path that differs per evaluation,
  # and discarding its context means nothing ever replaces it with the real one. Copied
  # into the store under a fixed name, it is the content-addressed path of the nixpkgs
  # source, the path the lock's narHash names. Cost: cached by the input's fingerprint
  # under lazy trees; otherwise one NAR hash of the nixpkgs source per evaluation (about
  # 5 s), memoised for every node of it. The kernel's outPath is a derivation
  # output, a function of its .drv, which keeps its context until the .drv is written.
  cluster.deploy.bootStack = {
    nixpkgs = builtins.unsafeDiscardStringContext (
      toString (
        builtins.path {
          path = pkgs.path;
          name = "source";
        }
      )
    );
    kernel = builtins.unsafeDiscardStringContext config.boot.kernelPackages.kernel.outPath;
  };

  cluster.deploy.canary = {
    inherit role;
    markerDir = "${clusterLib.juicefs.mountPoint}/.cluster-deploy/canary-booted";
    markerMount = clusterLib.juicefs.mountPoint;
    requireReport = config.cluster.bootReport.enable;
    # The unlock is what the fleet's next reboots depend on, on every node with boot security.
    requireCleanUnlock = config.cluster.boot.enable;
  };

  # --refresh bypasses the flake tarball cache so a fresh push is picked up within
  # the interval.
  cluster.deploy.targetCommand = "nix build --refresh --no-link --print-out-paths ${lib.escapeShellArg toplevel}";
  cluster.deploy.pullInterval = d.pullInterval;

  # Topology and library settings only, so a nixpkgs or kernel bump does not trip the gate.
  # The authorized keys are a hash so that the contract holds no key material and stays
  # comparable. All of this is read only when the toplevel is built, after the assertions
  # in modules/boot-security.nix have had their say.
  cluster.deploy.bootContract =
    if !boot.enable then
      {
        insecurePlaintextBoot = true;
        inherit requiredMounts;
      }
    else
      {
        inherit requiredMounts;
        luksDevices = lib.mapAttrs (_: device: device.device) config.boot.initrd.luks.devices;
        # What decides how a leg is opened: its crypttab options, where `tpm2-device=auto`
        # makes systemd-cryptsetup try the TPM slot before it asks, and TPM2 support in the
        # initrd. A closure without either builds, activates, and waits at the prompt at its
        # next reboot.
        unlock = {
          tpm2 = config.boot.initrd.systemd.tpm2.enable;
          crypttabExtraOpts = lib.mapAttrs (
            _: device: device.crypttabExtraOpts
          ) config.boot.initrd.luks.devices;
        };
        identityHash = boot.identity.hash;
        # Where the initrd looks for the secret, and where the bootloader install reads the
        # initrd's host key. Both were written once, at install: a new default here would
        # pass every check at build time and halt the node at its next boot (the identity),
        # or leave the next new generation without its host key.
        identityPath = boot.identity.path;
        hostKeyPath = boot.ssh.hostKeyPath;
        inherit (boot) espMounts;
        initrdSshPort = boot.ssh.port;
        wan = {
          inherit (boot.network.wan) interface address4 gateway4;
        };
        initrdKernelModules = boot.network.kernelModules;
        authorizedKeysSha256 = builtins.hashString "sha256" (
          lib.concatStringsSep "\n" (lib.sort lib.lessThan boot.ssh.authorizedKeys)
        );
      };

  # Private GitHub access for `nix build`/`nixos-rebuild` flake fetches. The
  # vars file's CONTENT is a nix.conf line ("access-tokens = github.com=…"), so
  # the token never lands in the store — see the github-token generator in
  # modules/vars.nix.
  #
  # `!include` (not `include`) is deliberate and load-bearing: it makes the file
  # OPTIONAL, so a node whose token has not been generated yet degrades to
  # "public repos only" instead of every single nix command failing to parse its
  # config — which on a pull-deployed fleet would be unrecoverable remotely.
  nix.extraOptions = ''
    !include ${config.clan.core.vars.generators.github-token.files."nix.conf".path}
  '';

  # `access-tokens` above only covers Nix's own `github:` fetcher. A
  # `git+https://` input makes Nix shell out to `git fetch`, which prompts for
  # a username and fails non-interactively — so private git+https inputs need
  # netrc as well. Nix's `netrc-file` setting feeds only Nix's OWN downloader
  # (tarballs, `github:`), never the git subprocess; git reads ~/.netrc through
  # curl. Every flake fetch on a node runs as root — the pull loop and the
  # `nixos-rebuild` a `clan machines update` runs remotely — so root's ~/.netrc
  # is the vars file. A symlink, so the target stays root-only (0400) and the
  # token never sits in a second place; created before any unit that fetches.
  #
  # Verified on node1 (2026-09-21): with only netrc-file set, every private
  # git+https input failed with "could not read Username for
  # 'https://github.com'", and `clan machines update` reported "Failed to fetch
  # git repository" on the remote; with the symlink, 401 -> Basic -> 200.
  nix.settings.netrc-file = config.clan.core.vars.generators.github-token.files."netrc".path;
  systemd.tmpfiles.rules = [
    "L+ /root/.netrc - - - - ${config.clan.core.vars.generators.github-token.files."netrc".path}"
  ];

  systemd.services.cluster-upgrade.description = "Pull + apply cluster config from ${d.flakeUrl}#${host}";

  # We drive `switch` ourselves; make sure the built-in (which can stage for
  # boot) isn't also enabled.
  system.autoUpgrade.enable = lib.mkDefault false;

  # The pull loop is the deployment mechanism; `clan machines update` is
  # break-glass. Requiring the machine to be named explicitly means a bare
  # `clan machines update` (which would otherwise hit the whole fleet) skips
  # these nodes rather than racing the timer on all of them at once.
  clan.core.deployment.requireExplicitUpdate = true;
}
