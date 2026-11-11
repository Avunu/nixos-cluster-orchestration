# A private cluster: everything that is yours, on top of the public library.
# See README.md in this directory for what goes where.
{
  description = "My cluster";

  inputs = {
    # Pin the library: every node applies this flake on a timer, so a bump should
    # be one reviewable commit. Replace REV with a commit of the library.
    cluster.url = "github:Avunu/nixos-cluster-orchestration/REV";
    # Build on the nixpkgs the library was tested against.
    nixpkgs.follows = "cluster/nixpkgs";

    # Your project flakes go here, and app files see them as `inputs.<name>`.
    # Follow the library's payload flake so both halves agree on one version:
    #
    # my-odoo-project = {
    #   url = "git+https://github.com/OWNER/my-odoo-project.git?ref=main&submodules=1";
    #   inputs.nixpkgs.follows = "nixpkgs";
    #   inputs.odoo-nix.follows = "cluster/odoo-nix";
    # };
  };

  outputs =
    inputs@{ self, cluster, ... }:
    let
      topology = import ./topology.nix;

      clan = cluster.lib.mkCluster {
        inherit self inputs topology;
        directory = ./.;
        meta = {
          name = "my-cluster";
          domain = "example.com";
        };
        # The operators' age public keys (age-keygen). Anyone listed can decrypt
        # every secret. Replace this example with your own.
        recipients = [ "age1d4xvnzk8ukfgsawg7alhva2lzp9cuztygzwpwdgvgtepzvv44e0qgvt7ar" ];
        # The operators' SSH public keys, for root and `admin` on every node.
        # Replace this example with your own, or you cannot log in.
        admins = [
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBzjhNlT3jB/hrz7YezwFvYss2fpK43h3qX2P2Aj9edN replace-me"
        ];
        appsDir = ./apps;
        hostsDir = ./hosts;
        # Optional:
        #   grafanaDashboards = ./dashboards;   # defaults to the library's
        #   extraModules = [ ./common.nix ];    # imported on every node
      };
    in
    {
      # `nixos-rebuild --flake .#<node>` (the pull loop) and `clan` read these.
      inherit (clan.config) nixosConfigurations clanInternals;

      # What `avc` reads.
      opsIndex = cluster.lib.mkOpsIndex { inherit clan topology; };

      # avc, clan, nomad and friends: `nix develop`, `nix run .#avc`.
      inherit (cluster) packages devShells;

      # What .github/workflows/merge-gate.yml builds before anything reaches `main`. The
      # library's boot tests, re-exported, so they run at THIS flake.lock, which is what
      # the nodes run, not at the library's own. Build one at a time (README.md); a plain
      # `nix flake check` here evaluates every node too.
      checks.x86_64-linux = {
        inherit (cluster.checks.x86_64-linux) boot-install boot-fallback;

        # The boot tests ran on the library's nixpkgs; the nodes build on this flake's
        # (clan takes the site's). They prove the nodes' boot only if those are one source,
        # which `nixpkgs.follows = "cluster/nixpkgs"` above makes them.
        nixpkgs-follows-library =
          inputs.nixpkgs.legacyPackages.x86_64-linux.runCommand "nixpkgs-follows-library" { }
            (
              if inputs.nixpkgs.outPath == cluster.inputs.nixpkgs.outPath then
                "touch $out"
              else
                ''
                  echo "this flake's nixpkgs is not the library's: the boot tests prove a different nixpkgs from the one the nodes build on. Set nixpkgs.follows = \"cluster/nixpkgs\"." >&2
                  exit 1
                ''
            );
      };
    };
}
