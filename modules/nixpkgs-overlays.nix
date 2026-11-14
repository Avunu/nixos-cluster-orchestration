# modules/nixpkgs-overlays.nix — what this library changes in nixpkgs.
#
# Imported on every host and in every app container (lib/mk-app-container.nix):
# a guest has its own nixpkgs, so the host's overlays do not reach it.
{
  nixpkgs.overlays = [
    # sops-nix's own `sops-install-secrets` (pkgs/sops-install-secrets/default.nix
    # in Mic92/sops-nix) still asks for `buildGo125Module` by name. nixpkgs removed
    # that alias 2026-09-15 ("Go 1.25 is end-of-life"), and sops-nix.inputs.nixpkgs
    # follows ours, so every node's eval broke. Restoring the alias here is the
    # unblock; the real fix is modules/vars.nix's move to secretStore = "age",
    # which stops clan from ever populating `sops.secrets` and so stops sops-nix's
    # setupSecrets activation script from forcing this in the first place. Drop
    # this entry once that migration is complete (sops/ removed) or sops-nix bumps
    # its builder upstream, whichever comes first.
    (final: _prev: {
      buildGo125Module = final.buildGo126Module;
    })

    # WAL-G for MariaDB (modules/db-mariadb.nix). nixpkgs builds only the PostgreSQL
    # command (`main/pg`); the MariaDB one is the same source, another subpackage,
    # with its own version variables. The binary is `wal-g-mysql`.
    #
    # WAL-G calls its MySQL/MariaDB interface unstable. checks.db-archive runs a
    # push, a retention pass and the refusals against this build: run it on every
    # version change.
    (final: _prev: {
      wal-g-mysql = final.wal-g.overrideAttrs (old: {
        pname = "wal-g-mysql";
        subPackages = [ "main/mysql" ];
        ldflags = [
          "-s"
          "-w"
          "-X github.com/wal-g/wal-g/cmd/mysql.walgVersion=${old.version}"
          "-X github.com/wal-g/wal-g/cmd/mysql.gitRevision=${old.src.rev}"
        ];
        # The upstream checks are the PostgreSQL command's.
        doCheck = false;
        doInstallCheck = false;
        postInstall = ''
          mv $out/bin/mysql $out/bin/wal-g-mysql
        '';
        meta = old.meta // {
          mainProgram = "wal-g-mysql";
        };
      });
    })
  ];
}
