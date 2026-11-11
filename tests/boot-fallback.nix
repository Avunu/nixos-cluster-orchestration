# What happens at the passphrase prompt on an encrypted node: the path every other unlock
# falls back to. On a node bound to Tang and the TPM: Tang refusing, dropping, or accepting
# and then never answering, which has to leave the prompt there at once and, for the last,
# recover by itself once Tang heals. And on fresh firmware, where the TPM has nothing to give,
# the node surviving a person: slow, wrong, on a different console, or behind a failed boot.
# Each boot that has to be typed through says so in its boot report, and the report counts
# the initrd SSH logins on the way. The disks come from the real disko script
# (tests/lib/boot-harness.nix).
{
  pkgs,
  lib,
  diskoModule,
  lanzabooteModule,
  mutant ? "",
  extraModule ? { },
}:
let
  harness = import ./lib/boot-harness.nix {
    inherit
      pkgs
      lib
      diskoModule
      lanzabooteModule
      ;
  };
in
harness.mkTest {
  name = "boot-fallback";
  inherit mutant extraModule;
  globalTimeout = 5400;
  # The boot report goes to the real Worker on the tang VM (report-passphrase,
  # report-initrd-ssh-logins).
  tangModule = harness.audit.tang;
  targetModule =
    { lib, pkgs, ... }:
    {
      imports = [ harness.audit.target ];
      # Reached by editing the unsigned loader.conf, as an attacker can. Without the gate,
      # zfs-import-rpool fails at about a minute, which is the fast way to emergency mode.
      specialisation.nogate.configuration.boot.initrd.systemd.services.rpool-unlock-gate.enable =
        lib.mkForce false;
      # The built-in negative control for the tarpit: the fleet's clevis without --max-time,
      # as nixpkgs ships it, and with the other fixes, so that it can unlock at all. Above
      # mkForce, so that it holds under a mutant that forces the package for the whole node.
      specialisation.stockclevis.configuration =
        { config, ... }:
        {
          cluster.boot.clevisPackage = lib.mkOverride 40 (config.system.build.clevisFor { maxTime = false; });
        };
      # A stage-2 sshd, so that a login after the initrd can show it is not counted as one
      # during it (report-initrd-ssh-logins).
      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [
        (import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs).snakeOilEd25519PublicKey
      ];
    };
  script = builtins.readFile ./lib/report-helpers.py + builtins.readFile ./boot-fallback.py;
}
