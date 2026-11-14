# What happens at the passphrase prompt on an encrypted node: the path every other unlock
# falls back to. On a node bound to the TPM whose firmware has changed: the TPM refuses, and
# the prompt has to be there within seconds, on the serial console, on the first VT and over
# initrd SSH. And on fresh firmware, where the TPM has nothing to give, the node surviving a
# person: slow, wrong, on a different console, or behind a failed boot. Each boot that has
# to be typed through says so in its boot report, and the report counts the initrd SSH
# logins on the way. The disks come from the real disko script (tests/lib/boot-harness.nix).
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
  # The boot report goes to the real Worker on the peer VM (report-passphrase,
  # report-initrd-ssh-logins).
  peerModule = harness.audit.peer;
  targetModule =
    { lib, pkgs, ... }:
    {
      imports = [ harness.audit.target ];
      # Reached by editing the unsigned loader.conf, as an attacker can. Without the gate,
      # zfs-import-rpool fails at about a minute, which is the fast way to emergency mode.
      specialisation.nogate.configuration.boot.initrd.systemd.services.rpool-unlock-gate.enable =
        lib.mkForce false;
      # A stage-2 sshd, so that a login after the initrd can show it is not counted as one
      # during it (report-initrd-ssh-logins).
      services.openssh.enable = true;
      users.users.root.openssh.authorizedKeys.keys = [
        (import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs).snakeOilEd25519PublicKey
      ];
    };
  script = builtins.readFile ./lib/report-helpers.py + builtins.readFile ./boot-fallback.py;
}
