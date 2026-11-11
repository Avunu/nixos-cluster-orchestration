# One disk gone, in each way a disk can be gone, and what's left of a node's storage
# promises on the disks it has. Nothing is bound yet, so the surviving leg's passphrase
# is typed once: "unattended" below means that nothing else is asked for. WS4's Clevis
# takes the typing away.
#
# The ESP half: each one boots alone, and the guarded install hook refuses or skips what it
# has to, without writing anywhere it shouldn't. Then two rescues: a damaged volume identity,
# and lost signing keys.
#
# The blocker this exists for: a present disk that can never open must not take the
# whole mirror down. The first design of the gate hung forever on one.
{
  pkgs,
  lib,
  diskoModule,
  lanzabooteModule,
  mutant ? "",
  extraModule ? { },
}:
(import ./lib/boot-harness.nix {
  inherit
    pkgs
    lib
    diskoModule
    lanzabooteModule
    ;
}).mkTest
  {
    name = "boot-degraded";
    inherit mutant extraModule;
    # A second generation that is on the node's disk already, so nothing has to be copied in
    # for a test to install one. The same kernel and initrd, a different closure.
    targetModule.specialisation.newgen.configuration.environment.etc."test-newgen".text = "2";
    script = builtins.readFile ./boot-degraded.py;
  }
