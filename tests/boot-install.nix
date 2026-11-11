# Fresh install to a sealed node, in the order a real node goes through it (section 2 of the
# design, S2 to S7): the real disko script with the keys it makes on the node, a first boot in
# Setup Mode, keys enrolled from the running OS, a boot that enforces them, Clevis bound with a
# delivered advertisement, and then boots nobody types into. On the way, every binding that
# would seal to a PCR 7 someone else can reproduce, or trust an unpinned Tang, is refused. A
# second generation and another kernel have to keep unlocking unattended. Each boot reports
# how it unlocked, to the real audit Worker on the tang VM.
{
  pkgs,
  lib,
  diskoModule,
  lanzabooteModule,
  mutant ? "",
  extraModule ? { },
  sealEdit ? null,
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
  name = "boot-install";
  inherit mutant extraModule sealEdit;
  # The boot report goes to the real Worker on the tang VM (report-clevis).
  tangModule = harness.audit.tang;
  targetModule =
    { lib, pkgs, ... }:
    {
      imports = [ harness.audit.target ];
      # On the node's disk already, so a deploy needs nothing copied in.
      specialisation.newgen.configuration.environment.etc."test-newgen".text = "2";
      # Another signed kernel and initrd, reached through the unsigned loader.conf.
      specialisation.kernelupdate.configuration.boot.kernelPackages = lib.mkForce pkgs.linuxPackages_6_12;
    };
  script = builtins.readFile ./lib/report-helpers.py + builtins.readFile ./boot-install.py;
}
