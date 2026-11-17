# Fresh install to a sealed node, in the order a real node goes through it (README,
# "Installing a node"): the real disko script on the machine's own TPM, with the keys it
# makes on the node; a first boot in Setup Mode that nobody types into, on the TPM slot the
# install left; keys enrolled from the running OS; a boot that enforces them, still on that
# slot; each leg bound to the TPM, sealed to PCR 7, with nothing sent to the node; and then
# boots nobody types into, one of them with the network cable out. On the way, a binding
# that would seal to a PCR 7 someone else can reproduce, or that nothing on the leg and no
# recovery key authorised, is refused. A second generation and another kernel have to keep
# unlocking unattended. Each boot reports how it unlocked, to the real audit Worker on the
# peer VM.
#
# The install through the real installer (nixos-anywhere, `avc boot stage`), the node's age
# identity and a TPM that is not the node's are tests/install-node.nix.
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
  # The boot report goes to the real Worker on the peer VM (report-tpm).
  peerModule = harness.audit.peer;
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
