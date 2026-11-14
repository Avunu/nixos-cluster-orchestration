# What someone with the disks and the firmware console can do, against a node with its own
# keys enrolled and both legs bound to its TPM: change the unsigned parts of the ESP, read
# everything on it, change what the firmware trusts or clear the TPM, replace the disks with
# their own (keeping a byte copy of the ESP and of each LUKS header), and reach the genuine
# initrd's emergency shell. Appendix O in the design has the mechanics. Each case is a
# copy-on-write overlay of one enrolled node, with copies of its firmware variables and TPM.
{
  pkgs,
  lib,
  diskoModule,
  lanzabooteModule,
  mutant ? "",
  extraModule ? { },
  skipEnroll ? false,
  sealEdit ? null,
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
    name = "boot-attack";
    inherit
      mutant
      extraModule
      skipEnroll
      sealEdit
      ;
    # Many more boots than the other boot tests: the firmware cases, the forged disks and the
    # emergency shells each need their own.
    globalTimeout = 7200;
    # Signed entries an attacker reaches by editing the unsigned loader.conf. The built-in
    # negative controls are among them: each takes out one protection, and its case has to
    # show the attack working without it, or the case with it proves nothing.
    targetModule =
      { lib, ... }:
      let
        initrdService = name: value: { boot.initrd.systemd.services.${name} = value; };
      in
      {
        specialisation = {
          # A read that stalls is not a verdict: 1.3 item 8. The timeout is the unit's 30s.
          stallcheck.configuration = initrdService "volume-identity-check" {
            serviceConfig.ExecStartPre = lib.mkForce "/bin/sleep 120";
          };
          nocheck.configuration = initrdService "volume-identity-check" { enable = lib.mkForce false; };
          noburn.configuration = initrdService "emergency-pcr-burn" { enable = lib.mkForce false; };
          nopurge.configuration = initrdService "initrd-keyring-purge" { enable = lib.mkForce false; };
          # Without the gate the import gives up at about a minute: the quick way to emergency
          # mode on a genuine node.
          nogate.configuration = initrdService "rpool-unlock-gate" { enable = lib.mkForce false; };
          # The same, with a TPM the burn can't reach.
          burnfail.configuration = lib.mkMerge [
            (initrdService "rpool-unlock-gate" { enable = lib.mkForce false; })
            (initrdService "emergency-pcr-burn" {
              environment.TPM2TOOLS_TCTI = lib.mkForce "device:/dev/null";
            })
          ];
          # A failure before tpm2.target that sends the initrd straight to emergency mode, the
          # way systemd's own initrd targets do it (OnFailureJobMode=replace-irreversibly).
          # With `isolate` instead, the isolation stops udev's coldplug, the TPM device never
          # appears, and the boot waits with no burn and no shell: closed, but not this case.
          earlyfail.configuration = initrdService "earlyfail" {
            description = "Fail before the TPM is up";
            unitConfig = {
              DefaultDependencies = false;
              OnFailure = "emergency.target";
              OnFailureJobMode = "replace-irreversibly";
            };
            before = [
              "tpm2.target"
              "sysinit.target"
            ];
            wantedBy = [ "sysinit.target" ];
            serviceConfig = {
              Type = "oneshot";
              ExecStart = "/bin/sh -c 'exit 1'";
            };
          };
        };
      };
    script = builtins.readFile ./boot-attack.py;
  }
