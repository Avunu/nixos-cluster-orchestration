# lib/disk-layout.nix — the plain layout, as a module.
#
# The layout itself is lib/mk-disk-layout.nix. This is the form tests/install-boot.nix
# hands to disko's makeDiskoTest, which installs it into a VM, REBOOTS, and asserts
# the machine comes back. A disk layout that partitions cleanly but produces an
# unbootable system is invisible until you reboot a remote machine with no console,
# so the layout has to be testable on its own.
#
# It therefore takes only `lib` — no `pkgs`, no `node`. makeDiskoTest calls it as
# `f { inherit lib; }` and rewrites `disk.<n>.device` to the VM's /dev/vdX, so
# nothing here may depend on the real device names being real.
{ lib, ... }:
import ./mk-disk-layout.nix {
  inherit lib;
  encrypted = false;
}
