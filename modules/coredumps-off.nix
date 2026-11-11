# modules/coredumps-off.nix — no process on a node leaves a core dump anywhere.
#
# A core dump is the process's memory: an app's database page cache, a session, a
# decrypted secret. On disk it outlives the process, and in a container it would land
# in the container's directory, which backups and the canary scan both read.
#
# `systemd.coredump.enable = false` is the WRONG fix: nixpkgs then sets the pattern to
# `core`, and the kernel writes `core` into the crashing process's working directory,
# on the host or in a container [RAN in the design's spike; mutant
# `coredump-enable-false` in tests/logging.nix proves the test catches it]. Leaving
# systemd-coredump in place and overriding only the pattern instead means its
# sysctl.d/50-coredump.conf is applied first and our 60-nixos.conf second, so the pipe
# wins; the same file sets fs.suid_dumpable=2, which the setting below takes back.
#
# DefaultLimitCORE=0 is belt and braces, not the control: a root process can raise its
# own limit (CAP_SYS_RESOURCE), and the limit doesn't apply to a pipe anyway. The
# pipe is what makes "nothing" true. Imported by modules/cluster-common.nix.
{ lib, ... }:
{
  boot.kernel.sysctl = {
    "kernel.core_pattern" = lib.mkForce (import ../lib/core-pattern.nix);
    # setuid programs never dump, whatever the pattern.
    "fs.suid_dumpable" = 0;
  };

  systemd.settings.Manager.DefaultLimitCORE = "0";
}
