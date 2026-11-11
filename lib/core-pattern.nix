# lib/core-pattern.nix — where the kernel sends a core dump on every node: nowhere.
#
# A pipe to a program that reads nothing and exits. Set by modules/coredumps-off.nix
# and compared by the boot audit (`cluster_core_pattern_ok`, modules/boot-security-core
# .nix); one literal so the two cannot drift apart.
#
# A pipe helper runs in the host's initial namespaces, so the pattern also covers
# every container: a container cannot point its own dumps anywhere else, because the
# pattern is global and /proc/sys is read-only inside it. The helper path doesn't
# exist in the initrd, where the kernel then writes nothing either.
"|/run/current-system/sw/bin/false"
