# lib/esp-sync-hook.nix — keeps the second ESP bootable on an opted-out node.
#
# systemd-boot writes only the primary ESP, so without this the second drive is an
# empty FAT partition and the machine is unbootable the moment the first one dies.
# It is here so that tests/install-boot.nix runs the same text the nodes run.
#
# Both mounts are checked because rsync's --delete does exactly what it says. With /boot
# unmounted it would see an empty directory and erase the surviving ESP, on the one day
# that ESP is all that is left. With /boot-fallback unmounted it would write the boot
# files into the root filesystem, where they look fine and boot nothing.
#
# It warns and carries on rather than failing, as the `|| true` it replaces did. A
# deploy must not stop because a mirror is degraded, and a node on one disk is
# already alerting. Nodes that have not opted out use Lanzaboote's guarded hook, which
# does refuse, because there a missing ESP means a missing signed entry.
{ pkgs }:
''
  if ${pkgs.util-linux}/bin/mountpoint -q /boot && ${pkgs.util-linux}/bin/mountpoint -q /boot-fallback; then
    ${pkgs.rsync}/bin/rsync -a --delete /boot/ /boot-fallback/ \
      || echo "WARN: esp-sync: rsync from /boot to /boot-fallback failed; the second ESP may be stale" >&2
  else
    echo "WARN: esp-sync: /boot and /boot-fallback are not both mounted; second ESP not updated" >&2
  fi
''
