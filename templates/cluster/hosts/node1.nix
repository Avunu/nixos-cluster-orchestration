# Per-node hardware quirks. Optional: a node without a file here is fine. Disk
# layout, bootloader and ZFS policy come from the library (modules/zfs-host.nix).
#
# NIC drivers for the initrd do not go here: they are topology data
# (`nodes.<n>.initrdNicModules`), because the boot contract depends on them.
{ ... }:
{
}
