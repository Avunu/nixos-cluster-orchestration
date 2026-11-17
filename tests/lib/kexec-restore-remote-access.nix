# nixos-images' nix/restore-remote-access.nix, less one line.
#
# Upstream's module also sets `boot.initrd.systemd.enable = true`, an option this
# nixpkgs has removed (a systemd initrd is the only kind left), and a definition of a
# removed option fails the evaluation. So tests/install-node.nix builds its kexec
# installer from nixos-images' modules with that file replaced by this one. Nothing else
# differs. Drop this file, and the `disabledModules` beside its import, once nixos-images
# stops setting the option.
{
  boot.initrd.systemd.services.restore-state-from-initrd = {
    unitConfig = {
      DefaultDependencies = false;
      RequiresMountsFor = "/sysroot /dev";
    };
    wantedBy = [ "initrd.target" ];
    requiredBy = [ "rw-etc.service" ];
    before = [ "rw-etc.service" ];
    serviceConfig.Type = "oneshot";
    # Restore ssh host and user keys if they are available.
    # This avoids warnings of unknown ssh keys.
    script = ''
      mkdir -m 700 -p /sysroot/root/.ssh
      mkdir -m 755 -p /sysroot/etc/ssh
      mkdir -m 755 -p /sysroot/root/network
      if [[ -f ssh/authorized_keys ]]; then
        install -m 400 ssh/authorized_keys /sysroot/root/.ssh
      fi
      install -m 400 ssh/ssh_host_* /sysroot/etc/ssh
      cp *.json /sysroot/root/network/
      if [[ -f machine-id ]]; then
        cp machine-id /sysroot/etc/machine-id
      fi
    '';
  };
}
