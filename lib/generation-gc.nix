# lib/generation-gc.nix — the weekly garbage collection, in place of nix.gc.
#
# nix.gc runs `nix-collect-garbage --delete-older-than 14d`, which deletes every system
# generation older than that but the profile's current one and the newest before the
# cutoff. Pull deploys never reboot, so a node routinely runs for weeks booted into a
# generation that is neither: GC deletes its link. Lanzaboote keeps the booted entry on the
# ESP only by finding /run/booted-system among the generation links it is given
# (protectedSystem), so the next bootloader install then drops the one entry that is known
# to boot, and keeps configurationLimit entries nobody has booted. A kernel or initrd
# regression in any of them leaves nothing proven to pick at the console. `avc boot
# rollback` also needs the booted generation in the profile.
#
# So: the system profile's generations older than the cutoff go, except the profile's
# current one and any that is the booted or the running closure. Every other profile gets
# what nix-collect-garbage would have done to it. Then the store is collected.
#
# A function of pkgs, so tests/deploy-safety.nix can run the fleet's own script.
{
  pkgs,
  nix ? pkgs.nix,
  olderThanDays ? 14,
}:
pkgs.writeShellApplication {
  name = "cluster-generation-gc";
  runtimeInputs = [
    nix
    pkgs.coreutils
    pkgs.findutils
    pkgs.gnused
  ];
  text = ''
    days=${toString olderThanDays}
    cutoff=$(( $(date +%s) - days * 86400 ))
    P=/nix/var/nix/profiles/system
    booted=$(readlink -f /run/booted-system || true)
    running=$(readlink -f /run/current-system || true)
    profile_current=$(readlink "$P" || true)

    old=()
    for l in "$P"-*-link; do
      [ -L "$l" ] || continue
      n=''${l#"$P"-}
      n=''${n%-link}
      t=$(readlink -f "$l")
      if [ "''${l##*/}" = "$profile_current" ] || [ "$t" = "$booted" ] || [ "$t" = "$running" ]; then
        continue
      fi
      # stat without -L: the link's own time, which is the generation's.
      [ "$(stat -c %Y "$l")" -lt "$cutoff" ] || continue
      old+=("$n")
    done
    if [ "''${#old[@]}" -gt 0 ]; then
      echo "cluster-generation-gc: deleting system generations ''${old[*]}; keeping the booted ($booted) and running ($running) ones"
      nix-env -p "$P" --delete-generations "''${old[@]}"
    fi

    # Every other profile, as nix-collect-garbage --delete-older-than would.
    others=$(
      for d in /nix/var/nix/profiles /root/.local/state/nix/profiles; do
        if [ -d "$d" ]; then find "$d" -name '*-link' -type l; fi
      done | sed -E 's/-[0-9]+-link$//' | sort -u
    )
    for p in $others; do
      if [ "$p" != "$P" ]; then
        nix-env -p "$p" --delete-generations "''${days}d"
      fi
    done

    nix-store --gc
  '';
}
