# modules/boot-security-core.nix — boot security, independent of clan.
#
# The encrypted root's unlock path, and the chain that makes an initrd worth trusting.
# LUKS devices come from the layout (lib/mk-disk-layout.nix); this adds the initrd that
# can open them, reachable over the network, patient with a slow human and not stuck on
# a dead disk, signed by Lanzaboote on both ESPs, and refusing any root filesystem that
# doesn't hold the volume identity secret. Each leg opens unattended from a TPM2 slot in
# its own LUKS header, sealed to PCR 7, and asks for the passphrase when the TPM refuses.
# Emergency mode burns PCR 7 first, so a shell there can't ask the TPM for the key.
# cluster-boot-seal is how an operator binds it, and refuses every binding someone else
# could reproduce.
#
# Written this way round so boot behaviour stays testable without clan: the boot
# VM tests import this module directly with literal values, and
# modules/boot-security.nix supplies vars and topology on a real node.
{
  config,
  lib,
  options,
  pkgs,
  utils,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.cluster.boot;

  # Values modules/boot-security.nix leaves undefined until they exist. Reading one
  # that is undefined throws a missing-option error, which would bury the refusal
  # that tells a new site what to do, so anything an assertion can reach asks first.
  haveEmergencyHash = options.cluster.boot.emergency.passwordHash.isDefined;
  haveIdentityHash = options.cluster.boot.identity.hash.isDefined;
  haveNicModules = options.cluster.boot.network.kernelModules.isDefined;

  # The crypttab option that makes systemd-cryptsetup wait for the TPM, rather than ask
  # for the passphrase because the TPM's driver had not loaded yet.
  # lib/mk-disk-layout.nix sets it on every leg.
  tpmOption = "tpm2-device=auto";

  legs = lib.mapAttrsToList (name: v: {
    inherit name;
    inherit (v) device;
  }) config.boot.initrd.luks.devices;

  # `systemd-cryptsetup@crypt\x2da.service`: the leg's own unit, escaped as systemd
  # generates it from the crypttab name.
  cryptsetupUnit = name: "systemd-cryptsetup@${lib.replaceStrings [ "-" ] [ "\\x2d" ] name}.service";

  # Runs when the root dataset is mounted, before nixos-install. On the root dataset
  # because that is the only placement that runs once and with the root mounted: a
  # hook on the pool itself wraps every leaf mount. Store paths directly, because the
  # disko script's closure is what reaches the installer.
  #
  # Idempotent, since `disko --mode mount` re-runs this on a reinstall that doesn't
  # format. An installer without these secrets must not produce a node: without the
  # host key its first bootloader install fails, and the identity check would refuse the
  # root on the first boot.
  #
  # The signing keys are made here, on the node, and never leave it (D7). sbctl's own
  # config is what points it into the new root. --disable-landlock because its sandbox
  # has no idea about /mnt, and that form is the one known to work in an installer.
  installRoot = config.disko.rootMountPoint;
  diskoHook = ''
    place() { # src dst mode
      if [ ! -e "${installRoot}$2" ]; then
        [ -s "$1" ] || { echo "disko-hook: $1 missing; refusing to install" >&2; exit 1; }
        ${pkgs.coreutils}/bin/install -D -m "$3" "$1" "${installRoot}$2"
      fi
    }
    place ${lib.escapeShellArg cfg.install.identitySecretFile} ${lib.escapeShellArg cfg.identity.path} 0400
    place ${lib.escapeShellArg cfg.install.hostKeyFile} ${lib.escapeShellArg cfg.ssh.hostKeyPath} 0400
    if [ ! -e "${installRoot}${cfg.pkiBundle}/keys" ]; then
      printf 'keydir: %s/keys\nguid: %s/GUID\n' "${installRoot}${cfg.pkiBundle}" "${installRoot}${cfg.pkiBundle}" > /tmp/sbctl.conf
      ${pkgs.sbctl}/bin/sbctl --disable-landlock --config /tmp/sbctl.conf create-keys \
        || { echo "disko-hook: sbctl create-keys failed; refusing to install" >&2; exit 1; }
    fi
  '';

  # Upstream's hook writes to whatever is at /boot, so with the ESP unmounted it fills the
  # root filesystem and reports success. So this replaces it, and goes through two passes.
  #
  # The first decides, before any ESP changes: an unmounted ESP is skipped with a warning
  # (that is what keeps a node with a dead disk deployable), none mounted is a refusal, and
  # too little room is a refusal, since ENOSPC part way leaves a stale .tmp holding all the
  # remaining space and never reaches the next ESP. Only then does the second pass install.
  # So a refusal never leaves one ESP ahead of the other.
  #
  # `need` is twice the current kernel and initrd, which is a floor and no promise: lzbt
  # installs before it collects garbage, so a full-size generation has to fit alongside
  # whatever is already there. check-esp-budget below is what sizes the partition.
  #
  # Compare with lzbt's own hook at every Lanzaboote bump (D9). tests/boot-degraded.py's
  # esp-* subtests are what catch a drift.
  lz = config.boot.lanzaboote;
  guardedHook = pkgs.writeShellScript "lzbt-guarded" ''
    PATH=${config.systemd.package}/lib/systemd:${pkgs.util-linux}/bin:${pkgs.coreutils}/bin:${pkgs.findutils}/bin:$PATH
    top=$(readlink -f /nix/var/nix/profiles/system)
    need=$(( 2 * ( $(stat -Lc %s "$top/kernel") + $(stat -Lc %s "$top/initrd") ) ))
    mounted=()
    for esp in ${lib.escapeShellArgs cfg.espMounts}; do
      if ! mountpoint -q "$esp"; then
        echo "lzbt-guard: WARNING: $esp is not a mountpoint, skipping it" >&2
        continue
      fi
      # lzbt names them <file>..tmp, next to the file they would become.
      find "$esp/EFI" "$esp/loader" -maxdepth 2 -name '*.tmp' -delete 2>/dev/null || true
      # Lanzaboote's stub packs these into the running initrd with no hash check, so a
      # signed boot must never leave them on an ESP it owns. A tripwire for drift:
      # systemd.import_credentials=no in the signed command line is the real control.
      if [ -d "$esp/loader/credentials" ] || compgen -G "$esp/EFI/Linux/*.extra" >/dev/null 2>&1; then
        echo "lzbt-guard: $esp carries loader/credentials or an *.extra companion dir; refusing" >&2
        exit 1
      fi
      avail=$(df --output=avail -B1 "$esp" | tail -n 1 | tr -d ' ')
      if [ "$avail" -lt "$need" ]; then
        echo "lzbt-guard: $esp has $avail bytes free, need $need; refusing" >&2
        exit 1
      fi
      mounted+=("$esp")
    done
    if [ "''${#mounted[@]}" = 0 ]; then
      echo "lzbt-guard: no ESP is mounted, refusing" >&2
      exit 1
    fi
    for esp in "''${mounted[@]}"; do
      ${lz.installCommand} \
        --public-key=${toString lz.publicKeyFile} \
        --private-key=${toString lz.privateKeyFile} \
        ${lib.optionalString (lz.protectedSystem != null) "--protected-system=${lz.protectedSystem}"} \
        "$esp" /nix/var/nix/profiles/system-*-link || exit 1
    done
  '';

  # A closure too big for the ESP should fail to build rather than fail at the boot that
  # needed it. lzbt installs before it collects garbage, so the peak is limit + 2 distinct
  # generations. 1024 MiB is the encrypted layout's ESP (lib/mk-disk-layout.nix, D8).
  # A function, so that tests/boot-closure.nix can prove this fails.
  espBudgetFor =
    espMiB:
    pkgs.runCommand "check-esp-budget" { } ''
      k=$(stat -Lc %s ${config.boot.kernelPackages.kernel}/${config.system.boot.loader.kernelFile})
      i=$(stat -Lc %s ${config.system.build.initialRamdisk}/initrd)
      total=$(( (k + i + 262144) * (${toString cfg.configurationLimit} + 2) + 1048576 ))
      echo "peak $((total / 1048576)) MiB of ${toString espMiB} MiB"
      [ "$total" -lt $(( ${toString espMiB} * 1048576 )) ]
      touch $out
    '';

  # What cluster-boot-audit runs. Text, so a test can take a control out of it.
  #
  # Anything that can't be read counts as bad. This feeds an alert, and an audit that reads
  # nothing must not report a clean pool.
  auditText = ''
    set -u
    export PATH=${
      lib.makeBinPath [
        config.boot.zfs.package
        pkgs.coreutils
        pkgs.cryptsetup
        pkgs.findutils
        pkgs.gawk
        pkgs.gnugrep
        pkgs.jq
        pkgs.lvm2
        pkgs.util-linux
      ]
    }
    bad=0
    # -P, not -L: with -L the paths become /dev/dm-N and it false-alarms. A leg that is gone
    # shows up by its GUID, so it isn't counted: a DEGRADED pool isn't a plaintext one.
    if vdevs=$(zpool list -vHP rpool); then
      for v in $(printf '%s\n' "$vdevs" | awk '$1 ~ /^\// {print $1}'); do
        case "$v" in
          /dev/mapper/crypt-*)
            # A name proves nothing: the mapping must really be dm-crypt.
            dmsetup table "$(basename "$v")" | grep -q ' crypt ' || bad=$((bad + 1))
            ;;
          *) bad=$((bad + 1)) ;;
        esac
      done
    else
      bad=$((bad + 1))
    fi
    m=/var/lib/prometheus-node-exporter-text
    mkdir -p "$m"
    {
      echo "cluster_zpool_plain_vdevs $bad"
      for e in ${lib.escapeShellArgs cfg.espMounts}; do
        mountpoint -q "$e" && r=1 || r=0
        echo "cluster_esp_mounted{esp=\"$e\"} $r"
      done
      echo "cluster_iommu_groups $(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
      [ -e /dev/watchdog0 ] && r=1 || r=0
      echo "cluster_watchdog_device $r"
      [ "$(cat /proc/sys/kernel/core_pattern)" = "${import ../lib/core-pattern.nix}" ] && r=1 || r=0
      echo "cluster_core_pattern_ok $r"
      # What the next boot depends on, while there is still time to fix it: a node whose
      # identity secret went missing halts at its next boot, on every generation, and a leg
      # with no TPM binding holds that boot at the prompt. Nothing else notices either
      # before the reboot. A leg that is absent is the DEGRADED pool's alert, not this one.
      f=${lib.escapeShellArg cfg.identity.path}
      if [ -f "$f" ] && [ ! -L "$f" ] \
        && [ "$(sha256sum < "$f" | cut -d' ' -f1)" = ${lib.escapeShellArg (if haveIdentityHash then cfg.identity.hash else "")} ]; then
        r=1
      else
        r=0
      fi
      echo "cluster_volume_identity_ok $r"
      for d in ${lib.escapeShellArgs (lib.mapAttrsToList (_: v: v.device) config.boot.initrd.luks.devices)}; do
        if [ -e "$d" ] && n=$(cryptsetup luksDump --dump-json-metadata "$d" 2>/dev/null \
          | jq '[.tokens[] | select(.type == "systemd-tpm2")] | length') && [ -n "$n" ]; then
          echo "cluster_boot_tpm_tokens{device=\"$d\"} $n"
        fi
      done
    } > "$m/boot_audit.prom.tmp"
    mv "$m/boot_audit.prom.tmp" "$m/boot_audit.prom"
  '';

  # A closure whose initrd cannot unlock unattended must fail to build, not fail at the boot
  # that needed it (D16). systemd-cryptsetup opens a leg through libcryptsetup's token
  # plugin, which loads the TPM libraries at run time, so nothing but the initrd's own file
  # list says they are there. The plugin's path is also the one whose log line the boot
  # report counts (modules/boot-report.py). In system.build, so that tests/boot-closure.nix
  # can build the negative case directly.
  initrdContents =
    pkgs.runCommand "check-initrd-contents"
      {
        nativeBuildInputs = [
          pkgs.zstd
          pkgs.cpio
          pkgs.gnugrep
          pkgs.gnused
        ];
      }
      ''
        f=${config.system.build.initialRamdisk}/initrd
        zstd -dc "$f" | cpio -t --quiet 2>/dev/null | sed 's|^\./||; s|^|/|' > list
        bad=0
        for want in \
          /lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so \
          /lib/libtss2-esys.so \
          /lib/libtss2-tcti-device.so; do
          grep -qF -- "$want" list || { echo "MISSING $want"; bad=$((bad + 1)); }
        done
        [ "$bad" = 0 ]
        echo "the initrd holds the TPM token plugin and the libraries it loads"
        touch $out
      '';

  # cluster-boot-seal, Appendix D of the design: what an operator runs on the node to enroll
  # keys and bind each leg to the TPM. Its job is mostly refusing: anything that would seal
  # the disk key to a PCR 7 that someone else can reproduce. Text, so a test can take a
  # control out.
  sealText = ''
    devices=(${lib.escapeShellArgs (lib.mapAttrsToList (_: v: v.device) config.boot.initrd.luks.devices)})
    identity_path=${lib.escapeShellArg cfg.identity.path}
    identity_hash=${lib.escapeShellArg (if haveIdentityHash then cfg.identity.hash else "")}
    burn_marker=/run/cluster-boot/pcr7-burned
    db_cert=${lib.escapeShellArg "${cfg.pkiBundle}/keys/db/db.pem"}
    event_log=/sys/kernel/security/tpm0/binary_bios_measurements
    pcr7_file=/sys/class/tpm/tpm0/pcr-sha256/7

    efi_flag() {
      local f="/sys/firmware/efi/efivars/$1-8be4df61-93ca-11d2-aa0d-00e098032b8c"
      if [ -e "$f" ]; then od -An -tu1 -j4 -N1 "$f" | tr -d ' '; else echo -1; fi
    }

    need_enforcing() {
      local sb sm
      sb=$(efi_flag SecureBoot)
      sm=$(efi_flag SetupMode)
      if [ "$sb" != 1 ] || [ "$sm" != 0 ]; then
        echo "refusing: SecureBoot=$sb SetupMode=$sm. Binding here seals to a PCR 7 anyone can reproduce." >&2
        exit 1
      fi
    }

    need_identity() {
      if [ ! -f "$identity_path" ] || [ -L "$identity_path" ]; then
        echo "refusing: no identity file" >&2
        exit 1
      fi
      if [ "$(sha256sum < "$identity_path" | cut -d' ' -f1)" != "$identity_hash" ]; then
        echo "refusing: identity file does not match the configured hash" >&2
        exit 1
      fi
    }

    # Emergency mode extended PCR 7 for this boot (emergency-pcr-burn writes the marker, and
    # /run survives switch-root). A seal taken now binds to the burned value: it passes its
    # own check, fails every normal boot, and is released by any later burn. So refuse.
    need_unburned() {
      if [ -e "$burn_marker" ]; then
        echo "refusing: PCR 7 was burned this boot (the node went through emergency mode). The binding is fine; reboot, then retry." >&2
        exit 1
      fi
    }

    # --device DEV, else every configured leg that is really LUKS, with a loud warning for
    # the rest. A node with one dead leg must still rebind and check its survivor, so this
    # is never all-or-nothing.
    selected=()
    select_devices() {
      local want=''${1:-} d
      selected=()
      for d in "''${devices[@]}"; do
        if [ -n "$want" ] && [ "$d" != "$want" ]; then continue; fi
        if [ -e "$d" ] && cryptsetup isLuks "$d" 2>/dev/null; then
          selected+=("$d")
        else
          echo "WARNING: $d is absent or not LUKS, skipping it. The pool is degraded." >&2
        fi
      done
      if [ "''${#selected[@]}" = 0 ]; then
        echo "refusing: no usable LUKS device" >&2
        exit 1
      fi
    }

    # Under enforcing Secure Boot the firmware logs into PCR 7, once per boot, each db entry
    # that let an image run (EDK2's measure-once rule). If something other than this node's
    # own cert was logged first, say an option ROM signed by the Microsoft UEFI CA on a node
    # enrolled with --microsoft, then any other binary that entry lets run adds nothing new
    # to PCR 7. If it runs unsigned code, that code can extend PCR 7 with our cert's event,
    # which anyone can compute from the public db, and reach the genuine value without our
    # initrd ever running. So a seal is only taken when the event log shows this node's cert
    # as the only certificate authority in PCR 7. An image allowed by its own hash (sbctl
    # --tpm-eventlog enrolls option ROMs that way) lets only that image run, so a hash entry
    # is accepted. The log has to replay to the PCR 7 the TPM holds, or it describes
    # something else. A log that can't be read or parsed is a refusal, not a pass.
    need_own_authority_only() {
      local yaml own replayed="" actual kind value data subject seen=0 foreign=()
      if ! yaml=$(tpm2_eventlog "$event_log" 2>&1); then
        echo "refusing: cannot read the TPM event log ($event_log): nothing says which Secure Boot authorities PCR 7 holds. ''${yaml##*$'\n'}" >&2
        exit 1
      fi
      if ! own=$(openssl x509 -in "$db_cert" -outform DER | od -An -v -tx1 | tr -d ' \n') || [ -z "$own" ]; then
        echo "refusing: cannot read this node's db certificate ($db_cert)" >&2
        exit 1
      fi
      # tpm2_eventlog prints an authority's VariableData as hex: a 16-byte SignatureOwner,
      # then the certificate (or the hash) that matched.
      while read -r kind value; do
        case "$kind" in
          AUTH)
            data=''${value:32}
            if [ "$data" = "$own" ]; then
              seen=1
            elif [ "''${#data}" != 64 ]; then
              subject=$(printf '%s' "$data" | tr a-f A-F | basenc --base16 -d 2>/dev/null \
                | openssl x509 -inform DER -noout -subject 2>/dev/null) || subject="an entry that is not a certificate"
              foreign+=("$subject")
            fi
            ;;
          PCR7) replayed=$value ;;
        esac
      done < <(printf '%s\n' "$yaml" | awk '
        /^- EventNum:/ { pcr = ""; type = "" }
        /^  PCRIndex:/ { pcr = $2 }
        /^  EventType:/ { type = $2 }
        /^    VariableData:/ && pcr == "7" && type == "EV_EFI_VARIABLE_AUTHORITY" { gsub(/"/, "", $2); print "AUTH", $2 }
        /^pcrs:/ { inpcrs = 1; next }
        inpcrs && /^  [A-Za-z0-9_]+:/ { bank = $1; next }
        inpcrs && bank == "sha256:" && $1 == "7" { v = $3; sub(/^0x/, "", v); print "PCR7", tolower(v) }
      ')
      actual=$(tr A-F a-f < "$pcr7_file" | tr -d ' \n')
      if [ "$replayed" != "$actual" ]; then
        echo "refusing: the TPM event log replays PCR 7 to '$replayed', and the TPM holds $actual: the log can't say what PCR 7 holds" >&2
        exit 1
      fi
      if [ "''${#foreign[@]}" != 0 ]; then
        printf 'PCR 7 records a Secure Boot authority other than this node'"'"'s own: %s\n' "''${foreign[@]}" >&2
        echo "refusing: whatever else that authority lets run can replay PCR 7 to this value. Enroll with cluster-boot-seal enroll (--tpm-eventlog, not --microsoft), or find what loads under it." >&2
        exit 1
      fi
      if [ "$seen" != 1 ]; then
        echo "refusing: the event log does not show this node's db certificate verifying the boot path" >&2
        exit 1
      fi
    }

    # How many TPM slots a leg's header holds.
    tpm_tokens() {
      cryptsetup luksDump --dump-json-metadata "$1" \
        | jq '[.tokens[] | select(.type == "systemd-tpm2")] | length'
    }

    # Whether a leg's TPM slot opens now: the unseal the next boot's initrd does, against
    # this boot's PCR 7. Nothing is activated, and stdin is closed so it can never turn
    # into a passphrase question. The token plugin is systemd's, and cryptsetup finds it
    # only through the library path.
    tpm_opens() {
      LD_LIBRARY_PATH=${config.systemd.package}/lib/cryptsetup \
        cryptsetup open --test-passphrase --token-only --token-type systemd-tpm2 "$1" 2>&1 < /dev/null
    }

    # `avc boot reboot` refuses on a 1 here. Returns: 0 every selected leg's TPM slot
    # opens, 1 one does not or a leg is unbound, 3 can't tell (burned). A dead leg was
    # skipped by select_devices rather than being fatal.
    check_tpm() {
      if [ -e "$burn_marker" ]; then
        echo "BURNED: PCR 7 was burned this boot; the TPM binding cannot be checked. Reboot to clear; do not rebind." >&2
        return 3
      fi
      local d n err ok=0
      for d in "''${selected[@]}"; do
        if ! n=$(tpm_tokens "$d"); then
          echo "FAILED: $d: its LUKS header can't be read" >&2
          ok=1
        elif [ "$n" = 0 ]; then
          echo "FAILED: $d has no TPM binding" >&2
          ok=1
        elif err=$(tpm_opens "$d"); then
          echo "OK: $d"
        else
          echo "FAILED: $d: its TPM slot does not open: ''${err%%$'\n'*}" >&2
          ok=1
        fi
      done
      return "$ok"
    }

    # One new TPM slot on a leg, sealed to this boot's PCR 7. The passphrase goes in on
    # stdin and never on a command line. With --wipe-slot the new slot is written first
    # and the leg's other TPM slots are removed after it, so a failure loses nothing.
    tpm_enroll() { # device [--wipe-slot=tpm2]
      printf %s "$pass" | systemd-cryptenroll --unlock-key-file=/dev/stdin \
        --tpm2-device=auto --tpm2-pcrs=7 "''${@:2}" "$1"
    }

    case "''${1:-}" in
      status)
        bootctl status --no-pager 2>/dev/null | grep -E 'Secure Boot|Setup Mode|Current Entry' || true
        echo "PCR 7: $(cat /sys/class/tpm/tpm0/pcr-sha256/7)"
        if [ -e "$burn_marker" ]; then
          echo "PCR 7 BURNED this boot (emergency recovery). Reboot to clear; do not rebind."
        fi
        select_devices
        for d in "''${selected[@]}"; do echo "$d: $(tpm_tokens "$d" 2>/dev/null || echo unreadable) TPM slot(s)"; done
        need_identity
        echo "identity OK"
        zpool status rpool | grep -E 'state:|crypt-' || true
        ;;
      enroll)
        if [ "$(efi_flag SetupMode)" != 1 ]; then
          echo "refusing: firmware is not in Setup Mode" >&2
          exit 1
        fi
        sbctl verify 2>&1 | grep -v 'is signed' | grep -v 'kernel-.*\.efi' || true
        # Option ROMs this boot measured go in db by hash, and nothing else. With Microsoft's
        # CA in db, a ROM it signed is logged in PCR 7 before our cert, and bind then refuses
        # (need_own_authority_only).
        sbctl enroll-keys ${if cfg.enrollMicrosoftKeys then "--microsoft" else "--tpm-eventlog"}
        echo "Now reboot, and unlock by hand once."
        ;;
      bind)
        shift
        replace=0
        want=""
        while [ $# -gt 0 ]; do
          case "$1" in
            --replace) replace=1; shift ;;
            --device) want=$2; shift 2 ;;
            *) echo "unknown argument: $1" >&2; exit 2 ;;
          esac
        done
        need_enforcing
        need_unburned
        need_own_authority_only
        need_identity
        select_devices "$want"
        # Every leg is looked at before any is touched, so a refusal changes nothing.
        if [ "$replace" != 1 ]; then
          for d in "''${selected[@]}"; do
            if [ "$(tpm_tokens "$d")" != 0 ]; then
              echo "refusing: $d is already bound; use --replace, or --device for the other leg" >&2
              exit 1
            fi
          done
        fi
        # The passphrase comes on stdin, with or without a final newline (clan vars get
        # writes none), and never on the command line.
        pass=""
        IFS= read -r pass || true
        if [ -z "$pass" ]; then
          echo "refusing: no passphrase on stdin" >&2
          exit 2
        fi
        for d in "''${selected[@]}"; do
          if [ "$replace" = 1 ]; then
            tpm_enroll "$d" --wipe-slot=tpm2
            # systemd-cryptenroll leaves a slot alone when its policy names the PCR 7 value
            # this boot has. One that still does not open (a replaced TPM, say) is worth
            # nothing, so it goes, and the leg gets a fresh one.
            if ! tpm_opens "$d" > /dev/null; then
              systemd-cryptenroll --wipe-slot=tpm2 "$d"
              tpm_enroll "$d"
            fi
          else
            tpm_enroll "$d"
          fi
        done
        unset pass
        check_tpm
        echo "Bound. Reboot and confirm it unlocks unattended."
        ;;
      check)
        select_devices
        check_tpm
        ;;
      # What the next boot's identity check will find. avc boot reboot refuses on a 1.
      identity)
        need_identity
        echo "identity OK"
        ;;
      *)
        echo "usage: cluster-boot-seal status|enroll|bind [--replace] [--device DEV]|check|identity" >&2
        exit 2
        ;;
    esac
  '';

  sealPackageFor =
    text:
    pkgs.writeShellApplication {
      name = "cluster-boot-seal";
      runtimeInputs = [
        config.boot.zfs.package
        config.systemd.package
        pkgs.coreutils
        pkgs.cryptsetup
        pkgs.gawk
        pkgs.gnugrep
        pkgs.jq
        pkgs.openssl
        pkgs.sbctl
        pkgs.tpm2-tools
        pkgs.util-linux
      ];
      inherit text;
    };
in
{
  options.cluster.boot = {
    enable = lib.mkEnableOption "boot security. Only modules/boot-security.nix sets this";

    espMounts = mkOption {
      type = types.nonEmptyListOf types.str;
      default = [
        "/boot"
        "/boot-fallback"
      ];
      description = "The ESPs. The first is efiSysMountPoint; the rest are extraEfiSysMountPoints.";
    };

    configurationLimit = mkOption {
      type = types.ints.between 2 5;
      default = 5;
      description = ''
        Generations kept on the ESP. This bounds only what stays on the ESP: a signed generation
        anyone copied off it still passes PCR 7 when put back, for as long as the Secure Boot
        signing keys are the same. Retiring a generation for good (an initrd authorized key
        removed, a fix to the boot path) needs new signing keys and a rebind.
      '';
    };

    pkiBundle = mkOption {
      type = types.str;
      default = "/var/lib/sbctl";
      description = "Secure Boot signing keys, on the encrypted root.";
    };

    enrollMicrosoftKeys = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether `cluster-boot-seal enroll` puts Microsoft's keys in db (`sbctl --microsoft`)
        rather than only the option ROMs this boot measured, by hash (`--tpm-eventlog`).
        Bind refuses either way when PCR 7 records an authority other than this node's own
        cert, so with Microsoft's CA enrolled and an option ROM it signed, the node can't
        be bound at all. Turning this on is a written risk acceptance: it lets
        Microsoft-signed software (a provider's rescue image, a revoked shim missing from
        dbx) run under Secure Boot on this node.
      '';
    };

    identity = {
      hash = mkOption {
        type = types.strMatching "[0-9a-f]{64}";
        description = "sha256 of the volume identity secret. Compiled into the signed initrd.";
      };
      path = mkOption {
        type = types.str;
        default = "/var/lib/volume-identity/secret";
        description = "Where the secret lives on the root dataset.";
      };
    };

    emergency.passwordHash = mkOption {
      type = types.str;
      description = "crypt(3) hash for boot.initrd.systemd.emergencyAccess.";
    };

    ssh = {
      port = mkOption {
        type = types.port;
        default = 2222;
        description = "Initrd sshd. Not 22, so the initrd host key never collides with the stage-2 one in known_hosts.";
      };
      hostKeyPath = mkOption {
        type = types.str;
        default = "/var/lib/initrd-ssh/ssh_host_ed25519_key";
        description = "Read by the bootloader installer at every new generation, so it must exist on the root.";
      };
      authorizedKeys = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "Operators' SSH public keys.";
      };
    };

    network = {
      wan = {
        interface = mkOption {
          type = types.str;
          description = "Public NIC.";
        };
        address4 = mkOption {
          type = types.str;
          description = "Public address, as a /32 with an on-link gateway, like stage 2.";
        };
        gateway4 = mkOption {
          type = types.str;
          description = "On-link gateway for address4.";
        };
      };
      kernelModules = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "NIC drivers for the initrd. Hardware-specific and not detectable at eval.";
      };
    };

    install = {
      identitySecretFile = mkOption {
        type = types.str;
        description = "Where the disko hook reads the volume identity secret from.";
      };
      hostKeyFile = mkOption {
        type = types.str;
        description = "Where the disko hook reads the initrd SSH host key from.";
      };
    };

    sealPackage = mkOption {
      type = types.package;
      internal = true;
      default = sealPackageFor sealText;
      defaultText = lib.literalMD "`cluster-boot-seal`, built from the configured devices and identity";
      description = "The seal tool. Internal: a test mutant replaces it to take one refusal out.";
    };

    iommuParams = mkOption {
      type = types.listOf types.str;
      default = [
        "intel_iommu=on"
        "iommu.passthrough=0"
        "iommu.strict=1"
      ];
      description = "Hardware may need board-specific values and a BIOS switch.";
    };
  };

  config = lib.mkIf cfg.enable {
    # Held here for whoever imports this module, including the boot tests, as well as
    # in modules/boot-security.nix. Those are the fleet's posture, and word it for a
    # person running a site. tests/security-policy.nix holds both sets.
    assertions = [
      {
        assertion = lib.all (d: lib.elem tpmOption d.crypttabExtraOpts) (
          lib.attrValues config.boot.initrd.luks.devices
        );
        message = "cluster.boot: every LUKS device needs ${tpmOption} in its crypttab options, or a leg can ask for the passphrase before the TPM is there to answer.";
      }
      {
        assertion = config.boot.initrd.systemd.tpm2.enable;
        message = "cluster.boot: boot.initrd.systemd.tpm2.enable must stay on: the initrd opens each leg from its TPM slot.";
      }
      {
        assertion = config.boot.lanzaboote.enable;
        message = "cluster.boot: boot.lanzaboote.enable must stay on: no Secure Boot, no PCR 7 to seal to.";
      }
      {
        assertion =
          builtins.length (lib.attrNames config.boot.initrd.luks.devices) >= 2
          && lib.all (lib.hasPrefix "crypt-") (lib.attrNames config.boot.initrd.luks.devices);
        message = "cluster.boot: needs at least two LUKS devices, each named crypt-*.";
      }
      {
        assertion = config.boot.zfs.devNodes == "/dev/mapper";
        message = "cluster.boot: zfs must scan only /dev/mapper, or a plaintext pool on the raw partitions can be imported.";
      }
      {
        assertion = lib.all (s: s.randomEncryption.enable) config.swapDevices;
        message = "cluster.boot: every swap device needs randomEncryption.";
      }
      {
        # An empty string is a password field that takes no password.
        assertion =
          !haveEmergencyHash
          || (
            builtins.isString config.boot.initrd.systemd.emergencyAccess
            && lib.hasPrefix "$" config.boot.initrd.systemd.emergencyAccess
          );
        message = "cluster.boot: initrd emergencyAccess has to be a crypt(3) hash.";
      }
      {
        assertion = !config.boot.loader.systemd-boot.editor;
        message = "cluster.boot: the boot menu's editor grants root through init=/bin/sh, so it stays off.";
      }
      {
        assertion = !config.boot.loader.efi.canTouchEfiVariables;
        message = "cluster.boot: no NVRAM writes from the bootloader install.";
      }
      {
        assertion = config.boot.initrd.network.flushBeforeStage2;
        message = "cluster.boot: flushBeforeStage2 has to stay on, or initrd addresses reach stage 2.";
      }
      {
        # Without these the initrd would have no network and nothing else would say so.
        assertion = haveNicModules;
        message = "cluster.boot: network.kernelModules must be set.";
      }
    ];

    # ── bootloader ──────────────────────────────────────────────────────────
    # Not touching the NVRAM is what makes an ESP on either disk bootable by its removable
    # path, with nothing stale in the firmware's boot order. Lanzaboote reads the editor
    # setting for its loader.conf, and timeout 0 shows the menu only on a key press.
    boot.lanzaboote = {
      enable = true;
      inherit (cfg) pkiBundle configurationLimit;
      extraEfiSysMountPoints = lib.tail cfg.espMounts;
    };
    boot.loader = {
      grub.enable = false;
      systemd-boot.enable = false;
      systemd-boot.editor = false;
      efi.canTouchEfiVariables = false;
      efi.efiSysMountPoint = lib.head cfg.espMounts;
      timeout = 0;
      # Initrd SSH's host key is an initrd secret.
      supportsInitrdSecrets = true;
      external.installHook = lib.mkForce guardedHook;
    };
    environment.etc."sbctl/sbctl.conf".text = ''
      keydir: ${cfg.pkiBundle}/keys
      guid: ${cfg.pkiBundle}/GUID
    '';
    environment.systemPackages = [
      pkgs.sbctl
      cfg.sealPackage
    ];

    # Build gates: a closure that could not unlock, or would not fit the ESP, fails to build
    # on the node and in CI, so a pull deploy never activates it (D16).
    system.checks = [
      initrdContents
      (espBudgetFor 1024)
    ];
    system.build = {
      inherit
        espBudgetFor
        initrdContents
        auditText
        sealText
        sealPackageFor
        ;
    };

    # ── storage ─────────────────────────────────────────────────────────────
    # Only opened dm-crypt mappings are candidates. A plaintext forged pool on the raw
    # partitions is not even scanned. Degraded import works through this in both
    # directions (D12), which is why it isn't by-id.
    boot.zfs.devNodes = "/dev/mapper";

    # ── initrd ──────────────────────────────────────────────────────────────
    # systemd.import_credentials=no closes Lanzaboote's unverified path for ESP
    # companion files into the initrd. noresume stops the hibernate-resume generator
    # reading an EFI variable anyone with the disk can write, before anything has
    # checked the root. Random-key swap already rules out a valid resume image; this
    # is at no cost. Both are in the signed command line, where loader.conf, which is
    # unsigned, cannot drop them.
    boot.kernelParams = cfg.iommuParams ++ [
      "systemd.import_credentials=no"
      "noresume"
    ];

    boot.initrd = {
      kernelModules = [ "dm_crypt" ];
      availableKernelModules = [
        "tpm_tis"
        "tpm_crb"
        "aesni_intel"
        "cryptd"
        "vfat"
        "nls_cp437"
        "nls_iso8859_1"
      ]
      ++ lib.optionals haveNicModules cfg.network.kernelModules;

      systemd = {
        # Hashed, and never `true`. The alternative, no shell at all, is D3.
        emergencyAccess = lib.mkIf haveEmergencyHash cfg.emergency.passwordHash;
        tpm2.enable = true;
        initrdBin = [ pkgs.iproute2 ];
        storePaths = [
          "${pkgs.tpm2-tools}/bin/tpm2_pcrextend"
          "${pkgs.keyutils}/bin/keyctl"
        ];

        # Inside the signed initrd, and never through boot.initrd.secrets: rotating one of
        # those reaches only the next new generation, and a missing file fails every new
        # generation. A public hash needs neither. The secret itself is on the root, which
        # is the point.
        contents."/etc/volume-identity.sha256" = lib.mkIf haveIdentityHash {
          text = cfg.identity.hash + "\n";
        };

        # The WAN NIC is how an operator reaches the prompt: /32 and an on-link gateway,
        # like stage 2. Nothing in the unlock uses the network, so nothing waits for it.
        network = {
          enable = true;
          networks."30-wan" = {
            matchConfig.Name = cfg.network.wan.interface;
            address = [ "${cfg.network.wan.address4}/32" ];
            routes = [
              {
                Gateway = cfg.network.wan.gateway4;
                GatewayOnLink = true;
              }
            ];
            networkConfig.LinkLocalAddressing = "no";
            linkConfig.RequiredForOnline = "no";
          };
        };

        # systemd-cryptsetup says nothing at its usual log level when a TPM slot opens a
        # leg: "Volume <name> activated with a LUKS token." is a debug line, and it is the
        # one modules/boot-report.py counts. Debug costs about 200 journal lines a leg per
        # boot, and none of them holds the passphrase (tests/boot-fallback.py looks).
        services."systemd-cryptsetup@" = {
          overrideStrategy = "asDropin";
          environment.SYSTEMD_LOG_LEVEL = "debug";
        };

        # nixpkgs' import loops 60s, tries once more, then exits 1, and is not ordered
        # after cryptsetup. So without this a human has about a minute from power-on,
        # and a mistyped passphrase can lose the race and import the pool DEGRADED.
        #
        # A leg holds the import only while its unit could still produce the mapping:
        #   - `failed`: it never will (bad header, not LUKS, I/O error), so give it up.
        #     tries=0 means a wrong passphrase never gets here.
        #   - `activating`: it is asking for a passphrase, or trying one. Wait, for as
        #     long as that takes.
        #   - anything else, past the deadline: the unit never started. Its device did
        #     not appear within x-systemd.device-timeout, so its job failed by
        #     dependency, which leaves it `inactive` rather than `failed`.
        # One bad leg must never take the mirror down with it: on the node it would be
        # an outage nobody can type their way out of.
        services.rpool-unlock-gate = {
          description = "Wait for every LUKS leg of rpool that can still open";
          unitConfig.DefaultDependencies = false;
          before = [ "zfs-import-rpool.service" ];
          requiredBy = [ "zfs-import-rpool.service" ];
          conflicts = [ "shutdown.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            TimeoutStartSec = "infinity";
          };
          script = ''
            deadline=$(($(date +%s) + 30))
            while :; do
              pending=0
              ${lib.concatMapStrings (l: ''
                if [ ! -e /dev/mapper/${l.name} ]; then
                  case "$(systemctl show -p ActiveState --value "${cryptsetupUnit l.name}")" in
                    failed) ;;
                    activating|active|reloading) pending=1 ;;
                    *) [ "$(date +%s)" -ge "$deadline" ] || pending=1 ;;
                  esac
                fi
              '') legs}
              [ "$pending" = 0 ] && break
              sleep 1
            done
          '';
        };

        # Anyone with the disks can rebuild them, with the same LUKS UUIDs, pool GUID and
        # labels, and a byte copy of the ESP. Secure Boot then happily boots the genuine
        # initrd on a forged root. What they don't have is the secret on the real root, so
        # this looks for it before anything comes from that root: initrd-root-fs.target
        # gates initrd-parse-etc, the /sysroot/nix mount and initrd-find-nixos-closure, and
        # initrd-nixos-activation exec's prepare-root from /sysroot while still in the
        # initrd, with the initrd's keys and network. So "before switch-root" would be too
        # late, which is why the ordering is what it is. Initrd binaries only.
        #
        # Only a verdict halts. A timeout or an I/O error isn't "this is the wrong disk", so
        # the unit has no FailureAction, and a read that fails for any other reason exits 1:
        # that fails initrd-root-fs.target and lands in emergency mode, with SSH recovery
        # still up. The check is what refuses a symlink, a FIFO or the wrong size before it
        # hashes anything, so a FIFO can't hang it either.
        services.volume-identity-check = {
          description = "Refuse a root filesystem that does not hold the volume identity secret";
          unitConfig = {
            DefaultDependencies = false;
            RequiresMountsFor = "/sysroot";
          };
          after = [ "sysroot.mount" ];
          requires = [ "sysroot.mount" ];
          before = [
            "initrd-root-fs.target"
            "initrd-parse-etc.service"
            "initrd-find-nixos-closure.service"
            "initrd-nixos-activation.service"
            "initrd-switch-root.target"
          ];
          requiredBy = [ "initrd-root-fs.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            TimeoutStartSec = "30s";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
          script = ''
            set -o pipefail
            f="/sysroot${cfg.identity.path}"
            want="$(cut -d' ' -f1 /etc/volume-identity.sha256)"
            refuse() { # a definite "wrong disk" verdict: halt
              echo "volume-identity: MISMATCH ($1). Refusing to boot this root." > /dev/console
              echo "volume-identity: MISMATCH ($1). Refusing to boot this root."
              sleep 1
              systemctl halt --force --force
              exit 1
            }
            # stat does not follow a symlink, so a symlinked secret reports "symbolic link",
            # and a FIFO reports "fifo". Only a missing file is a verdict here; an unreadable
            # one (I/O error) is not.
            if ! st="$(stat -c '%F:%s' -- "$f" 2>&1)"; then
              case "$st" in
                *"No such file"*) refuse "secret missing" ;;
                *) echo "volume-identity: UNREADABLE ($st). Not a verdict; failing to emergency."; exit 1 ;;
              esac
            fi
            [ "$st" = "regular file:64" ] || refuse "wrong type or size: $st"
            got="$(sha256sum < "$f" | cut -d' ' -f1)" \
              || { echo "volume-identity: UNREADABLE (read failed). Not a verdict; failing to emergency."; exit 1; }
            [ "$got" = "$want" ] && { echo "volume-identity: OK"; exit 0; }
            refuse "hash differs"
          '';
        };

        # A leg given up on stays `failed` through switch-root, in stage 2, as a unit
        # stage 2 has never heard of. That is the one state a pull deploy reads as a bad
        # closure, on a node whose only problem is a disk (lib/cluster-upgrade.nix). The
        # DEGRADED pool is what says so, and it says it for every way of losing a leg.
        services.forget-given-up-legs = {
          description = "Do not carry failed cryptsetup units into stage 2";
          unitConfig.DefaultDependencies = false;
          after = [ "initrd-fs.target" ];
          before = [
            "initrd.target"
            "initrd-cleanup.service"
          ];
          wantedBy = [ "initrd.target" ];
          serviceConfig.Type = "oneshot";
          script = "systemctl reset-failed 'systemd-cryptsetup@*.service'";
        };

        # Under enforcing Secure Boot a failed /sysroot mount lands in emergency mode in the
        # genuine initrd, with PCR 7 intact. Whoever gets a shell there can ask the TPM for
        # the real disk key, and the emergency password's hash is on the ESP for anyone to
        # crack. So PCR 7 is extended before any shell can start, and the TPM refuses to
        # unseal for the rest of the boot. The next boot is unattended again.
        #
        # requiredBy, so a burn that fails (no TPM to reach) keeps the local shell from
        # starting: recovery is then initrd SSH, which stays up. wants as well as after,
        # because emergency mode isolates, and a failure early enough not to have pulled in
        # the TPM's chain must still pull it in. The marker in /run outlives switch-root, so
        # stage 2 and cluster-boot-seal know the binding only looks broken this boot, and
        # must not be resealed to the burned value.
        services.emergency-pcr-burn = {
          description = "Extend PCR 7 so the TPM refuses to unseal for the rest of this boot";
          unitConfig.DefaultDependencies = false;
          wants = [
            "systemd-modules-load.service"
            "tpm2.target"
          ];
          after = [
            "systemd-modules-load.service"
            "tpm2.target"
          ];
          before = [
            "emergency.service"
            "rescue.service"
          ];
          requiredBy = [
            "emergency.service"
            "rescue.service"
          ];
          environment.TPM2TOOLS_TCTI = "device:/dev/tpmrm0";
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            TimeoutStartSec = "30s";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
          script = ''
            i=0
            while [ ! -e /dev/tpmrm0 ] && [ "$i" -lt 20 ]; do sleep 1; i=$((i + 1)); done
            ${pkgs.tpm2-tools}/bin/tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
            mkdir -p /run/cluster-boot
            : > /run/cluster-boot/pcr7-burned
            echo "emergency-pcr-burn: PCR 7 burned for this boot"
          '';
        };

        # A typed passphrase is cached as a `user cryptsetup` key in root's keyring, which is
        # how one answer opens both legs, and it stays there for about two minutes into
        # stage 2. Nothing in stage 2 needs it. `keyctl purge` searches only the caller's
        # session keyring tree, and a service gets a private session keyring by default,
        # which would make this a silent no-op. KeyringMode=shared links root's user keyring
        # into it.
        services.initrd-keyring-purge = {
          description = "Remove the cached LUKS passphrase from root's keyring";
          unitConfig.DefaultDependencies = false;
          after = [
            "cryptsetup.target"
            "initrd-fs.target"
          ];
          before = [
            "initrd.target"
            "initrd-cleanup.service"
          ];
          wantedBy = [ "initrd.target" ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            KeyringMode = "shared";
          };
          script = "${pkgs.keyutils}/bin/keyctl purge user cryptsetup || true";
        };
      };

      network = {
        enable = true;
        flushBeforeStage2 = true;
        ssh = {
          enable = true;
          inherit (cfg.ssh) port authorizedKeys;
          hostKeys = [ cfg.ssh.hostKeyPath ];
        };
      };
    };

    disko.devices.zpool.rpool.datasets.root.postMountHook = diskoHook;

    # ── swap ────────────────────────────────────────────────────────────────
    # A random-key swap device gets its mapping from a oneshot service nixpkgs generates,
    # and with its disk gone that service fails. nofail covers the swap unit and not the
    # service, so a node on one good disk would carry a failed unit, every switch would
    # report it, and a pull deploy would count every closure as failed on an otherwise
    # healthy node. This leaves the swap device's own job to time out quietly under nofail.
    systemd.services =
      lib.listToAttrs (
        map (
          sw:
          lib.nameValuePair "mkswap-${sw.deviceName}" {
            unitConfig.ConditionPathExists = sw.device;
          }
        ) (lib.filter (sw: sw.randomEncryption.enable) config.swapDevices)
      )
      // {
        # nixpkgs points this unit at the ESP with SYSTEMD_ESP_PATH
        # (nixos/modules/system/boot/loader/efi.nix), and bootctl takes a path given that way
        # without checking it is an ESP at all. The ESPs are nofail, so local-fs.target, all
        # the unit waits for, does not wait for their mounts: started while /boot was still
        # being mounted, it wrote loader/random-seed into the root under the mountpoint
        # (boot-degraded, esp-unmounted-guard), and on a node whose first ESP is gone it did
        # so every boot. So it waits for that mount's job, done or failed, and runs only if the
        # ESP is mounted then. It writes the first ESP only; the second needs nothing here.
        systemd-boot-random-seed = {
          after = [ "${utils.escapeSystemdPath (lib.head cfg.espMounts)}.mount" ];
          unitConfig.ConditionPathIsMountPoint = lib.head cfg.espMounts;
        };
        cluster-boot-audit = {
          description = "Audit boot security state (metrics)";
          serviceConfig = {
            Type = "oneshot";
            ExecStart = pkgs.writeShellScript "cluster-boot-audit" auditText;
          };
        };
      };
    systemd.timers.cluster-boot-audit = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = "5min";
      };
    };
  };
}
