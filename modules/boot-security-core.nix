# modules/boot-security-core.nix — boot security, independent of clan.
#
# The encrypted root's unlock path, and the chain that makes an initrd worth trusting.
# LUKS devices come from the layout (lib/mk-disk-layout.nix); this adds the initrd that
# can open them, reachable over the network, patient with a slow human and not stuck on
# a dead disk, signed by Lanzaboote on both ESPs, and refusing any root filesystem that
# doesn't hold the volume identity secret. Clevis unlocks it unattended, with the TPM
# (PCR 7) and Tang together, over a VLAN that exists only in the initrd. Emergency mode
# burns PCR 7 first, so a shell there can't ask for the key. cluster-boot-seal is how an
# operator binds it, and refuses every binding someone else could reproduce.
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
  haveVlan = options.cluster.boot.tang.vlanId.isDefined;
  haveTangAddress = options.cluster.boot.tang.address.isDefined;
  haveEmergencyHash = options.cluster.boot.emergency.passwordHash.isDefined;
  haveIdentityHash = options.cluster.boot.identity.hash.isDefined;
  haveNicModules = options.cluster.boot.network.kernelModules.isDefined;
  haveTangUrl = options.cluster.boot.tang.url.isDefined;
  haveThumbprints = options.cluster.boot.tang.thumbprints.isDefined;

  vlanIf = "${cfg.network.trunk.interface}.${toString cfg.tang.vlanId}";

  # Shell shared by cluster-boot-seal's `check` and the boot audit: whether one Tang
  # sub-JWE of a Clevis token was bound to an advertisement a pinned key signed. A node
  # nobody rebound after a Tang rotation or reinstall keeps slots for a key that is no
  # longer pinned, and they unlock only while Tang still holds that key: once
  # `tang-keys rotate-finish` deletes it, the next boot waits at the prompt. Nothing on
  # the Tang host can see that, so the node has to.
  #
  # clevis-encrypt-tang stores the advertisement's JWKSet in the sub-JWE's protected
  # header (.clevis.tang.adv), and its verify keys' S256 thumbprints are what
  # cluster.boot.tang.thumbprints pins (verified_thp checks the same at bind). Returns 0
  # pinned, 1 not, 2 the header can't be read. Steps, not one pipeline: the audit runs
  # without pipefail. What it does not do: check the header's signature. It answers "was
  # this bound before the rotation", not "is this binding genuine"; whoever can write a
  # LUKS header has better attacks than a forged one.
  tangPinnedText = ''
    thumbprints=(${lib.escapeShellArgs (if haveThumbprints then cfg.tang.thumbprints else [ ])})
    tang_sub_pinned() {
      local hdr adv ver thps t
      hdr=$(cut -d. -f1 <<<"$1" | jose b64 dec -i-) || return 2
      adv=$(jq -ce '.clevis.tang.adv' <<<"$hdr") || return 2
      ver=$(jose jwk use -i- -r -u verify -o- <<<"$adv") || return 2
      thps=$(jose jwk thp -i- -a S256 <<<"$ver") || return 2
      [ -n "$thps" ] || return 2
      for t in "''${thumbprints[@]}"; do
        if printf '%s\n' "$thps" | grep -qxF -- "$t"; then
          return 0
        fi
      done
      return 1
    }
  '';

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
        pkgs.iproute2
        pkgs.jose
        pkgs.jq
        pkgs.lvm2
        pkgs.util-linux
      ]
    }
    ${tangPinnedText}
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
      ip link show ${vlanIf} >/dev/null 2>&1 && r=1 || r=0
      echo "cluster_tang_vlan_present $r"
      echo "cluster_iommu_groups $(find /sys/kernel/iommu_groups -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
      [ -e /dev/watchdog0 ] && r=1 || r=0
      echo "cluster_watchdog_device $r"
      [ "$(cat /proc/sys/kernel/core_pattern)" = "${import ../lib/core-pattern.nix}" ] && r=1 || r=0
      echo "cluster_core_pattern_ok $r"
      # What the next boot depends on, while there is still time to fix it: a node whose
      # identity secret went missing halts at its next boot, on every generation, and a leg
      # with no Clevis binding holds that boot at the prompt. Nothing else notices either
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
          | jq '[.tokens[] | select(.type == "clevis")] | length') && [ -n "$n" ]; then
          echo "cluster_boot_clevis_tokens{device=\"$d\"} $n"
        fi
        # Slots whose Tang key is no longer pinned; a header that can't be read counts.
        if [ -e "$d" ] && meta=$(cryptsetup luksDump --dump-json-metadata "$d" 2>/dev/null); then
          u=0
          for tok in $(jq -r '.tokens | to_entries[] | select(.value.type=="clevis") | .key' <<<"$meta"); do
            pinned=1
            if jwe=$(cryptsetup token export --token-id "$tok" "$d" 2>/dev/null | jq -c .jwe) \
              && protected=$(jq -r .protected <<<"$jwe" | jose b64 dec -i-) \
              && subs=$(jq -r '.clevis.sss.jwe[]' <<<"$protected"); then
              for sub in $subs; do
                if [ "$(cut -d. -f1 <<<"$sub" | jose b64 dec -i- | jq -r .clevis.pin)" = tang ]; then
                  tang_sub_pinned "$sub" || pinned=0
                fi
              done
            else
              pinned=0
            fi
            [ "$pinned" = 1 ] || u=$((u + 1))
          done
          echo "cluster_boot_clevis_unpinned_tokens{device=\"$d\"} $u"
        fi
      done
    } > "$m/boot_audit.prom.tmp"
    mv "$m/boot_audit.prom.tmp" "$m/boot_audit.prom"
  '';

  # Three fixes to stock clevis. The fleet takes all three; a test that needs one taken
  # out (a mutant, a built-in negative control) asks for exactly that one through
  # system.build.clevisFor, so it removes nothing else.
  #
  # 1. replyFix, required for an unattended unlock. boot.initrd.clevisLuksAskpass
  #    stores ${config.systemd.package}/lib/systemd/systemd-reply-password in the
  #    initrd, but pkgs.clevis hard-codes the path from pkgs.systemd.
  #    config.systemd.package has an `apply` that adds a patch, so the store paths
  #    differ and every recovered passphrase is thrown away.
  # 2. maxTime, required for an unattended unlock. nixpkgs carries only
  #    --connect-timeout 10. A Tang that accepts and goes silent hangs curl forever
  #    without --max-time. --replace-fail on purpose: a nixpkgs change must break the
  #    build, not silently lose the timeout.
  # 3. recoverOnce: one key recovery at Tang per device per boot. Each answer is
  #    pushed to the kernel keyring, the other leg drops its pending question to try
  #    that (wrong) passphrase, and the reply Clevis was about to send it is lost;
  #    stock clevis then recovers the key again. Tang's count of /rec is a signal
  #    (2 on a normal boot), so the askpass keeps what it recovered and answers the
  #    device's next question with it. The patch fails the build if it stops applying.
  clevisFor =
    {
      replyFix ? true,
      maxTime ? true,
      recoverOnce ? true,
    }:
    (if replyFix then pkgs.clevis.override { systemd = config.systemd.package; } else pkgs.clevis)
    .overrideAttrs
      (old: {
        patches = (old.patches or [ ]) ++ lib.optional recoverOnce ./clevis-askpass-recover-once.patch;
        postPatch =
          (old.postPatch or "")
          + lib.optionalString maxTime ''
            substituteInPlace src/pins/tang/clevis-decrypt-tang \
              --replace-fail 'curl --connect-timeout 10' 'curl --connect-timeout 5 --max-time 15'
          '';
      });
  clevisFixed = clevisFor { };

  # A closure whose initrd cannot unlock must fail to build, not fail at the boot that
  # needed it (D16). Every absolute store path the askpass script calls has to be in the
  # initrd: stock clevis names pkgs.systemd's systemd-reply-password, which isn't, and
  # then every key it recovers is thrown away. A function of the package, so that
  # tests/boot-closure.nix can build the negative case directly.
  initrdContentsFor =
    clevis:
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
        script=${clevis}/libexec/.clevis-luks-askpass-wrapped
        [ -s "$script" ] || { echo "MISSING the askpass script itself: $script"; exit 1; }
        bad=0
        for p in $(grep -aoE '/nix/store/[a-z0-9]{32}-[^ "'"'"':;)]+' "$script" | sort -u); do
          grep -qxF "$p" list || { echo "MISSING $p"; bad=$((bad + 1)); }
        done
        [ "$bad" = 0 ]
        echo "every store path the askpass script calls is in the initrd"
        touch $out
      '';

  # cluster-boot-seal, Appendix D of the design: what an operator runs on the node to enroll
  # keys and bind Clevis. Its job is mostly refusing: anything that would seal the disk key
  # to a PCR 7 that someone else can reproduce. Text, so a test can take a control out.
  sealText = ''
    devices=(${lib.escapeShellArgs (lib.mapAttrsToList (_: v: v.device) config.boot.initrd.luks.devices)})
    url=${lib.escapeShellArg (if haveTangUrl then cfg.tang.url else "")}
    ${tangPinnedText}
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

    # Prints the signing thumbprint if the advertisement's signature checks and the key is
    # one we pinned. A 200 from /adv proves nothing, so the signature is what counts. The
    # check has its own `||`: this runs in a command substitution, where errexit is off.
    verified_thp() {
      local adv=$1 keys sig thps t
      keys=$(jose fmt -j- -g payload -y -o- < "$adv")
      sig=$(printf '%s' "$keys" | jose jwk use -i- -r -u verify -o-)
      if ! printf '%s' "$sig" | jose jws ver -i "$adv" -k- -a > /dev/null; then
        echo "refusing: the advertisement's signature does not verify" >&2
        return 1
      fi
      thps=$(printf '%s' "$sig" | jose jwk thp -i- -a S256)
      for t in "''${thumbprints[@]}"; do
        if printf '%s\n' "$thps" | grep -qxF -- "$t"; then
          printf '%s' "$t"
          return 0
        fi
      done
      echo "refusing: advertisement is not signed by a pinned key: $thps" >&2
      return 1
    }

    # The TPM share alone, no Tang needed. `avc boot reboot` refuses on a 1 here. D24 called
    # this advisory because it read as failing on healthy nodes; that was the here-string
    # below, and with printf it reads 0 on a healthy bound node (tests/boot-install.py).
    # Returns: 0 ok, 1 a share failed or a leg is unbound, 3 can't tell (burned), 4 a slot
    # is bound to a Tang key that is no longer pinned (and nothing worse).
    # Every clevis token on every selected device, not just token 0, so a second slot from a
    # disk swap is seen, and a dead leg is skipped rather than fatal.
    check_tpm_share() {
      if [ -e "$burn_marker" ]; then
        echo "BURNED: PCR 7 was burned this boot; the TPM share cannot be checked. Reboot to clear; do not rebind." >&2
        return 3
      fi
      local d tok jwe protected sub pin prc ok=0 n
      for d in "''${selected[@]}"; do
        n=0
        for tok in $(cryptsetup luksDump --dump-json-metadata "$d" \
            | jq -r '.tokens | to_entries[] | select(.value.type=="clevis") | .key'); do
          n=$((n + 1))
          jwe=$(cryptsetup token export --token-id "$tok" "$d" | jq -c .jwe)
          protected=$(jq -r .protected <<<"$jwe" | jose b64 dec -i-)
          for sub in $(jq -r '.clevis.sss.jwe[]' <<<"$protected"); do
            pin=$(cut -d. -f1 <<<"$sub" | jose b64 dec -i- | jq -r .clevis.pin)
            if [ "$pin" = tang ]; then
              prc=0
              tang_sub_pinned "$sub" || prc=$?
              case $prc in
                0) echo "Tang key pinned: $d token $tok" ;;
                1)
                  echo "FAILED: $d token $tok: bound to a Tang key that is not pinned (not in cluster.boot.tang.thumbprints); rebind with --replace" >&2
                  [ "$ok" = 1 ] || ok=4
                  ;;
                *)
                  echo "FAILED: $d token $tok: its Tang share's header can't be read" >&2
                  ok=1
                  ;;
              esac
              continue
            fi
            [ "$pin" = tpm2 ] || continue
            # printf, not <<<: a here-string adds a newline, and clevis decrypt then prints
            # the share and exits 1 anyway, which reads as the TPM refusing (RAN, swtpm).
            if err=$(printf '%s' "$sub" | clevis decrypt 2>&1 > /dev/null); then
              echo "OK: $d token $tok"
            else
              echo "FAILED: $d token $tok: the TPM refused its share: ''${err##*$'\n'}" >&2
              ok=1
            fi
          done
        done
        if [ "$n" = 0 ]; then
          echo "FAILED: $d has no Clevis binding" >&2
          ok=1
        fi
      done
      return "$ok"
    }

    case "''${1:-}" in
      status)
        bootctl status --no-pager 2>/dev/null | grep -E 'Secure Boot|Setup Mode|Current Entry' || true
        echo "PCR 7: $(cat /sys/class/tpm/tpm0/pcr-sha256/7)"
        if [ -e "$burn_marker" ]; then
          echo "PCR 7 BURNED this boot (emergency recovery). Reboot to clear; do not rebind."
        fi
        select_devices
        for d in "''${selected[@]}"; do echo "$d: $(clevis luks list -d "$d" 2>/dev/null || true)"; done
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
        adv=""
        replace=0
        want=""
        while [ $# -gt 0 ]; do
          case "$1" in
            --adv) adv=$2; shift 2 ;;
            --replace) replace=1; shift ;;
            --device) want=$2; shift 2 ;;
            *) echo "unknown argument: $1" >&2; exit 2 ;;
          esac
        done
        if [ -z "$adv" ]; then
          echo "--adv is required: stage 2 has no route to Tang" >&2
          exit 2
        fi
        need_enforcing
        need_unburned
        need_own_authority_only
        need_identity
        select_devices "$want"
        thp=$(verified_thp "$adv")
        # The passphrase comes on stdin, with or without a final newline (clan vars get
        # writes none), and never on the command line.
        pass=""
        IFS= read -r pass || [ -n "$pass" ]
        if [ -z "$pass" ]; then
          echo "refusing: no passphrase on stdin" >&2
          exit 2
        fi
        pin=$(jq -cn --arg u "$url" --arg t "$thp" --arg a "$adv" \
          '{t:2,pins:{tang:[{url:$u,thp:$t,adv:$a}],tpm2:[{pcr_bank:"sha256",pcr_ids:"7"}]}}')
        for d in "''${selected[@]}"; do
          old=""
          if [ "$replace" = 1 ]; then
            old=$(clevis luks list -d "$d" 2>/dev/null | cut -d: -f1 || true)
          elif [ -n "$(clevis luks list -d "$d" 2>/dev/null || true)" ]; then
            echo "refusing: $d is already bound; use --replace, or --device for the other leg" >&2
            exit 1
          fi
          # Bind FIRST, then unbind the old slot, so a bad advertisement loses nothing.
          # Never `clevis luks regen`: it hard-codes -y and drops thp.
          printf %s "$pass" | clevis luks bind -y -k - -d "$d" sss "$pin"
          for s in $old; do clevis luks unbind -f -d "$d" -s "$s"; done
        done
        unset pass
        check_tpm_share
        echo "Bound. Reboot and confirm it unlocks unattended."
        ;;
      check)
        select_devices
        check_tpm_share
        ;;
      # What the next boot's identity check will find. avc boot reboot refuses on a 1.
      identity)
        need_identity
        echo "identity OK"
        ;;
      *)
        echo "usage: cluster-boot-seal status|enroll|bind --adv FILE [--replace] [--device DEV]|check|identity" >&2
        exit 2
        ;;
    esac
  '';

  sealPackageFor =
    text:
    pkgs.writeShellApplication {
      name = "cluster-boot-seal";
      runtimeInputs = [
        cfg.clevisPackage
        config.boot.zfs.package
        config.systemd.package
        pkgs.coreutils
        pkgs.cryptsetup
        pkgs.gawk
        pkgs.gnugrep
        pkgs.jose
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
      trunk.interface = mkOption {
        type = types.str;
        description = "Parent NIC of the Tang VLAN.";
      };
      kernelModules = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "NIC drivers for the initrd. Hardware-specific and not detectable at eval.";
      };
    };

    tang = {
      url = mkOption {
        type = types.str;
        description = "Pin target, used by the seal tool. An IP literal: the initrd has no DNS.";
      };
      thumbprints = mkOption {
        type = types.nonEmptyListOf types.str;
        description = "Signing key thumbprints the seal tool accepts.";
      };
      vlanId = mkOption {
        type = types.int;
        description = "The Tang VLAN, which exists only in the initrd.";
      };
      address = mkOption {
        type = types.str;
        description = "This node's address on the Tang VLAN, in CIDR form.";
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

    clevisPackage = mkOption {
      type = types.package;
      default = clevisFixed;
      defaultText = lib.literalMD "clevis with the systemd and `--max-time` fixes";
      description = "Tests override this with stock clevis to prove the hang.";
    };

    sealPackage = mkOption {
      type = types.package;
      internal = true;
      default = sealPackageFor sealText;
      defaultText = lib.literalMD "`cluster-boot-seal`, built from the configured devices, Tang and identity";
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
        assertion =
          config.boot.initrd.clevisLuksAskpass.enable && config.boot.initrd.clevisLuksAskpass.useTang;
        message = "cluster.boot: boot.initrd.clevisLuksAskpass needs enable and useTang: the unlock is the TPM and Tang together.";
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
        assertion = !haveVlan || builtins.stringLength vlanIf <= 15;
        message = "cluster.boot: <trunk>.<vlanId> is over the kernel's 15 characters for an interface name.";
      }
      {
        # Without these the initrd would have no network and nothing else would say so.
        assertion = haveVlan && haveTangAddress && haveNicModules;
        message = "cluster.boot: tang.vlanId, tang.address and network.kernelModules must be set.";
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
      (initrdContentsFor cfg.clevisPackage)
      (espBudgetFor 1024)
    ];
    system.build = {
      inherit
        clevisFor
        espBudgetFor
        initrdContentsFor
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
      kernelModules = [
        "8021q"
        "dm_crypt"
      ];
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

        # The WAN NIC is how an operator reaches the prompt: /32 and an on-link
        # gateway, like stage 2. The trunk NIC carries only the Tang VLAN here, and
        # vlan-teardown below removes it before stage 2. RequiredForOnline is `no` on the
        # WAN NIC because an unlock must not wait for a network it does not use, and
        # `routable` on the VLAN because Clevis waits for network-online.target.
        network = lib.mkIf (haveVlan && haveTangAddress) {
          enable = true;
          netdevs."20-${vlanIf}" = {
            netdevConfig = {
              Name = vlanIf;
              Kind = "vlan";
            };
            vlanConfig.Id = cfg.tang.vlanId;
          };
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
          # 35, not 40: nixpkgs copies stage 2's `networking.interfaces` into the initrd as
          # 40-<name>, and the first file in sort order matching a link wins.
          networks."35-trunk" = {
            matchConfig.Name = cfg.network.trunk.interface;
            vlan = [ vlanIf ];
            networkConfig.LinkLocalAddressing = "no";
            linkConfig.RequiredForOnline = "carrier";
          };
          networks."50-${vlanIf}" = {
            matchConfig.Name = vlanIf;
            address = [ cfg.tang.address ];
            networkConfig.LinkLocalAddressing = "no";
            linkConfig.RequiredForOnline = "routable";
          };
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

        # flushBeforeStage2 only sets KeepConfiguration=no. A VLAN link that no stage-2
        # .network matches stays up, with its address, into stage 2. So the initrd deletes
        # it, once the root is known good and before anything from the root runs. Without
        # this, "the Tang VLAN exists only in the initrd" is false, and anything on the node
        # could reach Tang.
        services.vlan-teardown = lib.mkIf haveVlan {
          description = "Remove the Tang VLAN before leaving the initrd";
          unitConfig.DefaultDependencies = false;
          after = [
            "volume-identity-check.service"
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
            ExecStart = "/bin/ip link del ${vlanIf}";
          };
        };

        # Under enforcing Secure Boot a failed /sysroot mount lands in emergency mode in the
        # genuine initrd, with PCR 7 intact and Tang reachable. Whoever gets a shell there
        # can ask Clevis for the real disk key, and the emergency password's hash is on the
        # ESP for anyone to crack. So PCR 7 is extended before any shell can start, and the
        # TPM refuses its share for the rest of the boot. The next boot is unattended again.
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

        # A passphrase, typed or recovered by Clevis, is cached as a `user cryptsetup` key in
        # root's keyring, and stays there for about two minutes into stage 2. Nothing in
        # stage 2 needs it. `keyctl purge` searches only the caller's session keyring tree,
        # and a service gets a private session keyring by default, which would make this a
        # silent no-op. KeyringMode=shared links root's user keyring into it.
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

      # Clevis answers the password queries in parallel with the prompt, from tokens in
      # the LUKS headers, so the prompt never waits for it and no JWE sits on the ESP. The
      # binding is the TPM (PCR 7) and Tang together, made by cluster-boot-seal.
      clevisLuksAskpass = {
        enable = true;
        useTang = true;
        package = cfg.clevisPackage;
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
