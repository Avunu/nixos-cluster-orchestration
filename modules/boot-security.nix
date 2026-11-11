# modules/boot-security.nix — what a node must be, and the one way out of it.
#
# A node either carries a reason in `topology.nodes.<n>.insecurePlaintextBoot`, or
# its evaluation fails unless the RESULTING configuration has LUKS under the pool,
# Lanzaboote, Clevis and the rest. The assertions below read results, not intent,
# so a host file that swaps `disko.devices` for a plain layout or forces
# `boot.lanzaboote.enable = false` fails too. tests/security-policy.nix proves each
# of them, one forced control at a time.
#
# This is fail-closed by construction: a new site that fills in nothing fails, and
# says what to do. They are assertions rather than `throw`s because `clan vars
# generate` evaluates the machine to discover its generators, before any of the
# values below can exist (lib/mk-app-container.nix documents the same rule). A
# throw would stop a new site from ever generating them. Assertions fire only when
# the toplevel is forced.
#
# The behaviour that satisfies them lives in modules/boot-security-core.nix. The
# assertions stay here as well as in the core: this is the fleet's posture, which
# must hold however the core is staged, and the boot VM tests import the core with
# states this module would refuse (their specialisations, to begin with).
{
  config,
  lib,
  pkgs,
  topology,
  node,
  nodeName,
  clusterLib,
  clusterSite,
  ...
}:
let
  optOut = node.insecurePlaintextBoot or null;
  optedOut = optOut != null;
  fleetKeysAck = topology.insecureFleetKeysOnPlaintextDisk or null;

  gens = config.clan.core.vars.generators;
  security = topology.security or { };
  tang = security.tang or { };
  tangIp = node.tangIp or null;
  tangSubnet = tang.subnet or null;
  nicModules = node.initrdNicModules or [ ];

  # Every refusal names the way out, so a new site is never left guessing. Each
  # message's first sentence is unique: tests/security-policy.nix matches on it, so
  # a test cannot pass because some other assertion failed.
  refuseUnless = assertion: what: {
    inherit assertion;
    message =
      "boot security: node ${nodeName}: ${what}\n"
      + "A node that may hold plaintext instead sets"
      + " topology.nodes.${nodeName}.insecurePlaintextBoot = \"<reason>\".";
  };

  # ── address checks ────────────────────────────────────────────────────────
  # clusterLib's arithmetic assumes well-formed input, and these fields come from a
  # hand-written topology. No leading zeros, because lib.toInt refuses them.
  octet = "(0|[1-9][0-9]{0,2})";
  isIp4 =
    s:
    let
      m =
        if builtins.isString s then builtins.match "${octet}\\.${octet}\\.${octet}\\.${octet}" s else null;
    in
    m != null && lib.all (o: lib.toInt o <= 255) m;
  isCidr4 =
    s:
    let
      m = if builtins.isString s then builtins.match "([^/]+)/(0|[1-9][0-9]?)" s else null;
    in
    m != null && isIp4 (builtins.head m) && lib.toInt (lib.last m) <= 32;
  # Exactly http://<ipv4>:<port>. The port is not optional: the Tang socket is not on
  # 80 in anything this repo ships, and a URL that fell back to 80 would only show up
  # as an unlock that cannot reach Tang.
  tangUrlIsIpLiteral =
    let
      m =
        if builtins.isString (tang.url or null) then
          builtins.match "http://([^/:]+):([1-9][0-9]{0,4})" tang.url
        else
          null;
    in
    m != null && isIp4 (builtins.head m) && lib.toInt (lib.last m) <= 65535;

  # What the Tang VLAN must not collide with. Its addresses are routed only in the
  # initrd, so an overlap would not show up as a stage-2 failure: it would show up
  # as an unlock that cannot reach Tang, or as Tang traffic going somewhere else.
  otherSubnets = lib.filter isCidr4 (
    lib.mapAttrsToList (_: v: v.subnet or null) (topology.vlans or { })
    ++ [
      (topology.mesh.subnet or null)
      (topology.privateServices or null)
    ]
  );

  # ── disk layout ───────────────────────────────────────────────────────────
  # Each disk's own content plus each of its partitions' content: a pool leg can be
  # a whole disk as easily as a partition.
  layoutContents = lib.concatMap (
    disk:
    let
      content = disk.content or null;
    in
    lib.optional (content != null) content
    ++ lib.filter (c: c != null) (
      map (p: p.content or null) (lib.attrValues (content.partitions or { }))
    )
  ) (lib.attrValues config.disko.devices.disk);
  plainZfsLegs = lib.filter (c: c.type or null == "zfs") layoutContents;
  luksZfsLegs = lib.filter (
    c: c.type or null == "luks" && ((c.content or null).type or null) == "zfs"
  ) layoutContents;

  luksNames = lib.attrNames config.boot.initrd.luks.devices;
  emergencyAccess = config.boot.initrd.systemd.emergencyAccess;

  # ── accounts raw_exec could run as ────────────────────────────────────────
  # Nomad's denied_host_uids is 0-4095,4097-65535. It cannot be widened:
  # 0-4095,4097-4294967294 OOM-panics the agent, because idset.Parse materialises
  # the range. A raw_exec task names its account, and Nomad only checks that account
  # against those ranges, so the gap above 65535 is closed here instead: no account
  # that a task could name can exist in it, and uid 4096 is nomad-apps' alone.
  #
  # Not part of the boot opt-out. raw_exec's lockdown runs in a VM as well as
  # anywhere, so it holds on every node.
  badUidAccounts = lib.filter (
    u: u.uid != null && (u.uid >= 65536 || (u.uid == 4096 && u.name != "nomad-apps"))
  ) (lib.attrValues config.users.users);
in
{
  imports = [ ./boot-security-core.nix ];

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = badUidAccounts == [ ];
          message =
            "users.users: raw_exec's denied_host_uids (0-4095,4097-65535) leaves uid 4096 for"
            + " nomad-apps and everything above 65535 uncovered, so neither may be configured."
            + " Offending accounts: "
            + lib.concatMapStringsSep ", " (u: "${u.name} (${toString u.uid})") badUidAccounts;
        }
      ];
    }

    # ── opted out ───────────────────────────────────────────────────────────
    #
    # Keeping client data off such a node protects nothing. Every node holds the fleet's
    # shared secrets whatever runs on it: the JuiceFS volume's key and passphrase
    # (juicefs-rsa), the S3 pair (ovh-s3), the restic password and the backup target's
    # credentials, all `share = true`. On a plaintext disk they sit next to the machine's
    # age key (/etc/secret-vars/key.txt) and their ciphertext in the store, so one pulled
    # or rescue-booted opted-out node decrypts them offline and, with the bucket, reads
    # every client's files and every backup. So the opt-out takes a second, site-wide
    # reason that says exactly that (topology.insecureFleetKeysOnPlaintextDisk), as the
    # one-member etcd does, and the warning and BootSecurityOptedOut say it too.
    (lib.mkIf optedOut {
      cluster.boot.enable = false;
      warnings = [
        (
          "node ${nodeName} opted out of boot security (insecurePlaintextBoot): ${toString optOut}."
          + " Its disks are plaintext and it has no Secure Boot, and it holds the fleet's shared keys"
          + " (JuiceFS volume key, S3, restic, backup target) next to its age key: one pulled drive"
          + " reads every client's files and backups, whatever runs on it."
        )
      ];
      assertions = [
        {
          assertion = builtins.isString optOut && lib.trim optOut != "";
          message = "boot security: node ${nodeName}: insecurePlaintextBoot must be a non-empty string saying why this node holds plaintext.";
        }
        {
          assertion = builtins.isString fleetKeysAck && lib.trim fleetKeysAck != "";
          message =
            "boot security: node ${nodeName}: an opted-out node exposes every client's data, not only its own."
            + " It holds the fleet's shared keys (juicefs-rsa, ovh-s3, restic, backup-target) on a plaintext disk"
            + " beside the age key that decrypts them, so one pulled drive reads every client's files and backups."
            + " Install it encrypted, or accept that for the whole site with"
            + " topology.insecureFleetKeysOnPlaintextDisk = \"<reason>\".";
        }
      ];
    })

    # ── not opted out ───────────────────────────────────────────────────────
    (lib.mkIf (!optedOut) {
      # Partitioning secrets are the one safe exception to
      # "every secret is neededFor = services" (tests/clan-coexist.nix): they are
      # needed only at install, when clan uploads them, never by the pull loop.
      # tests/security-policy.nix holds them to an exact allowlist.
      #
      # `luks` and `volume-identity` must never be regenerated once a node is
      # installed: the disks and the identity check are bound to these values. Plain
      # `clan vars generate <node>` leaves a generator alone only while every one of
      # its files exists and its validation hash matches, so adding a file or a
      # `validation` here replaces the values on the next run. And `--generator` is
      # not a filter: it reruns the generator named, with or without `--regenerate`.
      clan.core.vars.generators = {
        luks = {
          files.passphrase.neededFor = "partitioning";
          runtimeInputs = [
            pkgs.coreutils
            pkgs.openssl
          ];
          script = ''openssl rand -hex 32 | tr -d '\n' > "$out/passphrase"'';
        };
        volume-identity = {
          files.secret.neededFor = "partitioning";
          files.hash.secret = false;
          runtimeInputs = [
            pkgs.coreutils
            pkgs.openssl
          ];
          script = ''
            openssl rand -hex 32 | tr -d '\n' > "$out/secret"
            sha256sum < "$out/secret" | cut -d' ' -f1 | tr -d '\n' > "$out/hash"
          '';
        };
        initrd-ssh = {
          files."ssh_host_ed25519_key".neededFor = "partitioning";
          files."ssh_host_ed25519_key.pub".secret = false;
          runtimeInputs = [
            pkgs.openssh
            pkgs.coreutils
          ];
          script = ''ssh-keygen -q -t ed25519 -N "" -C initrd-host -f "$out/ssh_host_ed25519_key"'';
        };
        emergency-access = {
          files.password.deploy = false;
          files.hash.secret = false;
          runtimeInputs = [
            pkgs.coreutils
            pkgs.openssl
            pkgs.mkpasswd
          ];
          script = ''
            openssl rand -hex 32 | tr -d '\n' > "$out/password"
            mkpasswd -m sha-512 --stdin < "$out/password" | tr -d '\n' > "$out/hash"
          '';
        };
      };

      # Values that may not exist yet are left undefined, not given a stand-in: they
      # are read only once the toplevel is forced, which the assertions below refuse
      # first. A made-up identity hash must never have a way into an initrd.
      cluster.boot = {
        enable = true;
        identity.hash = lib.mkIf gens.volume-identity.files.hash.exists gens.volume-identity.files.hash.value;
        emergency.passwordHash = lib.mkIf gens.emergency-access.files.hash.exists gens.emergency-access.files.hash.value;
        ssh = {
          port = security.initrdSshPort or 2222;
          authorizedKeys = clusterSite.admins;
        };
        network = {
          wan = {
            interface = node.wanInterface;
            address4 = node.publicIp4;
            gateway4 = node.publicGw4;
          };
          trunk.interface = node.vrackInterface;
          kernelModules = lib.mkIf (nicModules != [ ]) nicModules;
        };
        tang = {
          url = lib.mkIf (tang ? url) tang.url;
          thumbprints = lib.mkIf (tang ? thumbprints) tang.thumbprints;
          # Not a type error for the core to trip over: the assertion below says what to do.
          vlanId = lib.mkIf (builtins.isInt (tang.vlanId or null)) tang.vlanId;
          address = lib.mkIf (
            tangIp != null && isCidr4 tangSubnet
          ) "${tangIp}/${toString (clusterLib.cidrPrefix tangSubnet)}";
        };
        install = {
          identitySecretFile = gens.volume-identity.files.secret.path;
          hostKeyFile = gens.initrd-ssh.files."ssh_host_ed25519_key".path;
        };
      };

      assertions = [
        # ── wiring ────────────────────────────────────────────────────────────
        (refuseUnless config.cluster.boot.enable "cluster.boot.enable was forced off.")
        (refuseUnless (config.specialisation == { })
          "specialisation is set. loader.conf on the ESP is unsigned, so anyone with the disk can select any signed entry, and the protections a specialisation drops go with it."
        )

        # ── bootloader ────────────────────────────────────────────────────────
        (refuseUnless config.boot.lanzaboote.enable "boot.lanzaboote.enable must be true: no Secure Boot, no PCR 7 to seal to.")
        # The name is all that can be read here. Upstream's hook writes to whatever is at
        # /boot, so a host file putting it back would fill the root with the ESP unmounted
        # and report success (modules/boot-security-core.nix). With the core forced off
        # there is no hook to read, and the refusal above says why.
        (refuseUnless
          (
            !config.cluster.boot.enable
            || lib.hasInfix "lzbt-guarded" (toString config.boot.loader.external.installHook)
          )
          "boot.loader.external.installHook must be the guarded hook: upstream's writes to the root filesystem when the ESP is unmounted, and reports success."
        )
        (refuseUnless (!config.boot.loader.systemd-boot.editor)
          "boot.loader.systemd-boot.editor must be false: the boot menu's editor grants root through init=/bin/sh."
        )
        (refuseUnless (
          !config.boot.loader.efi.canTouchEfiVariables
        ) "boot.loader.efi.canTouchEfiVariables must be false.")

        # ── disks ─────────────────────────────────────────────────────────────
        (refuseUnless (
          plainZfsLegs == [ ]
        ) "disko.devices has a plain zfs partition: every leg of the pool must sit inside LUKS.")
        (refuseUnless (builtins.length luksZfsLegs >= 2)
          "disko.devices has fewer than two LUKS partitions holding zfs: the pool must be a mirror of encrypted legs."
        )
        (refuseUnless (
          builtins.length luksNames >= 2
        ) "boot.initrd.luks.devices has fewer than two devices.")
        (refuseUnless (lib.all (lib.hasPrefix "crypt-") luksNames) "boot.initrd.luks.devices has a name without the crypt- prefix: the vdev audit and boot.zfs.devNodes rely on it.")
        (refuseUnless (config.boot.zfs.devNodes == "/dev/mapper")
          "boot.zfs.devNodes must be /dev/mapper: otherwise a plaintext forged pool on the raw partitions gets scanned and imported."
        )
        (refuseUnless (lib.all (s: s.randomEncryption.enable)
          config.swapDevices
        ) "swapDevices has an entry without randomEncryption: plaintext swap holds whatever memory held.")

        # ── the root ─────────────────────────────────────────────────────────
        # Every signed generation stays bootable with PCR 7 intact for as long as the signing
        # keys are the same, and not only while it is on an ESP: anyone can copy one off and
        # put it back (configurationLimit bounds the ESP, not that). So one built without this
        # would let a forged root run until the keys change.
        # Running before initrd-root-fs.target is the part that matters: before switch-root
        # is too late, since prepare-root runs from the root inside the initrd.
        (refuseUnless
          (
            let
              check = config.boot.initrd.systemd.services.volume-identity-check or null;
            in
            check != null
            && check.enable
            && lib.elem "initrd-root-fs.target" check.before
            && lib.elem "initrd-root-fs.target" check.requiredBy
          )
          "boot.initrd.systemd.services.volume-identity-check must run, and before initrd-root-fs.target: without it the signed initrd boots a forged root."
        )

        # Same reasoning: every signed generation must carry the burn. A generation without
        # it hands whoever reaches its emergency shell the disk key, through Clevis, until the
        # signing keys change. requiredBy is the part that keeps a shell from starting when
        # the burn could not run.
        (refuseUnless
          (
            let
              burn = config.boot.initrd.systemd.services.emergency-pcr-burn or null;
            in
            burn != null
            && burn.enable
            && lib.all (u: lib.elem u burn.requiredBy && lib.elem u burn.before) [
              "emergency.service"
              "rescue.service"
            ]
          )
          "boot.initrd.systemd.services.emergency-pcr-burn must run, and be required by emergency.service and rescue.service: without it an initrd shell can ask Clevis for the disk key."
        )
        # The Tang VLAN must exist only in the initrd, or anything running on the node can
        # reach Tang, and Tang is half of the disk key.
        (refuseUnless
          (
            let
              teardown = config.boot.initrd.systemd.services.vlan-teardown or null;
            in
            teardown != null && teardown.enable && lib.elem "initrd.target" teardown.wantedBy
          )
          "boot.initrd.systemd.services.vlan-teardown must run: flushBeforeStage2 alone leaves the Tang VLAN up in stage 2."
        )

        # ── unlock ────────────────────────────────────────────────────────────
        (refuseUnless
          (config.boot.initrd.clevisLuksAskpass.enable && config.boot.initrd.clevisLuksAskpass.useTang)
          "boot.initrd.clevisLuksAskpass.enable and useTang must be true: the unlock needs both the TPM and Tang."
        )
        # A crypt(3) hash, so never `true` (no password at all) and never "": nixpkgs
        # treats any string as access granted, and writes it as root's password
        # field, where an empty one again means no password.
        #
        # Not read until the hash exists. The core sets this option from
        # cluster.boot.emergency.passwordHash, which stays undefined until then on
        # purpose, and reading it here would turn "boot vars are missing" into a
        # missing-option error. Nothing is lost: that assertion refuses the node.
        (refuseUnless
          (
            !gens.emergency-access.files.hash.exists
            || (builtins.isString emergencyAccess && lib.hasPrefix "$" emergencyAccess)
          )
          "boot.initrd.systemd.emergencyAccess must be a crypt(3) hash: anything else is a shell with no password, or none at all."
        )
        (refuseUnless config.boot.initrd.network.flushBeforeStage2 "boot.initrd.network.flushBeforeStage2 must be true: initrd addresses must not leak into stage 2.")
        (refuseUnless (
          builtins.stringLength "${config.cluster.boot.network.trunk.interface}.${toString (tang.vlanId or "")}"
          <= 15
        ) "the Tang VLAN's interface name <trunk>.<vlanId> is over the kernel's 15 characters.")

        # ── generated values ──────────────────────────────────────────────────
        (refuseUnless (
          gens.volume-identity.files.hash.exists
          && gens.emergency-access.files.hash.exists
          && gens.initrd-ssh.files."ssh_host_ed25519_key.pub".exists
        ) "boot vars are missing. Run: clan vars generate ${nodeName}, then git add vars secrets.")

        # ── topology ──────────────────────────────────────────────────────────
        (refuseUnless (
          tang ? url && tang ? thumbprints && tang ? vlanId && tang ? subnet
        ) "topology.security.tang must set url, thumbprints, vlanId and subnet.")
        (refuseUnless tangUrlIsIpLiteral "topology.security.tang.url must be http://<ipv4>:<port>: the initrd has no DNS.")
        (refuseUnless
          (
            builtins.isList (tang.thumbprints or null)
            && tang.thumbprints != [ ]
            && lib.all (t: builtins.isString t && builtins.match "[A-Za-z0-9_-]{43}" t != null) tang.thumbprints
          )
          "topology.security.tang.thumbprints must be a non-empty list of S256 thumbprints: copy them from the Tang host."
        )
        (refuseUnless (
          builtins.isInt (tang.vlanId or null) && tang.vlanId >= 1 && tang.vlanId <= 4094
        ) "topology.security.tang.vlanId must be a VLAN id, 1 to 4094.")
        # modules/overlay-network.nix makes <trunk>.<vlans.X.id> in stage 2 on the same trunk,
        # so the same id would bring the Tang VLAN's segment straight back up after
        # vlan-teardown removed it, and "only in the initrd" would be false.
        (refuseUnless (
          !lib.elem (tang.vlanId or null) (
            lib.mapAttrsToList (_: v: v.id or null) (topology.vlans or { })
          )
        ) "topology.security.tang.vlanId is also a vlans.*.id: the Tang VLAN must exist only in the initrd.")
        (refuseUnless (isCidr4 tangSubnet) "topology.security.tang.subnet must be an IPv4 CIDR.")
        (refuseUnless (
          isCidr4 tangSubnet && !lib.any (clusterLib.cidrsOverlap tangSubnet) otherSubnets
        ) "topology.security.tang.subnet overlaps vlans, mesh.subnet or privateServices.")
        (refuseUnless (
          isCidr4 tangSubnet && isIp4 tangIp && clusterLib.cidrContains tangSubnet tangIp
        ) "tangIp must be an address inside topology.security.tang.subnet.")
        (refuseUnless (builtins.isList nicModules && nicModules != [ ])
          "initrdNicModules must list the initrd's NIC drivers: they are hardware-specific and cannot be detected at eval."
        )
        (refuseUnless (topology.alerting.auditUrl or null != null)
          "topology.alerting.auditUrl is null: only an opted-out node may run without the off-host audit trail."
        )
      ];
    })
  ];
}
