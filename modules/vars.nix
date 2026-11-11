# modules/vars.nix — cluster-wide secrets, as clan vars generators.
#
# Replaces the agenix wiring (modules/secrets.nix + the filesystem-derived
# recipient registry in secrets.nix, both deleted). Per-client secrets are NOT
# here: each app's generators are declared by its kind (modules/kinds/) from
# its entry in apps/, so a client's secrets live and die with the client.
#
# ── how this reaches a node ──────────────────────────────────────────────────
# `clan.core.vars.settings.secretStore = "age"` (flake.nix), clan-core's own
# plain-`age` vars backend — NOT sops-nix. `clan vars generate` runs each
# script in an offline sandbox and commits the age-encrypted result to
# secrets/clan-vars/shared/<generator>/<file>/<file>.age. clanCore's age.nix
# decrypts every such file in an ACTIVATION SCRIPT during `nixos-rebuild
# switch`, using nothing but the `age` CLI — no Go tool, no sops-nix.
#
# We were already on this shape in spirit before the backend switch: the node
# decrypts with its own per-machine age keypair, generated into the repo by
# clan under secrets/age-keys/machines/<name>/ and delivered ONCE by `clan
# machines install` (nixos-anywhere --extra-files) to
# `clan.core.vars.age.secretLocation`/key.txt (default /etc/secret-vars). After
# that the PULL loop (modules/pull-deploy.nix) needs no clan CLI, no network
# beyond the flake fetch, and nothing uploaded — the key persists.
#
# We tried to keep agenix's nicer property (the node's SSH HOST key as the
# identity, so nothing is distributed at all). It does not survive first boot:
# you cannot encrypt to a host key before the host exists, and activation fails
# on a secret it cannot decrypt, so a fresh node could never complete its first
# switch. Something must be delivered at install either way — true of the age
# backend just as it was of sops.
#
# What therefore MUST hold — and what tests/clan-coexist.nix asserts — is that
# every secret stays `neededFor = "services"` (the default). "activation" and
# "partitioning" secrets are uploaded out of band by clan on each install/update;
# the pull loop uploads nothing, so such a secret would work on a pushed node and
# silently break on every pulled one.
#
# The one exception is modules/boot-security.nix's `luks`, `volume-identity` and
# `initrd-ssh` secrets, on nodes that have not opted out. They are `neededFor =
# "partitioning"` because disko and its hook read them, once, at install, and nothing
# reads them on a running node, so the pull loop uploading nothing cannot break them.
# They are declared there, not here, because an opted-out node must not have them.
# tests/security-policy.nix holds them to an exact allowlist.
#
# ── share = true ─────────────────────────────────────────────────────────────
# Most of what is here is ONE value for the whole fleet (the same S3 credentials,
# the same gossip key), so it lives in vars/shared/ rather than being regenerated
# per machine. A per-machine gossip key would simply not form a cluster.
#
# The exceptions are per machine on purpose: `nomad-tls` and `nomad-login`, because
# what a node holds is what a thief gets from it and a worker must hold only its own
# roles; and `wg-ctrl`, because a mesh key is what a node is known by.
{
  lib,
  pkgs,
  node,
  topology,
  clusterLib,
  ...
}:
let
  pki = clusterLib.nomadPki;
  isServer = clusterLib.net.hasTag "nomad-server" node;
  isLeader = clusterLib.net.hasTag "nomad-leader" node;
  loginRoles = pki.loginRoles node;
in
{
  clan.core.vars.generators = {
    # The operator's Cloudflare API token for what wrangler's OAuth cannot do
    # (Access apps, DNS records, minting R2 tokens), read by a site-provisioning
    # tool when CF_PROVISION_TOKEN is not set. An operator secret, not a machine's:
    # deploy = false keeps it off every node; admins read it with
    #   clan vars get node1 cloudflare/provision-token
    cloudflare = {
      share = true;
      prompts.provision-token = {
        description = "cloudflare: the operator's API token for site provisioning (Account: R2 Storage, Cloudflare Tunnel, Access Apps and Policies, API Tokens -- write; Account Settings read. Zone: DNS write, Zone read)";
        type = "hidden";
        persist = true;
      };
      files.provision-token.deploy = false;
    };

    # ── S3 object storage ─────────────────────────────────────────────────
    # Issued by the provider, so it cannot be generated — prompted once and stored.
    # Consumed by JuiceFS (both halves) and by the backup provider.
    ovh-s3 = {
      share = true;
      prompts."access-key" = {
        description = "Object storage S3 access key";
        persist = true;
      };
      prompts."secret-key" = {
        description = "Object storage S3 secret key";
        type = "hidden";
        persist = true;
      };
    };

    # ── JuiceFS metadata PostgreSQL ─────────────────────────────────────────
    # Ours to choose, so it is generated rather than prompted. Every node needs
    # it (they all mount), hence shared.
    juicefs-pg = {
      share = true;
      files.password = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      # No punctuation: this ends up inside a postgres:// URL assembled in a
      # shell script, where a '@' or '/' would silently truncate the host.
      script = ''
        openssl rand -hex 32 | tr -d '\n' > "$out/password"
      '';
    };

    # ── JuiceFS volume encryption ───────────────────────────────────────────
    # The RSA key JuiceFS wraps every object's data key with. `format` and `load`
    # take the PEM; every client needs the passphrase, because the PEM is stored in
    # the metadata encrypted with it. Shared: one volume, one key.
    #
    # NEVER regenerate it. A volume's key can't be changed, so a new key reads
    # nothing already written: rotation means a new volume and a copy. Mark it
    # `never` in the rotation policy. The PEM and its passphrase belong in the
    # offline kit: with the S3 credentials they are all a total loss needs to
    # rebuild the metadata from the bucket's dumps (`total-loss-escrow-only` in
    # tests/jfs-encrypted.nix). The PEM also travels inside every metadata dump,
    # protected only by the passphrase, so the passphrase is the secret that matters.
    #
    # PKCS8 (OpenSSL 3's genrsa writes it), which JuiceFS accepts [RAN]. No
    # punctuation in the passphrase: it is exported into a shell environment.
    juicefs-rsa = {
      share = true;
      files."rsa.pem" = { };
      files."rsa-passphrase" = { };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''
        openssl rand -hex 32 | tr -d '\n' > "$out/rsa-passphrase"
        openssl genrsa -aes256 -passout file:"$out/rsa-passphrase" -out "$out/rsa.pem" 4096
      '';
    };

    # ── Nomad TLS (HTTP and RPC) ──────────────────────────────────────────────
    # The CA signs nomad-tls offline, on the operator's machine, and never reaches
    # a node: `ca.key` is deploy = false. `ca.crt` is not secret, but it is
    # deployed as one so that production and the VM fixtures use one code path
    # (/run/secrets/...). Regenerating it cascades to every machine's nomad-tls,
    # which under the pull loop is a hard cut, not a rolling rotation.
    nomad-ca = {
      share = true;
      files."ca.key" = {
        secret = true;
        deploy = false;
      };
      files."ca.crt" = { };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''
        ${pki.functions}
        make_ca "$out/ca.key" "$out/ca.crt" ${toString pki.caDays}
      '';
    };

    # Per machine, NOT shared: a worker must hold only client.global.nomad (see
    # lib/nomad-pki.nix). `agent` is what the Nomad agent serves and presents;
    # `cli` is what local API consumers present (verify_https_client).
    #
    # No pkgs.nomad here: it is unfree, and clan's generator path forces its own
    # nixpkgs, so it would fail the unfree check. openssl does the same job.
    nomad-tls = {
      dependencies = [ "nomad-ca" ];
      files."agent.key" = { };
      files."agent.crt" = { };
      files."cli.key" = { };
      files."cli.crt" = { };
      # A change here (a new control IP, a promotion to server, a rotation) reissues
      # this machine's certificates, and only this machine's.
      validation = {
        ip = node.controlIp;
        inherit isServer;
        rotation = topology.security.nomadTlsRotation or 0;
      };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''
        ${pki.functions}
        pki_out=$out
        pki_ca_crt=$in/nomad-ca/ca.crt
        pki_ca_key=$in/nomad-ca/ca.key
        pki_days=${toString pki.certDays}
        issue agent ${pki.agentName isServer} ${
          lib.escapeShellArg (
            pki.agentSans {
              inherit isServer;
              inherit (node) controlIp;
            }
          )
        }
        issue cli ${pki.cliName} ${lib.escapeShellArg pki.cliSans}
      '';
    };

    # ── Nomad gossip encryption ─────────────────────────────────────────────
    # The serf key, as the HCL file Nomad loads with -config (modules/cluster-common.nix),
    # so it never sits in the store-rendered settings. Shared by definition: servers
    # with different keys cannot gossip. Declared ONLY on servers: clients do not
    # gossip, and the key plus a server certificate is a voter, so a worker that is
    # stolen from must not have it.
    #
    # Nomad copies the key into <data_dir>/server/serf.keyring on first start and
    # uses that file from then on, ignoring this one. Regenerating the key therefore
    # changes nothing on a running server: rotation is `nomad operator gossip keyring`.
    nomad-gossip = lib.mkIf isServer {
      share = true;
      files."gossip.hcl" = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      script = ''
        ${pki.functions}
        gossip_hcl "$out/gossip.hcl"
      '';
    };

    # ── Nomad ACL bootstrap token ───────────────────────────────────────────
    # GENERATED, not prompted, and that ordering matters: `nomad acl bootstrap`
    # will accept an OPERATOR-SUPPLIED token (`nomad acl bootstrap <path>`), so
    # we mint it here and hand it to Nomad rather than asking Nomad for one.
    #
    # Prompting for it was a deadlock: `clan machines install` runs every
    # generator BEFORE installing, so it asked for a token that can only exist
    # after the cluster it is about to install is already running.
    #
    # Must be a UUID — Nomad validates the format of an operator-supplied
    # bootstrap token and rejects anything else.
    #
    # It is the management token, so it is declared ONLY on the `nomad-leader` node,
    # and there only `nomad-acl-init` reads it (modules/nomad-acl.nix). Everything
    # else logs in for a scoped token (`nomad-login` below). Kept rather than deleted
    # after bootstrap: root on any server can mint a new one through
    # <data_dir>/server/acl-bootstrap-reset anyway, and policy changes need it.
    nomad-acl = lib.mkIf isLeader {
      share = true;
      files.token = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.util-linux
      ];
      script = ''
        uuidgen -r | tr -d '\n' > "$out/token"
      '';
    };

    # ── Nomad login: the key that signs, and what it signed ─────────────────
    # The private key never reaches a node (deploy = false): it signs on the
    # operator's machine, at `clan vars generate`. The public half is what the
    # leader's `nomad-acl-init` gives the `clan` auth method. Regenerating it
    # invalidates every node's JWTs at once; that is its rotation (manual).
    nomad-jwt = {
      share = true;
      files."signing.key" = {
        secret = true;
        deploy = false;
      };
      files."signing.pub" = { };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''
        ${pki.functions}
        make_jwt_key "$out/signing.key" "$out/signing.pub"
      '';
    };

    # One JWT per role this machine logs in as (lib/nomad-pki.nix loginRoles), and
    # only those: a worker holds no `registrar` and no `autoscaler`. Per machine, so
    # each names its node, and a stolen one is that node's roles only.
    nomad-login = {
      dependencies = [ "nomad-jwt" ];
      files = lib.genAttrs (map (r: "jwt-${r}") loginRoles) (_: { });
      # A new role (a tag added) or a rotation reissues this machine's JWTs only. A
      # string, not the list: clan's `validation` takes scalars or a set of them, and a
      # list fails `clan vars generate` on every node (tests/security-policy.nix,
      # "clan vars generate can read every generator").
      validation = {
        roles = lib.concatStringsSep "," loginRoles;
        rotation = topology.security.nomadTlsRotation or 0;
      };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''
        ${pki.functions}
        ${lib.concatMapStrings (r: ''
          mint_jwt ${r} ${lib.escapeShellArg node.hostName} ${pki.jwtAudience} "$in/nomad-jwt/signing.key" ${toString pki.jwtDays} > "$out/jwt-${r}"
        '') loginRoles}
      '';
    };

    # ── The control mesh (modules/mesh-control.nix) ─────────────────────────
    # Per machine: a node's key is what the others list it by. The private half is
    # read by networkd itself, hence its owner. The public half is a public value in
    # the repository, which is how every peer finds it (no node reads another's
    # secret). Regenerating it is a rotation: commit it, and both this node and every
    # peer must switch before the mesh between them works again
    # (`one-sided-key-change-recovers`). Mark it manual in the rotation policy.
    wg-ctrl = {
      files.private = {
        owner = "systemd-network";
      };
      files.public.secret = false;
      runtimeInputs = [
        pkgs.wireguard-tools
        pkgs.coreutils
      ];
      script = ''
        wg genkey > "$out/private"
        wg pubkey < "$out/private" | tr -d '\n' > "$out/public"
      '';
    };

    # ── The off-host audit trail (modules/audit-ship.nix) ───────────────────
    # Per machine: the Worker attributes every event to the token that sent it, and
    # refuses one that names another node, so a stolen token speaks for one node only.
    # Declared only when the topology has somewhere to send to. Regenerating it needs
    # the Worker's AUDIT_TOKENS updated too (`avc audit tokens`), or that node's events
    # wait in its spool, refused with 401, until it is.
    audit = lib.mkIf ((topology.alerting.auditUrl or null) != null) {
      files.token = { };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''openssl rand -hex 32 | tr -d '\n' > "$out/token"'';
    };

    # ── the canary (modules/canary-scan.nix) ──────────────────────────────────
    # A string that must never turn up in plaintext where client data must not be:
    # temp dirs, the journal, core dumps, swap, the ESPs, the raw disks, the object
    # storage under the JuiceFS volume. The scan plants it on the volume and in nothing
    # else, and reads it as a credential, so it is on no disk in the clear. One for the
    # fleet: a hit names its node by where it was found. Regenerating it is harmless
    # (the next scan rewrites the planted file); `CANARY-` keeps it greppable by eye.
    canary = {
      share = true;
      files.value = { };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''printf 'CANARY-%s\n' "$(openssl rand -hex 16)" | tr -d '\n' > "$out/value"'';
    };

    # ── GitHub token for the pull loop ──────────────────────────────────────
    # modules/pull-deploy.nix adds this file to nix.conf with `!include`, so the
    # FILE CONTENT must be a nix.conf line rather than a bare token. Rendering
    # it here keeps the token itself out of every other consumer's shape.
    github-token = {
      share = true;
      files."nix.conf" = { };
      # A SECOND rendering of the same token, as netrc. Both are needed and they
      # cover different fetchers:
      #
      #   nix.conf `access-tokens`  -> Nix's own `github:` fetcher
      #   netrc                     -> `git+https://` inputs, where Nix shells
      #                                out to git, which knows nothing about
      #                                access-tokens and prompts for a username
      #
      # app files commonly pull project flakes (a Frappe bench, an Odoo project) as
      # `git+https://…` (they need submodules, which the `github:` fetcher
      # cannot do), so without netrc every evaluation on a node fails with
      #   fatal: could not read Username for 'https://github.com'
      # modules/pull-deploy.nix links it as root's ~/.netrc: that is where the
      # git subprocess looks, not Nix's netrc-file setting.
      #
      # The token needs read access to the CONTENTS of every private input
      # (a fine-grained PAT: Contents: read on the cluster repo and each
      # private project repo), not just repository metadata.
      files."netrc" = { };
      prompts.token = {
        description = "GitHub token with read access to the private cluster repo";
        type = "hidden";
      };
      runtimeInputs = [ pkgs.coreutils ];
      script = ''
        tok=$(tr -d '\n' < "$prompts/token")
        printf 'access-tokens = github.com=%s\n' "$tok" > "$out/nix.conf"
        printf 'machine github.com login x-access-token password %s\n' "$tok" > "$out/netrc"
      '';
    };
  };
}
