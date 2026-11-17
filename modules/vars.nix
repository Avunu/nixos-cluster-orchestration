# modules/vars.nix — the cluster-wide secrets, as generators.
#
# How a generator is declared, where its files are kept and how they reach a node is
# modules/secrets.nix. Per-client secrets are NOT here: each app's generators are
# declared by its kind (modules/kinds/) from its entry in apps/, so a client's secrets
# live and die with the client.
#
# Every file here is read by services (`neededFor = "services"`, the default) or by
# nobody on a node (`deploy = false`). The one exception is modules/boot-security.nix's
# `luks`, `volume-identity` and `initrd-ssh` secrets, on nodes that have not opted out.
# They are `neededFor = "partitioning"` because disko and its hook read them, once, at
# install, and nothing reads them on a running node. They are declared there, not
# here, because an opted-out node must not have them. tests/security-policy.nix holds
# them to an exact allowlist.
#
# ── share = true ─────────────────────────────────────────────────────────────
# Most of what is here is ONE value for the whole fleet (the same S3 credentials,
# the same gossip key), so it lives in secrets/shared/ rather than being regenerated
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
  loginRoles = pki.loginRoles node;
in
{
  cluster.secrets.generators = {
    # The operator's Cloudflare API token for what wrangler's OAuth cannot do
    # (Access apps, DNS records, minting R2 tokens), read by a site-provisioning
    # tool when CF_PROVISION_TOKEN is not set. An operator secret, not a machine's:
    # deploy = false keeps it off every node; admins read it with
    #   agenix view secrets/shared/cloudflare/provision-token.age
    cloudflare = {
      share = true;
      prompts.provision-token = {
        description = "cloudflare: the operator's API token for site provisioning (Account: R2 Storage, Cloudflare Tunnel, Access Apps and Policies, API Tokens -- write; Account Settings read. Zone: DNS write, Zone read)";
        type = "hidden";
        persist = true;
      };
      files.provision-token.deploy = false;
    };

    # ── what `avc cloud` holds (lib/cloud.nix) ───────────────────────────────
    # The OVH API's three values, for an application of the operator's own
    # (https://<endpoint>/createToken): what makes buckets, users and their S3 keys in
    # the Public Cloud project. Operator secrets like the token above: on no node.
    # Cloudflare's side of `avc cloud` uses that token, `cloudflare/provision-token`.
    cloud-ovh = lib.mkIf ((topology.cloud.ovh or null) != null) {
      share = true;
      prompts.application-key = {
        description = "OVH API application key (avc cloud)";
        persist = true;
      };
      prompts.application-secret = {
        description = "OVH API application secret";
        type = "hidden";
        persist = true;
      };
      prompts.consumer-key = {
        description = "OVH API consumer key, with GET, POST, PUT and DELETE on /cloud/project/<project>/*";
        type = "hidden";
        persist = true;
      };
      files.application-key.deploy = false;
      files.application-secret.deploy = false;
      files.consumer-key.deploy = false;
    };
    # What OpenTofu's state (cloud/terraform.tfstate in the site's repository) is
    # encrypted with: it holds every key pair and tunnel secret the providers issued.
    # Bound to that file: a new passphrase reads none of it.
    cloud-state = lib.mkIf ((topology.cloud or { }) != { }) {
      share = true;
      files.passphrase.deploy = false;
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      script = ''
        openssl rand -hex 32 | tr -d '\n' > "$out/passphrase"
      '';
    };

    # ── S3 object storage ─────────────────────────────────────────────────
    # Issued by the provider, so it cannot be generated — prompted once and stored.
    # Consumed by JuiceFS (both halves). `avc cloud apply` writes it where the
    # topology has `cloud.ovh`.
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

    # ── JuiceFS metadata: Patroni ───────────────────────────────────────────
    # The metadata database's own three (modules/storage-juicefs-pg.nix): its
    # superuser, the role its members replicate as, and the password Patroni's API
    # wants for anything that changes the cluster. Every node has a member, hence
    # shared. No punctuation: they pass through shell and a pgpass file.
    juicefs-patroni = {
      share = true;
      files.superuser = { };
      files.replication = { };
      files.restapi = { };
      runtimeInputs = [
        pkgs.coreutils
        pkgs.openssl
      ];
      script = ''
        for f in superuser replication restapi; do
          openssl rand -hex 32 | tr -d '\n' > "$out/$f"
        done
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
    # No pkgs.nomad here: openssl does the same job, and whoever generates needs no
    # unfree package for it.
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
    # Prompting for it was a deadlock: every generator runs BEFORE a node is
    # installed, so it asked for a token that can only exist
    # after the cluster it is about to install is already running.
    #
    # Must be a UUID — Nomad validates the format of an operator-supplied
    # bootstrap token and rejects anything else.
    #
    # It is the management token, so it is declared on the Nomad servers and on no
    # worker, and there only `nomad-acl-init` reads it (modules/nomad-acl.nix). Everything
    # else logs in for a scoped token (`nomad-login` below). Kept rather than deleted
    # after bootstrap: root on any server can mint a new one through
    # <data_dir>/server/acl-bootstrap-reset anyway, and policy changes need it.
    nomad-acl = lib.mkIf isServer {
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
    # operator's machine, when the secrets are generated. The public half is what the
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
    # only those: a worker holds no `registrar`. Per machine, so
    # each names its node, and a stolen one is that node's roles only.
    nomad-login = {
      dependencies = [ "nomad-jwt" ];
      files = lib.genAttrs (map (r: "jwt-${r}") loginRoles) (_: { });
      # A new role (a tag added) or a rotation reissues this machine's JWTs only. A
      # string, not the list: `validation` takes scalars or a set of them, because a
      # list's order would be part of its hash (tests/security-policy.nix, "every
      # generator of a new site can be read").
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

    # ── The pipeline's agent (modules/ci-agent.nix) ─────────────────────────
    # Per machine, like the audit trail's: the cluster-ci Worker answers a token with
    # that node's previews and their tunnel secrets, so a stolen one speaks for one
    # node, and with read-only tokens for the site's repositories
    # (modules/github-access.nix). Declared only when the topology names a Worker. Regenerating it needs the
    # Worker's AGENT_TOKENS updated too (`avc ci tokens`), or the node's agent is
    # refused with 401 until it is.
    ci = lib.mkIf ((topology.ci.url or null) != null) {
      files.token = { };
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''openssl rand -hex 32 | tr -d '\n' > "$out/token"'';
    };

    # ── The GitHub App (workers/cluster-ci) ─────────────────────────────────
    # All of the cluster's GitHub access is one App: the Worker's webhooks, comments and
    # statuses, and the read-only tokens it hands the nodes (modules/github-access.nix).
    # Its private key is the operators' and the Worker's: `deploy = false` keeps it off
    # every node, and `avc ci app private-key | wrangler secret put
    # GITHUB_APP_PRIVATE_KEY` is how the Worker gets it. `avc ci installations` signs
    # with it on the operator's machine, to list who has installed the App.
    #
    # The id is not a secret (it is in the Worker's wrangler.toml). The webhook secret
    # is ours to choose, so it is generated: paste it into the App's settings.
    # Regenerating: a new private key is made at GitHub (the App's settings), then
    # prompted for here; either value changed needs its `wrangler secret put` again.
    github-app = lib.mkIf ((topology.ci.url or null) != null) {
      share = true;
      prompts.app-id = {
        description = "GitHub App: its App ID (the number on the App's settings page)";
        persist = true;
      };
      prompts.private-key = {
        description = "GitHub App: a private key, the .pem as GitHub downloads it (the App's settings, Private keys)";
        type = "multiline-hidden";
        persist = true;
      };
      files.app-id.secret = false;
      files.private-key.deploy = false;
      files.webhook-secret.deploy = false;
      runtimeInputs = [
        pkgs.openssl
        pkgs.coreutils
      ];
      script = ''openssl rand -hex 32 | tr -d '\n' > "$out/webhook-secret"'';
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
  };
}
