# lib/cloud.nix — what the site needs from its providers, as one OpenTofu configuration.
#
#   nix eval --json .#cloud.config    the configuration (main.tf.json)
#   nix eval --json .#cloud.writeback where each output goes in the repository
#
# Derived, never edited: the buckets are the ones the topology names, the tunnels and
# DNS records are the ones the apps' hostnames need. `avc cloud plan` and `apply`
# (tools/avc/avc/flows/cloud.py) run OpenTofu over it on the operator's machine, with
# the providers' credentials from vars that no node holds, and put what the providers
# hand back where the rest of the site reads it: S3 key pairs into `clan vars`, a new
# tunnel's id into `apps/<app>.json`, its credentials into the app's own var.
#
# What it makes, where `topology.cloud` names the provider:
#
#   OVH          per bucket (JuiceFS's, the binary cache's when an app is one, and the
#                state backup's when it is on the same endpoint): the bucket, a user of its own, that user's S3 key pair, and a
#                policy that reaches this bucket and no other. No user may delete an
#                object VERSION, and the state backup's bucket is versioned, with
#                versions past `noncurrentDays` expired: a node taken over can hide what
#                is there, not destroy it.
#   Cloudflare   per app with a hostname: its tunnel (locally configured, as the
#                container expects), a proxied CNAME per hostname in a zone the
#                topology lists, and for FreeIPA the private route to its address. The
#                audit trail's R2 bucket, locked, when the topology names one.
#
# Not here: the Workers' own code and secrets (wrangler deploys those), API tokens (the
# permission groups are the account's to name), Access policies (who may sign in is not
# in the topology), and a WordPress site's R2 bucket (the site provisioner's).
#
# A tunnel made by hand before this existed is adopted, not replaced: an app that has a
# `tunnel.id` gets an `import` block for it, which is a no-op once it is in the state,
# and its secret and name are left as they are. A DNS record made by hand has no id the
# topology knows, so it is imported by hand or deleted first (`avc cloud tofu import`).
#
# Buckets and tunnels carry `prevent_destroy`: removing one from the topology fails the
# plan instead of deleting client data.
{
  lib,
  topology,
  clusterLib,
  nixosConfigurations,
}:
let
  cloud = topology.cloud or { };
  ovh = cloud.ovh or null;
  cf = cloud.cloudflare or null;

  reference = clusterLib.net.referenceNode topology;
  cfg = nixosConfigurations.${reference}.config;
  apps = cfg.cluster.nomadApps;
  clusterName = cfg.clan.core.settings.name;

  # A resource name: letters, digits and underscores.
  slug = s: lib.replaceStrings [ "." "-" "/" ":" ] [ "_" "_" "_" "_" ] s;
  ref =
    type: name: attr:
    "\${${type}.${name}.${attr}}";

  # ── OVH object storage ─────────────────────────────────────────────────────
  os = topology.objectStorage;
  state = topology.backup.state or null;
  buckets = lib.optionalAttrs (ovh != null) (
    {
      juicefs = {
        name = os.juicefsBucket;
        versioned = false;
        # JuiceFS's own key pair, on every node (modules/storage-juicefs.nix).
        vars = {
          access = "ovh-s3/access-key";
          secret = "ovh-s3/secret-key";
        };
        description = "${clusterName}: the cluster's own JuiceFS volume";
      };
    }
    # Each app's own volume (lib/juicefs.nix, "Volumes"): a bucket, and a pair that
    # opens that bucket and no other.
    // lib.listToAttrs (
      map (
        volume:
        lib.nameValuePair "jfs_${slug volume}" {
          name = clusterLib.juicefs.appBucket os volume;
          versioned = false;
          vars = {
            access = "${clusterLib.juicefs.appS3Generator volume}/access-key";
            secret = "${clusterLib.juicefs.appS3Generator volume}/secret-key";
          };
          description = "${clusterName}: ${volume}'s JuiceFS volume";
        }
      ) (clusterLib.juicefs.volumeApps cfg.clusterApps)
    )
    # The state backup's, when it is on this provider. One elsewhere is not ours to make.
    //
      lib.optionalAttrs
        (state != null && (state.target.type or "") == "s3" && state.target.endpoint == os.endpoint)
        {
          state_backup = {
            name = state.target.bucket;
            versioned = true;
            vars = {
              access = "backup-state-target/access-key";
              secret = "backup-state-target/secret-key";
            };
            description = "${clusterName}: the state backup";
          };
        }
    # The binary cache's (modules/kinds/attic.nix), when an app is one.
    // lib.concatMapAttrs (
      _: a:
      lib.optionalAttrs ((a.attic or null) != null && (a.attic.storage.type or "") == "s3") {
        cache = {
          name = a.attic.bucket;
          versioned = false;
          vars = {
            access = "cache-s3/access-key";
            secret = "cache-s3/secret-key";
          };
          description = "${clusterName}: the binary cache";
        };
      }
    ) apps
  );

  # What a user may do, in its one bucket. Everything restic and JuiceFS need, deleting
  # an object included (a prune, a file removed), and not `s3:DeleteObjectVersion`: on
  # a versioned bucket a delete then hides, and nothing of this user's destroys.
  policyFor =
    name:
    builtins.toJSON {
      Statement = [
        {
          Sid = "ThisBucketOnly";
          Effect = "Allow";
          Action = [
            "s3:GetObject"
            "s3:PutObject"
            "s3:DeleteObject"
            "s3:ListBucket"
            "s3:GetBucketLocation"
            "s3:ListBucketMultipartUploads"
            "s3:ListMultipartUploadParts"
            "s3:AbortMultipartUpload"
          ];
          Resource = [
            "arn:aws:s3:::${name}"
            "arn:aws:s3:::${name}/*"
          ];
        }
      ];
    };

  ovhResources = lib.optionalAttrs (buckets != { }) {
    ovh_cloud_project_storage = lib.mapAttrs (
      _: b:
      {
        service_name = ovh.project;
        region_name = ovh.region;
        inherit (b) name;
        lifecycle.prevent_destroy = true;
      }
      // lib.optionalAttrs b.versioned { versioning.status = "enabled"; }
    ) buckets;
    ovh_cloud_project_user = lib.mapAttrs (_: b: {
      service_name = ovh.project;
      inherit (b) description;
      role_name = "objectstore_operator";
    }) buckets;
    ovh_cloud_project_user_s3_credential = lib.mapAttrs (k: _: {
      service_name = ovh.project;
      user_id = ref "ovh_cloud_project_user" k "id";
    }) buckets;
    ovh_cloud_project_user_s3_policy = lib.mapAttrs (k: b: {
      service_name = ovh.project;
      user_id = ref "ovh_cloud_project_user" k "id";
      policy = policyFor b.name;
    }) buckets;
  };
  versioned = lib.filterAttrs (_: b: b.versioned) buckets;
  ovhLifecycle = lib.optionalAttrs (versioned != { }) {
    ovh_cloud_project_storage_object_bucket_lifecycle_configuration = lib.mapAttrs (k: _: {
      service_name = ovh.project;
      region_name = ovh.region;
      container_name = ref "ovh_cloud_project_storage" k "name";
      rules = [
        {
          id = "expire-hidden-versions";
          status = "enabled";
          noncurrent_version_expiration.noncurrent_days = ovh.noncurrentDays or 30;
          abort_incomplete_multipart_upload.days_after_initiation = 7;
        }
      ];
    }) versioned;
  };

  # ── Cloudflare ─────────────────────────────────────────────────────────────
  zones = cf.zones or { };
  # The zone a hostname is in: the longest listed name it ends with.
  zoneOf =
    host:
    let
      fits = lib.filter (z: host == z || lib.hasSuffix ".${z}" host) (lib.attrNames zones);
    in
    if fits == [ ] then
      null
    else
      lib.foldl' (a: z: if lib.stringLength z > lib.stringLength a then z else a) (lib.head fits) fits;

  tunneled = lib.optionalAttrs (cf != null) (
    lib.filterAttrs (_: a: a.tunnel.ingress != { } || a.tunnel.id != "") apps
  );
  hostnames = lib.concatLists (
    lib.mapAttrsToList (
      app: a:
      map (host: {
        inherit app host;
        zone = zoneOf host;
      }) (lib.attrNames a.tunnel.ingress)
    ) tunneled
  );
  managedHosts = lib.filter (h: h.zone != null) hostnames;
  privateRoutes = lib.filterAttrs (_: a: (a.freeipa or null) != null) tunneled;

  cfResources =
    lib.optionalAttrs (tunneled != { }) {
      # A new tunnel's secret. One made by hand keeps its own: see ignore_changes.
      random_bytes = lib.mapAttrs' (
        app: _: lib.nameValuePair "tunnel_${slug app}" { length = 32; }
      ) tunneled;
      cloudflare_zero_trust_tunnel_cloudflared = lib.mapAttrs' (
        app: _:
        lib.nameValuePair (slug app) {
          account_id = cf.accountId;
          name = "${clusterName}-${app}";
          # The ingress rules are in the container's own configuration
          # (lib/mk-app-container.nix), not at Cloudflare.
          config_src = "local";
          tunnel_secret = ref "random_bytes" "tunnel_${slug app}" "base64";
          lifecycle = {
            prevent_destroy = true;
            ignore_changes = [
              "tunnel_secret"
              "name"
            ];
          };
        }
      ) tunneled;
    }
    // lib.optionalAttrs (managedHosts != [ ]) {
      cloudflare_dns_record = lib.listToAttrs (
        map (
          h:
          lib.nameValuePair (slug h.host) {
            zone_id = zones.${h.zone};
            name = h.host;
            type = "CNAME";
            content = "${ref "cloudflare_zero_trust_tunnel_cloudflared" (slug h.app) "id"}.cfargotunnel.com";
            proxied = true;
            ttl = 1;
            comment = "${clusterName}: ${h.app}";
          }
        ) managedHosts
      );
    }
    // lib.optionalAttrs (privateRoutes != { }) {
      # WARP clients reach the server's private address through its tunnel
      # (modules/kinds/freeipa.nix).
      cloudflare_zero_trust_tunnel_cloudflared_route = lib.mapAttrs' (
        app: a:
        lib.nameValuePair (slug app) {
          account_id = cf.accountId;
          tunnel_id = ref "cloudflare_zero_trust_tunnel_cloudflared" (slug app) "id";
          network = "${a.freeipa.privateIp4}/32";
          comment = "${clusterName}: ${app}";
        }
      ) privateRoutes;
    }
    // lib.optionalAttrs (cf != null && (cf.auditBucket or null) != null) {
      cloudflare_r2_bucket.audit = {
        account_id = cf.accountId;
        name = cf.auditBucket;
        lifecycle.prevent_destroy = true;
      };
      # Nothing in the trail can be deleted or overwritten before its time, by anyone.
      cloudflare_r2_bucket_lock.audit = {
        account_id = cf.accountId;
        bucket_name = ref "cloudflare_r2_bucket" "audit" "name";
        rules = [
          {
            id = "audit-retention";
            enabled = true;
            condition = {
              type = "Age";
              max_age_seconds = (cf.auditLockDays or 365) * 86400;
            };
          }
        ];
      };
    };

  resources = lib.recursiveUpdate (lib.recursiveUpdate ovhResources ovhLifecycle) cfResources;
in
{
  # Whether there is anything to run OpenTofu for.
  enabled = ovh != null || cf != null;

  config = {
    terraform = {
      required_providers =
        lib.optionalAttrs (ovh != null) { ovh.source = "ovh/ovh"; }
        // lib.optionalAttrs (cf != null) {
          cloudflare.source = "cloudflare/cloudflare";
          random.source = "hashicorp/random";
        };
      # Beside this file, in the site's repository, encrypted (the key is not here:
      # avc passes it in TF_ENCRYPTION).
      backend.local.path = "terraform.tfstate";
    };
    provider =
      lib.optionalAttrs (ovh != null) { ovh.endpoint = ovh.endpoint; }
      // lib.optionalAttrs (cf != null) { cloudflare = { }; };
  }
  // lib.optionalAttrs (resources != { }) { resource = resources; }
  // lib.optionalAttrs (tunneled != { }) {
    # Adopt the tunnel an app already names. Nothing happens for one already adopted.
    "import" = lib.mapAttrsToList (app: a: {
      to = "cloudflare_zero_trust_tunnel_cloudflared.${slug app}";
      id = "${cf.accountId}/${a.tunnel.id}";
    }) (lib.filterAttrs (_: a: a.tunnel.id != "") tunneled);
  }
  // {
    output =
      lib.concatMapAttrs (k: _: {
        "s3_${k}_access_key" = {
          value = ref "ovh_cloud_project_user_s3_credential" k "access_key_id";
          sensitive = true;
        };
        "s3_${k}_secret_key" = {
          value = ref "ovh_cloud_project_user_s3_credential" k "secret_access_key";
          sensitive = true;
        };
      }) buckets
      // lib.mapAttrs' (
        app: _:
        lib.nameValuePair "tunnel_${slug app}" {
          value = {
            id = ref "cloudflare_zero_trust_tunnel_cloudflared" (slug app) "id";
            secret = ref "random_bytes" "tunnel_${slug app}" "base64";
          };
          sensitive = true;
        }
      ) tunneled;
  };

  # Where each output belongs. avc reads this, never the configuration.
  writeback = {
    # output name -> clan var (generator/file), written when the value differs.
    vars = lib.concatMapAttrs (k: b: {
      "s3_${k}_access_key" = b.vars.access;
      "s3_${k}_secret_key" = b.vars.secret;
    }) buckets;
    # A tunnel made here, for an app that named none: its id into apps/<app>.json, and
    # the connector's credentials file into the app's var. One that was adopted has
    # both already, and the secret in the state is not its own.
    tunnels = lib.mapAttrs (app: a: {
      output = "tunnel_${slug app}";
      known = a.tunnel.id != "";
      accountId = cf.accountId;
      # The app's own, or the default it gets once it has an id (modules/apps.nix).
      credentials =
        if a.tunnel.credentials == null then
          "${app}-cf/cloudflared"
        else
          "${a.tunnel.credentials.generator}/${a.tunnel.credentials.file}";
    }) tunneled;
    # Hostnames in no zone the topology lists: their records are someone else's to make.
    unmanagedHosts = map (h: h.host) (lib.filter (h: h.zone == null) hostnames);
    # A machine to name when reading and writing vars: any holds the shared ones.
    machine = reference;
  };
}
