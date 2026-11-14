# lib/backup-target.nix — where backups go, as data.
#
# The backup target is a restic repository *base*: every app gets its own
# repository under it (`<base>/<appRepoPath salt app>`, see modules/backup.nix), so
# this file only has to answer, per backend type:
#
#   repository target path  -> the RESTIC_REPOSITORY string
#   options target          -> extra `-o` flags every restic call needs
#   env target              -> non-secret environment
#   credentialEnv target    -> env var name -> credential file (id | secret)
#
# Swapping backends is therefore: change `topology.backup.target`, set the two
# `backup-target` vars to the new backend's credentials, and move history with
# `restic copy` (per app) once. Nothing else in the cluster names a backend.
{ lib }:
let
  trimSlash = s: lib.removeSuffix "/" s;

  types = {
    # Any S3-compatible store: MinIO, AWS, R2, B2's S3 API, OVH, Garage...
    s3 = {
      repository =
        t: path: "s3:${trimSlash t.endpoint}/${t.bucket}${lib.optionalString (path != "") "/${path}"}";
      # Path-style addressing: without it restic asks for <bucket>.<endpoint>,
      # which a single-host MinIO (and most self-hosted S3) does not serve.
      options = _t: [ "s3.bucket-lookup=path" ];
      env = t: { AWS_DEFAULT_REGION = t.region or "us-east-1"; };
      credentialEnv = {
        AWS_ACCESS_KEY_ID = "id";
        AWS_SECRET_ACCESS_KEY = "secret";
      };
    };
    # restic's own REST server (rest-server), e.g. with --append-only.
    rest = {
      repository = t: path: "rest:${trimSlash t.url}${lib.optionalString (path != "") "/${path}"}";
      options = _t: [ ];
      env = _t: { };
      credentialEnv = {
        RESTIC_REST_USERNAME = "id";
        RESTIC_REST_PASSWORD = "secret";
      };
    };
    b2 = {
      repository = t: path: "b2:${t.bucket}:${path}";
      options = _t: [ ];
      env = _t: { };
      credentialEnv = {
        B2_ACCOUNT_ID = "id";
        B2_ACCOUNT_KEY = "secret";
      };
    };
    # A path on the node itself -- tests, or a locally mounted disk/NFS share.
    local = {
      repository = t: path: "${trimSlash t.path}${lib.optionalString (path != "") "/${path}"}";
      options = _t: [ ];
      env = _t: { };
      credentialEnv = { };
    };
  };

  backend =
    t:
    types.${t.type}
      or (throw "topology.backup.target.type: unknown backend \"${t.type}\" (one of: ${lib.concatStringsSep ", " (lib.attrNames types)})");
in
{
  # Where an app's repository sits under the base: `apps/<sha256 of salt + app>`.
  # The plain `apps/<app>` showed the storage provider every app's name, and apps are
  # often named for clients [RAN, design 1.21]. Restic's contents and file names are
  # opaque already; its `keys/<id>` objects still show the node's hostname and the
  # user (section 6 of the design accepts that). `topology.backup.repoSalt` keeps the
  # hash from being a lookup of known app names. Changing the salt moves EVERY app to
  # a new, empty repository: the old ones stay where they were, and nothing finds them.
  appRepoPath = salt: app: "apps/${builtins.hashString "sha256" (salt + app)}";

  # Where an app's database archive sits in the archive bucket (modules/db-archive.nix):
  # `db/<sha256>`, for the same reason. The hash is not the repository path's: the
  # same app's two paths, side by side, do not match. The salt is as fixed here as
  # there. A new one starts every app on a new, empty archive.
  dbArchivePrefix = salt: app: "db/${builtins.hashString "sha256" ("db-archive:" + salt + app)}";

  supportedTypes = lib.attrNames types;
  repository = t: path: (backend t).repository t path;
  options = t: (backend t).options t;
  env = t: (backend t).env t;
  credentialEnv = t: (backend t).credentialEnv;
}
