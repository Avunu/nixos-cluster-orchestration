# VM test: the JuiceFS volume is encrypted, a plaintext one is refused, and the
# restore path works with the key and only with the key (design WS11, 1.18, App. I).
#
# Three machines:
#
#   s3       `rclone serve s3`, the object storage (nixpkgs marks MinIO insecure).
#            Every object the test plants goes in through the S3 API: writing into
#            rclone's backing directory hits its directory cache and invalidated an
#            earlier run [RAN, design]. The test only READS the backing directory, to
#            grep what the provider would see.
#   node1    the fixture's node1, as far as JuiceFS goes: the REAL modules/vars.nix,
#            modules/storage-juicefs.nix and modules/storage-juicefs-meta.nix under
#            clanCore, with the cluster harness's fixture secrets at the paths clan's
#            age backend uses. Its control-mesh address is on a dummy interface
#            standing in for wg-ctrl (WireGuard is another test's business), and
#            nothing of Nomad's is here. Units, scripts and credentials are
#            production's; only the object-storage endpoint is this VM's `s3`.
#   rescue   only the JuiceFS, rclone and restic CLIs. Nothing of the cluster.
#
# Subtests, in this order (the order matters for the mutants, below):
#
#   metric-exported                the mount wrote cluster_jfs_encrypted 1, and
#                                  status shows the key
#   ciphertext-in-bucket           a canary file's content and its name: 0 hits in
#                                  the bucket, its automatic metadata dump included;
#                                  juicefs_uuid is ciphertext. Positive control for
#                                  the name: a manual `juicefs dump` (plaintext, no
#                                  key needed: a runbook fact) does contain it
#   restic-password-wrong          a restic repository on the same S3: canary 0 hits,
#                                  a wrong password exits 12, the right one restores
#   status-field-gate              a plaintext volume: status says
#                                  EncryptAlgo=aes256gcm-rsa and KeyEncrypted, so a
#                                  check on those would pass it; the gate (in
#                                  juicefs-format) still refuses, rc 3
#   refuse-plaintext-metadata      juicefs-format leaves that volume as it was
#   refuse-plaintext-mount         juicefs-mount refuses it: rc 3, unit failed and not
#                                  restarted, nothing mounted, cluster_jfs_encrypted 0
#   positive-control-plaintext     the same canary written to that plaintext volume
#                                  IS found in its bucket, and so is its UUID: the
#                                  greps above can see plaintext
#   objects-no-dump-refused        empty metadata, chunks but no dump: rc 4, nothing
#                                  created
#   object-storage-down-no-verdict empty metadata and S3 down: rc 4, nothing created,
#                                  and systemd retrying it. A failed listing never
#                                  reads as an empty bucket
#   restore-from-dump              empty metadata, the newest dump restored with the
#                                  key, the canary reads back, the gate passes
#   stale-dump-refused             the newest dump years old: rc 5, nothing loaded;
#                                  restored once an override names that dump
#   no-passphrase-refused          restore with an empty passphrase: refused, no table
#   wrong-passphrase-refused       restore with a wrong passphrase: refused, no table
#   wrong-pem-load-refused         restore with another PEM: refused, no table
#   planted-plaintext-dump-refused a newer plaintext dump planted in the bucket:
#                                  refused, no table
#   interrupted-load-recovers      JuiceFS's tables but no format row (a load cut
#                                  short): dropped, and the restore goes through
#   interrupted-restore-recovers   a load whose `config` never ran (secret "removed"),
#                                  S3 down: rc 4, retried by systemd, the pair put
#                                  back once S3 returns, and the mount works
#   s3-key-rotation                a new ovh-s3 pair reaches the settings, the running
#                                  mount reloads it and writes with the old key revoked
#   probe-needs-the-mount          jfs-probe reads 1 on the mount and 0 on the bare
#                                  directory a dead mount leaves
#   metadata-down                  PostgreSQL stopped: the mount says "metadata
#                                  unreachable", exits 4, writes NO metric and keeps
#                                  retrying; it mounts on its own once PostgreSQL is
#                                  back
#   total-loss-escrow-only         node1 gone: the PEM, its passphrase and the S3
#                                  credentials alone rebuild metadata (SQLite, on
#                                  `rescue`) from the bucket's dump and read the canary
#
# Mutants (flake.nix legacyPackages.mutants, through `cluster.juicefs.scriptEdit`):
#   jfs-no-gate              the gate out of the mount script -> refuse-plaintext-mount
#   jfs-gate-on-encryptalgo  the gate judges EncryptAlgo (the fake fix) -> status-field-gate
#   format-no-key-flags      the key flags off `juicefs load` -> restore-from-dump
#   jfs-restore-any-age      no age check on the dump -> stale-dump-refused
#   jfs-s3-not-reapplied     the S3 pair put back only right after a load ->
#                            interrupted-restore-recovers
#   jfs-probe-no-mount-check the probe writes wherever /mnt/jfs is -> probe-needs-the-mount
#
# Run: nix build .#checks.x86_64-linux.jfs-encrypted -L   (needs KVM; about 4 GB RAM)
{
  pkgs,
  lib,
  topology,
  harnessFor,
  clanCoreModule,
  mutant ? "",
  extraModule ? { },
}:
let
  s3Port = 8333;
  # The fixture topology, with the object storage at this test's `s3` VM. Plain http:
  # what is under test is what reaches the bucket, not the transport, and
  # tests/cluster-single.nix covers the https path.
  testTopology = lib.recursiveUpdate topology {
    objectStorage.endpoint = "http://s3:${toString s3Port}";
  };
  harness = harnessFor testTopology;
  clusterLib = import ../lib { inherit lib; };
  net = clusterLib.net;
  jfs = clusterLib.juicefs;
  os = testTopology.objectStorage;
  node = testTopology.nodes.node1;
  meshIp = net.meshIp testTopology node;

  s3ak = harness.fixtureFor "ovh-s3" "access-key";
  s3sk = harness.fixtureFor "ovh-s3" "secret-key";
  pgpass = harness.fixtureFor "juicefs-pg" "password";
  # The plaintext control volume's bucket, and the restic repository's.
  plainBucket = "ci-plain";
  resticBucket = "ci-restic";

  # Another key under the same passphrase, so a load with it fails on the key and
  # not on the passphrase.
  wrongPem = pkgs.runCommand "jfs-wrong-pem" { nativeBuildInputs = [ pkgs.openssl ]; } ''
    openssl genrsa -aes256 -passout file:${harness.pki}/rsa-passphrase -out $out 2048
  '';

  tools = [
    pkgs.juicefs
    pkgs.rclone
    pkgs.jq
    pkgs.gzip
  ];
in
pkgs.testers.runNixOSTest {
  name = "jfs-encrypted";

  node.specialArgs = {
    topology = testTopology;
    inherit clusterLib;
  };

  nodes = {
    s3 =
      { pkgs, ... }:
      {
        virtualisation.memorySize = 512;
        networking.firewall.enable = false;
        systemd.services.s3 = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          serviceConfig.Restart = "on-failure";
          # The buckets are directories: creating one is not writing an object.
          script = ''
            mkdir -p ${
              lib.concatMapStringsSep " " (b: "/srv/s3/${b}") [
                os.juicefsBucket
                plainBucket
                resticBucket
              ]
            }
            # The fixture's pair, or the pairs in /run/s3-auth, one a line: how the
            # rotation subtest issues a new key and then revokes the old one.
            keys=()
            if [ -s /run/s3-auth ]; then
              while read -r k; do keys+=(--auth-key "$k"); done < /run/s3-auth
            else
              keys=(--auth-key ${s3ak},${s3sk})
            fi
            exec ${pkgs.rclone}/bin/rclone serve s3 --addr 0.0.0.0:${toString s3Port} \
              "''${keys[@]}" /srv/s3
          '';
        };
        environment.systemPackages = [ pkgs.gzip ];
      };

    node1 =
      { config, pkgs, ... }:
      {
        imports = [
          clanCoreModule
          ../modules/vars.nix
          ../modules/storage-juicefs.nix
          ../modules/storage-juicefs-meta.nix
          # Only the generators the JuiceFS units read: the rest are Nomad's and the
          # mesh's, whose owners (systemd-network) this VM doesn't have.
          (harness.secretsModuleFor (
            gen:
            lib.elem gen [
              "ovh-s3"
              "juicefs-pg"
              "juicefs-rsa"
            ]
          ))
          extraModule
        ];
        _module.args = {
          inherit node;
          nodeName = "node1";
        };

        virtualisation.memorySize = 2048;
        virtualisation.cores = 2;
        system.stateVersion = testTopology.stateVersion;

        clan.core.enableRecommendedDefaults = false;
        clan.core.settings.state-version.enable = false;
        clan.core.settings.machine.name = "node1";
        # The fixture's directory, as a string for the reason in tests/fixtures/default.nix.
        clan.core.settings.directory = toString ./fixtures;
        clan.core.vars.settings.secretStore = "age";

        # The control-mesh address the metadata URL names (lib/net.nix jfsMetaHost),
        # under the unit name every mesh-bound service waits for.
        systemd.services."${net.meshIf}-ready" = {
          wantedBy = [ "multi-user.target" ];
          before = [
            "postgresql.service"
            "juicefs-mount.service"
          ];
          path = [ pkgs.iproute2 ];
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
          };
          script = ''
            ip link add ${net.meshIf} type dummy 2>/dev/null || true
            ip addr replace ${meshIp}/24 dev ${net.meshIf}
            ip link set ${net.meshIf} up
          '';
        };

        # No Nomad here: nothing to advertise to. And no write probe: the test takes
        # the mount away on purpose, more than once.
        systemd.services.jfs-nomad-meta.enable = lib.mkForce false;
        systemd.timers.jfs-probe.enable = lib.mkForce false;

        environment.systemPackages = tools ++ [ pkgs.util-linux ];
      };

    rescue =
      { pkgs, ... }:
      {
        virtualisation.memorySize = 1024;
        environment.systemPackages = tools ++ [ pkgs.restic ];
      };
  };

  testScript =
    { nodes, ... }:
    let
      gens = nodes.node1.clan.core.vars.generators;
    in
    ''
      import json
      import secrets
      import time

      MUTANT = "${mutant}"
      ${builtins.readFile ./lib/control.py}

      PEM = "${gens.juicefs-rsa.files."rsa.pem".path}"
      S3AK_PATH = "${gens.ovh-s3.files."access-key".path}"
      S3SK_PATH = "${gens.ovh-s3.files."secret-key".path}"
      S3AK = "${s3ak}"
      S3SK = "${s3sk}"
      FORMAT_STATE = "/var/lib/juicefs-format"
      PROBE_METRIC = "/var/lib/prometheus-node-exporter-text/jfs_probe.prom"
      PASS = "${gens.juicefs-rsa.files."rsa-passphrase".path}"
      WRONG_PEM = "${wrongPem}"
      META = "${jfs.metaDb}"
      META_URL = "postgres://${jfs.metaDb}:${pgpass}@${meshIp}:${toString jfs.metaPort}/${jfs.metaDb}"
      VOL = "${jfs.jfsName}"
      BUCKET = "${os.juicefsBucket}"
      PLAIN = "${plainBucket}"
      RESTIC = "${resticBucket}"
      S3_URL = "${os.endpoint}"
      MNT = "${jfs.mountPoint}"
      METRIC = "/var/lib/prometheus-node-exporter-text/jfs_encrypted.prom"
      # rclone, configured as juicefs-format configures it: from the environment.
      RCLONE_ENV = ("RCLONE_CONFIG_JFS_TYPE=s3 RCLONE_CONFIG_JFS_PROVIDER=Other"
                    f" RCLONE_CONFIG_JFS_ENDPOINT={S3_URL} RCLONE_CONFIG_JFS_REGION=${os.region}"
                    " RCLONE_CONFIG_JFS_ACCESS_KEY_ID=${s3ak} RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY=${s3sk}")

      CANARY = "JFS-CANARY-" + secrets.token_hex(16)
      CANARY_NAME = "jfs-canary-name-" + secrets.token_hex(8)

      def psql(sql, db="postgres"):
          return node1.succeed(f"runuser -u postgres -- psql -v ON_ERROR_STOP=1 --no-psqlrc -d {db} -tAc \"{sql}\"").strip()

      def tables():
          return int(psql("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'", META))

      def wipe_metadata():
          """The metadata node's disk lost: an empty database, as a reinstall leaves it."""
          node1.succeed("systemctl stop jfs-health.service juicefs-mount.service juicefs-format.service")
          node1.succeed("systemctl reset-failed jfs-health.service juicefs-mount.service juicefs-format.service")
          psql(f"DROP DATABASE {META} WITH (FORCE)")
          psql(f"CREATE DATABASE {META} OWNER {META}")
          assert tables() == 0

      def status(url=META_URL):
          return json.loads(node1.succeed(f"juicefs status '{url}' 2>/dev/null"))

      def since():
          return node1.succeed("date +%s").strip()

      def journal(unit, ts):
          return node1.succeed(f"journalctl -u {unit} --since @{ts} --no-pager -o cat")

      def main_status(unit):
          return int(node1.succeed(f"systemctl show -p ExecMainStatus --value {unit}").strip())

      def run_format(keep_retrying=False):
          """juicefs-format once, as boot runs it. (rc of the unit's main process, its log)
          An outage (rc 4) leaves the unit waiting to retry on its own; unless the case is
          about that retry, it is cancelled here, so a retry can't run into the next case."""
          ts = since()
          node1.execute("systemctl restart juicefs-format.service")
          rc = main_status("juicefs-format.service")
          log = journal("juicefs-format.service", ts)
          if rc == 4 and not keep_retrying:
              node1.execute("systemctl stop juicefs-format.service")
          return rc, log

      def substate(unit):
          return node1.succeed(f"systemctl show -p SubState --value {unit}").strip()

      def mount_within(seconds):
          """Start the mount and wait for it, without raising: a mutant must reach its control."""
          node1.execute("systemctl reset-failed juicefs-mount.service; systemctl start juicefs-mount.service")
          deadline = time.monotonic() + seconds
          while time.monotonic() < deadline:
              if mounted():
                  node1.execute("systemctl start jfs-health.service")
                  return True
              time.sleep(2)
          return False

      def stored_secret():
          raw = psql("SELECT value FROM jfs_setting WHERE name = 'format'", META)
          return json.loads(raw).get("SecretKey") if raw else None

      def newest_dump():
          dumps = [d for d in rclone(f"lsf jfs:{BUCKET}/{VOL}/meta/ --files-only").split() if d.startswith("dump-")]
          return sorted(dumps)[-1]

      def load_by_hand():
          """What a restore leaves when its `config` step never ran: the newest dump loaded with
          the key, and the dump's redacted secret ("removed") in the settings."""
          d = newest_dump()
          rclone(f"copyto jfs:{BUCKET}/{VOL}/meta/{d} /tmp/{d}")
          node1.succeed(f"JFS_RSA_PASSPHRASE=$(cat {PASS}) juicefs load '{META_URL}' /tmp/{d}"
                        f" --encrypt-rsa-key {PEM} --encrypt-algo ${jfs.encryptAlgo} 2>/dev/null && rm -f /tmp/{d}")
          return d

      def bucket_hits(path, needle):
          """Files under the S3 VM's backing `path` holding `needle`, read raw and, where
          they are gzip, decompressed (zcat -f passes anything else through)."""
          out = s3.succeed(
              # grep -c, not -q: -q exits at the first match, zcat dies of SIGPIPE, and
              # the driver's pipefail turns that into a failed command.
              f"find {path} -type f -print0 | while IFS= read -r -d ''' f; do"
              f" if zcat -f \"$f\" 2>/dev/null | grep -acF -- '{needle}' >/dev/null; then echo \"$f\"; fi;"
              " done || true"
          )
          return [l for l in out.splitlines() if l]

      def rclone(args):
          return node1.succeed(f"{RCLONE_ENV} rclone {args}")

      def set_secret(path, src=None, content=None):
          if src is not None:
              node1.succeed(f"cp {src} {path}")
          else:
              node1.succeed(f"printf %s '{content}' > {path}")

      def mounted():
          return node1.execute(f"mountpoint -q {MNT}")[0] == 0

      def canary_ok(where=MNT):
          return node1.execute(f"grep -qxF -- '{CANARY}' {where}/{CANARY_NAME}")[0] == 0

      def main():
          s3.start()
          s3.wait_for_unit("s3.service")
          s3.wait_for_open_port(${toString s3Port})
          node1.start()
          rescue.start()

          with subtest("metric-exported"):
              for u in ["postgresql.service", "juicefs-pg-password.service", "juicefs-format.service",
                        "juicefs-mount.service", "jfs-health.service"]:
                  node1.wait_for_unit(u)
              node1.wait_until_succeeds(f"mountpoint -q {MNT}", timeout=120)
              metric = node1.succeed(f"cat {METRIC}").strip()
              st = status()["Setting"]
              detail = f"metric {metric!r}; EncryptKey {st.get('EncryptKey')!r}, EncryptAlgo {st.get('EncryptAlgo')!r}"
              print(f"metric-exported: {detail}")
              control("metric-exported", metric == "cluster_jfs_encrypted 1" and st.get("EncryptKey") == "removed", detail)
              UUID = st["UUID"]

          with subtest("ciphertext-in-bucket"):
              node1.succeed(f"echo '{CANARY}' > {MNT}/{CANARY_NAME} && sync")
              s3.wait_until_succeeds(f"find /srv/s3/{BUCKET}/{VOL}/chunks -type f | grep -q .", timeout=60)
              # An automatic metadata dump, which is what the restore path reads. The
              # mount makes the first one interval/10 after it starts and refuses an
              # interval under 5 minutes unless told otherwise; production's (1 h) would
              # take 6 minutes. So a second, short-lived client of the same volume.
              node1.succeed(
                  f"mkdir -p /mnt/dumper /var/cache/dumper && JFS_RSA_PASSPHRASE=$(cat {PASS})"
                  f" SKIP_BACKUP_META_CHECK=true juicefs mount -d '{META_URL}' /mnt/dumper"
                  " --backup-meta 10s --cache-dir /var/cache/dumper --no-usage-report"
              )
              s3.wait_until_succeeds(f"ls /srv/s3/{BUCKET}/{VOL}/meta/ | grep -q '^dump-.*\\.json\\.gz$'", timeout=120)
              node1.succeed("juicefs umount /mnt/dumper")
              dump = s3.succeed(f"ls /srv/s3/{BUCKET}/{VOL}/meta/ | grep '^dump-' | sort | tail -1").strip()
              content = bucket_hits(f"/srv/s3/{BUCKET}", CANARY)
              names = bucket_hits(f"/srv/s3/{BUCKET}", CANARY_NAME)
              uuid_obj = f"/srv/s3/{BUCKET}/{VOL}/juicefs_uuid"
              uuid_plain = bucket_hits(uuid_obj, UUID)
              uuid_size = int(s3.succeed(f"stat -c %s {uuid_obj}").strip())
              dump_gz = s3.execute(f"gzip -t /srv/s3/{BUCKET}/{VOL}/meta/{dump}")[0] == 0
              # Positive control for the name grep: a manual dump is plaintext and has it.
              node1.succeed(f"juicefs dump '{META_URL}' /tmp/manual-dump.json 2>/dev/null")
              manual = node1.execute(f"grep -cF -- '{CANARY_NAME}' /tmp/manual-dump.json")[1].strip()
              node1.succeed("rm -f /tmp/manual-dump.json")
              detail = (f"content hits {content}, name hits {names}, uuid in juicefs_uuid {uuid_plain}"
                        f" (size {uuid_size}), dump {dump} gzip-valid {dump_gz}, name in a manual dump {manual}")
              print(f"ciphertext-in-bucket: {detail}")
              control("ciphertext-in-bucket",
                      content == [] and names == [] and uuid_plain == [] and uuid_size > 0
                      and not dump_gz and int(manual or 0) > 0, detail)

          with subtest("restic-password-wrong"):
              rescue.succeed(f"""cat > /root/restic.sh <<'EOF'
      set -eu
      export AWS_ACCESS_KEY_ID=${s3ak} AWS_SECRET_ACCESS_KEY=${s3sk}
      export RESTIC_REPOSITORY=s3:{S3_URL}/{RESTIC}
      export RESTIC_PASSWORD=ci-restic-right
      mkdir -p /root/data && echo '{CANARY}' > /root/data/{CANARY_NAME}
      restic init >/dev/null
      restic backup /root/data >/dev/null
      rc=0; RESTIC_PASSWORD=ci-restic-wrong restic snapshots >/dev/null 2>/root/wrong.err || rc=$?
      echo "wrong=$rc"
      restic restore latest --target /root/restored >/dev/null
      grep -qxF '{CANARY}' /root/restored/root/data/{CANARY_NAME} && echo restored=1
      EOF""")
              out = rescue.succeed("bash /root/restic.sh")
              content = bucket_hits(f"/srv/s3/{RESTIC}", CANARY)
              names = bucket_hits(f"/srv/s3/{RESTIC}", CANARY_NAME)
              detail = f"{out.split()}; content hits {content}, name hits {names}"
              print(f"restic-password-wrong: {detail}")
              control("restic-password-wrong",
                      "wrong=12" in out and "restored=1" in out and content == [] and names == [], detail)

          # ── a plaintext volume where the encrypted one was ──────────────────────
          with subtest("status-field-gate"):
              wipe_metadata()
              node1.succeed(
                  f"juicefs format --storage s3 --bucket {S3_URL}/{PLAIN} --access-key ${s3ak}"
                  f" --secret-key ${s3sk} --trash-days 1 '{META_URL}' {VOL} 2>/dev/null"
              )
              st = status()["Setting"]
              plain_meta = node1.succeed(f"juicefs status '{META_URL}' 2>/dev/null | jq -S .Setting")
              listing = s3.succeed(f"find /srv/s3/{BUCKET} /srv/s3/{PLAIN} -type f | sort | sha256sum")
              looks = st.get("EncryptAlgo") == "aes256gcm-rsa" and st.get("KeyEncrypted") is True
              rc, log = run_format()
              detail = (f"EncryptAlgo {st.get('EncryptAlgo')!r}, KeyEncrypted {st.get('KeyEncrypted')!r},"
                        f" EncryptKey {st.get('EncryptKey')!r}; juicefs-format rc {rc}")
              print(f"status-field-gate: {detail}")
              control("status-field-gate", looks and "EncryptKey" not in st and rc == 3
                      and "REFUSING: the volume at this metadata engine is NOT encrypted" in log, detail)

          with subtest("refuse-plaintext-metadata"):
              # The same run as above: it changed nothing, in the metadata or in either bucket.
              after = node1.succeed(f"juicefs status '{META_URL}' 2>/dev/null | jq -S .Setting")
              same = after == plain_meta
              objects = s3.succeed(f"find /srv/s3/{BUCKET} /srv/s3/{PLAIN} -type f | sort | sha256sum") == listing
              trash = status()["Setting"].get("TrashDays")
              detail = (f"rc {rc}; setting unchanged {same}; objects unchanged {objects};"
                        f" TrashDays {trash} (the encrypted branch would make it ${toString jfs.trashDays})")
              print(f"refuse-plaintext-metadata: {detail}")
              control("refuse-plaintext-metadata", rc == 3 and same and objects and trash == 1, detail)

          with subtest("refuse-plaintext-mount"):
              node1.succeed(f"rm -f {METRIC}")
              ts = since()
              node1.succeed("systemctl start juicefs-mount.service")
              node1.wait_until_succeeds(
                  "systemctl is-failed --quiet juicefs-mount.service || mountpoint -q " + MNT, timeout=120)
              time.sleep(8)   # past RestartSec: a refusal must not come back
              failed = node1.execute("systemctl is-failed --quiet juicefs-mount.service")[0] == 0
              rc = main_status("juicefs-mount.service")
              metric = node1.execute(f"cat {METRIC}")[1].strip()
              log = journal("juicefs-mount.service", ts)
              detail = f"failed {failed}, rc {rc}, mounted {mounted()}, metric {metric!r}"
              print(f"refuse-plaintext-mount: {detail}")
              control("refuse-plaintext-mount",
                      failed and rc == 3 and not mounted() and metric == "cluster_jfs_encrypted 0"
                      and "REFUSING" in log, detail)

          with subtest("positive-control-plaintext"):
              node1.succeed(
                  f"mkdir -p /mnt/plain /var/cache/plain && juicefs mount -d '{META_URL}' /mnt/plain"
                  " --cache-dir /var/cache/plain --no-usage-report --backup-meta 0"
              )
              node1.succeed(f"echo '{CANARY}' > /mnt/plain/{CANARY_NAME} && sync")
              s3.wait_until_succeeds(f"find /srv/s3/{PLAIN}/{VOL}/chunks -type f | grep -q .", timeout=60)
              uuid = status()["Setting"]["UUID"]
              # The plaintext dump planted later: what someone with only bucket access
              # could write.
              node1.succeed(f"juicefs dump '{META_URL}' /tmp/plain-dump.json.gz 2>/dev/null")
              node1.succeed("juicefs umount /mnt/plain")
              content = bucket_hits(f"/srv/s3/{PLAIN}", CANARY)
              uuid_hit = bucket_hits(f"/srv/s3/{PLAIN}/{VOL}/juicefs_uuid", uuid)
              detail = f"content hits {content}, uuid in juicefs_uuid {uuid_hit}"
              print(f"positive-control-plaintext: {detail}")
              control("positive-control-plaintext", len(content) >= 1 and len(uuid_hit) == 1, detail)

          # ── restore, and what it refuses ─────────────────────────────────────────
          with subtest("objects-no-dump-refused"):
              wipe_metadata()
              rclone(f"move jfs:{BUCKET}/{VOL}/meta jfs:{BUCKET}/ci-held")
              rc, log = run_format()
              t = tables()
              rclone(f"move jfs:{BUCKET}/ci-held jfs:{BUCKET}/{VOL}/meta")
              detail = f"rc {rc}, tables {t}"
              print(f"objects-no-dump-refused: {detail}")
              # 5, not 4: a verdict for a human, which systemd does not retry.
              control("objects-no-dump-refused",
                      rc == 5 and t == 0 and "refusing to format" in log and "destroys every file" in log, detail)

          with subtest("object-storage-down-no-verdict"):
              # Still no metadata, and now no S3 either. A failed listing is not an
              # empty bucket: formatting here would put a new volume over the old one.
              s3.succeed("systemctl stop s3.service")
              rc, log = run_format(keep_retrying=True)
              # An outage is retried by systemd (RestartForceExitStatus=4), not left failed.
              retrying = substate("juicefs-format.service")
              node1.execute("systemctl stop juicefs-format.service")
              t = tables()
              s3.succeed("systemctl start s3.service")
              s3.wait_for_open_port(${toString s3Port})
              detail = f"rc {rc}, tables {t}, unit {retrying}"
              print(f"object-storage-down-no-verdict: {detail}")
              control("object-storage-down-no-verdict",
                      rc == 4 and t == 0 and "object storage unreachable" in log and "restoring" not in log
                      and retrying == "auto-restart", detail)

          def restored():
              node1.succeed("systemctl start juicefs-mount.service")
              node1.wait_until_succeeds(f"mountpoint -q {MNT}", timeout=120)
              node1.succeed("systemctl start jfs-health.service")

          with subtest("restore-from-dump"):
              rc, log = run_format()
              ok = rc == 0 and "restoring dump-" in log
              if ok:
                  restored()
              st = status()["Setting"] if ok else {}
              metric = node1.execute(f"cat {METRIC}")[1].strip()
              detail = f"rc {rc}, EncryptKey {st.get('EncryptKey')!r}, canary {ok and canary_ok()}, metric {metric!r}; log tail {log[-300:]!r}"
              print(f"restore-from-dump: {detail}")
              control("restore-from-dump",
                      ok and st.get("EncryptKey") == "removed" and canary_ok() and metric == "cluster_jfs_encrypted 1", detail)

          with subtest("stale-dump-refused"):
              # The newest dump is years old: the dumps stopped. Restoring it would lose
              # everything since, so a human decides, by naming that exact dump.
              stale = "dump-2020-01-01-000000.json.gz"
              newest = newest_dump()
              rclone(f"move jfs:{BUCKET}/{VOL}/meta jfs:{BUCKET}/ci-held-dumps")
              rclone(f"copyto jfs:{BUCKET}/ci-held-dumps/{newest} jfs:{BUCKET}/{VOL}/meta/{stale}")
              wipe_metadata()
              rc, log = run_format()
              t = tables()
              node1.succeed(f"echo {stale} > {FORMAT_STATE}/restore-stale-dump")
              rc2, log2 = run_format()
              consumed = node1.execute(f"test -e {FORMAT_STATE}/restore-stale-dump")[0] != 0
              back = rc2 == 0 and mount_within(120) and canary_ok()
              rclone(f"deletefile jfs:{BUCKET}/{VOL}/meta/{stale}")
              rclone(f"move jfs:{BUCKET}/ci-held-dumps jfs:{BUCKET}/{VOL}/meta")
              detail = (f"refused: rc {rc}, tables {t}, log tail {log[-260:]!r}; with the override: rc {rc2},"
                        f" restored {stale}: {('restoring ' + stale) in log2}, override consumed {consumed}, canary {back}")
              print(f"stale-dump-refused: {detail}")
              control("stale-dump-refused",
                      rc == 5 and t == 0 and "refusing to restore" in log
                      and rc2 == 0 and ("restoring " + stale) in log2 and consumed and back, detail)

          node1.succeed(f"cp {PASS} /root/pass.good && cp {PEM} /root/pem.good")

          def refused_restore(name, expect):
              wipe_metadata()
              rc, log = run_format()
              t = tables()
              detail = f"rc {rc}, tables {t}, expected {expect!r} in the log: {expect in log}"
              print(f"{name}: {detail}")
              return rc == 1 and t == 0 and expect in log, detail

          with subtest("no-passphrase-refused"):
              set_secret(PASS, content="")
              ok, detail = refused_restore("no-passphrase-refused", "passphrase is required to private key")
              control("no-passphrase-refused", ok, detail)

          with subtest("wrong-passphrase-refused"):
              set_secret(PASS, content="0123456789abcdef0123456789abcdef")
              ok, detail = refused_restore("wrong-passphrase-refused", "cannot decode encrypted private keys")
              control("wrong-passphrase-refused", ok, detail)

          with subtest("wrong-pem-load-refused"):
              set_secret(PASS, src="/root/pass.good")
              set_secret(PEM, src=WRONG_PEM)
              ok, detail = refused_restore("wrong-pem-load-refused", "decryption error")
              control("wrong-pem-load-refused", ok, detail)

          with subtest("planted-plaintext-dump-refused"):
              set_secret(PEM, src="/root/pem.good")
              planted = "dump-2099-01-01-000000.json.gz"
              rclone(f"copyto /tmp/plain-dump.json.gz jfs:{BUCKET}/{VOL}/meta/{planted}")
              ok, detail = refused_restore("planted-plaintext-dump-refused", "malformed ciphertext")
              rclone(f"deletefile jfs:{BUCKET}/{VOL}/meta/{planted}")
              control("planted-plaintext-dump-refused", ok, detail)

          # Back to a working volume with the right key, for what follows.
          rc, log = run_format()
          assert rc == 0, log
          restored()
          assert canary_ok()

          with subtest("interrupted-load-recovers"):
              # A load cut short: JuiceFS's tables, and no format row. JuiceFS refuses to
              # load into a database that has any table, so without the cleanup every
              # later run fails the same way.
              wipe_metadata()
              load_by_hand()
              psql("DELETE FROM jfs_setting WHERE name = 'format'", META)
              before = tables()
              said = node1.execute(f"juicefs status '{META_URL}' 2>&1 >/dev/null")[1]
              rc, log = run_format()
              back = rc == 0 and mount_within(120) and canary_ok()
              detail = (f"tables before {before}, status said not formatted: {'not formatted' in said};"
                        f" rc {rc}, canary {back}; log tail {log[-300:]!r}")
              print(f"interrupted-load-recovers: {detail}")
              control("interrupted-load-recovers",
                      before > 0 and "not formatted" in said and rc == 0 and "a restore was interrupted" in log
                      and back, detail)

          with subtest("interrupted-restore-recovers"):
              # A restore whose `config` step failed after the load: the settings keep the
              # dump's redacted secret. With S3 down the run is an outage (4) and systemd
              # retries it; once S3 is back the retry puts the pair back and the mount works.
              wipe_metadata()
              load_by_hand()
              before = stored_secret()
              s3.succeed("systemctl stop s3.service")
              rc, log = run_format(keep_retrying=True)
              retrying = substate("juicefs-format.service")
              s3.succeed("systemctl start s3.service")
              s3.wait_for_open_port(${toString s3Port})
              recovered = False
              for _ in range(60):
                  if node1.execute("systemctl is-active --quiet juicefs-format.service")[0] == 0:
                      recovered = True
                      break
                  time.sleep(2)
              restarts = node1.succeed("systemctl show -p NRestarts --value juicefs-format.service").strip()
              after = stored_secret()
              back = mount_within(120) and canary_ok()
              detail = (f"secret before {before!r}; with S3 down rc {rc}, unit {retrying}; recovered on its own"
                        f" {recovered} after {restarts} restarts, secret now removed: {after == 'removed'}; mount and"
                        f" canary {back}; log tail {log[-300:]!r}")
              print(f"interrupted-restore-recovers: {detail}")
              control("interrupted-restore-recovers",
                      before == "removed" and rc == 4 and "could not put the object-storage credentials" in log
                      and retrying == "auto-restart" and recovered and after not in (None, "", "removed") and back,
                      detail)

          with subtest("s3-key-rotation"):
              # ovh-s3 rotated: the new pair reaches the volume's settings when the unit
              # re-runs (a switch does, through restartTriggers), the RUNNING mount picks it
              # up, and still writes once the old key is revoked.
              new_ak = "ci-rotated-" + secrets.token_hex(4)
              new_sk = secrets.token_hex(20)
              s3.succeed(f"printf '%s\\n%s\\n' '{S3AK},{S3SK}' '{new_ak},{new_sk}' > /run/s3-auth"
                         " && systemctl restart s3.service")
              s3.wait_for_open_port(${toString s3Port})
              set_secret(S3AK_PATH, content=new_ak)
              set_secret(S3SK_PATH, content=new_sk)
              ts = since()
              rc, log = run_format()
              ak = status()["Setting"].get("AccessKey")
              reloaded = False
              for _ in range(90):
                  if new_ak in journal("juicefs-mount.service", ts):
                      reloaded = True
                      break
                  time.sleep(2)
              # The old key revoked at the issuer.
              s3.succeed(f"printf '%s\\n' '{new_ak},{new_sk}' > /run/s3-auth && systemctl restart s3.service")
              s3.wait_for_open_port(${toString s3Port})
              wrote = node1.execute(f"timeout 120 dd if=/dev/urandom of={MNT}/ci-rotated bs=1M count=2 conv=fsync status=none")[0]
              node1.execute(f"rm -f {MNT}/ci-rotated")
              # Both pairs again, for the escrow case at the end (the rescue VM has the fixture's).
              s3.succeed(f"printf '%s\\n%s\\n' '{S3AK},{S3SK}' '{new_ak},{new_sk}' > /run/s3-auth"
                         " && systemctl restart s3.service")
              s3.wait_for_open_port(${toString s3Port})
              detail = (f"run rc {rc}, stored AccessKey is the new one {ak == new_ak}, the mount reloaded it {reloaded},"
                        f" write with the old key revoked rc {wrote}; log tail {log[-200:]!r}")
              print(f"s3-key-rotation: {detail}")
              control("s3-key-rotation",
                      rc == 0 and "vars not yet applied" in log and ak == new_ak and reloaded and wrote == 0, detail)

          with subtest("probe-needs-the-mount"):
              # The write probe on the mount, then on the bare directory a dead mount leaves.
              rc_up = node1.execute("systemctl start jfs-probe.service")[0]
              up = node1.execute(f"cat {PROBE_METRIC}")[1]
              node1.succeed("systemctl stop jfs-health.service juicefs-mount.service")
              node1.execute(f"mountpoint -q {MNT} && umount -l {MNT}")
              bare = not mounted()
              rc_down = node1.execute("systemctl start jfs-probe.service")[0]
              down = node1.execute(f"cat {PROBE_METRIC}")[1]
              node1.execute("systemctl reset-failed jfs-probe.service")
              back = mount_within(120)
              detail = f"mounted: rc {rc_up} {up.split()[:2]}; bare directory {bare}: rc {rc_down} {down.split()[:2]}; remounted {back}"
              print(f"probe-needs-the-mount: {detail}")
              control("probe-needs-the-mount",
                      rc_up == 0 and "cluster_jfs_probe_success 1" in up and bare
                      and rc_down != 0 and "cluster_jfs_probe_success 0" in down and back, detail)

          with subtest("metadata-down"):
              node1.succeed("systemctl stop jfs-health.service juicefs-mount.service")
              node1.succeed(f"rm -f {METRIC}")
              node1.succeed("systemctl stop postgresql.service")
              ts = since()
              node1.succeed("systemctl start juicefs-mount.service")
              node1.wait_until_succeeds(
                  f"journalctl -u juicefs-mount.service --since @{ts} -o cat | grep -q 'metadata unreachable'", timeout=180)
              node1.wait_until_succeeds("test \"$(systemctl show -p ExecMainStatus --value juicefs-mount.service)\" = 4", timeout=60)
              node1.wait_until_succeeds("test \"$(systemctl show -p NRestarts --value juicefs-mount.service)\" -ge 1", timeout=120)
              failed = node1.execute("systemctl is-failed --quiet juicefs-mount.service")[0] == 0
              no_metric = node1.execute(f"test -e {METRIC}")[0] != 0
              refusing = "REFUSING" in journal("juicefs-mount.service", ts)
              node1.succeed("systemctl start postgresql.service")
              node1.wait_until_succeeds(f"mountpoint -q {MNT}", timeout=180)
              node1.succeed("systemctl start jfs-health.service")
              metric = node1.execute(f"cat {METRIC}")[1].strip()
              detail = (f"while down: failed {failed}, metric written {not no_metric}, REFUSING logged {refusing};"
                        f" after: mounted, metric {metric!r}, canary {canary_ok()}")
              print(f"metadata-down: {detail}")
              control("metadata-down", not failed and no_metric and not refusing
                      and metric == "cluster_jfs_encrypted 1" and canary_ok(), detail)

          with subtest("total-loss-escrow-only"):
              pem = node1.succeed(f"cat {PEM}")
              passphrase = node1.succeed(f"cat {PASS}")
              node1.crash()
              rescue.succeed("mkdir -p /root/escrow && chmod 0700 /root/escrow")
              rescue.succeed(f"cat > /root/escrow/rsa.pem <<'EOF'\n{pem}EOF")
              rescue.succeed(f"printf %s '{passphrase}' > /root/escrow/rsa-passphrase")
              rescue.succeed(f"""cat > /root/rebuild.sh <<'EOF'
      set -eu
      # The escrow and nothing else: the PEM, its passphrase, the S3 credentials.
      export RCLONE_CONFIG_JFS_TYPE=s3 RCLONE_CONFIG_JFS_PROVIDER=Other
      export RCLONE_CONFIG_JFS_ENDPOINT={S3_URL} RCLONE_CONFIG_JFS_REGION=${os.region}
      export RCLONE_CONFIG_JFS_ACCESS_KEY_ID=${s3ak} RCLONE_CONFIG_JFS_SECRET_ACCESS_KEY=${s3sk}
      export JFS_RSA_PASSPHRASE="$(cat /root/escrow/rsa-passphrase)"
      mkdir -p /root/r /mnt/rescue
      latest=$(rclone lsf jfs:{BUCKET}/{VOL}/meta/ --files-only | grep '^dump-.*\\.json\\.gz$' | sort | tail -1)
      rclone copyto "jfs:{BUCKET}/{VOL}/meta/$latest" "/root/r/$latest"
      m=sqlite3:///root/r/meta.db
      juicefs load "$m" "/root/r/$latest" --encrypt-rsa-key /root/escrow/rsa.pem --encrypt-algo ${jfs.encryptAlgo}
      juicefs config "$m" --access-key ${s3ak} --secret-key ${s3sk} --yes
      juicefs mount -d "$m" /mnt/rescue --read-only --no-bgjob --cache-dir /root/r/cache --no-usage-report
      echo "restored from $latest"
      EOF""")
              rc, out = rescue.execute("env -i PATH=/run/current-system/sw/bin HOME=/root bash /root/rebuild.sh > /root/rebuild.log 2>&1; rc=$?; tail -n 5 /root/rebuild.log; exit $rc")
              read = rescue.execute(f"grep -qxF -- '{CANARY}' /mnt/rescue/{CANARY_NAME}")[0] == 0
              key = rescue.execute("juicefs status sqlite3:///root/r/meta.db 2>/dev/null | jq -r .Setting.EncryptKey")[1].strip()
              detail = f"rebuild rc {rc}, canary read {read}, EncryptKey {key!r}; log tail {out.strip()[-300:]!r}"
              print(f"total-loss-escrow-only: {detail}")
              control("total-loss-escrow-only", rc == 0 and read and key == "removed", detail)

      run_main(main)
    '';
}
