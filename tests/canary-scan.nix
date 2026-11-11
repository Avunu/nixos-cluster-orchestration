# VM test: the canary scan (modules/canary-scan.nix, design WS14, Appendix K). Every
# class has its positive control: a scan that cannot find anything proves nothing.
#
# Two machines:
#
#   s3      `rclone serve s3` (as in tests/jfs-encrypted.nix), and the off-host audit
#           receiver: the REAL watchdog Worker behind tests/lib/audit-stub.mjs, on http.
#   node1   the REAL modules/canary-scan.nix, with the real modules/vars.nix,
#           storage-juicefs.nix and storage-juicefs-meta.nix under clanCore for the s3
#           class (the jfs-encrypted pattern: fixture secrets, a dummy interface for the
#           mesh address), modules/coredumps-off.nix, and the audit spool's sender.
#           Extra disks, by serial: an ESP (vfat at /boot), a plain swap (declared
#           noauto), a random-key swap (as the encrypted layout makes it), and a plain and
#           a LUKS disk for the raw class (cluster.canary.rawDisks on). zswap is off, so
#           what is swapped out is on the swap device and not in a RAM pool.
#
# The scan runs as its unit runs it, through `systemctl start`. The test only plants and
# removes the canary, and reads the unit's metrics.
#
# Subtests, in order:
#
#   seed-timestamp                    before any scan: canary.prom holds the seed's
#                                     timestamp and nothing else
#   baseline-all-zero                 every class reported, every one 0, the run ok and
#                                     its timestamp moved on
#   s3-encrypted-no-hits              the canary is planted on the encrypted volume,
#                                     `juicefs info` names its objects, and neither they
#                                     nor anything else in the bucket hold it
#   s3-positive-control-plaintext     the same scan pointed at a plaintext volume finds it
#                                     in its object, and so does a grep of that bucket
#   cannot-look-fails                 a volume that is not mounted: the unit fails, the s3
#                                     line is missing, the timestamp stays where it was
#   tmp-positive-control, tmp-removed /tmp and /var/tmp, with a FIFO in /tmp that must not
#                                     hold the scan
#   event-delivered                   the hit reached the Worker as a `canary` event
#   esp-positive-control, esp-removed a file on the vfat ESP
#   esp-unmounted-cannot-look         an ESP directory with nothing mounted on it: alone the
#                                     class fails the unit; beside a mounted ESP it is skipped
#   journal-entry-compressed          the planted entry is in the journal (journalctl)
#                                     and NOT in the journal files as text: journald
#                                     compressed it, so a grep of the files is blind
#   journal-positive-control          the scan finds it anyway   <- canary-raw-grep-journal
#   journal-container-positive-control  that journal file, moved to a container's journal
#                                     directory and gone from the host's, is still found
#   journal-removed
#   coredump-real-core-raw-grep-blind a real core through systemd-coredump (the pipe put
#                                     back for one crash) is .zst, holds the canary
#                                     (zstdcat), and a grep of the file finds nothing
#   coredump-positive-control         the scan counts it, and a file in a container's
#                                     coredump directory, whatever their content
#   coredump-removed                  and the pipe that discards cores is back
#   swap-positive-control             memory holding the canary swapped to the PLAIN swap
#   swap-removed                      that device wiped
#   swap-dm-crypt                     the same through the random-key swap: the mapping
#                                     holds it, the device under it does not, 0 hits
#   raw-positive-control, raw-removed the canary on the plain disk, and under LUKS on the
#                                     other, which the raw class must not see
#   all-zero-at-end                   nothing planted is left anywhere, and nothing the
#                                     test did put the canary somewhere unplanned
#
# Mutant (flake.nix legacyPackages.mutants, through cluster.canary.script):
#   canary-raw-grep-journal   the journal class greps the journal files -> journal-positive-control
#
# Run: nix build .#checks.x86_64-linux.canary-scan -L   (needs KVM; about 3 GB RAM)
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
  auditPort = 8444;
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
  # The plaintext control volume's bucket.
  plainBucket = "ci-plain";
  # node1's token at the stub Worker. A test value with no other use.
  auditToken = "ci-canary-scan-audit-token";

  disk = serial: "/dev/disk/by-id/virtio-${serial}";
  disks = [
    {
      serial = "esp";
      size = 64;
    }
    {
      serial = "swapplain";
      size = 256;
    }
    {
      serial = "swapcrypt";
      size = 256;
    }
    {
      serial = "rawplain";
      size = 32;
    }
    {
      serial = "rawluks";
      size = 64;
    }
  ];

  # Memory that holds the canary many times over, more of it than its cgroup may keep in
  # RAM, so the kernel has to swap it out. Reads the canary from the credential's source
  # file: the literal is on no command line.
  hog = pkgs.writeText "ci-canary-hog.py" ''
    import sys, time
    c = open(sys.argv[1]).read().strip()
    line = (c + " ") * 64 + "\n"
    blob = line * 80000
    time.sleep(100000)
  '';
in
pkgs.testers.runNixOSTest {
  name = "canary-scan";

  node.specialArgs = {
    topology = testTopology;
    inherit clusterLib;
  };

  nodes = {
    s3 =
      { pkgs, ... }:
      {
        virtualisation.memorySize = 768;
        networking.firewall.enable = false;
        systemd.services.s3 = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network-online.target" ];
          wants = [ "network-online.target" ];
          serviceConfig.Restart = "on-failure";
          script = ''
            mkdir -p /srv/s3/${os.juicefsBucket} /srv/s3/${plainBucket}
            exec ${pkgs.rclone}/bin/rclone serve s3 --addr 0.0.0.0:${toString s3Port} \
              --auth-key ${s3ak},${s3sk} /srv/s3
          '';
        };
        systemd.services.audit-stub = {
          description = "The off-host audit receiver: the real Worker, on files";
          wantedBy = [ "multi-user.target" ];
          environment = {
            WORKER = "${../workers/cluster-watchdog}/src/index.js";
            PORT = toString auditPort;
            OUT = "/var/lib/audit-stub";
            AUDIT_TOKENS = builtins.toJSON {
              ${auditToken} = {
                sender = "node1";
                kinds = [ "canary" ];
              };
            };
          };
          serviceConfig.ExecStart = "${pkgs.nodejs_22}/bin/node ${./lib/audit-stub.mjs}";
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
          ../modules/canary-scan.nix
          ../modules/coredumps-off.nix
          (harness.secretsModuleFor (
            gen:
            lib.elem gen [
              "ovh-s3"
              "juicefs-pg"
              "juicefs-rsa"
              "canary"
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
        virtualisation.emptyDiskImages = map (d: {
          inherit (d) size;
          driveConfig.deviceExtraOpts.serial = d.serial;
        }) disks;
        # The ESP the esp class finds by its type, as both ESPs on a node are found.
        virtualisation.fileSystems."/boot" = {
          device = disk "esp";
          fsType = "vfat";
          autoFormat = true;
          options = [ "umask=0077" ];
        };
        # Over the test framework's own `swapDevices = mkVMOverride [ ]`. The random-key
        # swap is the encrypted layout's (lib/mk-disk-layout.nix); the plain one is a
        # control, declared so the class's device list includes it, and swapped on by the
        # test only.
        swapDevices = lib.mkOverride 9 [
          {
            device = disk "swapplain";
            options = [
              "noauto"
              "nofail"
            ];
          }
          {
            device = disk "swapcrypt";
            randomEncryption.enable = true;
          }
        ];
        # Swapped-out pages go to the device, not to a compressed pool in RAM.
        boot.kernelParams = [ "zswap.enabled=0" ];

        system.stateVersion = testTopology.stateVersion;
        clan.core.enableRecommendedDefaults = false;
        clan.core.settings.state-version.enable = false;
        clan.core.settings.machine.name = "node1";
        clan.core.settings.directory = toString ./fixtures;
        clan.core.vars.settings.secretStore = "age";

        # The control-mesh address the metadata URL names (lib/net.nix jfsMetaHost).
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
        systemd.services.jfs-nomad-meta.enable = lib.mkForce false;
        systemd.timers.jfs-probe.enable = lib.mkForce false;

        # The audit trail's sender, to the Worker on `s3`. Journal shipping is another
        # test's business.
        cluster.audit = {
          enable = true;
          url = "http://s3:${toString auditPort}/event";
          tokenFile = "${pkgs.writeText "ci-canary-audit-token" auditToken}";
          node = "node1";
          journal.enable = false;
        };

        cluster.canary.rawDisks = true;
        cluster.canary.rawDevices = [
          (disk "rawplain")
          (disk "rawluks")
        ];

        environment.systemPackages = [
          pkgs.juicefs
          pkgs.jq
          pkgs.zstd
          pkgs.cryptsetup
          pkgs.python3
          pkgs.util-linux
        ];
      };
  };

  testScript =
    { nodes, ... }:
    let
      gens = nodes.node1.clan.core.vars.generators;
      cryptSwap = lib.findFirst (s: s.randomEncryption.enable) null nodes.node1.swapDevices;
    in
    ''
      import json
      import re
      import time

      MUTANT = "${mutant}"
      ${builtins.readFile ./lib/control.py}

      VALUE = "${gens.canary.files.value.path}"
      METRICS = "/var/lib/prometheus-node-exporter-text/canary.prom"
      MNT = "${jfs.mountPoint}"
      BUCKET = "${os.juicefsBucket}"
      PLAIN = "${plainBucket}"
      S3_URL = "${os.endpoint}"
      DROPIN = "/run/systemd/system/cluster-canary-scan.service.d"
      CLASSES = {"tmp", "coredump", "journal", "swap", "esp", "raw", "s3"}
      SWAP_PLAIN = "${disk "swapplain"}"
      SWAP_CRYPT_RAW = "${disk "swapcrypt"}"
      SWAP_CRYPT_MAP = "${cryptSwap.realDevice}"
      RAW_PLAIN = "${disk "rawplain"}"
      RAW_LUKS = "${disk "rawluks"}"
      RAW_LUKS_MAP = "/dev/mapper/ci-rawluks"
      CORE_PIPE = "${import ../lib/core-pattern.nix}"
      CONTAINER = "/var/lib/nixos-containers/ci-probe"

      def journal_mark():
          out = node1.succeed("journalctl -q -n 1 --show-cursor --no-pager | tail -n 1").strip()
          assert out.startswith("-- cursor: "), f"no journal cursor: {out!r}"
          return out[len("-- cursor: "):]

      def metrics():
          text = node1.succeed(f"cat {METRICS}")
          hits = {m.group(1): int(m.group(2))
                  for m in re.finditer(r'^cluster_canary_hits\{path_class="(\w+)"\} (\d+)$', text, re.M)}
          last = re.search(r"^cluster_canary_last_run_timestamp_seconds (\d+)$", text, re.M)
          return text, hits, (int(last.group(1)) if last else None)

      def scan():
          """The unit, once, as its timer starts it. (ok, hits, last_run, its log)"""
          cur = journal_mark()
          rc, _ = node1.execute("timeout 600 systemctl start cluster-canary-scan.service")
          result = node1.succeed("systemctl show -p Result --value cluster-canary-scan.service").strip()
          log = node1.succeed(f"journalctl -u cluster-canary-scan.service --after-cursor='{cur}' -o cat --no-pager")
          node1.execute("systemctl reset-failed cluster-canary-scan.service")
          _, hits, last = metrics()
          return rc == 0 and result == "success", hits, last, log

      def dropin(text):
          if text is None:
              node1.succeed(f"rm -rf {DROPIN} && systemctl daemon-reload")
          else:
              node1.succeed(f"mkdir -p {DROPIN} && printf '[Service]\\n%s\\n' '{text}' > {DROPIN}/ci.conf"
                            " && systemctl daemon-reload")

      def bucket_hits(path, needle):
          """Files under the S3 VM's backing `path` holding `needle`, raw and, where they
          are gzip, decompressed (as tests/jfs-encrypted.nix reads its buckets)."""
          out = s3.succeed(
              f"find {path} -type f -print0 | while IFS= read -r -d ''' f; do"
              f" if zcat -f \"$f\" 2>/dev/null | grep -acF -- '{needle}' >/dev/null; then echo \"$f\"; fi;"
              " done || true"
          )
          return [l for l in out.splitlines() if l]

      def direct_count(dev):
          """Lines holding the canary on a device, read past its page cache."""
          return int(node1.succeed(f"dd if={dev} iflag=direct bs=4M status=none | grep -cF -f {VALUE} || true").strip())

      def swap_used_mb():
          m = dict(l.split(":") for l in node1.succeed("cat /proc/meminfo").splitlines())
          return (int(m["SwapTotal"].split()[0]) - int(m["SwapFree"].split()[0])) // 1024

      def hog_start():
          node1.succeed("systemd-run --unit=ci-canary-hog -p MemoryMax=32M -p MemorySwapMax=infinity"
                        f" ${pkgs.python3}/bin/python3 ${hog} {VALUE}")
          node1.wait_until_succeeds("test $(( $(awk '/^SwapTotal/{t=$2} /^SwapFree/{f=$2} END{print t-f}' /proc/meminfo) / 1024 )) -ge 64",
                                    timeout=120)

      def hog_stop():
          node1.succeed("systemctl stop ci-canary-hog.service")
          node1.execute("systemctl reset-failed ci-canary-hog.service")

      def main():
          s3.start()
          s3.wait_for_unit("s3.service")
          s3.wait_for_open_port(${toString s3Port})
          s3.wait_for_unit("audit-stub.service")
          s3.wait_for_open_port(${toString auditPort})
          node1.start()
          for u in ["postgresql.service", "juicefs-format.service", "juicefs-mount.service",
                    "cluster-canary-seed.service", "multi-user.target"]:
              node1.wait_for_unit(u)
          node1.wait_until_succeeds(f"mountpoint -q {MNT}", timeout=180)
          node1.succeed("mountpoint -q /boot")
          CANARY = node1.succeed(f"cat {VALUE}").strip()
          assert len(CANARY) >= 16, CANARY

          # The raw class's encrypted disk: LUKS with a throwaway key file, opened.
          node1.succeed(
              "printf %s ci-raw-key-not-a-secret > /root/rawkey && "
              f"cryptsetup luksFormat --batch-mode --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 {RAW_LUKS} /root/rawkey && "
              f"cryptsetup open --key-file /root/rawkey {RAW_LUKS} ci-rawluks"
          )

          with subtest("seed-timestamp"):
              text, hits, seed = metrics()
              timer = node1.succeed("systemctl is-active cluster-canary-scan.timer").strip()
              detail = f"canary.prom {text.strip()!r}; timer {timer}"
              print(f"seed-timestamp: {detail}")
              control("seed-timestamp", hits == {} and seed is not None and len(text.strip().splitlines()) == 1
                      and timer == "active", detail)

          with subtest("baseline-all-zero"):
              time.sleep(1.1)
              ok, hits, last, log = scan()
              detail = f"ok {ok}, hits {hits}, last {last} (seed {seed}); log {log.strip()[-400:]!r}"
              print(f"baseline-all-zero: {detail}")
              control("baseline-all-zero", ok and set(hits) == CLASSES and all(v == 0 for v in hits.values())
                      and last is not None and last > seed, detail)
              last_ok = last

          with subtest("s3-encrypted-no-hits"):
              planted = node1.execute(f"cmp -s {VALUE} {MNT}/.canary/node1")[0] == 0
              info = node1.succeed(f"juicefs info {MNT}/.canary/node1 2>/dev/null")
              objs = [l.split("|")[2].strip() for l in info.splitlines() if "chunks/" in l]
              key = json.loads(node1.succeed("juicefs status 'postgres://${jfs.metaDb}:${harness.fixtureFor "juicefs-pg" "password"}@${meshIp}:${toString jfs.metaPort}/${jfs.metaDb}' 2>/dev/null"))["Setting"].get("EncryptKey")
              in_bucket = bucket_hits(f"/srv/s3/{BUCKET}", CANARY)
              detail = f"planted {planted}, objects {objs}, EncryptKey {key!r}, s3 hits {hits['s3']}, bucket files holding it {in_bucket}"
              print(f"s3-encrypted-no-hits: {detail}")
              control("s3-encrypted-no-hits", planted and len(objs) >= 1 and key == "removed"
                      and hits["s3"] == 0 and in_bucket == [], detail)

          with subtest("s3-positive-control-plaintext"):
              node1.succeed(
                  "mkdir -p /var/lib/ci-plain /mnt/plain /var/cache/ci-plain && "
                  f"juicefs format --storage s3 --bucket {S3_URL}/{PLAIN} --access-key ${s3ak} --secret-key ${s3sk}"
                  " sqlite3:///var/lib/ci-plain/meta.db plainfs 2>/dev/null && "
                  "juicefs mount -d sqlite3:///var/lib/ci-plain/meta.db /mnt/plain --cache-dir /var/cache/ci-plain"
                  " --no-usage-report --backup-meta 0 2>/dev/null"
              )
              dropin(f"Environment=JFS_MOUNT=/mnt/plain S3_BUCKET={PLAIN}")
              ok, hits, last, log = scan()
              dropin(None)
              in_bucket = bucket_hits(f"/srv/s3/{PLAIN}", CANARY)
              node1.succeed("juicefs umount /mnt/plain")
              detail = f"ok {ok}, s3 hits {hits.get('s3')}, bucket files holding it {in_bucket}; log {log.strip()[-300:]!r}"
              print(f"s3-positive-control-plaintext: {detail}")
              control("s3-positive-control-plaintext", ok and hits.get("s3", 0) > 0 and len(in_bucket) >= 1, detail)
              last_ok = last

          with subtest("cannot-look-fails"):
              node1.succeed("mkdir -p /mnt/ci-not-mounted")
              dropin("Environment=JFS_MOUNT=/mnt/ci-not-mounted")
              time.sleep(1.1)
              ok, hits, last, log = scan()
              dropin(None)
              detail = f"ok {ok}, classes {sorted(hits)}, last {last} (before {last_ok}); log {log.strip()[-300:]!r}"
              print(f"cannot-look-fails: {detail}")
              control("cannot-look-fails", not ok and set(hits) == CLASSES - {"s3"} and last == last_ok
                      and "class=s3 NOT scanned" in log, detail)

          with subtest("tmp-positive-control"):
              node1.succeed(f"cp {VALUE} /tmp/ci-plant && mkdir -p /var/tmp/ci && cp {VALUE} /var/tmp/ci/plant"
                            " && mkfifo /tmp/ci-fifo")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, tmp hits {hits.get('tmp')} (2 planted, and a FIFO)"
              print(f"tmp-positive-control: {detail}")
              control("tmp-positive-control", ok and hits.get("tmp") == 2, detail)

          with subtest("event-delivered"):
              def delivered(_):
                  rc, out = s3.execute("cat /var/lib/audit-stub/audit.jsonl 2>/dev/null")
                  evs = [json.loads(l)["value"] for l in out.splitlines() if l.strip()]
                  return [e for e in evs if e.get("kind") == "canary" and e.get("path_class") == "tmp"]
              retry(lambda last_try: bool(delivered(last_try)), timeout_seconds=90)
              ev = delivered(True)[0]
              rejected = node1.succeed("ls -A /var/lib/cluster-audit/rejected 2>/dev/null || true").strip()
              detail = f"event {ev}, rejected {rejected!r}"
              print(f"event-delivered: {detail}")
              # The Worker stores what it accepted, plus who sent it and when.
              control("event-delivered", ev.get("node") == "node1" and ev.get("sender") == "node1"
                      and ev.get("hits") == 2 and rejected == ""
                      and set(ev) - {"sender", "received"} == {"kind", "node", "path_class", "hits", "at"}, detail)

          with subtest("tmp-removed"):
              node1.succeed("rm -rf /tmp/ci-plant /var/tmp/ci /tmp/ci-fifo")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, tmp hits {hits.get('tmp')}"
              print(f"tmp-removed: {detail}")
              control("tmp-removed", ok and hits.get("tmp") == 0, detail)

          with subtest("esp-positive-control"):
              node1.succeed(f"cp {VALUE} /boot/ci-plant && sync")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, esp hits {hits.get('esp')}"
              print(f"esp-positive-control: {detail}")
              control("esp-positive-control", ok and hits.get("esp") == 1, detail)

          with subtest("esp-removed"):
              node1.succeed("rm /boot/ci-plant && sync")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, esp hits {hits.get('esp')}"
              print(f"esp-removed: {detail}")
              control("esp-removed", ok and hits.get("esp") == 0, detail)

          with subtest("esp-unmounted-cannot-look"):
              # An ESP that did not mount (nofail) leaves its directory, with whatever is on
              # the root filesystem under it. That is not the ESP: alone, the class could not
              # look and the unit fails; beside a mounted one, it is skipped with a line.
              node1.succeed(f"mkdir -p /mnt/ci-esp-gone && cp {VALUE} /mnt/ci-esp-gone/ci-plant")
              dropin('Environment="ESP_DIRS=/mnt/ci-esp-gone"')
              time.sleep(1.1)
              ok, hits, last, log = scan()
              dropin('Environment="ESP_DIRS=/boot /mnt/ci-esp-gone"')
              ok2, hits2, _, log2 = scan()
              dropin(None)
              node1.succeed("rm -rf /mnt/ci-esp-gone")
              detail = (f"alone: ok {ok}, classes {sorted(hits)}, log {log.strip()[-200:]!r};"
                        f" beside /boot: ok {ok2}, esp hits {hits2.get('esp')}, skip logged {'not a mount point; skipped' in log2}")
              print(f"esp-unmounted-cannot-look: {detail}")
              control("esp-unmounted-cannot-look",
                      not ok and "esp" not in hits and "class=esp NOT scanned" in log
                      and ok2 and hits2.get("esp") == 0 and "/mnt/ci-esp-gone is not a mount point; skipped" in log2,
                      detail)

          # ── journal ────────────────────────────────────────────────────────────────
          with subtest("journal-entry-compressed"):
              # Random padding, so the field compresses and the canary is not left as a
              # literal run in it. The canary comes from the file: nothing on a command line.
              node1.succeed(
                  "{ head -c 3000 /dev/urandom | base64 -w0; printf ' '; cat " + VALUE + "; printf ' ';"
                  " head -c 3000 /dev/urandom | base64 -w0; } | systemd-cat -t ci-canary-plant"
              )
              node1.succeed("journalctl --sync")
              seen = int(node1.succeed(f"journalctl -t ci-canary-plant -o cat --no-pager | grep -cF -f {VALUE} || true").strip())
              raw = int(node1.succeed(f"{{ grep -rlF -f {VALUE} /var/log/journal /run/log/journal 2>/dev/null || true; }} | wc -l").strip())
              detail = f"journalctl sees it {seen}, journal files holding it as text {raw}"
              print(f"journal-entry-compressed: {detail}")
              control("journal-entry-compressed", seen == 1 and raw == 0, detail)

          with subtest("journal-positive-control"):
              ok, hits, last, log = scan()
              detail = f"ok {ok}, journal hits {hits.get('journal')}"
              print(f"journal-positive-control: {detail}")
              control("journal-positive-control", ok and hits.get("journal", 0) > 0, detail)

          with subtest("journal-container-positive-control"):
              mid = node1.succeed("cat /etc/machine-id").strip()
              node1.succeed("journalctl --rotate")
              node1.succeed(f"mkdir -p {CONTAINER}/var/log/journal/{mid} && cp /var/log/journal/{mid}/system@*.journal {CONTAINER}/var/log/journal/{mid}/")
              time.sleep(2)
              node1.succeed("journalctl --vacuum-time=1s")
              host = int(node1.succeed(f"journalctl -t ci-canary-plant -o cat --no-pager | grep -cF -f {VALUE} || true").strip())
              ok, hits, last, log = scan()
              detail = f"ok {ok}, host journal holds it {host}, journal hits {hits.get('journal')}"
              print(f"journal-container-positive-control: {detail}")
              control("journal-container-positive-control", ok and host == 0 and hits.get("journal", 0) > 0, detail)

          with subtest("journal-removed"):
              node1.succeed(f"rm -rf {CONTAINER}/var/log/journal/{mid}")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, journal hits {hits.get('journal')}"
              print(f"journal-removed: {detail}")
              control("journal-removed", ok and hits.get("journal") == 0, detail)

          # ── coredump ───────────────────────────────────────────────────────────────
          with subtest("coredump-real-core-raw-grep-blind"):
              # systemd-coredump's own pipe, for one crash; systemd-sysctl puts ours back.
              node1.succeed("sysctl -p /etc/sysctl.d/50-coredump.conf")
              rc, _ = node1.execute(
                  "bash -c 'c=$(cat " + VALUE + "); x=$c$c$c; ulimit -c unlimited; kill -SEGV $$'")
              node1.wait_until_succeeds("ls /var/lib/systemd/coredump/ | grep -q .", timeout=60)
              node1.succeed("systemctl restart systemd-sysctl.service")
              cores = node1.succeed("ls /var/lib/systemd/coredump/").split()
              core = "/var/lib/systemd/coredump/" + cores[0]
              raw = int(node1.succeed(f"grep -cF -f {VALUE} {core} || true").strip())
              inside = int(node1.succeed(f"zstdcat {core} | grep -cF -f {VALUE} || true").strip())
              detail = f"crash rc {rc}, cores {cores}, raw grep {raw}, decompressed {inside}"
              print(f"coredump-real-core-raw-grep-blind: {detail}")
              control("coredump-real-core-raw-grep-blind",
                      rc == 139 and len(cores) == 1 and core.endswith(".zst") and raw == 0 and inside > 0, detail)

          with subtest("coredump-positive-control"):
              node1.succeed(f"mkdir -p {CONTAINER}/var/lib/systemd/coredump && echo x > {CONTAINER}/var/lib/systemd/coredump/core.ci")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, coredump hits {hits.get('coredump')} (the real core and a container's file)"
              print(f"coredump-positive-control: {detail}")
              control("coredump-positive-control", ok and hits.get("coredump") == 2, detail)

          with subtest("coredump-removed"):
              node1.succeed(f"rm -f /var/lib/systemd/coredump/* {CONTAINER}/var/lib/systemd/coredump/core.ci")
              pattern = node1.succeed("cat /proc/sys/kernel/core_pattern").strip()
              ok, hits, last, log = scan()
              detail = f"ok {ok}, coredump hits {hits.get('coredump')}, core_pattern {pattern!r}"
              print(f"coredump-removed: {detail}")
              control("coredump-removed", ok and hits.get("coredump") == 0 and pattern == CORE_PIPE, detail)

          # ── swap ───────────────────────────────────────────────────────────────────
          with subtest("swap-positive-control"):
              node1.succeed(f"swapoff {SWAP_CRYPT_MAP} && mkswap {SWAP_PLAIN} >/dev/null && swapon {SWAP_PLAIN}")
              hog_start()
              used = swap_used_mb()
              ok, hits, last, log = scan()
              hog_stop()
              detail = f"ok {ok}, swap in use {used} MB (plain only), swap hits {hits.get('swap')}"
              print(f"swap-positive-control: {detail}")
              control("swap-positive-control", ok and hits.get("swap", 0) > 0, detail)

          with subtest("swap-removed"):
              node1.succeed(f"swapoff {SWAP_PLAIN} && blkdiscard -f -z {SWAP_PLAIN}")
              ok, hits, last, log = scan()
              detail = f"ok {ok}, swap hits {hits.get('swap')}"
              print(f"swap-removed: {detail}")
              control("swap-removed", ok and hits.get("swap") == 0, detail)

          with subtest("swap-dm-crypt"):
              node1.succeed(f"swapon {SWAP_CRYPT_MAP}")
              hog_start()
              used = swap_used_mb()
              dm = direct_count(SWAP_CRYPT_MAP)
              under = direct_count(SWAP_CRYPT_RAW)
              ok, hits, last, log = scan()
              hog_stop()
              detail = f"ok {ok}, swap in use {used} MB (random-key only), through the mapping {dm}, under it {under}, swap hits {hits.get('swap')}"
              print(f"swap-dm-crypt: {detail}")
              control("swap-dm-crypt", ok and dm > 0 and under == 0 and hits.get("swap") == 0, detail)

          # ── raw ────────────────────────────────────────────────────────────────────
          with subtest("raw-positive-control"):
              node1.succeed(f"dd if={VALUE} of={RAW_PLAIN} bs=1M seek=1 conv=notrunc,fsync status=none")
              node1.succeed(f"dd if={VALUE} of={RAW_LUKS_MAP} bs=1M seek=1 conv=notrunc,fsync status=none")
              ok, hits, last, log = scan()
              mapped = direct_count(RAW_LUKS_MAP)
              detail = f"ok {ok}, raw hits {hits.get('raw')} (planted on the plain disk, and under LUKS: mapping holds it {mapped})"
              print(f"raw-positive-control: {detail}")
              control("raw-positive-control", ok and hits.get("raw") == 1 and mapped == 1, detail)

          with subtest("raw-removed"):
              node1.succeed(f"dd if=/dev/zero of={RAW_PLAIN} bs=1M seek=1 count=1 conv=notrunc,fsync status=none")
              ok, hits, last, log = scan()
              mapped = direct_count(RAW_LUKS_MAP)
              detail = f"ok {ok}, raw hits {hits.get('raw')}, LUKS mapping still holds it {mapped}"
              print(f"raw-removed: {detail}")
              control("raw-removed", ok and hits.get("raw") == 0 and mapped == 1, detail)

          with subtest("all-zero-at-end"):
              ok, hits, last, log = scan()
              rejected = node1.succeed("ls -A /var/lib/cluster-audit/rejected 2>/dev/null || true").strip()
              detail = f"ok {ok}, hits {hits}, rejected events {rejected!r}"
              print(f"all-zero-at-end: {detail}")
              control("all-zero-at-end", ok and set(hits) == CLASSES and all(v == 0 for v in hits.values())
                      and rejected == "", detail)

      run_main(main)
    '';
}
