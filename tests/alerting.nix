# VM test: an alert travels the whole path and arrives as a well-formed email.
#
#   Prometheus rule -> Alertmanager -> alert-email-bridge -> send-notification-email
#     -> (stub) Cloudflare Email Sending API
#
# Runs the REAL modules/alerting-core.nix; only the API is a stub, recording
# every request so the test can assert: one POST per recipient, the account in
# the URL, the bearer token from the credential file, the sender, and a subject
# naming the alert. Also: `cluster-alert-test` goes the same way; the
# always-firing Watchdog is NOT emailed but relayed, with its bearer token, to
# the dead-man's /heartbeat; and the weekly report summarises real backup
# metrics (one app fresh, one never backed up).
#
# Run: nix build .#checks.x86_64-linux.alerting -L   (needs KVM)
{ pkgs, lib }:
let
  stub = pkgs.writers.writePython3 "stub-cloudflare" { } ''
    import http.server
    import json


    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            rec = {
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "body": json.loads(body),
            }
            with open("/var/lib/stub-cf/requests.jsonl", "a") as f:
                f.write(json.dumps(rec) + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success": true}')

        def log_message(self, *a):
            return


    http.server.HTTPServer(("127.0.0.1", 9999), H).serve_forever()
  '';
in
pkgs.testers.runNixOSTest {
  name = "cluster-alerting";

  nodes.machine = {
    imports = [ ../modules/alerting-core.nix ];
    virtualisation.memorySize = 1536;

    services.prometheus = {
      enable = true;
      globalConfig.evaluation_interval = "5s";
      rules = [
        (builtins.toJSON {
          groups = [
            {
              name = "test";
              rules = [
                {
                  alert = "TestFiring";
                  expr = "vector(1)";
                  labels.severity = "critical";
                  annotations.summary = "a test alert fired";
                }
              ];
            }
          ];
        })
      ];
    };

    # Backup metrics for the weekly report, the way nodes publish them.
    services.prometheus.exporters.node = {
      enable = true;
      enabledCollectors = [ "textfile" ];
      extraFlags = [ "--collector.textfile.directory=/var/lib/prometheus-node-exporter-text" ];
    };
    services.prometheus.scrapeConfigs = [
      {
        job_name = "node";
        scrape_interval = "5s";
        static_configs = [ { targets = [ "127.0.0.1:9100" ]; } ];
      }
    ];
    systemd.tmpfiles.rules = [ "d /var/lib/prometheus-node-exporter-text 0755 root root -" ];

    cluster.alerting = {
      cloudflareAccountId = "acct123";
      from = "alerts@example.com";
      to = [
        "a@example.com"
        "b@example.com"
      ];
      tokenFile = "${pkgs.writeText "cf-token" "test-token"}";
      apiBase = "http://127.0.0.1:9999/client/v4";
      backupApps = [
        "fresh"
        "ghost"
      ];
      heartbeat = {
        url = "http://127.0.0.1:9999/heartbeat";
        tokenFile = "${pkgs.writeText "watchdog-token" "wd-token"}";
      };
    };

    systemd.services.stub-cf = {
      wantedBy = [ "multi-user.target" ];
      before = [ "alert-email-bridge.service" ];
      serviceConfig = {
        ExecStart = stub;
        StateDirectory = "stub-cf";
      };
    };
  };

  testScript = ''
    import json

    def requests():
        out = machine.succeed("cat /var/lib/stub-cf/requests.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def with_subject(word):
        return [r for r in requests() if word in r["body"].get("subject", "")]

    machine.start()
    for unit in ["stub-cf", "alert-email-bridge", "alertmanager", "prometheus"]:
        machine.wait_for_unit(f"{unit}.service")

    with subtest("a firing rule becomes one email per recipient"):
        machine.wait_until_succeeds(
            "test $(grep -c TestFiring /var/lib/stub-cf/requests.jsonl) -ge 2", timeout=120
        )
        got = with_subject("TestFiring")
        assert sorted(r["body"]["to"] for r in got[:2]) == ["a@example.com", "b@example.com"], got
        for r in got:
            assert r["path"] == "/client/v4/accounts/acct123/email/sending/send", r
            assert r["auth"] == "Bearer test-token", r
            assert r["body"]["from"] == "alerts@example.com", r
            assert r["body"]["subject"].startswith("[FIRING"), r
            assert "a test alert fired" in r["body"]["text"], r

    with subtest("cluster-alert-test takes the same path"):
        machine.succeed("cluster-alert-test")
        machine.wait_until_succeeds(
            "grep -q ClusterAlertTest /var/lib/stub-cf/requests.jsonl", timeout=90
        )

    with subtest("the Watchdog heartbeat is never emailed"):
        assert with_subject("Watchdog") == [], with_subject("Watchdog")

    with subtest("the Watchdog is relayed to the dead-man, with its token"):
        machine.wait_until_succeeds(
            "grep -q '\"path\": \"/heartbeat\"' /var/lib/stub-cf/requests.jsonl", timeout=120
        )
        beats = [r for r in requests() if r["path"] == "/heartbeat"]
        assert beats[0]["auth"] == "Bearer wd-token", beats[0]

    with subtest("the weekly report summarises backups"):
        machine.succeed(
            "echo \"cluster_backup_last_success_timestamp_seconds{app=\\\"fresh\\\"} $(date +%s)\""
            " > /var/lib/prometheus-node-exporter-text/b.prom"
        )
        machine.wait_until_succeeds(
            "curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=cluster_backup_last_success_timestamp_seconds'"
            " | grep -q fresh", timeout=60
        )
        status, out = machine.execute(
            "systemctl start cluster-weekly-report.service; rc=$?;"
            " journalctl -u cluster-weekly-report --no-pager -o cat | tail -20; exit $rc"
        )
        assert status == 0, out
        report = with_subject("[REPORT]")
        assert len(report) == 2, json.dumps(requests(), indent=1)
        r = report[0]["body"]
        dump = json.dumps(r, indent=1)
        assert r["subject"].startswith("[REPORT] weekly: 1/2 apps backed up"), dump
        assert "ok   fresh" in r["text"], dump
        assert "LATE ghost" in r["text"], dump
        assert "last backup: never" in r["text"], dump
  '';
}
