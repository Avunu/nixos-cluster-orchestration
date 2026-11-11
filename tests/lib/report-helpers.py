# Reading a boot report, on the target and at the audit receiver. Spliced before the
# script of the boot tests that check it (boot-install, boot-fallback), after the boot
# harness. The receiver is the real Worker on the tang VM (tests/lib/audit-stub.mjs).
import json

AUDIT_OUT = "/var/lib/audit-stub"
REPORT = "/var/lib/prometheus-node-exporter-text/boot_report.prom"
STAGE2_ADDRESS = "192.0.2.20"


def report_metrics():
    """boot_report.prom of this boot, as {series: value}, once the report has run."""
    target.wait_until_succeeds(
        "test \"$(systemctl show -p ActiveState --value cluster-boot-report.service)\" = active", timeout=120
    )
    text = target.succeed(f"cat {REPORT}")
    return dict(line.rsplit(" ", 1) for line in text.splitlines() if line.strip())


def rerun_report():
    target.succeed("systemctl restart cluster-boot-report.service")
    return report_metrics()


def this_boot():
    return target.succeed("cat /proc/sys/kernel/random/boot_id").strip()


def stored(kind):
    """What the Worker put in its trail, of one kind, oldest first."""
    _, out = tang.execute(f"cat {AUDIT_OUT}/audit.jsonl 2>/dev/null")
    return [o["value"] for o in map(json.loads, out.splitlines()) if o["value"].get("kind") == kind]


def delivered_boot_event(boot_id, timeout=180):
    """The newest boot event the Worker stored for this boot, or None. The node's sender
    retries until the Worker takes it, so None here is a refusal or no event at all."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = [e for e in stored("boot") if e.get("boot_id") == boot_id]
        if found:
            return found[-1]
        time.sleep(2)
    return None


def refused_requests():
    """Requests the Worker answered with anything but 204, for the detail of a failure."""
    _, out = tang.execute(f"cat {AUDIT_OUT}/requests.jsonl 2>/dev/null")
    return [r for r in map(json.loads, out.splitlines()) if r.get("status") != 204]


def last_email():
    """The subject of the Worker's last email, for the record."""
    _, out = tang.execute(f"tail -n 1 {AUDIT_OUT}/emails.jsonl 2>/dev/null")
    return json.loads(out).get("subject") if out.strip() else None
