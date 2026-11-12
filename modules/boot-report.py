# The stage-2 boot report: what a node says about its own boot (design 1.19,
# Appendix J). Run once per boot by cluster-boot-report.service, after the journal
# holds the initrd's lines. Reads only local facts; writes node_exporter textfile
# metrics and, through the audit spool, an event for the off-host trail.
#
# The unlock is judged per leg, by one line its systemd-cryptsetup@<leg>.service logged
# in the initrd: "Volume <leg> activated with a LUKS token.", which it logs only once the
# leg's TPM slot has opened it, at debug level (modules/boot-security-core.nix turns that
# on), and which survives switch-root in the journal. A leg opened by a typed passphrase
# never logs it. Not by the absence of a prompt or of an error: a leg with no TPM slot
# asks without any error at all. journald sets the unit field, so no other process can
# write the line under that unit's name. If a systemd bump rewords the line, every boot
# reports a passphrase unlock and the canary gate stops the bump there.
#
# Settings, from the unit's environment:
#   LUKS_NAMES        the LUKS legs the initrd opens (boot.initrd.luks.devices), by name
#   EXPECTED_DEVICES  how many of them there are
#   OPTED_OUT         "1" on a node with insecurePlaintextBoot: it says so, and nothing else
#   NODE              the name the audit trail knows this node by
#   METRICS_DIR       node_exporter's textfile directory
#   SPOOL_DIR         the audit spool (modules/audit-ship-core.nix), or "" for no event
import json
import os
import re
import subprocess
import sys
import time

LEGS = os.environ.get("LUKS_NAMES", "").split()
EXPECTED = int(os.environ.get("EXPECTED_DEVICES", "0"))
OPTED_OUT = os.environ.get("OPTED_OUT", "") == "1"
NODE = os.environ.get("NODE") or os.uname().nodename
METRICS = os.environ.get("METRICS_DIR", "/var/lib/prometheus-node-exporter-text")
SPOOL = os.environ.get("SPOOL_DIR", "")
EFI = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
SB_VAR = f"/sys/firmware/efi/efivars/SecureBoot-{EFI}"
SM_VAR = f"/sys/firmware/efi/efivars/SetupMode-{EFI}"
REFUSED = "TPM policy does not match current system state"


def unit_of(leg):
    """systemd-cryptsetup@<leg>.service, the leg's name escaped the way systemd does."""
    out = []
    for i, c in enumerate(leg):
        if c == "/":
            out.append("-")
        elif c.isascii() and (c.isalnum() or c in ":_" or (c == "." and i > 0)):
            out.append(c)
        else:
            out.extend("\\x%02x" % b for b in c.encode())
    return "systemd-cryptsetup@%s.service" % "".join(out)


def run(*a):
    return subprocess.run(a, capture_output=True, text=True, check=True).stdout


def message(e):
    """MESSAGE as text. journald hands over bytes it cannot decode as a list of ints."""
    m = e.get("MESSAGE") or ""
    return bytes(m).decode("utf-8", "replace") if isinstance(m, list) else m


def journal(*matches):
    for line in run("journalctl", "-b", "-o", "json", "--no-pager", *matches).splitlines():
        if line.strip():
            yield json.loads(line)


def efi_flag(path):
    """The one byte after the variable's four bytes of attributes; -1 if unreadable, which
    the alert reads as not enforcing."""
    try:
        with open(path, "rb") as f:
            data = f.read()
        return data[-1] if len(data) >= 5 else -1
    except OSError:
        return -1


def systemd_us(prop):
    return int(run("systemctl", "show", "-p", prop, "--value").strip() or 0)


def write_metrics(lines):
    os.makedirs(METRICS, exist_ok=True)
    tmp = os.path.join(METRICS, "boot_report.prom.tmp")
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, os.path.join(METRICS, "boot_report.prom"))


def spool(event, name):
    """Hands the event to cluster-audit-send, which delivers it and only then deletes it.
    Written whole and renamed, so the sender never sees half a file."""
    os.makedirs(SPOOL, mode=0o700, exist_ok=True)
    path = os.path.join(SPOOL, name)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(event, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(SPOOL, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def booted_generation(booted):
    """The system profile generation whose closure is the one that booted, or -1."""
    profiles = "/nix/var/nix/profiles"
    best = -1
    try:
        names = os.listdir(profiles)
    except OSError:
        return -1
    for name in names:
        m = re.fullmatch(r"system-(\d+)-link", name)
        if m and os.path.realpath(os.path.join(profiles, name)) == booted:
            best = max(best, int(m[1]))
    return best


now = int(time.time())

if OPTED_OUT:
    # No Secure Boot, no TPM binding: nothing to say about the unlock. The timestamp is
    # written all the same, so BootReportMissing notices a report that never ran.
    write_metrics(
        [
            "cluster_boot_report_timestamp_seconds %d" % now,
            "cluster_boot_insecure_optout 1",
        ]
    )
    print(json.dumps({"node": NODE, "opted_out": True}))
    sys.exit(0)

userspace_us = systemd_us("UserspaceTimestampMonotonic")
initrd_us = systemd_us("InitRDTimestampMonotonic")

# Only the initrd's lines count: the initrd's journal is this boot's too, so its entries
# are told apart by time, before stage 2's systemd started.
tpm_ok = set()
tpm_refused = set()
unit_lines = 0
for leg in LEGS:
    for e in journal(f"_SYSTEMD_UNIT={unit_of(leg)}"):
        if int(e["__MONOTONIC_TIMESTAMP"]) >= userspace_us:
            continue
        unit_lines += 1
        msg = message(e)
        if msg == f"Volume {leg} activated with a LUKS token.":
            tpm_ok.add(leg)
        if REFUSED in msg:
            tpm_refused.add(leg)

# A login during the initrd is a human on the unlock path, whatever else happened, told
# apart from a stage-2 login the same way. _UID=0 because only root's sshd-session writes these; any
# user can name a process sshd-session.
ssh_initrd = []
ssh_all = 0
for e in journal("_COMM=sshd-session", "_COMM=sshd", "_UID=0"):
    if message(e).startswith("Accepted "):
        ssh_all += 1
        if int(e["__MONOTONIC_TIMESTAMP"]) < userspace_us:
            ssh_initrd.append(message(e))

n = len(tpm_ok)
unlock = "tpm" if n >= EXPECTED > 0 else ("mixed" if n > 0 else "passphrase")

try:
    with open("/sys/class/tpm/tpm0/pcr-sha256/7") as f:
        pcr7 = f.read().strip().lower()
except OSError:
    pcr7 = ""
if not re.fullmatch(r"[0-9a-f]{0,64}", pcr7):
    pcr7 = ""
booted = os.path.realpath("/run/booted-system")

with open("/proc/sys/kernel/random/boot_id") as f:
    boot_id = f.read().strip()
initrd_ms = (userspace_us - initrd_us) // 1000 if initrd_us else -1
report = {
    "kind": "boot",
    "node": NODE,
    "boot_id": boot_id,
    "unlock": unlock,
    "tpm_devices": n,
    "expected_devices": EXPECTED,
    "initrd_ssh_logins": len(ssh_initrd),
    "secure_boot": efi_flag(SB_VAR),
    "setup_mode": efi_flag(SM_VAR),
    "pcr7": pcr7,
    "generation": booted_generation(booted),
    # The store hash: the name after it is not the Worker's business.
    "toplevel": os.path.basename(booted)[:32] or "unknown",
    "initrd_ms": initrd_ms,
    "at": now,
}
print(json.dumps(report))
print(
    "debug unit_lines=%d tpm=%s refused=%s initrd_us=%d userspace_us=%d ssh_all=%d"
    % (unit_lines, sorted(tpm_ok), sorted(tpm_refused), initrd_us, userspace_us, ssh_all)
)

# cluster_reboot_pending is not here: deploy.prom writes it (lib/cluster-upgrade.nix),
# and two files with one series collide in node_exporter.
write_metrics(
    [
        "cluster_boot_report_timestamp_seconds %d" % now,
        "cluster_boot_insecure_optout 0",
        "cluster_boot_unlock_passphrase %d" % (0 if unlock == "tpm" else 1),
        "cluster_boot_unlock_tpm_devices %d" % n,
        "cluster_boot_unlock_expected_devices %d" % EXPECTED,
        # The TPM opened every leg on the unlock path that really ran (design 1.3 item 17,
        # D24), which a stage-2 test of the slot would not show.
        "cluster_unlock_tpm_ok %d" % (1 if unlock == "tpm" else 0),
        "cluster_boot_initrd_ssh_logins %d" % len(ssh_initrd),
        # Legs whose TPM refused to unseal on this boot: PCR 7 is not what the slot was
        # sealed to.
        "cluster_boot_tpm_refusals %d" % len(tpm_refused),
        "cluster_boot_initrd_seconds %d" % (initrd_ms // 1000 if initrd_ms >= 0 else -1),
        "cluster_boot_secure_boot_enabled %d" % report["secure_boot"],
        "cluster_boot_setup_mode %d" % report["setup_mode"],
        'cluster_boot_pcr7_info{value="%s"} 1' % pcr7,
    ]
)

if SPOOL:
    spool(report, "%d-boot-%s.json" % (time.time_ns(), boot_id))
