# The machinery of the boot-* tests. Spliced into a test's script after the constants
# tests/lib/boot-harness.nix defines and tests/lib/control.py. Nothing in here decides
# whether a test passes.
#
# Disks live outside the VMs. One provisioning gives a frozen base, and each case boots
# copy-on-write overlays of it, so one install serves many independent cases. `target`
# and `installer` share those disks and never run at once.
import os
import re
import shlex
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path

WORK = Path(os.environ.get("NIX_BUILD_TOP") or os.environ.get("TMPDIR") or "/tmp") / "bh"
BASE = WORK / "base"
# swtpm's socket path has a 108-byte limit, so this stays short.
TPM = WORK / "t"

PROMPT = re.compile(r"Please enter passphrase for disk")
# What to answer when all that matters is getting through. A prompt has no newline, so it stays in
# the driver's read buffer until some later line flushes it, and with both legs asking and nothing
# else happening, none may. The agent's own line does end, and comes with every query.
ANY_PROMPT = re.compile(r"Please enter passphrase for disk|Starting password query on /dev/ttyS0")
EMERGENCY = re.compile(r"Reached target .*Emergency Mode")
# Leaving the initrd: PID 1 says this on the serial console, which the backdoor can't, since
# connecting to it can't be undone. Nothing on the console names stage 2 itself: there is no
# "Welcome to" line there.
SWITCHED = re.compile(r"systemd\[1\]: Switching root\.")
# A halt says so on the way down. The kernel's own last line can be a long time coming, or lost,
# with ZFS still writing to devices that have stopped, and those errors can land in the middle
# of systemctl's line, which is why this matches only the end of the word. Seen: `Halting.[...]
# I/O error` on one line, and `H[...] I/O error` then `alting.` on two.
HALTED = re.compile(r"System halted|alting\.")

WRONG = "this-is-not-the-passphrase"

_cases = 0
_firmwares = 0


def run(*args):
    subprocess.run([str(a) for a in args], check=True, capture_output=True)


def new_blank(path):
    run(QEMU_IMG, "create", "-f", "qcow2", path, f"{DISK_MIB}M")


def new_overlay(path, letter, base=None):
    run(QEMU_IMG, "create", "-f", "qcow2", "-F", "qcow2", "-b", (base or BASE) / f"{letter}.qcow2", path)


def use_disks(path):
    """The disk set the next VM started will see."""
    os.environ["BOOT_DISKS"] = str(path)


def new_case(a="overlay", b="overlay", base=None):
    """A disk set for one case. Each leg is an overlay of a frozen disk set, by default the
    base, or a blank replacement."""
    global _cases
    _cases += 1
    path = WORK / "cases" / str(_cases)
    path.mkdir(parents=True)
    for letter, kind in (("a", a), ("b", b)):
        if kind == "overlay":
            new_overlay(path / f"{letter}.qcow2", letter, base)
        else:
            new_blank(path / f"{letter}.qcow2")
    return path


def freeze(disks):
    """Makes this disk set a checkpoint for new_case(base=...)."""
    for letter in "ab":
        (disks / f"{letter}.qcow2").chmod(stat.S_IRUSR)
    return disks


def new_firmware(source=None):
    """A machine's firmware variables and TPM, which outlast a power cycle. Fresh, this is a
    machine nobody has configured, in Setup Mode. Or a copy of another's, so that one
    enrollment serves many cases. Under TPM because of swtpm's socket path limit."""
    global _firmwares
    _firmwares += 1
    path = TPM / f"f{_firmwares}"
    (path / "t").mkdir(parents=True)
    if source is not None:
        shutil.copy2(source / "vars.fd", path / "vars.fd")
        for state in (source / "t").iterdir():
            if state.is_file() and not state.is_socket() and state.name != "pid":
                shutil.copy2(state, path / "t" / state.name)
    return path


# ── provisioning ──────────────────────────────────────────────────────────


def installer_up(disks):
    use_disks(disks)
    installer.start()
    installer.wait_for_unit("multi-user.target")


def seed_secrets(identity=True):
    """/run/partitioning-secrets, at the paths clan would upload to."""
    installer.succeed(
        f"install -D -m 0400 /dev/null {PASSWORD_FILE}",
        f"printf %s '{PASSPHRASE}' > {PASSWORD_FILE}",
        f"mkdir -p $(dirname {HOST_KEY_FILE})",
        f"[ -e {HOST_KEY_FILE} ] || ssh-keygen -q -t ed25519 -N '' -C initrd-host -f {HOST_KEY_FILE}",
    )
    if identity:
        installer.succeed(
            f"install -D -m 0400 /dev/null {IDENTITY_SECRET_FILE}",
            f"printf %s '{IDENTITY_SECRET}' > {IDENTITY_SECRET_FILE}",
        )
    else:
        installer.succeed(f"rm -f {IDENTITY_SECRET_FILE}")


def release_disks():
    """Lets go of whatever a disko run left behind."""
    installer.execute(
        "umount -R /mnt || true; zpool export -f rpool || true; cryptsetup close crypt-a || true; cryptsetup close crypt-b || true"
    )


def esp_differences(machine, a, b):
    """What differs between two ESPs, or nothing. lzbt builds and signs each ESP's files
    separately, and both sbsign's signature and objcopy's PE header carry the time, so two
    copies are byte-identical only if they were made in the same second, which a plain diff -r
    gets right sometimes. So a PE is compared with its signature off and those two header
    fields, the timestamp and the checksum that follows from it, zeroed. Whether a
    signature is good is a separate question, and `sbctl verify` is what answers it. The
    loader's random seed, if it has one, is its own and no part of a generation."""
    return machine.succeed(
        f"""
        cd {a}; find . -type f ! -name random-seed | sort > /tmp/esp-a
        cd {b}; find . -type f ! -name random-seed | sort > /tmp/esp-b
        cd /
        diff /tmp/esp-a /tmp/esp-b || true
        while read -r f; do
          [ -e "{b}/$f" ] || continue
          cmp -s "{a}/$f" "{b}/$f" && continue
          cp "{a}/$f" /tmp/esp-one; cp "{b}/$f" /tmp/esp-two
          for pe in /tmp/esp-one /tmp/esp-two; do
            sbattach --remove "$pe" >/dev/null 2>&1 || true
            header=$(od -An -tu4 -j60 -N4 "$pe" | tr -d ' ')
            dd if=/dev/zero of="$pe" bs=1 seek=$((header + 8)) count=4 conv=notrunc status=none
            dd if=/dev/zero of="$pe" bs=1 seek=$((header + 88)) count=4 conv=notrunc status=none
          done
          cmp -s /tmp/esp-one /tmp/esp-two || echo "differs: $f"
        done < /tmp/esp-a
        """
    ).strip()


def provision(inspect=None):
    """The real disko script, from an empty disk, then nixos-install, as `clan machines
    install` does. Only the secrets' upload is the test's own. `inspect` runs with the new
    system still mounted at /mnt."""
    global HOST_KEY_LINE
    BASE.mkdir(parents=True)
    TPM.mkdir(parents=True)
    for letter in "ab":
        new_blank(BASE / f"{letter}.qcow2")
    installer_up(BASE)

    seed_secrets(identity=False)
    rc, out = installer.execute(
        f"rc=0; {DISKO} --yes-wipe-all-disks > /tmp/disko.log 2>&1 || rc=$?; tail -n 20 /tmp/disko.log; exit $rc",
        timeout=600,
    )
    control(
        "disko-hook-refuses-missing-secret",
        rc != 0 and "refusing to install" in out,
        f"rc={rc}: {out[-400:]}",
    )
    release_disks()

    seed_secrets()
    installer.succeed(f"{DISKO} --yes-wipe-all-disks >&2", timeout=600)
    installer.succeed(
        f"nixos-install --root /mnt --system {TOPLEVEL} --no-root-passwd --no-channel-copy < /dev/null >&2",
        timeout=1200,
    )
    # A leg's ESP is only a way back if it matches. The one mutant with one ESP is the one
    # thing here that has to survive not matching: it's disk-a-dead that has to catch it.
    if MUTANT != "disk-a-dead":
        out = esp_differences(installer, "/mnt/boot", "/mnt/boot-fallback")
        control("both-esps-identical-after-install", out == "", out)
    # espread compares the initrd on the ESP with this. It isn't kept anywhere else.
    HOST_KEY_LINE = installer.succeed(f"sed -n 2p {HOST_KEY_FILE}").strip()
    if inspect is not None:
        inspect()
    release_disks()
    installer.shutdown()
    for letter in "ab":
        (BASE / f"{letter}.qcow2").chmod(stat.S_IRUSR)


def edit_esp(disks, *commands):
    """From the installer, what anyone with the disk can do to the unsigned ESP."""
    installer_up(disks)
    for part in ("disk-nvme0-ESP", "disk-nvme1-ESP"):
        installer.succeed(
            "mkdir -p /e",
            f"mount /dev/disk/by-partlabel/{part} /e",
            *commands,
            "umount /e",
        )
    installer.shutdown()


def select_entry(disks, specialisation, generation=1):
    # loader.conf is unsigned, and every signed entry on the ESP is fair game. Fails if no
    # such entry exists, because a selection that silently didn't apply boots the default.
    pattern = f"nixos-generation-{generation}-specialisation-{specialisation}-*"
    edit_esp(
        disks,
        f"ls /e/EFI/Linux/{pattern}.efi",
        f"sed -i 's/^default .*/default {pattern}/' /e/loader/loader.conf",
        f"grep -qF 'default {pattern}' /e/loader/loader.conf",
    )


# ── booting ───────────────────────────────────────────────────────────────


def boot(disks, machine=None, firmware=None):
    """Powers on from these disks. With no firmware given, fresh variables and a fresh TPM,
    as a machine nobody has configured. Returns the monotonic time of power-on."""
    machine = machine or target
    use_disks(disks)
    firmware = firmware or new_firmware()
    machine.efi_vars_path = firmware / "vars.fd"
    os.environ["NIX_SWTPM_DIR"] = str(firmware / "t")
    started = time.monotonic()
    machine.start()
    return started


def power_off(machine=None):
    machine = machine or target
    if machine.connected:
        machine.shutdown()
    elif machine.process is not None and machine.process.poll() is not None:
        # Firmware with nothing left to try resets, and the driver's -no-reboot ends QEMU.
        machine.wait_for_shutdown()
    else:
        machine.crash()


# ── reading the serial console ────────────────────────────────────────────
#
# Several writers share the serial port: the kernel's console, userspace on the tty (the agent's
# passphrase prompt), and userspace messages that go through the kernel log and come out as
# kernel records (systemd's own lines, the agent's "Starting password query"). Lines are not
# whole messages. Seen in these tests' own runs:
#
# - A record that runs to the end of its line can land in the middle of anything else. A
#   passphrase prompt has no newline of its own and takes a while to go out, so it ends up in
#   pieces on separate lines (a boot-fallback run, WS13 verification; the control then saw no
#   prompt in 60 s and failed):
#
#     Please enter pas[    2.785062] usb 1-1: Manufacturer: QEMU
#     sphrase for disk[    2.785913] usb 1-1: SerialNumber: 28754-0000:00:1d.7-1
#      disk-nvme0-luks (crypt-a): [    2.551702] systemd-tty-ask-password-agent[212]: Starting ...
#
# - A record can itself be cut that way, by other records. Its text then resumes at the start of
#   the following lines, and its newline comes later still, often as an empty line. Most
#   relayed userspace messages that get cut are cut like this (FLAKE3 verification, boot-no-gate):
#
#     Please enter passphrase for disk disk-nvme1-luks (crypt-b): (press TAB for no echo) [    2.475782] systemd[1]: Started ...
#     [    2.477353] systemd-tty-ask-p[    2.712832] ata2: SATA max UDMA/133 ...
#     assword-agent[190]: Starting pas[    2.714659] ata3: SATA max UDMA/133 ...
#     sword query on /dev/ttyS0.[    2.716188] ata4: SATA max UDMA/133 ...
#     (an empty line)
#
# - Text can be lost, and a relayed message and the prompt can run into each other with no
#   record start between them: `[    2.298684] systemd[1]: Started Dispatch PassPlease enter
#   passphrase for disk ...`, the rest of systemd's line never printed.
#
# So nothing that reads these lines can say which writer wrote which character. What the
# reader does is mechanical, and that is what it promises. It reads the log twice over:
#
# 1. Each line as it stands. That is all this used to do, and it still finds everything it found.
# 2. The console with every record that ran to the end of its line taken out: from each line,
#    the text before the last record start on it, joined to the next line's, and so on up to a
#    line with no record start at all, whose newline was not a record's. That line ends the
#    joined text, and nothing is joined across it. The joined text is the console's own
#    characters in their order, less those records; every other character is kept, a cut
#    record's start included. In the example above that gives the prompt, then `[    2.477353]
#    systemd-tty-ask-password-agent[190]: Starting password query on /dev/ttyS0.`: what was
#    written, in that order, with nothing that was not written.
#
# The joined text can hold more than one writer's text, as it does there, because the console
# put them in that order. A match in it is a match in what the console printed less those
# records, not proof that one writer wrote it in one go. That serves both kinds of check here: a
# prompt or the agent's line is found when records cut it, and a payload's or a shell's marker,
# or a relayed `systemd[1]: ...` line, that a check needs NOT to see is seen when records cut it.
# A match made only by the joining is logged with the lines it came from.
#
# Quietening the console was the other way out, and was not taken: it changes the system
# under test (its kernel command line, so every UKI), it hides the systemd lines the tests
# read (they reach the console as kernel records too, and one of them cut the prompt above),
# and it would only make this rarer. Reading the agent's ask files instead needs initrd SSH,
# which several cases and mutants take away or test.

# The start of a kernel record as the console prints it: `[%5lu.%06lu] `. systemd's status
# column (`[  OK  ]`, with or without colour) doesn't look like this.
KERNEL_RECORD = re.compile(r"\[ *\d+\.\d{6}\] ")


class ConsoleReader:
    """A machine's serial log read from a line on, as it grows."""

    def __init__(self, machine, start=0):
        self.machine = machine
        self.index = start
        # The console since the last line with no record on it, the records that ran to the end
        # of their lines taken out; the first line it comes from; and where in it each later
        # line's part begins.
        self.joined = ""
        self.first = start
        self.cuts = []

    def texts(self):
        """(index past the line, text, cuts) for what has arrived since the last call: each
        line as it is (cuts None), then, each time a line adds to text that records cut, that
        text joined so far, with the offsets where each later line's part begins. Within one
        joined text every yield adds exactly one cut, so the first has one."""
        lines = self.machine.full_console_log
        while self.index < len(lines):
            line = lines[self.index]
            self.index += 1
            yield self.index, line, None
            last = None
            for last in KERNEL_RECORD.finditer(line):
                pass
            part = line if last is None else line[: last.start()]
            if not self.joined:
                self.first = self.index - 1
            elif part:
                self.cuts.append(len(self.joined))
            self.joined += part
            if part and self.cuts:
                yield self.index, self.joined, tuple(self.cuts)
            if last is None:
                self.joined, self.cuts = "", []

    def search(self, regex):
        """(index past the line, match) for the first match in what has arrived, or None."""
        for index, text, cuts in self.texts():
            found = regex.search(text)
            if found is not None:
                if cuts is not None:
                    self.machine.log(
                        f"console: {regex.pattern!r} found only with the records that ended "
                        f"their lines taken out, lines {self.first + 1} to {index}: {found.group(0)!r}"
                    )
                return index, found
        return None


def console_findall(machine, regex):
    """Every match in the whole serial log, each once: in a line as it is, or, if it crosses a
    cut, in the joined text (ConsoleReader), read once that text is complete."""
    found = []
    joined = None

    def crossing(text, cuts):
        for match in regex.finditer(text):
            if any(match.start() < cut < match.end() for cut in cuts):
                found.append(match)

    for _, text, cuts in ConsoleReader(machine).texts():
        if cuts is None:
            found.extend(regex.finditer(text))
            continue
        if len(cuts) == 1 and joined is not None:
            crossing(*joined)
        joined = (text, cuts)
    if joined is not None:
        crossing(*joined)
    return found


def console_seen(machine, regex):
    """Whether the serial log has this anywhere, so far."""
    return ConsoleReader(machine).search(regex) is not None


def wait_console_match(machine, regex, timeout, start=0):
    """(index past the line where the first match ends, the match), or (None, None) at the
    timeout. The driver's wait_for_console_text can't look back, and raises rather than
    answers. A timeout of 0 reads what is there once."""
    deadline = time.monotonic() + timeout
    reader = ConsoleReader(machine, start)
    while True:
        found = reader.search(regex)
        if found is not None:
            return found
        if time.monotonic() >= deadline:
            return None, None
        time.sleep(0.2)


def wait_console(machine, regex, timeout, start=0):
    """Index just past the line where the first match ends, or None at the timeout."""
    return wait_console_match(machine, regex, timeout, start)[0]


def next_prompt(machine, after, timeout=45, regex=PROMPT):
    """Index past the next passphrase prompt on the serial console, or None."""
    return wait_console(machine, regex, timeout, after)


def serial(machine=None):
    machine = machine or target
    return lambda text: machine.send_console(text + "\n")


def tty0(machine=None):
    machine = machine or target
    return lambda text: machine.send_chars(text + "\n", delay=0.05)


def wait_stage2(machine, timeout):
    """Whether the stage-2 backdoor answered in time. connect() can't be cancelled, so
    it gets its own thread, and a test that sees False fails or crashes the VM."""
    thread = threading.Thread(target=machine.connect, daemon=True)
    thread.start()
    thread.join(timeout)
    return not thread.is_alive()


def type_until_console(machine, send, answer, regex, timeout=240):
    """Answers each prompt until the console says something matching. Returns whether it did."""
    after = 0
    reader = ConsoleReader(machine)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if reader.search(regex) is not None:
            return True
        found = next_prompt(machine, after, 0.5, ANY_PROMPT)
        if found is not None:
            after = found
            time.sleep(0.5)
            send(answer)
    return False


def connecting(machine):
    """A thread waiting for the stage-2 backdoor. connect() can't be cancelled, so one wait is
    handed on to the next (type_until_stage2's `thread`) rather than started twice. Stage 2
    answering is the only sign of an unlock this relies on: a console line can be lost or
    garbled on its way out of the serial port."""
    thread = threading.Thread(target=machine.connect, daemon=True)
    thread.start()
    return thread


def type_until_stage2(machine, send, after=0, timeout=240, thread=None):
    """Answers each prompt with the passphrase until stage 2 is up. One answer normally
    opens both legs, through the kernel keyring, but that isn't what this is testing."""
    thread = thread or connecting(machine)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and thread.is_alive():
        found = next_prompt(machine, after, 1, ANY_PROMPT)
        if found is not None:
            after = found
            time.sleep(0.5)
            send(PASSPHRASE)
    return not thread.is_alive()


# ── reading a booted node ─────────────────────────────────────────────────


def pool_status(machine=None):
    return (machine or target).succeed("zpool status -P rpool")


def both_legs_online(status):
    state = re.search(r"state: (\S+)", status)
    legs = {
        leg: re.search(rf"/dev/mapper/{leg}\s+(\S+)", status) for leg in ("crypt-a", "crypt-b")
    }
    return (
        state is not None
        and state.group(1) == "ONLINE"
        and all(m is not None and m.group(1) == "ONLINE" for m in legs.values())
    )


def root_is_the_pool(machine=None):
    return (machine or target).succeed("findmnt -no SOURCE /").strip() == "rpool/root"


EFI_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"


def efi_flag(name):
    """A one-byte EFI variable, past its four bytes of attributes."""
    return target.succeed(f"od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/{name}-{EFI_GLOBAL}").strip()


def secure_boot_status():
    """What bootctl says: `enabled (user)`, `disabled (setup)`."""
    found = re.search(r"Secure Boot: (.+)", target.succeed("bootctl status --no-pager --esp-path=/boot 2>&1 || true"))
    return found.group(1).strip() if found else ""


def enforcing():
    return secure_boot_status().startswith("enabled (user)") and efi_flag("SetupMode") == "0"


def pcr7():
    return target.succeed("cat /sys/class/tpm/tpm0/pcr-sha256/7").strip()


def booted_closure():
    return target.succeed("readlink -f /run/booted-system").strip()


def set_generation(closure):
    """What a deploy does before it activates anything: a new generation in the profile."""
    target.succeed(f"nix-env -p /nix/var/nix/profiles/system --set {closure}")


def install_bootloader():
    """(rc, output) of installing the bootloader for the profile's current generation."""
    return target.execute(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration boot 2>&1 | tail -n 25; exit ${PIPESTATUS[0]}",
        timeout=600,
    )


def on_esp(esp, generation):
    """Stubs of that generation, specialisations aside, on one ESP."""
    return target.succeed(
        f"find {esp}/EFI/Linux -name 'nixos-generation-{generation}-*.efi' ! -name '*-specialisation-*'"
    ).split()


def enroll_keys():
    return target.execute("sbctl enroll-keys --microsoft 2>&1")


def sealed_checkpoint():
    """S3 to S5 of the install: boots once in Setup Mode, enrolls from the OS, and boots again
    with Secure Boot enforcing. Returns frozen disks and the firmware that goes with them."""
    disks = new_case()
    firmware = new_firmware()
    boot(disks, firmware=firmware)
    control("sealed-first-boot", type_until_stage2(target, serial()), "no first boot")
    target.wait_for_unit("multi-user.target")
    if not SKIP_ENROLL:
        rc, out = enroll_keys()
        control("sealed-enroll", rc == 0, out)
    power_off()
    if not SKIP_ENROLL:
        boot(disks, firmware=firmware)
        control("sealed-second-boot", type_until_stage2(target, serial()), "no boot once enrolled")
        control("sealed-enforcing", enforcing(), secure_boot_status())
        power_off()
    # swtpm exits a moment after QEMU, and the copies of this are taken next.
    time.sleep(2)
    return freeze(disks), firmware


# ── reaching the initrd ───────────────────────────────────────────────────

SSH_OPTS = (
    "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 "
    f"-o BatchMode=yes -o LogLevel=ERROR -i /root/id -p {SSH_PORT}"
)


def ssh_ready():
    tang.succeed(f"install -m 0600 {SSH_KEY} /root/id")


def initrd_ssh(command, timeout=60):
    """(rc, output) of a command run in the initrd over the WAN NIC, from the peer."""
    return tang.execute(
        f"ssh -n {SSH_OPTS} root@{WAN_ADDRESS} {shlex.quote(command)} 2>&1",
        timeout=timeout,
    )


def wait_initrd_ssh(timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc, _ = initrd_ssh("true", timeout=15)
        if rc == 0:
            return True
        time.sleep(1)
    return False


def answer_over_ssh(password):
    """What an operator does: run the agent on a terminal and type."""
    return tang.execute(
        f"(sleep 2; printf '%s\\n' '{password}'; sleep 3) | timeout 30 ssh -tt {SSH_OPTS} "
        f"root@{WAN_ADDRESS} systemd-tty-ask-password-agent --query 2>&1",
        timeout=45,
    )


# ── changing the shape of the machine ─────────────────────────────────────


def without_drive(letter):
    """A start script with that drive physically gone: no blank replacement, no device at
    all. Returns a function that puts the original back."""
    original = target.start_command
    text = Path(original._cmd).read_text()
    edited, count = re.subn(
        rf"-drive [^\n]*?/{letter}\.qcow2[^\n]*?-device virtio-blk-pci,[^\s\\]*",
        "",
        text,
    )
    if count != 1:
        raise Exception(f"expected one drive {letter} in the start script, found {count}")
    path = WORK / f"run-without-{letter}"
    path.write_text(edited)
    path.chmod(0o755)
    target.start_command = type(original)(str(path))

    def restore():
        target.start_command = original

    return restore


# ── Clevis, Tang and the TPM ──────────────────────────────────────────────

TPM_ONLY = "/var/lib/boot-test/tpm-only.jwe"


def fetch_adv():
    """What an operator does on the Tang host: its own advertisement, over loopback. Stage 2
    of a node has no route to Tang, which is why the advertisement is delivered."""
    return tang.succeed(f"curl -sf http://127.0.0.1:{TANG_PORT}/adv").strip()


def foreign_adv():
    """A well-formed advertisement signed by keys nobody pinned: tangd itself, run once over
    stdin on a fresh key directory."""
    out = tang.succeed(
        "d=$(mktemp -d); "
        f"{TANGD_KEYGEN} $d >/dev/null; "
        f"printf 'GET /adv HTTP/1.1\\r\\nHost: tang\\r\\n\\r\\n' | {TANGD} $d 2>/dev/null"
    )
    return out.split("\r\n\r\n", 1)[1].strip()


def put_adv(adv, path="/run/adv.jws"):
    target.succeed(f"printf %s {shlex.quote(adv)} > {path}")
    return path


def bind(adv, *args):
    """(rc, output) of cluster-boot-seal bind, with the passphrase on stdin as `avc boot bind`
    sends it: no final newline."""
    path = put_adv(adv)
    extra = " ".join(shlex.quote(a) for a in args)
    return target.execute(
        f"printf %s {shlex.quote(PASSPHRASE)} | cluster-boot-seal bind --adv {path} {extra} 2>&1",
        timeout=300,
    )


def clevis_tokens(machine=None):
    """Clevis tokens per leg, read from the LUKS headers."""
    machine = machine or target
    return {
        name: int(
            machine.succeed(
                f"cryptsetup luksDump --dump-json-metadata {device} "
                "| jq '[.tokens[] | select(.type == \"clevis\")] | length'"
            ).strip()
        )
        for name, device in sorted(LUKS_DEVICES.items())
    }


def rec_count():
    """Key recoveries Tang has answered, so far. tangd logs one line per request."""
    return int(tang.succeed("journalctl -o cat --no-pager | grep -c 'POST /rec/.* => 200' || true").strip())


def vlan_up_by_hand():
    """Stage 2 has no route to Tang. The test alone puts one back, to ask Clevis for a key."""
    target.succeed(
        f"ip link add link {TRUNK} name {TANG_VLAN} type vlan id {VLAN_ID}",
        f"ip addr add {TANG_NODE_ADDRESS}/{TANG_PREFIX} dev {TANG_VLAN}",
        f"ip link set {TRUNK} up",
        f"ip link set {TANG_VLAN} up",
        f"timeout 30 sh -c 'until ping -c 1 -W 1 {TANG_ADDRESS} >/dev/null; do sleep 1; done'",
    )


def vlan_down_by_hand():
    target.succeed(f"ip link del {TANG_VLAN}")


def real_keys():
    """sha256 of the key each leg's Clevis slot opens with, from the genuine system. What a
    stolen JWE must decrypt to for an attack to count as reproduced."""
    keys = {}
    vlan_up_by_hand()
    for name, device in sorted(LUKS_DEVICES.items()):
        slot = target.succeed(f"clevis luks list -d {device} | cut -d: -f1").split()[0]
        keys[name] = target.succeed(
            f"clevis luks pass -d {device} -s {slot} | sha256sum | cut -d' ' -f1"
        ).strip()
    vlan_down_by_hand()
    return keys


def tpm_only_answer():
    """(rc, output) of the TPM's own answer to a JWE sealed to PCR 7 alone. Tang plays no part,
    so a refusal here is the TPM's."""
    return target.execute(f"clevis decrypt < {TPM_ONLY} 2>&1")


def bound_checkpoint(sealed, sealed_firmware):
    """S6 of the install, from an enforcing checkpoint: one typed boot, the advertisement
    delivered, both legs bound to Tang and PCR 7. Also leaves a JWE sealed to PCR 7 alone, so
    that later cases can ask the TPM by itself. Returns frozen disks, their firmware, the real
    keys, and PCR 7 as it was bound."""
    disks = new_case(base=sealed)
    firmware = new_firmware(sealed_firmware)
    boot(disks, firmware=firmware)
    control("bound-boot", type_until_stage2(target, serial()), "no stage 2 to bind from")
    target.wait_for_unit("multi-user.target")
    rc, out = bind(fetch_adv())
    control("bound", rc == 0 and set(clevis_tokens().values()) == {1}, f"rc={rc}\n{out}")
    target.succeed(
        "mkdir -p /var/lib/boot-test",
        f"echo tpm-canary | clevis encrypt tpm2 '{{\"pcr_bank\":\"sha256\",\"pcr_ids\":\"7\"}}' > {TPM_ONLY}",
    )
    rc, out = tpm_only_answer()
    control("bound-tpm-only-opens-here", rc == 0 and "tpm-canary" in out, out)
    keys = real_keys()
    bound_pcr7 = pcr7()
    power_off()
    time.sleep(2)
    return freeze(disks), firmware, keys, bound_pcr7


def boot_unattended(disks, firmware, timeout=120):
    """Powers on and types nothing. Returns whether stage 2 came up, and how long it took."""
    started = boot(disks, firmware=firmware)
    booted = wait_stage2(target, timeout)
    return booted, time.monotonic() - started


def stop_tang():
    tang.succeed("systemctl stop tangd.socket")


def start_tang():
    tang.succeed("systemctl start tangd.socket")
