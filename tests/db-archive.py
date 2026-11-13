import shlex
import time


def sql(query):
    return maria.succeed("mariadb -N -B -e " + shlex.quote(query)).strip()


def gtid():
    return sql("SELECT @@gtid_binlog_pos")


def archive(arguments):
    """db-archive, as an operator or a timer runs it: (status, output)."""
    return maria.execute(f"db-archive {arguments} 2>&1")


def objects(below=""):
    """Every object in the app's storage, as paths below its prefix."""
    return maria.succeed(f"cd {STORAGE} && find ./{below} -type f 2>/dev/null | sort || true").split()


def stored(text):
    """The stored objects that hold this text in the clear."""
    return maria.succeed(f"grep -r -a -l -F {shlex.quote(text)} /srv/s3 || true").split()


def metrics():
    out = {}
    for line in maria.succeed(f"cat {METRICS} 2>/dev/null || true").splitlines():
        name, _, value = line.partition(" ")
        out[name.removeprefix("cluster_db_archive_")] = value
    return out


def marker():
    return maria.succeed(f"cat {MARKER} 2>/dev/null || true").strip()


def pushed(generation):
    return maria.succeed(f"cat {STATE}/gen-{generation}/pushed-gtid 2>/dev/null || echo unset").strip()


def base_backups(generation):
    return [
        o.rsplit("/", 1)[1].removesuffix("_backup_stop_sentinel.json")
        for o in objects(f"gen-{generation}/basebackups_005")
        if o.endswith("_backup_stop_sentinel.json")
    ]


def until(seconds, probe):
    """The first true answer of probe() within the time, else its last answer."""
    deadline = time.monotonic() + seconds
    while True:
        answer = probe()
        if answer or time.monotonic() > deadline:
            return answer
        time.sleep(2)


def idle(unit):
    until(120, lambda: maria.execute(f"systemctl is-active {unit}")[1].strip() in ("inactive", "failed"))


def s3(up):
    if up:
        maria.succeed("systemctl start s3.service")
        maria.wait_for_open_port(9000)
    else:
        maria.succeed("systemctl stop s3.service")
        maria.wait_for_closed_port(9000)


def write_row(text):
    sql(f"INSERT INTO canarydb.t (v) VALUES ('{text}')")


def first_generation():
    """Nobody runs anything: the timer finds an empty archive and starts generation 1."""
    # Its first base backup is started with it, not left to the hourly timer.
    started = until(180, lambda: marker() == "1" and objects("gen-1/binlog_005") and base_backups(1))
    seen = metrics()
    control(
        "timer-starts-generation-one",
        bool(started) and seen.get("generation") == "1" and seen.get("refused") == "0",
        f"marker {marker()!r}, objects {objects()}, metrics {seen}",
    )
    # From here the script drives each run itself.
    maria.succeed("systemctl stop db-archive-push.timer db-archive-base.timer")
    idle("db-archive-push.service")
    idle("db-archive-base.service")


def push_is_confirmed_and_encrypted():
    sql("CREATE DATABASE canarydb")
    sql("CREATE TABLE canarydb.t (id INT AUTO_INCREMENT PRIMARY KEY, v TEXT)")
    write_row(CANARY)
    before = objects("gen-1/binlog_005")
    rc, out = archive("push")
    after = objects("gen-1/binlog_005")
    control(
        "push-recorded-position",
        rc == 0 and len(after) > len(before) and pushed(1) == gtid(),
        f"rc {rc}, {len(before)} -> {len(after)} logs, pushed {pushed(1)!r}, at {gtid()!r}: {out}",
    )
    # The search can see the canary where it is in the clear, so not finding it means something.
    local = maria.succeed(f"grep -a -l -F {CANARY} {DATA_DIR}/mysql-bin.[0-9]* || true").split()
    assert local, "the canary is not in the local binary log, so the search below proves nothing"
    control("canary-encrypted-in-storage", not stored(CANARY), f"in the clear in {stored(CANARY)}")

    # Nothing written, nothing shipped, and still a success.
    rc, out = archive("push")
    assert rc == 0 and objects("gen-1/binlog_005") == after, f"an idle push: rc {rc}, {out}"
    age = time.time() - float(metrics().get("last_ok_timestamp_seconds", "0"))
    assert age < 120, f"last_ok is {age:.0f}s old after a successful push"


def closed_log():
    """The newest closed binary log: the one before the one being written."""
    names = [line.split()[0] for line in sql("SHOW BINARY LOGS").splitlines()]
    return names[-2]


def walg_cache_is_not_trusted():
    """WAL-G uploads the logs numbered after the one its cache names, and drops a
    cache only when it names a log beyond the newest. One that names the log being
    written is kept: binlog-push then skips that log, uploads nothing and exits 0."""
    maria.succeed(f"test -s {WALG_CACHE}")
    current = sql("SHOW BINARY LOGS").splitlines()[-1].split()[0]
    maria.succeed(f"""echo '{{"LastArchivedBinlog":"{current}"}}' > {WALG_CACHE}""")
    write_row("after-the-cache-was-moved")
    rc, out = archive("push")
    control(
        "walg-cache-is-not-trusted",
        rc == 0 and pushed(1) == gtid(),
        f"rc {rc}, pushed {pushed(1)!r}, at {gtid()!r}: {out}",
    )
    # What the archiver recorded as pushed is in storage, by the test's own look.
    name = closed_log()
    assert name == current, f"the push closed {name}, and the cache was set to {current}"
    there = [o for o in objects("gen-1/binlog_005") if o.endswith(f"/{name}.lz4")]
    control("recorded-push-is-in-storage", bool(there), f"{name} is recorded as pushed; storage has {objects('gen-1/binlog_005')}")


def renumbered_logs():
    """RESET MASTER numbers the logs from 1 again. Generation 1 already holds a log
    of every such name, from the history before it."""
    sql("RESET MASTER")
    write_row("after-the-logs-were-renumbered")
    before = objects()
    rc, out = archive("push")
    control(
        "renumbered-logs-refused",
        rc != 0 and objects() == before and metrics().get("refused") == "1",
        f"rc {rc}, new objects {sorted(set(objects()) - set(before))}, metrics {metrics()}: {out}",
    )
    # The refusal does not rest on the archiver's own bookkeeping: without it, storage is asked.
    maria.succeed(f"rm -rf {STATE}/gen-1")
    rc, out = archive("push")
    assert rc != 0 and objects() == before and "renumbered" in out, f"without the record: rc {rc}, {out}"


def no_key_no_upload():
    second = CANARY + "-second"
    maria.succeed(f": > {KEY_FILE}")
    write_row(second)
    before = objects()
    rc, out = archive("push")
    after = objects()
    control(
        "no-key-no-upload",
        rc != 0 and after == before and not stored(second),
        f"rc {rc}, new objects {sorted(set(after) - set(before))}, in the clear in {stored(second)}: {out}",
    )
    maria.succeed(f"printf %s not-a-key > {KEY_FILE}")
    rc, out = archive("push")
    assert rc != 0 and objects() == before, f"a key that is not hexadecimal: rc {rc}, {out}"
    maria.succeed(f"printf %s {KEY} > {KEY_FILE}")
    rc, out = archive("push")
    assert rc == 0 and pushed(1) == gtid() and not stored(second), f"with the key back: rc {rc}, {out}"


def marker_missing():
    maria.succeed(f"mv {MARKER} /root/marker.kept")
    write_row("written-without-a-marker")
    before = objects()
    rc, out = archive("push")
    control(
        "marker-missing-over-data-refused",
        rc != 0 and marker() == "" and objects() == before and metrics().get("refused") == "1",
        f"rc {rc}, marker {marker()!r}, new objects {sorted(set(objects()) - set(before))}, "
        f"metrics {metrics()}: {out}",
    )

    # Storage that does not answer is not an empty archive.
    s3(False)
    rc, out = archive("push")
    control(
        "unlisted-archive-is-not-empty",
        rc != 0 and marker() == "" and metrics().get("refused") == "1",
        f"rc {rc}, marker {marker()!r}, metrics {metrics()}: {out}",
    )
    s3(True)


def next_generation():
    rc, out = archive("next-generation")
    assert rc == 2 and "generation 2" in out and marker() == "", f"without --yes: rc {rc}, {out}"
    rc, out = archive("next-generation --yes")
    assert rc == 0 and marker() == "2", f"next-generation --yes: rc {rc}, marker {marker()!r}, {out}"
    # It starts the new generation's base backup itself.
    first = until(180, lambda: base_backups(2))
    idle("db-archive-base.service")
    seen = metrics()
    assert first and seen.get("generation") == "2" and seen.get("refused") == "0", f"{first}, {seen}"
    assert float(seen.get("last_base_timestamp_seconds", "0")) > 0, seen

    write_row("in-generation-two")
    rc, out = archive("push")
    assert rc == 0 and pushed(2) == gtid() and objects("gen-2/binlog_005"), f"rc {rc}, {out}"


def base_backups_and_retention():
    first = base_backups(2)
    early = objects("gen-2/binlog_005")
    assert early, "generation 2 holds no binary log from before its second base backup"
    rc, out = archive("base")
    assert rc == 0 and base_backups(2) == first, f"a base backup that was not due: rc {rc}, {base_backups(2)}"
    time.sleep(1)
    rc, out = archive("base --force")
    second = base_backups(2)
    assert rc == 0 and len(second) == 2, f"rc {rc}, {second}: {out}"
    time.sleep(1)
    rc, out = archive("base --force")
    third = base_backups(2)
    assert rc == 0 and len(third) == 2 and first[0] not in third, f"rc {rc}, {first} -> {third}: {out}"
    # The binary logs from before the oldest base backup kept go with the base backups.
    left = sorted(set(early) & set(objects("gen-2/binlog_005")))
    assert not left, f"binary logs older than every base backup kept are still stored: {left}"

    # What is stored can be read with the key, and not with another.
    maria.succeed("mkdir -p /root/fetched /root/fetched-wrong")
    fetch = "WALG_STREAM_RESTORE_COMMAND='mbstream -x -C {}' db-archive wal-g backup-fetch LATEST 2>&1"
    rc, out = maria.execute(fetch.format("/root/fetched"))
    tables = maria.succeed("ls /root/fetched/canarydb 2>/dev/null || true").split()
    assert rc == 0 and any(t.startswith("t.") for t in tables), f"fetch: rc {rc}, {tables}: {out}"
    maria.succeed(f"printf %s {OTHER_KEY} > {KEY_FILE}")
    rc, out = maria.execute(fetch.format("/root/fetched-wrong"))
    left = maria.succeed("ls /root/fetched-wrong").split()
    maria.succeed(f"printf %s {KEY} > {KEY_FILE}")
    assert rc != 0 and "canarydb" not in left, f"a fetch with another key: rc {rc}, {left}: {out}"


def earlier_generations():
    """Generation 1 is an earlier one now. It is kept for as long as a restore reaches
    back, which is a day here, and after that it is deleted when asked and not before."""
    kept = objects("gen-1")
    current = objects("gen-2")
    assert kept and current, f"generation 1: {len(kept)} objects, generation 2: {len(current)}"
    rc, out = archive("drop-generation 1 --yes")
    control(
        "generation-inside-the-window-is-kept",
        rc != 0 and objects("gen-1") == kept,
        f"rc {rc}, {len(kept)} -> {len(objects('gen-1'))} objects: {out}",
    )
    rc, out = archive("generations")
    assert rc == 0 and "gen-1: last written" in out and "kept until" in out, f"rc {rc}, {out}"
    assert "gen-2: this data directory's" in out, out
    assert metrics().get("droppable_generations") == "0", metrics()

    # Storage is files here. Generation 1 is made three days old, and the archive
    # is given a later generation than this data directory's, as old.
    maria.succeed(
        f"find {STORAGE}/gen-1 -exec touch -d '3 days ago' {{}} + && cp -a {STORAGE}/gen-1 {STORAGE}/gen-10"
    )
    # rclone lists from its own cache of the directory.
    s3(False)
    s3(True)
    later = objects("gen-10")
    assert len(later) == len(kept)
    rc, out = archive("generations")
    assert rc == 0 and "drop-generation 1 --yes" in out and "gen-10: later" in out, f"rc {rc}, {out}"
    assert metrics().get("droppable_generations") == "1", metrics()

    rc, out = archive("drop-generation 10 --yes")
    control(
        "later-generation-is-not-dropped",
        rc != 0 and objects("gen-10") == later,
        f"rc {rc}, {len(later)} -> {len(objects('gen-10'))} objects: {out}",
    )
    rc, out = archive("drop-generation 2 --yes")
    assert rc != 0 and objects("gen-2") == current, f"this data directory's own generation: rc {rc}, {out}"
    rc, out = archive("drop-generation 1")
    assert rc == 2 and objects("gen-1") == kept, f"without --yes: rc {rc}, {out}"
    # Storage that does not answer has not said the generation is old.
    s3(False)
    rc, out = archive("drop-generation 1 --yes")
    s3(True)
    assert rc not in (0, 2) and objects("gen-1") == kept, f"without storage: rc {rc}, {out}"

    rc, out = archive("drop-generation 1 --yes")
    assert rc == 0 and not objects("gen-1"), f"rc {rc}, {len(objects('gen-1'))} objects left: {out}"
    # Generation 1, and not also generation 10.
    assert objects("gen-10") == later and objects("gen-2") == current, f"{out}: {objects()}"
    assert metrics().get("droppable_generations") == "0", metrics()
    rc, out = archive("drop-generation 1 --yes")
    assert rc == 0 and "holds nothing" in out, f"a second time: rc {rc}, {out}"

    maria.succeed(f"rm -rf {STORAGE}/gen-10 {STORAGE}/gen-1")
    s3(False)
    s3(True)


def timer_survives_an_outage():
    maria.succeed("systemctl start db-archive-push.timer")
    s3(False)
    write_row("during-the-outage")
    failed = until(
        90,
        lambda: maria.succeed("systemctl show -p Result --value db-archive-push.service").strip() == "exit-code",
    )
    assert failed, "no failed push while storage was down"
    assert pushed(2) != gtid(), "a push was recorded while storage was down"
    write_row("still-during-the-outage")
    s3(True)
    caught_up = until(90, lambda: pushed(2) == gtid())
    control(
        "timer-recovers-after-an-outage",
        bool(caught_up),
        f"pushed {pushed(2)!r}, at {gtid()!r}: "
        + maria.succeed("systemctl status db-archive-push.timer db-archive-push.service 2>&1 | head -30 || true"),
    )
    maria.succeed("systemctl stop db-archive-push.timer")
    idle("db-archive-push.service")


def clean_stop():
    write_row("just-before-the-stop")
    at = gtid()
    assert pushed(2) != at
    maria.succeed("systemctl stop mysql.service")
    control(
        "clean-stop-ships-the-last-log",
        pushed(2) == at,
        f"pushed {pushed(2)!r}, stopped at {at!r}: "
        + maria.succeed("journalctl -u mysql.service -n 20 --no-pager -o cat || true"),
    )

    # Without storage the last push fails, and the stop is still a stop.
    maria.succeed("systemctl start mysql.service")
    write_row("before-a-stop-without-storage")
    s3(False)
    began = time.monotonic()
    maria.succeed("systemctl stop mysql.service")
    took = time.monotonic() - began
    state = maria.execute("systemctl is-active mysql.service")[1].strip()
    assert state == "inactive" and took < 80, f"mysql.service is {state} after a {took:.0f}s stop"
    s3(True)


def main():
    maria.wait_for_unit("s3.service")
    maria.wait_for_open_port(9000)
    maria.wait_for_unit("mysql.service")
    first_generation()
    push_is_confirmed_and_encrypted()
    walg_cache_is_not_trusted()
    no_key_no_upload()
    renumbered_logs()
    marker_missing()
    next_generation()
    base_backups_and_retention()
    earlier_generations()
    timer_survives_an_outage()
    clean_stop()


run_main(main)
