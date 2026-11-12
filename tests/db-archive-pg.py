import shlex
import time


def sql(query):
    command = "cd / && runuser -u postgres -- psql -X -At -v ON_ERROR_STOP=1 -d postgres -c "
    return pg.succeed(command + shlex.quote(query)).strip()


def archive(arguments):
    """db-archive, as an operator or a timer runs it: (status, output)."""
    return pg.execute(f"db-archive {arguments} 2>&1")


def objects(below=""):
    """Every object in the app's storage, as paths below its prefix."""
    return pg.succeed(f"cd {STORAGE} && find ./{below} -type f 2>/dev/null | sort || true").split()


def stored(text):
    """The stored objects that hold this text in the clear."""
    return pg.succeed(f"grep -r -a -l -F {shlex.quote(text)} /srv/s3 || true").split()


def not_ciphertext():
    """The stored objects that do not begin as pgBackRest's encrypted files do."""
    return pg.succeed(
        f"cd {STORAGE} && find . -type f | sort | while read -r f; do "
        '[ "$(head -c 8 "$f")" = Salted__ ] || echo "$f"; done'
    ).split()


def metrics():
    out = {}
    for line in pg.succeed(f"cat {METRICS} 2>/dev/null || true").splitlines():
        name, _, value = line.partition(" ")
        out[name.removeprefix("cluster_db_archive_")] = value
    return out


def last_ok():
    return float(metrics().get("last_ok_timestamp_seconds", "0"))


def marker():
    return pg.succeed(f"cat {MARKER} 2>/dev/null || true").strip()


def wal():
    """The WAL segment being written."""
    return sql("SELECT pg_walfile_name(pg_current_wal_lsn())")


def switch():
    sql("SELECT pg_switch_wal()")


def waiting():
    """How many closed WAL segments PostgreSQL still has to hand over."""
    return int(pg.succeed(f"find {DATA_DIR}/pg_wal/archive_status -name '*.ready' | wc -l").strip())


def archived(generation, name):
    return [o for o in objects(f"gen-{generation}/archive") if f"/{name}-" in o]


def backups(generation):
    """The complete base backups of a generation, by label."""
    return sorted(
        o.split("/")[-2] for o in objects(f"gen-{generation}/backup") if o.endswith("/backup.manifest")
    )


def gap():
    return pg.succeed(f"ls {GAP} {GAP}.closing 2>/dev/null || true").split()


def until(seconds, probe):
    """The first true answer of probe() within the time, else its last answer."""
    deadline = time.monotonic() + seconds
    while True:
        answer = probe()
        if answer or time.monotonic() > deadline:
            return answer
        time.sleep(2)


def idle(unit):
    until(240, lambda: pg.execute(f"systemctl is-active {unit}")[1].strip() in ("inactive", "failed"))


def s3(up):
    if up:
        pg.succeed("systemctl start s3.service")
        pg.wait_for_open_port(9000)
    else:
        pg.succeed("systemctl stop s3.service")
        pg.wait_for_closed_port(9000)


def write_row(text):
    sql(f"INSERT INTO t (v) VALUES ('{text}')")


def journal():
    return pg.succeed(
        "journalctl -u postgresql.service -u db-archive-push.service -u db-archive-base.service "
        "-n 40 --no-pager -o cat || true"
    )


def first_generation():
    """Nobody runs anything: the timer finds an empty archive and starts generation 1."""
    started = until(300, lambda: marker() == "1" and backups(1))
    seen = metrics()
    control(
        "pg-timer-starts-generation-one",
        bool(started) and seen.get("generation") == "1" and seen.get("refused") == "0",
        f"marker {marker()!r}, objects {objects()}, metrics {seen}: {journal()}",
    )
    # From here the script drives each run itself.
    pg.succeed("systemctl stop db-archive-push.timer db-archive-base.timer")
    idle("db-archive-push.service")
    idle("db-archive-base.service")


def wal_is_shipped_and_encrypted():
    sql("CREATE TABLE t (id SERIAL PRIMARY KEY, v TEXT)")
    write_row(CANARY)
    name = wal()
    # The search can see the canary where it is in the clear, so not finding it means something.
    local = pg.succeed(f"grep -a -l -F {CANARY} {DATA_DIR}/pg_wal/{name} || true").split()
    assert local, "the canary is not in the local WAL, so the search below proves nothing"
    # Nobody switches the segment or runs a push.
    there = until(90, lambda: archived(1, name))
    control("pg-wal-reaches-storage", bool(there), f"{name} is not in {objects('gen-1/archive')}: {journal()}")
    control(
        "pg-storage-is-encrypted",
        not not_ciphertext() and not stored(CANARY),
        f"not ciphertext: {not_ciphertext()}; the canary in the clear in {stored(CANARY)}",
    )

    until(30, lambda: waiting() == 0)
    rc, out = archive("push")
    age = time.time() - last_ok()
    assert rc == 0 and age < 60, f"a push with nothing waiting: rc {rc}, last_ok {age:.0f}s old: {out}"


def no_key_no_upload():
    second = CANARY + "-second"
    pg.succeed(f": > {KEY_FILE}")
    rc, out = archive("push")
    assert rc != 0, f"a push with an empty key file: rc {rc}, {out}"
    before = objects()
    write_row(second)
    name = wal()
    switch()
    time.sleep(20)
    after = objects()
    control(
        "pg-no-key-no-upload",
        after == before and waiting() >= 1 and not stored(second),
        f"new objects {sorted(set(after) - set(before))}, {waiting()} waiting, "
        f"in the clear in {stored(second)}: {out}",
    )
    pg.succeed(f"printf %s not-a-key > {KEY_FILE}")
    rc, out = archive("push")
    assert rc != 0 and objects() == before, f"a key that is not hexadecimal: rc {rc}, {out}"
    pg.succeed(f"printf %s {KEY} > {KEY_FILE}")
    rc, out = archive("push")
    assert rc == 0, f"with the key back: rc {rc}, {out}"
    # PostgreSQL asks again by itself, within a minute.
    there = until(150, lambda: archived(1, name) and waiting() == 0)
    assert there and not stored(second) and not not_ciphertext(), f"with the key back: {journal()}"


def marker_missing():
    pg.succeed(f"mv {MARKER} /root/marker.kept")
    before = objects()
    rc, out = archive("push")
    write_row("written-without-a-marker")
    switch()
    time.sleep(20)
    control(
        "pg-marker-missing-over-data-refused",
        rc != 0 and marker() == "" and objects() == before and metrics().get("refused") == "1",
        f"rc {rc}, marker {marker()!r}, new objects {sorted(set(objects()) - set(before))}, "
        f"metrics {metrics()}: {out}",
    )

    # Storage that does not answer is not an empty archive.
    s3(False)
    rc, out = archive("push")
    control(
        "pg-unlisted-archive-is-not-empty",
        rc != 0 and marker() == "" and metrics().get("refused") == "1",
        f"rc {rc}, marker {marker()!r}, metrics {metrics()}: {out}",
    )
    s3(True)


def next_generation():
    old = objects("gen-1")
    rc, out = archive("next-generation")
    assert rc == 2 and "generation 2" in out and marker() == "", f"without --yes: rc {rc}, {out}"
    rc, out = archive("next-generation --yes")
    assert rc == 0 and marker() == "2", f"next-generation --yes: rc {rc}, marker {marker()!r}, {out}"
    # It starts the new generation's base backup itself.
    first = until(300, lambda: backups(2))
    idle("db-archive-base.service")
    seen = metrics()
    assert first and seen.get("generation") == "2" and seen.get("refused") == "0", f"{first}, {seen}: {journal()}"
    assert float(seen.get("last_base_timestamp_seconds", "0")) > 0, seen

    write_row("in-generation-two")
    name = wal()
    there = until(90, lambda: archived(2, name))
    assert there, f"{name} is not in generation 2: {objects('gen-2/archive')}: {journal()}"
    assert objects("gen-1") == old, "generation 1 changed after generation 2 began"


def base_backups_and_retention():
    rc, out = archive("push")
    assert rc == 0, f"rc {rc}, {out}"
    first = backups(2)
    rc, out = archive("base")
    assert rc == 0 and backups(2) == first, f"a base backup that was not due: rc {rc}, {backups(2)}: {out}"
    time.sleep(1)
    rc, out = archive("base --force")
    second = backups(2)
    assert rc == 0 and len(second) == 2, f"rc {rc}, {second}: {out}"
    time.sleep(1)
    rc, out = archive("base --force")
    third = backups(2)
    assert rc == 0 and len(third) == 2 and first[0] not in third, f"rc {rc}, {first} -> {third}: {out}"
    assert not not_ciphertext(), f"not ciphertext: {not_ciphertext()}"

    # What is stored can be read with the key, and not with another.
    pg.succeed("install -d -m 0700 -o postgres -g postgres /var/lib/pg-fetched /var/lib/pg-fetched-wrong")
    rc, out = archive("pgbackrest restore --pg1-path=/var/lib/pg-fetched")
    got = pg.succeed("ls -A /var/lib/pg-fetched").split()
    assert rc == 0 and "PG_VERSION" in got and "base" in got, f"restore: rc {rc}, {got}: {out}"
    # The marker stays out of a base backup: what is restored is not yet any generation.
    assert not [f for f in got if "db-archive" in f], f"the archiver's own files were restored: {got}"
    pg.succeed(f"printf %s {OTHER_KEY} > {KEY_FILE}")
    rc, out = archive("pgbackrest restore --pg1-path=/var/lib/pg-fetched-wrong")
    left = pg.succeed("ls -A /var/lib/pg-fetched-wrong").split()
    pg.succeed(f"printf %s {KEY} > {KEY_FILE}")
    assert rc != 0 and "PG_VERSION" not in left, f"a restore with another key: rc {rc}, {left}: {out}"
    rc, out = archive("push")
    assert rc == 0, f"with the key back: rc {rc}, {out}"


def queue_is_bounded():
    """With storage away PostgreSQL keeps what it could not hand over. Up to the limit."""
    until(60, lambda: waiting() == 0)
    rc, out = archive("push")
    held = last_ok()
    assert rc == 0 and not gap(), f"before the outage: rc {rc}, gap {gap()}: {out}"
    s3(False)
    for n in range(5):
        write_row(f"during-the-long-outage-{n}")
        switch()
    bounded = until(150, lambda: gap() and waiting() <= 2)
    control(
        "pg-wal-queue-is-bounded",
        bool(bounded),
        f"{waiting()} segments waiting, gap {gap()}: {journal()}",
    )
    s3(True)
    drained = until(180, lambda: waiting() == 0)
    assert drained, f"{waiting()} segments still waiting with storage back: {journal()}"

    # The segments that were dropped are in no archive, so the metric does not move...
    labels = backups(2)
    rc, out = archive("push")
    assert rc == 0 and last_ok() == held, f"a push over a gap: rc {rc}, last_ok {held} -> {last_ok()}: {out}"
    # ...until a base backup, which that push started though none was due.
    closed = until(240, lambda: not gap() and set(backups(2)) - set(labels))
    control(
        "pg-gap-forces-base-backup",
        bool(closed),
        f"gap {gap()}, base backups {labels} -> {backups(2)}: {journal()}",
    )
    idle("db-archive-base.service")
    rc, out = archive("push")
    assert rc == 0 and last_ok() > held, f"a push after the gap was closed: rc {rc}, {held} -> {last_ok()}: {out}"


def recovers_after_an_outage():
    pg.succeed("systemctl start db-archive-push.timer")
    s3(False)
    write_row("during-the-outage")
    name = wal()
    switch()
    time.sleep(25)
    held = last_ok()
    time.sleep(25)
    assert waiting() >= 1 and last_ok() == held and not archived(2, name), (
        f"with storage down: {waiting()} waiting, last_ok {held} -> {last_ok()}"
    )
    s3(True)
    caught_up = until(180, lambda: archived(2, name) and last_ok() > held)
    control(
        "pg-archive-recovers-after-an-outage",
        bool(caught_up) and not gap(),
        f"{name} in storage: {archived(2, name)}, last_ok {held} -> {last_ok()}, gap {gap()}: {journal()}",
    )
    pg.succeed("systemctl stop db-archive-push.timer")
    idle("db-archive-push.service")


def clean_stop():
    write_row("just-before-the-stop")
    name = wal()
    pg.succeed("systemctl stop postgresql.service")
    control(
        "pg-clean-stop-ships-the-last-wal",
        bool(archived(2, name)),
        f"{name} is not in storage: {journal()}",
    )

    # Without storage the last segment stays behind, and the stop is still a stop.
    pg.succeed("systemctl start postgresql.service")
    write_row("before-a-stop-without-storage")
    s3(False)
    began = time.monotonic()
    pg.succeed("systemctl stop postgresql.service")
    took = time.monotonic() - began
    state = pg.execute("systemctl is-active postgresql.service")[1].strip()
    # A container is given 90 seconds to stop.
    assert state == "inactive" and took < 80, f"postgresql.service is {state} after a {took:.0f}s stop"
    s3(True)


def main():
    pg.wait_for_unit("s3.service")
    pg.wait_for_open_port(9000)
    pg.wait_for_unit("postgresql.service")
    first_generation()
    wal_is_shipped_and_encrypted()
    no_key_no_upload()
    marker_missing()
    next_generation()
    base_backups_and_retention()
    queue_is_bounded()
    recovers_after_an_outage()
    clean_stop()


run_main(main)
