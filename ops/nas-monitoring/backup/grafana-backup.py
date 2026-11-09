"""Daily backup of grafana.db into /backup/grafana, keeping the last KEEP.

sqlite3's backup API takes a consistent snapshot of a live database, WAL
included. /data must be mounted read-write: SQLite touches the -shm file even
when it only reads.

RUN_AT_UTC is HH:MM in UTC (00:30 UTC = 03:30 MSK). ONCE=1 runs one backup
immediately and exits.
"""
import datetime as dt
import gzip
import os
import shutil
import sqlite3
import time

DST = "/backup/grafana"
KEEP = 7
RUN_AT_UTC = os.environ.get("RUN_AT_UTC", "00:30")


def backup() -> None:
    os.makedirs(DST, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M")
    tmp = "/tmp/grafana.db"
    # mode=rw: a plain connect() would create an empty grafana.db when the
    # file is missing and then back up that empty database.
    src = sqlite3.connect("file:/data/grafana.db?mode=rw", uri=True)
    dst = sqlite3.connect(tmp)
    src.backup(dst)
    dst.close()
    src.close()

    out = f"{DST}/grafana-{stamp}.db.gz"
    # Write to .part and rename, so a failure midway never leaves a truncated
    # grafana-*.db.gz that counts toward KEEP.
    part = out + ".part"
    with open(tmp, "rb") as f, gzip.open(part, "wb") as g:
        shutil.copyfileobj(f, g)
    os.replace(part, out)
    os.unlink(tmp)
    print(f"written {out} ({os.path.getsize(out)} bytes)", flush=True)

    # The timestamp format sorts lexically in chronological order.
    snaps = sorted(f for f in os.listdir(DST) if f.startswith("grafana-") and f.endswith(".db.gz"))
    for old in snaps[:-KEEP]:
        os.unlink(f"{DST}/{old}")
        print("pruned", old, flush=True)
    print("kept:", len(snaps[-KEEP:]), flush=True)


def seconds_until(hhmm: str) -> float:
    now = dt.datetime.now(dt.timezone.utc)
    h, m = map(int, hhmm.split(":"))
    nxt = now.replace(hour=h, minute=m, second=0, microsecond=0)
    if nxt <= now:
        nxt += dt.timedelta(days=1)
    return (nxt - now).total_seconds()


if os.environ.get("ONCE") == "1":
    backup()
else:
    while True:
        wait = seconds_until(RUN_AT_UTC)
        print(f"next grafana backup in {int(wait)} s", flush=True)
        time.sleep(wait)
        try:
            backup()
        except Exception as e:  # keep the loop alive; the log shows the failure
            print(f"grafana backup failed: {e!r}", flush=True)
