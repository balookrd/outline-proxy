"""Daily backup of grafana.db into /backup/grafana, keeping the last KEEP.

sqlite3's backup API takes a consistent snapshot of a live database, WAL
included. /data must be mounted read-write: SQLite touches the -shm file even
when it only reads.

RUN_AT_UTC is HH:MM in UTC (00:30 UTC = 03:30 MSK). ONCE=1 runs one backup
immediately and exits.

After a successful run the script pushes
nas_backup_last_success_timestamp_seconds{backup="grafana"} to PUSH_URL.
"""
import datetime as dt
import gzip
import os
import re
import shutil
import sqlite3
import time
import urllib.request

DST = "/backup/grafana"
KEEP = 7
RUN_AT_UTC = os.environ.get("RUN_AT_UTC", "00:30")
PUSH_URL = os.environ.get("PUSH_URL", "http://198.18.1.105:8428/api/v1/import/prometheus")


if not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", RUN_AT_UTC):
    # Fail at start: a bad value would otherwise surface only as a crash
    # at the first scheduling attempt, or not at all with ONCE=1.
    raise SystemExit(f"RUN_AT_UTC must be HH:MM in UTC, got {RUN_AT_UTC!r}")


def report_success(name: str) -> None:
    """Record the time of the last successful run in VictoriaMetrics.

    vmalert's BackupStale / BackupMissing (ops/alerting/vmalert/rules.yaml)
    alert on this series. A failed push is logged, not raised: the backup
    itself succeeded, and a missing sample shows up as BackupStale anyway.
    """
    line = f'nas_backup_last_success_timestamp_seconds{{backup="{name}"}} {int(time.time())}\n'
    req = urllib.request.Request(PUSH_URL, data=line.encode(), method="POST")
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except OSError as e:  # URLError is an OSError
        print(f"could not report success to {PUSH_URL}: {e!r}", flush=True)

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
    report_success("grafana")


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
