"""Daily backup of the Jellyfin app data from the NVMe (/volume2) to the HDD.

Each run writes /backup/jellyfin/jellyfin-YYYYMMDD-HHMM.tar.gz with:
  data/jellyfin.db   consistent snapshot of the live database (sqlite3
                     backup API, WAL included), so Jellyfin keeps running
  config/            system.xml, encoding.xml, network.xml, ...
  root/              library definitions (options.xml per library)
  data/...           the rest of config/data except the database files
  plugins/           the UGOS plugin path (plugin settings)
and keeps the newest KEEP archives. config/metadata (posters, NFO, ~600 MB)
is mirrored incrementally into /backup/jellyfin/metadata instead: only
changed files are copied, files gone from the source are removed.

Not backed up: config/log and /cache (Jellyfin rebuilds both).

/src/config must be mounted read-write: SQLite touches jellyfin.db-shm even
when it only reads. The files belong to root, so the container runs as root
and hands the results to OWNER_UID:OWNER_GID.

RUN_AT_UTC is HH:MM in UTC (01:45 UTC = 04:45 MSK). ONCE=1 runs one backup
immediately and exits.

After a successful run the script pushes
nas_backup_last_success_timestamp_seconds{backup="jellyfin"} to PUSH_URL.
"""
import datetime as dt
import os
import re
import shutil
import sqlite3
import tarfile
import time
import urllib.request

SRC = "/src/config"
PLUGINS = "/src/plugins"
DST = "/backup/jellyfin"
META_DST = f"{DST}/metadata"
KEEP = int(os.environ.get("KEEP", "14"))
RUN_AT_UTC = os.environ.get("RUN_AT_UTC", "01:45")
# Another compose project: the monitoring network and the name
# victoria-metrics are not reachable from here, so docker-compose.yaml passes
# the host address.
PUSH_URL = os.environ["PUSH_URL"]
OWNER = (int(os.environ.get("OWNER_UID", "1000")), int(os.environ.get("OWNER_GID", "0")))

# Live database files and the leftover pre-12.x database: the snapshot below
# replaces the former, the latter is not needed for a restore.
SKIP_IN_DATA = ("jellyfin.db", "library.db")


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

def snapshot_db(tmp: str) -> None:
    # mode=rw: a plain connect() would create an empty jellyfin.db when the
    # file is missing and then back up that empty database.
    src = sqlite3.connect(f"file:{SRC}/data/jellyfin.db?mode=rw", uri=True)
    dst = sqlite3.connect(tmp)
    src.backup(dst)
    dst.close()
    src.close()
    chk = sqlite3.connect(tmp)
    res = chk.execute("PRAGMA integrity_check").fetchone()[0]
    chk.close()
    if res != "ok":
        raise RuntimeError(f"integrity_check of the snapshot: {res}")


def data_filter(info: tarfile.TarInfo):
    name = os.path.basename(info.name)
    top = info.name.split("/")
    # Only skip the database files directly in data/, not files with the same
    # prefix deeper down.
    if len(top) == 2 and top[0] == "data" and name.startswith(SKIP_IN_DATA):
        return None
    return info


def write_archive() -> str:
    stamp = time.strftime("%Y%m%d-%H%M")
    out = f"{DST}/jellyfin-{stamp}.tar.gz"
    tmp_db = "/tmp/jellyfin.db"
    snapshot_db(tmp_db)
    # Write to .part and rename, so a failure midway never leaves a truncated
    # jellyfin-*.tar.gz that counts toward KEEP.
    part = out + ".part"
    with tarfile.open(part, "w:gz") as tar:
        tar.add(tmp_db, arcname="data/jellyfin.db")
        for sub in ("config", "root"):
            tar.add(f"{SRC}/{sub}", arcname=sub)
        tar.add(f"{SRC}/data", arcname="data", filter=data_filter)
        if os.path.isdir(PLUGINS):
            tar.add(PLUGINS, arcname="plugins")
    os.replace(part, out)
    os.unlink(tmp_db)
    os.chown(out, *OWNER)
    print(f"written {out} ({os.path.getsize(out)} bytes)", flush=True)
    return out


def prune() -> None:
    # The timestamp format sorts lexically in chronological order.
    snaps = sorted(f for f in os.listdir(DST) if f.startswith("jellyfin-") and f.endswith(".tar.gz"))
    for old in snaps[:-KEEP]:
        os.unlink(f"{DST}/{old}")
        print("pruned", old, flush=True)
    print("kept:", len(snaps[-KEEP:]), flush=True)


def mirror_metadata() -> None:
    src_root = f"{SRC}/metadata"
    copied = removed = 0
    seen = set()
    for dirpath, _dirs, files in os.walk(src_root):
        rel = os.path.relpath(dirpath, src_root)
        ddir = os.path.normpath(os.path.join(META_DST, rel))
        os.makedirs(ddir, exist_ok=True)
        seen.add(ddir)
        for f in files:
            s, d = os.path.join(dirpath, f), os.path.join(ddir, f)
            seen.add(d)
            st = os.stat(s)
            try:
                dt_ = os.stat(d)
                if dt_.st_size == st.st_size and int(dt_.st_mtime) == int(st.st_mtime):
                    continue
            except FileNotFoundError:
                pass
            shutil.copy2(s, d)
            copied += 1
    # Remove what is gone from the source; bottom-up so directories empty out
    # before they are checked.
    for dirpath, dirs, files in os.walk(META_DST, topdown=False):
        for f in files:
            p = os.path.join(dirpath, f)
            if p not in seen:
                os.unlink(p)
                removed += 1
        if dirpath != META_DST and dirpath not in seen:
            os.rmdir(dirpath)
    os.chown(META_DST, *OWNER)
    for dirpath, dirs, files in os.walk(META_DST):
        for n in dirs + files:
            os.lchown(os.path.join(dirpath, n), *OWNER)
    print(f"metadata mirror: {copied} copied, {removed} removed", flush=True)


def backup() -> None:
    os.makedirs(DST, exist_ok=True)
    os.chown(DST, *OWNER)
    write_archive()
    prune()
    mirror_metadata()
    report_success("jellyfin")


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
        print(f"next jellyfin backup in {int(wait)} s", flush=True)
        time.sleep(wait)
        try:
            backup()
        except Exception as e:  # keep the loop alive; the log shows the failure
            print(f"jellyfin backup failed: {e!r}", flush=True)
