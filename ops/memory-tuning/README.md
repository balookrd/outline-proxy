# Memory tuning

Source of truth for the per-node cgroup memory limits of `outline-ws-rust` and
`outline-ss-rust`: [`fleet.tsv`](fleet.tsv) declares the limits,
[`apply.sh`](apply.sh) makes each node match it.

Real fleet node names, domains and addresses in this document are replaced with stand-ins: `198.51.100.0/24` is the home network (`.102`, `.104` etc. are the last octet). The mapping lives in the local, uncommitted `FLEET.local.md`.

Until 2026-08-24 these limits were hand-placed on each node, lived nowhere in the
repo, were lost on OS reinstall, and still carried `MIMALLOC_*` env that jemalloc
ignores.

## Table format

One row per node in `fleet.tsv`, columns separated by tabs or spaces; lines
starting with `#` are comments:

```
short   ssh_target                   ws_high  ws_max  ss_high  ss_max
.104    mmv@198.51.100.104             600M     700M    130M     150M
```

| Column | Used by | Meaning |
|---|---|---|
| `short` | `install.sh --host` (provisioning), `apply.sh <host>` | short node name |
| `ssh_target` | `apply.sh` | ssh target the limits are pushed to; also accepted as `apply.sh <host>` |
| `ws_high` / `ws_max` | both | `MemoryHigh` / `MemoryMax` of `outline-ws-rust` |
| `ss_high` / `ss_max` | both | `MemoryHigh` / `MemoryMax` of `outline-ss-rust` |

- A dash (`-`) means the service does not run on that node — its drop-in is left
  untouched.
- Every limit carries a soft reclaim step: `High < Max`. Below `High` nothing
  happens; between `High` and `Max` the kernel reclaims and throttles the
  service; at `Max` it OOM-kills. `High = Max` (the old state) meant no soft
  step — straight to the kill.
- `Max` stays below the node's `MemAvailable`. With a limit above available RAM
  the node swaps to zram and hits a system OOM before the cgroup counts that
  high. The measured headroom per node is in the spec (see
  [Reference](#reference)).
- `apply.sh` compares the live RSS against `High` assuming an `M` suffix
  (`high_mib=${high%M}`); keep the `High` values in `M`.

## Applying

Run from the development machine; the script `cd`s into its own directory and
reaches each node over ssh with `sudo bash`:

```bash
./apply.sh --dry-run          # show what would change on every node
./apply.sh                    # apply to every node
./apply.sh mmv@198.51.100.104   # one node (ssh target or short name)
```

For each service with a limit in the table `apply.sh` writes a single drop-in
`/etc/systemd/system/<unit>.service.d/20-memory.conf` (`MemoryAccounting=yes`,
`MemoryHigh`, `MemoryMax`), runs `systemctl daemon-reload`, then applies the
limits to the running service without a restart
(`systemctl set-property --runtime`). It also:

- removes `30-mem-tuning.conf` (dead `MIMALLOC_*` env);
- removes stray `*.pre-*` / `*.bak.*` files in the drop-in directory;
- removes any `/etc/systemd/system.control/<unit>.service.d` override left by a
  manual `set-property` (persistent and higher-priority — it would mask the
  table after a reboot);
- writes `THREAD_STACK_SIZE_KB=512` for `outline-ws-rust` into its own
  `30-thread-stack.conf`.

Limits take effect live. The thread-stack env only changes on the next restart,
but its value is unchanged here, so nothing needs restarting.

`apply.sh` refuses a unit whose live `MemoryCurrent` is already at or above the
new `High` and prints `REFUSE <unit>: current …MiB >= new High …MiB` — applying
it would start reclaiming immediately. Raise the limit or investigate the
process first. A node that already matches the table prints `ok <unit>: already
matches`.

## Provisioning from scratch

A reinstalled node comes up with the limits already in place:
`collect-from-reference.sh` copies `fleet.tsv` into the bundle
(`<bundle>/memory-tuning/fleet.tsv`), and the `services` phase of `install.sh`
finds the node's row by `--host` (matched against `short`) and writes the same
`20-memory.conf` (and `30-thread-stack.conf` for the client) before it enables
and starts the units. No `set-property` is needed: systemd reads the drop-in
when the unit starts.

A node absent from `fleet.tsv` is left at systemd defaults, and `install.sh`
warns `memory-tuning: --host '<host>' not in fleet.tsv`. A service with `-`
limits in its row is left at defaults without a warning. A bundle without
`memory-tuning/fleet.tsv` (collected before the table existed) is skipped with
a message.

After the initial provision, edits to the table reach live nodes through
`apply.sh`; re-running the provisioner for a limit change is not needed.

## Reference

Design: [`docs/superpowers/specs/2026-08-24-memory-tuning-source.md`](../../docs/superpowers/specs/2026-08-24-memory-tuning-source.md).
