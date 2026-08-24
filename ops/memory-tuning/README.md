# Memory tuning

Source of truth for the per-node cgroup memory limits of `outline-ws-rust` and
`outline-ss-rust`.

Until 2026-08-24 these limits were hand-placed on each node, lived nowhere in the
repo, were lost on OS reinstall, and still carried `MIMALLOC_*` env that jemalloc
ignores. This directory replaces that: [`fleet.tsv`](fleet.tsv) declares the
limits, [`apply.sh`](apply.sh) makes each node match it.

## Table

One row per node in `fleet.tsv`, tab-separated:

```
host   ws_high  ws_max  ss_high  ss_max
```

- A dash (`-`) means the service does not run on that node — its drop-in is left
  untouched.
- Every limit carries a soft reclaim step: `High < Max`. Below `High` nothing
  happens; between `High` and `Max` the kernel reclaims and throttles the
  service; at `Max` it OOM-kills. `High = Max` (the old state) meant no soft
  step — straight to the kill.
- **`Max` stays below the node's `MemAvailable`.** A limit above available RAM is
  a fake fuse: the node swaps to zram and hits a system OOM before the cgroup
  counts that high. See the spec for the measured headroom per node.

## Applying

```bash
./apply.sh --dry-run          # show what would change on every node
./apply.sh                    # apply to every node
./apply.sh mmv@198.18.1.104   # one node
```

For each service `apply.sh` writes a single canonical drop-in
`/etc/systemd/system/<unit>.service.d/20-memory.conf`, then applies the limits to
the running service **without a restart** (`set-property --runtime`). It also:

- removes `30-mem-tuning.conf` (dead `MIMALLOC_*` env);
- removes any `/etc/systemd/system.control/<unit>.d` override left by a manual
  `set-property` (persistent and higher-priority — it would mask the table after
  a reboot);
- writes `THREAD_STACK_SIZE_KB=512` for clients into its own
  `30-thread-stack.conf`.

Limits take effect live. The thread-stack env only changes on the next restart,
but its value is unchanged here, so nothing needs restarting.

`apply.sh` refuses a unit whose live RSS already exceeds the new `High` (that
would trigger an immediate reclaim storm) — raise the limit or investigate the
process first.

## Not covered

Placing these drop-ins during a from-scratch provision (so a reinstalled node
comes up already tuned) is a separate task — it needs the per-node limits mapped
onto `provision-node`'s group profiles. Until then, run `apply.sh` by hand after
provisioning; the source is at least versioned now.

## Reference

Design: [`docs/superpowers/specs/2026-08-24-memory-tuning-source.md`](../../docs/superpowers/specs/2026-08-24-memory-tuning-source.md).
