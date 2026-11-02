#!/usr/bin/env python3
"""Diff the browser snapshots against the baselines.

Usage: compare.py <baseline-dir> <snapshot-dir> <report.md>

Every `<baseline-dir>/<browser>.json` is compared with the snapshot of the
same name. The report is Markdown. Exit code: 0 — every snapshot matches,
1 — drift, 2 — a snapshot is missing or lacks a layer the baseline has (a
capture failure, not drift; it wins over 1).
"""
import difflib
import json
import os
import sys

MATCH, DRIFT, INCOMPLETE = 0, 1, 2

LAYERS = ("tcp_h2", "tcp_h1", "quic", "h2", "h1")


def _fmt(value):
    return json.dumps(value, sort_keys=True)


def _is_header_list(value):
    return isinstance(value, list) and value and all(
        isinstance(x, list) and len(x) == 2 and isinstance(x[0], str) for x in value)


def diff(old, new, path=""):
    """[(path, old, new)] for every leaf that differs; lists are leaves."""
    if isinstance(old, dict) and isinstance(new, dict):
        out = []
        for key in sorted(set(old) | set(new)):
            out += diff(old.get(key), new.get(key), f"{path}.{key}" if path else key)
        return out
    return [] if old == new else [(path, old, new)]


# Layers holding one entry per request kind: a kind the baseline has but the
# snapshot lacks was not captured, which is a capture failure, not drift.
KIND_LAYERS = (("h2", "headers"), ("h2", "priority"), ("h1",))


def _walk(obj, keys):
    for key in keys:
        obj = obj.get(key) if isinstance(obj, dict) else None
    return obj


def incomplete_layers(baseline, snapshot):
    out = [layer for layer in LAYERS
           if baseline.get(layer) and not snapshot.get(layer)]
    for keys in KIND_LAYERS:
        base = _walk(baseline, keys)
        snap = _walk(snapshot, keys)
        if isinstance(base, dict) and isinstance(snap, dict):
            out += [".".join((*keys, kind)) for kind, v in sorted(base.items())
                    if v is not None and snap.get(kind) is None]
    return out


def report_browser(name, baseline, snapshot):
    """(code, markdown lines) for one browser."""
    if snapshot is None:
        return INCOMPLETE, [f"## {name}", "", "Snapshot missing: the capture failed.", ""]
    missing = incomplete_layers(baseline, snapshot)
    if missing:
        return INCOMPLETE, [f"## {name}", "", f"Snapshot lacks layers: {', '.join(missing)}.", ""]
    changes = diff(baseline, snapshot)
    if not changes:
        return MATCH, [f"## {name}: matches the baseline ({baseline['major']})", ""]
    lines = [f"## {name}: drift", ""]
    if baseline["major"] != snapshot["major"]:
        lines += [f"**{name} {baseline['major']} → {snapshot['major']}**: update the UA and "
                  "`sec-ch-ua` in `crates/outline-transport/src/fingerprint_profile.rs`, "
                  "then `scripts/fingerprint-drift/baseline/*.json`.", ""]
    for path, old, new in changes:
        if path == "major":
            continue
        if _is_header_list(old) and _is_header_list(new):
            lines += [f"- `{path}`:", "", "```diff"]
            lines += [ln for ln in difflib.unified_diff(
                [f"{n}: {v}" for n, v in old], [f"{n}: {v}" for n, v in new],
                "baseline", "snapshot", lineterm="", n=1)]
            lines += ["```"]
        else:
            lines += [f"- `{path}`: `{_fmt(old)}` → `{_fmt(new)}`"]
    return DRIFT, lines + [""]


def _load(path):
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def main(argv):
    baseline_dir, snapshot_dir, report_path = argv[1], argv[2], argv[3]
    code, lines = MATCH, ["# Browser fingerprint drift", ""]
    for file in sorted(os.listdir(baseline_dir)):
        if not file.endswith(".json"):
            continue
        name = file[:-len(".json")]
        c, ls = report_browser(name, _load(os.path.join(baseline_dir, file)),
                               _load(os.path.join(snapshot_dir, file)))
        code = max(code, c)
        lines += ls
    with open(report_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
