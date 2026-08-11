#!/usr/bin/env python3
"""Write the access-key artifacts for every user in a node's config.toml.

Three files per user: <user>.conf (Outline), <user>.json (Xray subscription
balanced across the cloud entry nodes) and <user>.txt (every URL, one per line).
The report goes to stdout; save-keys.sh redirects it into users.txt.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifacts  # noqa: E402
import config_model  # noqa: E402
import xray_json  # noqa: E402

DEFAULT_CONFIG = "/opt/outline/outline-ss-rust/config.toml"

# There is deliberately no default output directory. The served directory's
# name is a secret — it is the only thing guarding the artifacts, which carry
# every user's password and vless_id — so it lives in the node's config.toml
# (`[access_keys] write_dir`, the same key the binary reads) and never in this
# repository. A hard-coded fallback here would publish it to anyone who can
# read the source.

# `config_url` is deliberately not reported: it was the same file as
# `outline_url` with a different scheme, and the very same link is already the
# first line of <user>.txt.
_REPORT_FIELDS = (
    ("conf", "written_conf"),
    ("json", "written_json"),
    ("txt", "written_txt"),
    ("outline_url", "outline_url"),
    ("happ_url", "happ_url"),
)


def write_atomic(path: Path, content: str) -> None:
    """Write via a temp file so a client never reads a half-written artifact."""
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def render_report(written: Sequence[dict]) -> str:
    blocks = []
    for record in written:
        lines = [f"user: {record['user']}"]
        lines.extend(
            f"{label}: {record[key]}" for key, label in _REPORT_FIELDS if record.get(key)
        )
        blocks.append("".join(f"{line}\n" for line in lines))
    return "\n".join(blocks)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate access-key artifacts.")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="outline-ss-rust config.toml")
    parser.add_argument(
        "--out-dir",
        default=None,
        help="where artifacts are written; overrides [access_keys] write_dir. "
        "One of the two is required — there is no built-in default.",
    )
    parser.add_argument(
        "--node",
        action="append",
        dest="nodes",
        help="entry node for the Xray balancer; repeat for each. Default: %s"
        % ", ".join(xray_json.DEFAULT_NODES),
    )
    parser.add_argument(
        "--file-extension",
        default=None,
        help="extension for the Outline artifact; overrides [access_keys] "
        "file_extension. The nodes rely on this: their config.toml has no "
        "file_extension and save-keys.sh passed the binary "
        "--access-key-file-extension .conf",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="render everything but write nothing"
    )
    args = parser.parse_args(argv)

    nodes = tuple(args.nodes) if args.nodes else xray_json.DEFAULT_NODES
    server = config_model.load(args.config)
    if args.file_extension is not None:
        server = replace(
            server,
            access_keys=replace(server.access_keys, file_extension=args.file_extension),
        )
    if not server.users:
        raise SystemExit(f"{args.config}: no enabled users")

    out_dir_raw = args.out_dir or server.access_keys.write_dir
    if not out_dir_raw:
        raise SystemExit(
            f"{args.config}: no output directory — set [access_keys] write_dir "
            "in the config or pass --out-dir"
        )

    out_dir = Path(out_dir_raw)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    ak = server.access_keys
    written: list[dict] = []
    for user in server.users:
        record: dict = {"user": user.name}

        outline = artifacts.outline_artifact(user, ak)
        if outline is not None:
            target = out_dir / f"{user.filename}{ak.file_extension}"
            if not args.dry_run:
                write_atomic(target, outline)
            record["conf"] = str(target)

        if artifacts.has_subscription(user):
            document = xray_json.build_config(user, nodes)
            target = out_dir / f"{user.filename}.json"
            if not args.dry_run:
                write_atomic(
                    target, json.dumps([document], indent=2, ensure_ascii=False) + "\n"
                )
            record["json"] = str(target)

        urls = artifacts.user_urls(user, ak, server.alpn_has_h3)
        if urls:
            target = out_dir / f"{user.filename}.txt"
            if not args.dry_run:
                write_atomic(target, "\n".join(urls) + "\n")
            record["txt"] = str(target)

        record["outline_url"] = artifacts.outline_url(user, ak)
        record["happ_url"] = artifacts.happ_url(user, ak)
        written.append(record)

    # Never a credential: paths and counts only.
    print(render_report(written), end="")
    print(f"\n{len(written)} user(s), {len(nodes)} balancer node(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
