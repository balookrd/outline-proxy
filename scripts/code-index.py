#!/usr/bin/env python3
"""Build a compact Rust workspace index for low-token code navigation.

The index is intentionally structural rather than exhaustive: it records Cargo
packages, targets, source files, top-level Rust items, and impl headers. Keep the
generated files under target/ and feed only the relevant slices to an agent.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_OUTPUT_DIR = Path("target/code-index")
DETACHED_WORKSPACES = (Path("android/rust"),)
VENDOR_PARTS = ("/vendor/",)

ITEM_RE = re.compile(
    r"""
    ^\s*
    (?P<vis>pub(?:\s*\([^)]*\))?)?\s*
    (?:(?:async|unsafe|const)\s+)*
    (?P<kind>fn|struct|enum|trait|union|type|const|static|mod)\s+
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)
MACRO_RULES_RE = re.compile(
    r"^\s*(?P<vis>pub(?:\s*\([^)]*\))?)?\s*macro_rules!\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
)
IMPL_RE = re.compile(r"^\s*(?P<unsafe>unsafe\s+)?impl(?:\s*<[^{};]*>)?\s+(?P<header>[^{};]+?)(?:\s*\{|$)")


@dataclass(frozen=True)
class Target:
    name: str
    kind: list[str]
    crate_types: list[str]
    src_path: str


@dataclass(frozen=True)
class Symbol:
    kind: str
    name: str
    line: int
    visibility: str
    module: str
    signature: str


@dataclass(frozen=True)
class ImplBlock:
    line: int
    header: str
    module: str


@dataclass(frozen=True)
class SourceFile:
    path: str
    module: str
    line_count: int
    symbols: list[Symbol]
    impls: list[ImplBlock]


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    workspace: str
    manifest_path: str
    package_root: str
    targets: list[Target]
    features: list[str]
    source_files: list[SourceFile]


def run_json(command: list[str], cwd: Path) -> dict[str, Any]:
    proc = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        raise RuntimeError(f"{' '.join(command)} failed:\n{proc.stderr.strip()}")
    return json.loads(proc.stdout)


def cargo_metadata(workspace_path: Path) -> dict[str, Any]:
    return run_json(["cargo", "metadata", "--format-version", "1", "--no-deps"], workspace_path)


def is_vendor_path(path: Path) -> bool:
    normalized = path.resolve().as_posix()
    return any(part in normalized for part in VENDOR_PARTS)


def relative_to_root(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def mask_comments(source: str) -> str:
    """Replace Rust comments with spaces while preserving byte-ish layout and lines."""
    out: list[str] = []
    i = 0
    block_depth = 0
    in_string = False
    in_char = False
    raw_hashes: int | None = None

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if block_depth:
            if ch == "/" and nxt == "*":
                block_depth += 1
                out.extend("  ")
                i += 2
                continue
            if ch == "*" and nxt == "/":
                block_depth -= 1
                out.extend("  ")
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if raw_hashes is not None:
            out.append(ch)
            if ch == '"':
                hashes = source[i + 1 : i + 1 + raw_hashes]
                if hashes == "#" * raw_hashes:
                    out.extend(hashes)
                    i += raw_hashes + 1
                    raw_hashes = None
                    continue
            i += 1
            continue

        if in_string:
            out.append(ch)
            if ch == "\\":
                if i + 1 < len(source):
                    out.append(source[i + 1])
                    i += 2
                    continue
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if in_char:
            out.append(ch)
            if ch == "\\":
                if i + 1 < len(source):
                    out.append(source[i + 1])
                    i += 2
                    continue
            elif ch == "'":
                in_char = False
            i += 1
            continue

        if ch == "/" and nxt == "/":
            out.extend("  ")
            i += 2
            while i < len(source) and source[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if ch == "/" and nxt == "*":
            block_depth = 1
            out.extend("  ")
            i += 2
            continue

        if ch == "r":
            raw = re.match(r'r(#+)"', source[i:])
            if raw:
                raw_hashes = len(raw.group(1))
                token = raw.group(0)
                out.append(token)
                i += len(token)
                continue
            if source.startswith('r"', i):
                raw_hashes = 0
                out.append('r"')
                i += 2
                continue

        if ch == '"':
            in_string = True
        elif ch == "'":
            in_char = True
        out.append(ch)
        i += 1

    return "".join(out)


def rust_module_path(file_path: Path, package_root: Path) -> str:
    src_dir = package_root / "src"
    try:
        rel = file_path.relative_to(src_dir)
    except ValueError:
        rel = file_path.relative_to(package_root)

    parts = list(rel.with_suffix("").parts)
    if parts in (["lib"], ["main"]):
        return "crate"
    if parts[-1] == "mod":
        parts = parts[:-1]
    return "::".join(parts) if parts else "crate"


def clean_signature(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())[:180]


def parse_rust_file(file_path: Path, package_root: Path, repo_root: Path) -> SourceFile:
    source = file_path.read_text(encoding="utf-8", errors="replace")
    masked = mask_comments(source)
    original_lines = source.splitlines()
    masked_lines = masked.splitlines()
    module = rust_module_path(file_path, package_root)

    symbols: list[Symbol] = []
    impls: list[ImplBlock] = []

    for line_no, masked_line in enumerate(masked_lines, start=1):
        original_line = original_lines[line_no - 1] if line_no - 1 < len(original_lines) else masked_line
        item = ITEM_RE.match(masked_line)
        if item:
            visibility = item.group("vis") or ""
            symbols.append(
                Symbol(
                    kind=item.group("kind"),
                    name=item.group("name"),
                    line=line_no,
                    visibility=visibility.strip(),
                    module=module,
                    signature=clean_signature(original_line),
                )
            )
            continue

        macro = MACRO_RULES_RE.match(masked_line)
        if macro:
            visibility = macro.group("vis") or ""
            symbols.append(
                Symbol(
                    kind="macro_rules",
                    name=macro.group("name"),
                    line=line_no,
                    visibility=visibility.strip(),
                    module=module,
                    signature=clean_signature(original_line),
                )
            )
            continue

        impl = IMPL_RE.match(masked_line)
        if impl:
            header = clean_signature(original_line)
            if header.startswith("impl"):
                impls.append(ImplBlock(line=line_no, header=header[:220], module=module))

    return SourceFile(
        path=relative_to_root(file_path, repo_root),
        module=module,
        line_count=len(original_lines),
        symbols=symbols,
        impls=impls,
    )


def collect_source_files(package_root: Path, targets: Iterable[Target], repo_root: Path) -> list[Path]:
    files: set[Path] = set()
    src_dir = package_root / "src"
    if src_dir.exists():
        files.update(path for path in src_dir.rglob("*.rs") if path.is_file())
    for target in targets:
        src = Path(target.src_path)
        if not src.is_absolute():
            src = repo_root / src
        if src.exists() and src.suffix == ".rs":
            files.add(src)
    return sorted(files)


def package_from_metadata(
    package: dict[str, Any],
    workspace_name: str,
    repo_root: Path,
    include_vendor: bool,
    package_filter: set[str],
) -> Package | None:
    manifest = Path(package["manifest_path"])
    package_root = manifest.parent
    if not include_vendor and is_vendor_path(package_root):
        return None
    if package_filter and package["name"] not in package_filter:
        return None

    targets = [
        Target(
            name=target["name"],
            kind=list(target.get("kind", [])),
            crate_types=list(target.get("crate_types", [])),
            src_path=relative_to_root(Path(target["src_path"]), repo_root),
        )
        for target in package.get("targets", [])
    ]

    source_files = [
        parse_rust_file(path, package_root, repo_root)
        for path in collect_source_files(package_root, targets, repo_root)
        if include_vendor or not is_vendor_path(path)
    ]

    return Package(
        name=package["name"],
        version=package["version"],
        workspace=workspace_name,
        manifest_path=relative_to_root(manifest, repo_root),
        package_root=relative_to_root(package_root, repo_root),
        targets=targets,
        features=sorted(package.get("features", {}).keys()),
        source_files=source_files,
    )


def load_workspace_packages(
    workspace_path: Path,
    workspace_name: str,
    repo_root: Path,
    include_vendor: bool,
    package_filter: set[str],
) -> list[Package]:
    metadata = cargo_metadata(workspace_path)
    workspace_members = set(metadata.get("workspace_members", []))
    packages: list[Package] = []
    for package in metadata.get("packages", []):
        if package["id"] not in workspace_members:
            continue
        parsed = package_from_metadata(package, workspace_name, repo_root, include_vendor, package_filter)
        if parsed is not None:
            packages.append(parsed)
    return packages


def package_symbol_count(package: Package) -> int:
    return sum(len(source.symbols) for source in package.source_files)


def package_impl_count(package: Package) -> int:
    return sum(len(source.impls) for source in package.source_files)


def as_json(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def markdown_table_row(cells: Iterable[Any]) -> str:
    rendered = [str(cell).replace("\n", " ").replace("|", r"\|") for cell in cells]
    return "| " + " | ".join(rendered) + " |"


def format_target(target: Target) -> str:
    kinds = ",".join(target.kind) if target.kind else "-"
    return f"{target.name} ({kinds})"


def write_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Code Index")
    lines.append("")
    lines.append("Generated for low-token navigation. Use this as a map, then open only the files and line ranges relevant to the task.")
    lines.append("")
    lines.append(f"- Generated at: `{data['generated_at']}`")
    lines.append(f"- Repository root: `{data['repo_root']}`")
    lines.append(f"- Packages: `{data['totals']['packages']}`")
    lines.append(f"- Rust files: `{data['totals']['rust_files']}`")
    lines.append(f"- Symbols: `{data['totals']['symbols']}`")
    lines.append(f"- Impl blocks: `{data['totals']['impl_blocks']}`")
    lines.append("")
    lines.append("## Packages")
    lines.append("")
    lines.append(markdown_table_row(["Package", "Workspace", "Path", "Files", "Symbols", "Impls", "Targets"]))
    lines.append(markdown_table_row(["---", "---", "---", "---:", "---:", "---:", "---"]))

    for package in data["packages"]:
        targets = ", ".join(format_target(Target(**target)) for target in package["targets"])
        lines.append(
            markdown_table_row(
                [
                    f"`{package['name']}`",
                    f"`{package['workspace']}`",
                    f"`{package['package_root']}`",
                    len(package["source_files"]),
                    sum(len(source["symbols"]) for source in package["source_files"]),
                    sum(len(source["impls"]) for source in package["source_files"]),
                    targets or "-",
                ]
            )
        )

    for package in data["packages"]:
        lines.append("")
        lines.append(f"## `{package['name']}`")
        lines.append("")
        lines.append(f"- Path: `{package['package_root']}`")
        lines.append(f"- Manifest: `{package['manifest_path']}`")
        if package["features"]:
            feature_list = ", ".join(f"`{feature}`" for feature in package["features"])
            lines.append(f"- Features: {feature_list}")
        lines.append("")
        lines.append(markdown_table_row(["File", "Module", "Lines", "Items", "Impls"]))
        lines.append(markdown_table_row(["---", "---", "---:", "---", "---"]))

        for source in package["source_files"]:
            item_names = ", ".join(
                f"`{symbol['kind']} {symbol['name']}`" for symbol in source["symbols"][:18]
            )
            if len(source["symbols"]) > 18:
                item_names += f", ... +{len(source['symbols']) - 18}"
            impls = ", ".join(f"`{impl['header']}`" for impl in source["impls"][:6])
            if len(source["impls"]) > 6:
                impls += f", ... +{len(source['impls']) - 6}"
            lines.append(
                markdown_table_row(
                    [
                        f"`{source['path']}`",
                        f"`{source['module']}`",
                        source["line_count"],
                        item_names or "-",
                        impls or "-",
                    ]
                )
            )

    lines.append("")
    return "\n".join(lines)


def build_index(args: argparse.Namespace) -> dict[str, Any]:
    repo_root = Path(args.repo_root).resolve()
    package_filter = set(args.package)
    packages: list[Package] = []

    packages.extend(
        load_workspace_packages(
            repo_root,
            "root",
            repo_root,
            include_vendor=args.include_vendor,
            package_filter=package_filter,
        )
    )

    if not args.skip_detached:
        indexed_roots = {(repo_root / pkg.package_root).resolve() for pkg in packages}
        for detached in DETACHED_WORKSPACES:
            detached_root = repo_root / detached
            if not detached_root.exists():
                continue
            if detached_root.resolve() in indexed_roots:
                continue
            packages.extend(
                load_workspace_packages(
                    detached_root,
                    detached.as_posix(),
                    repo_root,
                    include_vendor=args.include_vendor,
                    package_filter=package_filter,
                )
            )

    packages.sort(key=lambda package: (package.workspace, package.name))
    rust_files = sum(len(package.source_files) for package in packages)
    symbols = sum(package_symbol_count(package) for package in packages)
    impls = sum(package_impl_count(package) for package in packages)

    return {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "repo_root": repo_root.as_posix(),
        "totals": {
            "packages": len(packages),
            "rust_files": rust_files,
            "symbols": symbols,
            "impl_blocks": impls,
        },
        "packages": [asdict(package) for package in packages],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", help="Repository root. Defaults to the current directory.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR.as_posix(), help="Directory for repo-map.md and symbols.json.")
    parser.add_argument("--package", action="append", default=[], help="Limit the index to one package name. Can be passed more than once.")
    parser.add_argument("--include-vendor", action="store_true", help="Include vendored Rust sources. Omitted by default.")
    parser.add_argument("--skip-detached", action="store_true", help="Skip detached workspaces such as android/rust.")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    output_dir = (repo_root / args.output_dir).resolve()

    try:
        index = build_index(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "symbols.json"
    markdown_path = output_dir / "repo-map.md"
    json_path.write_text(as_json(index), encoding="utf-8")
    markdown_path.write_text(write_markdown(index), encoding="utf-8")

    print(f"wrote {relative_to_root(markdown_path, repo_root)}")
    print(f"wrote {relative_to_root(json_path, repo_root)}")
    print(
        "indexed "
        f"{index['totals']['packages']} packages, "
        f"{index['totals']['rust_files']} Rust files, "
        f"{index['totals']['symbols']} symbols, "
        f"{index['totals']['impl_blocks']} impl blocks"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
