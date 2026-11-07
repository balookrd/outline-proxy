# Code index

`scripts/code-index.py` builds a local structural index of the Rust workspace
for navigation with a small token budget. It records Cargo packages, targets,
source files, top-level Rust items and `impl` headers. It needs `python3` and
`cargo` on `PATH` (it reads the package list from `cargo metadata --no-deps`)
and no extra Python packages.

The index is a map, not a replacement for the sources: use it to find the
relevant module and symbol, then open only the source ranges the change needs.

## Generate

Run from the repository root:

```bash
python3 scripts/code-index.py
```

Outputs:

- `target/code-index/repo-map.md` — compact Markdown map for humans and agents.
- `target/code-index/symbols.json` — machine-readable package/file/symbol data.

`target/` is ignored by git, so the generated index stays local.

## Options

| Flag | Default | Effect |
|---|---|---|
| `--package <name>` | all packages | limit the index to one package; repeat for several |
| `--skip-detached` | off | skip detached workspaces (`android/rust`) |
| `--include-vendor` | off | include vendored Rust sources (`vendor/`) |
| `--output-dir <dir>` | `target/code-index` | where to write `repo-map.md` and `symbols.json`; a relative path is resolved against `--repo-root` |
| `--repo-root <dir>` | `.` (current directory) | repository root |

Limit the index to the packages a task touches:

```bash
python3 scripts/code-index.py --package outline-transport
python3 scripts/code-index.py --package outline-ss-rust --package outline-wire
```

Skip the detached Android workspace when it is not relevant:

```bash
python3 scripts/code-index.py --skip-detached
```

Include vendored sources only when working on the patched copies:

```bash
python3 scripts/code-index.py --include-vendor
```

## Query examples

Find where a symbol is declared:

```bash
rg 'poll_shutdown|H3DatagramChannel|Resume' target/code-index/repo-map.md
```

Inspect the JSON with `jq`:

```bash
jq '.packages[] | select(.name == "outline-transport") | .source_files[] | select(.path | contains("/h3/")) | {path, module, symbols: [.symbols[].name]}' target/code-index/symbols.json
```

Each symbol in `symbols.json` has `kind`, `name`, `line`, `visibility`, `module`
and `signature`. For type information, references and diagnostics use
`rust-analyzer`; the index does not resolve names.
