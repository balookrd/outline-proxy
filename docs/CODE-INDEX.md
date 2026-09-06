# Code Index

`scripts/code-index.py` builds a local structural index for low-token navigation
through the Rust workspace. It records Cargo packages, targets, source files,
top-level Rust items, and `impl` headers without adding new dependencies.

The generated index is a map, not a source-of-truth replacement: use it to find
the relevant module and symbol, then open only the focused source ranges needed
for the change.

## Generate

```bash
python3 scripts/code-index.py
```

Outputs:

- `target/code-index/repo-map.md` — compact Markdown map for humans and agents.
- `target/code-index/symbols.json` — machine-readable package/file/symbol data.

`target/` is ignored by git, so generated indexes stay local.

## Focused Slices

Limit the index to one or more packages when a task is localized:

```bash
python3 scripts/code-index.py --package outline-transport
python3 scripts/code-index.py --package outline-ss-rust --package outline-wire
```

Skip the detached Android workspace if it is not relevant:

```bash
python3 scripts/code-index.py --skip-detached
```

Vendored Rust sources are excluded by default. Include them only when working on
the patched copies:

```bash
python3 scripts/code-index.py --include-vendor
```

## Query Examples

Find where a symbol is declared:

```bash
rg 'poll_shutdown|H3TransportStream|Resume' target/code-index/repo-map.md
```

Inspect the JSON with `jq`:

```bash
jq '.packages[] | select(.name == "outline-transport") | .source_files[] | select(.path | contains("/h3/")) | {path, module, symbols: [.symbols[].name]}' target/code-index/symbols.json
```

For deeper semantic questions, pair this structural index with `rust-analyzer`
features such as go-to-definition, find-references, hover type information, and
diagnostics.
