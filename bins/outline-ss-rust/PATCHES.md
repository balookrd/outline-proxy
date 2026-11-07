# Local patches

The inventory of patches to vendored crates lives at the monorepo root. One
`vendor/` directory is shared by the whole workspace, so there is one inventory
for both binaries:

- [PATCHES.md](../../PATCHES.md) ([Русский](../../PATCHES.ru.md))

The regenerated patch artifacts are in the root as well: `h3-0.0.8.patch`,
`sockudo-ws-1.7.5.patch`, `quinn-proto-0.11.19.patch`, `rustls-0.23.46.patch`,
`hyper-1.12.0.patch`.
