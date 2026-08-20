# Changelog — outline-ui

`outline-ui` is the aggregating dashboard service that serves both the WS and SS
dashboards from one binary, deployed to k3s as a container image. Releases are
tracked by the **deployed image tag** (`outline-ui:1.0.x`); the crate itself is
at `0.2.0`. This log records user- and operator-visible changes, not every
commit.

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.0.6] - 2026-08-19

### Changed

- Themed full-width banner hero on the landing page, with a rebranded badge and favicon.
- The container image is built **without provenance / SBOM attestations**, so it stays a plain single-arch image and pulls on every k3s node instead of failing on nodes that lack a local cache.

## [1.0.5] - 2026-08-14

### Added

- **Uplink groups tab** — group CRUD, drag-and-drop reorder, and apply, with a `GroupDrawer` policy form (key fields plus data-driven advanced knobs). The dashboard proxies `/ws/dashboard/api/groups` to the server's `/control/uplink_groups`.

### Fixed

- Clear a stale `reselect_at` on a mode switch and guard NaN advanced fields; emit `shared_resume`, `reselect_sync`, and `routing_scope` unconditionally so a PATCH can disable them.

## [1.0.4] - 2026-08-14

### Added

- Drag-and-drop **reorder of uplinks within a group**, and URL-part chips for share-link fields.

## [1.0.3] - 2026-08-14

### Added

- **Routing tab** — rule CRUD, drag-and-drop reorder, and hot-apply, with honest feedback when a change cannot be applied without a restart.

## [1.0.1 – 1.0.2] - 2026-08-13

### Added

- WS **topology** read view (groups, wire chains, statuses) and operations (activate, soft-switch, reselect, enable); a single-chip wire-chain coloured by transport with a tunnel accent, plus switch-reason display.
- The SPA bundle is embedded behind the `embed-assets` feature with an SPA fallback; a frontend CI job was added.

### Changed

- Removed the legacy HTML dashboards and `__BASE__` templating in favour of the embedded SPA.

### Fixed

- Light-theme contrast across chips, metrics, and status; SS delete content-type (415); error and host-port hardening.

## [1.0.0] - 2026-08-12

### Added

- Initial **`outline-ui` aggregating dashboard service**: serves the WS and SS dashboards from one binary (`/ws` and `/ss` on one port), aggregating node control APIs with no data plane of its own. Includes the SS users table with CRUD parity (drawer, block, delete), WS uplinks CRUD with hot-apply and a per-uplink fallbacks editor, design tokens / theme / router / shell / landing, and a visibility-aware polling primitive. Deployed to the k3s `monitoring` namespace; the two binary-embedded dashboards were pointed at it.

---

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
