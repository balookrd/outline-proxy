# Changelog — outline-ui

`outline-ui` is the aggregating dashboard service that serves both the WS and SS
dashboards from one binary, deployed to k3s as a container image. Releases are
cut as `ui-v*` tags; within a release the service ships as a sequence of
**deployed image tags** (`outline-ui:1.0.x`), listed below the release they
belong to. This log records user- and operator-visible changes, not every
commit.

The format follows [Keep a Changelog](https://keepachangelog.com/).

## [1.9.3] - 2026-09-14

### Changed

- **Seamless vector brand banners for landing hero.** Replaced `banner-dark.png` and `banner-light.png` with clean, vector-rendered banners featuring crisp typography and refined shield gradients, completely eliminating background seam artifacts and bounding box discoloration in both light and dark landing themes.

## [1.9.2] - 2026-09-12

### Changed

- **Vibrant Electric Blue squircle badge for universal contrast.** Replaced low-contrast disc backings with a high-luminance electric blue squircle badge (`#0284C7` → `#2563EB` → `#1D4ED8`) featuring a crisp white shield and tunnel arrow symbol. The middle-spectrum luminance provides sharp contrast on both pure dark (`#020617`, dark tabs) and pure light (`#FFFFFF`, light tabs) surfaces with zero risk of blending into background chrome.

## [1.9.1] - 2026-09-12

### Changed

- **Theme-adaptive icons and favicons for enhanced contrast.** Separate dark and light variants of the brand emblem and favicon are now served:
  - Topbar branding displays `outline-logo-light.png` on light themes and `outline-logo-dark.png` on dark themes with zero layout flicker via CSS theme selectors.
  - Page favicon adapts to browser color scheme preferences (`prefers-color-scheme: dark`/`light`) and dynamically synchronizes with in-app manual theme toggling in `theme.svelte.ts`.

## [1.3.0] - 2026-08-27

### Changed

- **The SS user form follows the server's endpoint model: a user is pure credentials.** The server refactor made carrier paths a startup-only `[[endpoint]]` list and turned users into credentials that work on every endpoint of their kind, so the per-user path fields no longer exist — and the control API now rejects them with `deny_unknown_fields`. The user drawer drops its "WS paths" and "XHTTP paths" fieldsets, and create/edit send only `id`, `password` / `vless_id`, `method`, `fwmark`, `aliases`, and `enabled`. Without this, the dashboard's create and update calls fail with 400 against a server on the new model. Clone still fetches the instance's server default — now just the cipher — so a default-method template can still generate a matching password.

## [1.2.0] - 2026-08-24

### Added

- **Clone an SS user from an existing one.** Provisioning a key meant inventing a password and copying paths by hand from another user; each row now carries a Clone action that opens the create form pre-filled from that user with fresh secrets, so only the `id` is left to type. The carrier (method, fwmark, ws / xhttp paths, enabled) is copied; `id` is blank because it must be unique and aliases are dropped because their names are unique server-side; secrets are generated only for the identities the template actually has (`has_password` / `has_vless_id`), matched to the cipher — SS-2022 gets base64 of a raw key of the exact length its variant needs, legacy AEAD an arbitrary secret, and a server-default method yields nothing rather than a guess. Where the template is silent the fields fall back to the instance's server defaults, so cloning a user that runs on the server-wide cipher still produces a working password. Path filling mirrors the server's own `effective_ws_path_ss` precedence (a split template stays split, a combined one stays combined), and the defaults fetch carries a generation token so a slow response cannot land on a drawer the operator has since reopened.
- **The dashboard proxies each instance's SS server defaults.** `GET /ss/dashboard/api/defaults?instance=<name>` forwards to that instance's `/control/defaults` the same way `list_users` forwards `/control/users`: the bearer token is injected server-side and the body passed through untouched, so no control credential reaches the browser. This is what lets Clone fill a user that runs on the server-wide cipher instead of leaving the field blank.

### Fixed

- **The theme toggle shows the theme it switches *to*, and the browser chrome follows the page.** The toggle rendered a hardcoded moon whatever the active theme was, so it never told you where clicking would take you; it now shows a sun on dark and a moon on light, tracking both the explicit choice and — when none is set — the OS preference as it changes, via a `matchMedia` listener rather than a one-shot read. `applyTheme` also maintains `<meta name="theme-color">` from the `--bg` tokens, so the browser's own chrome follows the page instead of staying on its default.

## [1.1.0] - 2026-08-20

Everything below shipped as the image rollouts that make up this release.

### Image 1.0.6 — 2026-08-19

#### Changed

- Themed full-width banner hero on the landing page, with a rebranded badge and favicon.
- The container image is built **without provenance / SBOM attestations**, so it stays a plain single-arch image and pulls on every k3s node instead of failing on nodes that lack a local cache.

### Image 1.0.5 — 2026-08-14

#### Added

- **Uplink groups tab** — group CRUD, drag-and-drop reorder, and apply, with a `GroupDrawer` policy form (key fields plus data-driven advanced knobs). The dashboard proxies `/ws/dashboard/api/groups` to the server's `/control/uplink_groups`.

#### Fixed

- Clear a stale `reselect_at` on a mode switch and guard NaN advanced fields; emit `shared_resume`, `reselect_sync`, and `routing_scope` unconditionally so a PATCH can disable them.

### Image 1.0.4 — 2026-08-14

#### Added

- Drag-and-drop **reorder of uplinks within a group**, and URL-part chips for share-link fields.

### Image 1.0.3 — 2026-08-14

#### Added

- **Routing tab** — rule CRUD, drag-and-drop reorder, and hot-apply, with honest feedback when a change cannot be applied without a restart.

### Image 1.0.1 – 1.0.2 — 2026-08-13

#### Added

- WS **topology** read view (groups, wire chains, statuses) and operations (activate, soft-switch, reselect, enable); a single-chip wire-chain coloured by transport with a tunnel accent, plus switch-reason display.
- The SPA bundle is embedded behind the `embed-assets` feature with an SPA fallback; a frontend CI job was added.

#### Changed

- Removed the legacy HTML dashboards and `__BASE__` templating in favour of the embedded SPA.

#### Fixed

- Light-theme contrast across chips, metrics, and status; SS delete content-type (415); error and host-port hardening.

### Image 1.0.0 — 2026-08-12

#### Added

- Initial **`outline-ui` aggregating dashboard service**: serves the WS and SS dashboards from one binary (`/ws` and `/ss` on one port), aggregating node control APIs with no data plane of its own. Includes the SS users table with CRUD parity (drawer, block, delete), WS uplinks CRUD with hot-apply and a per-uplink fallbacks editor, design tokens / theme / router / shell / landing, and a visibility-aware polling primitive. Deployed to the k3s `monitoring` namespace; the two binary-embedded dashboards were pointed at it.

---

*Русская версия: [CHANGELOG.ru.md](CHANGELOG.ru.md)*
