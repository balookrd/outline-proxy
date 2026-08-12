# Statically linked musl binary: nothing else is needed at runtime, so the image
# is the binary and nothing more. No shell, no package manager, no libc —
# the attack surface of the container is the service itself.
#
# Deliberately not a multi-stage build. The binary is cross-compiled OUTSIDE
# Docker (`cargo zigbuild`, same as outline-ss-rust/outline-ws-rust — see
# README.md's "Deployment" section) and this Dockerfile only packages the
# result into scratch. Compiling aarch64-musl inside a Docker rust stage
# would need its own toolchain and would fight that established model
# instead of reusing it.
#
# The binary MUST be built with `--features embed-assets` against a freshly
# `pnpm build`-ed bins/outline-ui/frontend/dist — that is what bakes the
# Svelte SPA into it. A binary built without the feature still runs and
# still passes /ws and /ss API traffic, but serves an "assets not embedded"
# stub at `/` instead of the dashboard.
FROM scratch
COPY target/aarch64-unknown-linux-musl/release/outline-ui /outline-ui
USER 65534:65534
EXPOSE 9000
ENTRYPOINT ["/outline-ui"]
