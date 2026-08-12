# Statically linked musl binary: nothing else is needed at runtime, so the image
# is the binary and nothing more. No shell, no package manager, no libc —
# the attack surface of the container is the service itself.
FROM scratch
COPY target/aarch64-unknown-linux-musl/release/outline-ui /outline-ui
USER 65534:65534
EXPOSE 9000
ENTRYPOINT ["/outline-ui"]
