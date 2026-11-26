# Docker Smoke & Compatibility Stand

> **Русская версия:** [`README.ru.md`](README.ru.md)

Lightweight local Docker stand for end-to-end verification of `outline-server` and `outline-client` `musl` release binaries (including optional cross-version compatibility checks against previously released Docker images).

## Quick start

Run the full build + smoke suite (`ws_h1` SS2022 + `xhttp_h1` VLESS with `padding` and `cover` enabled, TCP + UDP echo + `/metrics` checks) and clean up containers automatically:

```bash
./scripts/docker-stand/stand.sh test
```

## Cross-version compatibility matrix

Pass previously released images via flags or environment variables (`OLD_SERVER_IMAGE`, `OLD_CLIENT_IMAGE`):

```bash
./scripts/docker-stand/stand.sh test \
  --old-server registry.k3s.beerloga.su/outline-server:26.11.3-c52ac2b5 \
  --old-client registry.k3s.beerloga.su/outline-client:26.11.3-c52ac2b5
```

## Manual inspection

```bash
./scripts/docker-stand/stand.sh build
./scripts/docker-stand/stand.sh up --mode ss-ws
./scripts/docker-stand/stand.sh smoke manual
./scripts/docker-stand/stand.sh logs
./scripts/docker-stand/stand.sh down
```

After finishing, run `cargo clean` if you want to reclaim `target/` disk space.
