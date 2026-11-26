# Docker-стенд для smoke-тестов и проверки совместимости

> **English version:** [`README.md`](README.md)

Лёгкий локальный Docker-стенд для сквозной проверки release `musl`-бинарей `outline-server` и `outline-client`, включая проверку обратной совместимости со старыми образами перед канареечной выкаткой.

## Быстрый старт

Сборка `musl`-бинарей, прогон smoke-тестов (`ws_h1` SS2022 и `xhttp_h1` VLESS с `padding` и `cover`: TCP + UDP echo через SOCKS5 и проверка `/metrics`) и автоматическая очистка контейнеров:

```bash
./scripts/docker-stand/stand.sh test
```

## Матрица совместимости со старым релизом

Укажите образы предыдущего релиза через флаги или переменные окружения (`OLD_SERVER_IMAGE`, `OLD_CLIENT_IMAGE`):

```bash
./scripts/docker-stand/stand.sh test \
  --old-server registry.k3s.beerloga.su/outline-server:26.11.3-c52ac2b5 \
  --old-client registry.k3s.beerloga.su/outline-client:26.11.3-c52ac2b5
```

## Ручной режим

```bash
./scripts/docker-stand/stand.sh build
./scripts/docker-stand/stand.sh up --mode ss-ws
./scripts/docker-stand/stand.sh smoke manual
./scripts/docker-stand/stand.sh logs
./scripts/docker-stand/stand.sh down
```

По завершении при необходимости очистите `target/` командой `cargo clean`.
