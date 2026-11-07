# Heartbeat-приёмник для dead-man switch

Внешний наблюдатель на `relay-a` и `relay-b`: присылает письмо, когда замолчал
сам мониторинг. Каталог содержит watcher `heartbeat-watch` (python3, только
stdlib), юниты `heartbeat-watch.service` / `heartbeat-watch.timer`,
nginx-сниппет `nginx-heartbeat.conf`, установщик `install.sh` и офлайновые
тесты `test-heartbeat-watch.sh`.

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `relay-a`…`relay-d` — промежуточные cloud-узлы; `exit-a`…`exit-e` — выходные узлы. Соответствие — в локальном некоммитируемом `FLEET.local.md`.

## Что не может сообщить Grafana

Grafana (в k3s, `monitoring/grafana`, до 2026-08-09 — docker на `.102`) шлёт
алерты о деградации аплинков. О собственной смерти она сообщить не может: если
упадут под Grafana, VictoriaMetrics, кластер k3s или домашний канал, не будет ни
алертов, ни признака, что алертов больше нет. Тишина в почте неотличима от «всё
хорошо».

Поэтому цепочка развёрнута наоборот: Grafana постоянно шлёт пульс наружу, а
снаружи за ним следят. Пропал пульс — пришло письмо.

## Как работает

```
Grafana (k3s)               relay-a / relay-b
   │                              │
   │ правило DeadMansSwitch       │
   │ (firing всегда, repeat 5m)   │
   └──POST /hb/<token>───────────►│ nginx: access_log heartbeat.log, 204
                                  │
                                  │ heartbeat-watch (systemd timer, раз в 5 мин)
                                  │ последняя запись старше 15 мин?
                                  └──► письмо через Gmail SMTP
```

Условие правила `DeadMansSwitch` в
[`ops/grafana/alerting/rules.yaml`](../grafana/alerting/rules.yaml) ходит в
датасорс: это `count(up) >= bool 1`, а не константа `vector(1)`. Если VictoriaMetrics умрёт, запрос перестанет
отвечать, правило перестанет срабатывать, пульс прекратится и наблюдатели
пришлют письмо. Константа в этом случае продолжила бы бодро пульсировать поверх
мёртвой базы.

Маршрут пульса — правило в
[`ops/grafana/alerting/policies.yaml`](../grafana/alerting/policies.yaml):
`DeadMansSwitch` уходит в contact point `heartbeat-observers` (два webhook'а,
`https://relay-a.fleet.example/hb/<токен>` и `https://relay-b.fleet.example/hb/<токен>`)
с `group_wait: 0s`, `group_interval: 1m`, `repeat_interval: 5m`.

Приёмник не поднимает ни своего порта, ни своего сертификата: на 443 слушает
`outline-ss-rust`, который нераспознанный HTTPS-трафик отдаёт в nginx на
`127.0.0.1:8080` с `proxy_protocol`. Сниппет подключается в тот же
`server`-блок `/etc/nginx/sites-enabled/fleet.example`, где уже лежат
`/rust-ws-exporter/metrics` и соседи, и отвечает `204` на
`location = /hb/<токен>`, записывая запрос в `/var/log/nginx/heartbeat.log`.

## Параметры watcher'а

| Флаг | Значение по умолчанию | Что делает |
|------|-----------------------|------------|
| `--log` | `/var/log/nginx/heartbeat.log` | лог приёмника; читается и `<log>.1` |
| `--state` | `/var/lib/heartbeat-watch/state.json` | файл состояния (`up`/`down`, время последнего письма) |
| `--threshold` | `900` | возраст последнего пульса в секундах, после которого состояние — `down` |
| `--repeat` | `21600` | интервал повторного письма `DOWN` в секундах, пока авария длится |
| `--dry-run` | — | печатает решение, ничего не шлёт и не пишет (см. «Проверка») |
| `--simulate` | — | как `--dry-run`, но сохраняет состояние; для тестов |

Юнит запускает watcher без флагов, то есть с этими значениями. Письмо `RESOLVED`
уходит один раз при возврате пульса.

## Два наблюдателя

Один наблюдатель не отличает смерть мониторинга от собственной изоляции:
провайдерские блокировки отрезают отдельные узлы (exit-d и exit-c недоступны из
РФ), и так же может отвалиться путь до любого cloud-узла.

Поэтому читать письма нужно так:

- письмо от одного узла — скорее всего сломан путь до этого узла;
- письма от обоих — действительно лежит мониторинг.

Имя наблюдателя (`socket.gethostname()`) стоит в теме письма
(`[relay-a] outline: no heartbeat from home Grafana`). При настоящей аварии приходит два
письма вместо одного.

## Установка

```bash
rsync -a --delete ops/heartbeat/ sysadm@relay-a.fleet.example:/tmp/heartbeat/
ssh sysadm@relay-a.fleet.example 'cd /tmp/heartbeat && sudo ./install.sh'
```

`install.sh` идемпотентен и не перезагружает nginx: он кладёт сниппет в
`/etc/nginx/snippets/heartbeat.conf`, добавляет `include` в
`/etc/nginx/sites-enabled/fleet.example` (копия до правки — в
`/etc/nginx/heartbeat-backups/`), проверяет конфиг через `nginx -t`, включает
`heartbeat-watch.timer` и печатает команду `systemctl reload nginx` для
владельца. Узел обслуживает боевой трафик, решение о `reload` принимает
человек. Без файла токена `install.sh` завершается с ошибкой, ничего не
установив; токен с символами вне `[A-Za-z0-9_-]` тоже отклоняется.

До запуска на узле должен лежать токен:

```bash
sudo install -d -m 0700 /etc/heartbeat-watch
printf '%s' '<токен>' | sudo tee /etc/heartbeat-watch/token >/dev/null
sudo chmod 0600 /etc/heartbeat-watch/token
```

Токен — общий секрет для обоих узлов и для URL webhook'а в Grafana; генерируется
один раз (`openssl rand -base64 24 | tr -d '=+/'`). В репозитории его нет: в
`nginx-heartbeat.conf` и в
[`ops/grafana/alerting/contact-points.yaml`](../grafana/alerting/contact-points.yaml)
стоит плейсхолдер `__HEARTBEAT_TOKEN__`. На узле его подставляет `install.sh`,
в Grafana — `ops/grafana/alerting/deploy.sh` из
`~/.config/outline/heartbeat-token` на машине разработчика.

## Секреты

| Файл | Права | Что внутри |
|------|-------|------------|
| `/etc/heartbeat-watch/token` | `0600 root` | общий токен heartbeat-URL |
| `/etc/heartbeat-watch/smtp.env` | `0600 root` | `SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_TO` |

`SMTP_PASSWORD` — app-password Google (16 символов, требует включённой
двухэтапной аутентификации), тот же, что у Grafana. `SMTP_HOST` задаётся как
`host:port`, без порта используется 587 (STARTTLS). Наблюдатели шлют почту
сами, не через Grafana: путь доставки не должен зависеть от того, за чем
следим.

## Проверка

```bash
curl -sS -o /dev/null -w '%{http_code}\n' https://relay-a.fleet.example/hb/<токен>   # 204
sudo tail -1 /var/log/nginx/heartbeat.log                                          # свежая строка
sudo /usr/local/sbin/heartbeat-watch --dry-run                                     # state=up
systemctl list-timers heartbeat-watch.timer --no-pager                             # NEXT в пределах 5 мин
```

Таймер: `OnBootSec=5min`, `OnUnitActiveSec=5min`, `AccuracySec=30s`.

`--dry-run` печатает решение и ничего не меняет: ни письма, ни файла
состояния. Вывод — `state=up`, `state=down send=DOWN`, `state=down send=none`
или `state=up send=RESOLVED`.

Флаг `--simulate` делает то же, но состояние сохраняет — он нужен тестам,
чтобы прогонять цепочку переходов. Руками его не запускайте: диагностика,
меняющая состояние, пометит аварию как «уже уведомлено» и проглотит следующее
настоящее письмо. Так и случилось при первой раскатке 2026-08-07, поэтому флаги
и разведены.

Поведение watcher'а покрыто офлайновыми тестами — `./test-heartbeat-watch.sh`
(нужен только python3, боевые узлы не трогает).

## Грабли

- Логротация. `/var/log/nginx/*.log` ротируется ежедневно, и сразу после
  ротации живой лог пуст. Watcher поэтому смотрит и в `heartbeat.log.1` —
  иначе каждую ночь возникала бы ложная авария.
- Отсутствие лога — не авария. До первого пульса судить не о чем, и свежая
  установка молчит. Письмо появляется только после того, как пульс был и
  пропал.
- Якорь вставки в nginx-конфиг. В `fleet.example` первым идёт закомментированный
  `:80`-блок с тем же `server_name *.fleet.example;`. Вставка по первому совпадению
  `server_name` уронила бы `include` вне `server`-блока, поэтому установщик
  цепляется за `listen 127.0.0.1:8080 proxy_protocol;` и требует ровно одного
  совпадения.
