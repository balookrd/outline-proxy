# Алертинг: vmalert и Alertmanager в k3s

Каталог содержит правила алертов (vmalert), конфиг Alertmanager и скрипты их проверки и раскатки. Документ нужен владельцу парка, который меняет пороги, маршруты уведомлений или проверяет, что алертинг жив. Манифесты подов лежат отдельно, в
[`ops/nanopi-r5c-k3s/apps/monitoring/`](../nanopi-r5c-k3s/apps/monitoring/)
(`vmalert.yaml`, `alertmanager.yaml`).

Реальные имена узлов, домены и адреса парка в этом документе заменены условными: `fleet.example` — домен парка; `relay-a`, `relay-b` — промежуточные cloud-узлы; `198.51.100.0/24` — домашняя сеть (`.102`, `.104`, `.105` — последний октет). Соответствие — в локальном некоммитируемом `FLEET.local.md`.

С 2026-11-09 это единственный источник алертов парка. Алертинг Grafana выключен; провижининг в [`ops/grafana/alerting/`](../grafana/alerting/) оставлен только для отката (см. «Откат»).

## Требования

| Что | Зачем |
|-----|-------|
| docker на машине разработчика | `test.sh` запускает `vmalert-tool` и `amtool` в контейнерах |
| `kubectl` и `KUBECONFIG=~/.kube/k3s-home.yaml` | `deploy.sh` применяет ConfigMap и Secret в namespace `monitoring` |
| `~/.config/outline/heartbeat-token` | токен URL пульса; тот же, что в `/etc/heartbeat-watch/token` на `relay-a` и `relay-b` |
| `~/.config/outline/telegram-bot-token` | токен бота Telegram |
| `~/.config/outline/telegram-chat-id` | целочисленный id чата; `deploy.sh` отклоняет всё, кроме цифр и `-` |
| Secret `grafana-smtp` в `monitoring`, ключ `smtp` | `deploy.sh` копирует пароль в Secret `alertmanager-smtp` |

Каталог с секретами переопределяется переменной `OUTLINE_SECRETS_DIR`. Чтобы получить `chat_id`, пользователь сам пишет боту первым: Telegram не отдаёт id до первого сообщения и запрещает боту писать первым. Файлы секретов — права `0600`. Если какого-то из трёх файлов нет или он пуст, `deploy.sh` завершается с ошибкой до любых изменений в кластере.

## Как работает

```
VictoriaMetrics ──запрос раз в 1 мин──► vmalert ──алерты──► Alertmanager ──► почта + Telegram (owner, owner-events)
      ▲                                    │                      │
      └────ALERTS, ALERTS_FOR_STATE────────┘                      └──webhook, каждые ~6 мин──► relay-a, relay-b
                                                                         (heartbeat-watch: нет пульса 15 мин → письмо)
```

- vmalert (`monitoring/vmalert`) каждую минуту выполняет 8 правил из `vmalert/rules.yaml` против `http://victoria-metrics.monitoring:8428`. Свои серии `ALERTS` и `ALERTS_FOR_STATE` он пишет туда же (`-remoteWrite.url`) и по ним восстанавливает таймеры `for` после рестарта (`-remoteRead.url`). Дашборд [`outline alerting`](../grafana/dashboards/outline-alerting.json) читает эти серии.
- Alertmanager (`monitoring/alertmanager`) группирует алерты и доставляет их по маршрутам из `alertmanager/alertmanager.yml`. Конфиг приезжает Secret'ом `alertmanager-config`, пароль SMTP — Secret'ом `alertmanager-smtp`.
- Оба пода без `nodeSelector` и без PVC: отказ одного узла k3s не убирает алертинг вместе с VictoriaMetrics.
- Правило `DeadMansSwitch` горит всегда, его уведомления и есть пульс. Приёмник на `relay-a` и `relay-b` описан в [`ops/heartbeat/README.md`](../heartbeat/README.md).

Семантика ошибок: нет данных — нет алерта; запрос упал — ничего не отправляется (как было `noDataState: OK` и `execErrState: OK` в Grafana). Мёртвую VictoriaMetrics ловит не массовое срабатывание правил, а замолчавший `DeadMansSwitch`.

## Правила

Файл [`vmalert/rules.yaml`](vmalert/rules.yaml), три группы (`uplink`, `nodes`, `heartbeat`), интервал вычисления у каждой `1m`. Пороги, `for` и `keep_firing_for` перенесены из Grafana без изменений. Обоснование каждого числа — в комментариях над правилами и в
[спеке](../../docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md); здесь оно не дублируется.

| Алерт | Выражение (сокращённо) | `for` | `keep_firing_for` | `severity` | Получатель |
|-------|------------------------|-------|-------------------|------------|------------|
| `TargetDown` | `up{job=~"rust-ws-exporter\|rust-ss-exporter\|unbound-exporter"} < 1` | 5m | 15m | critical | `owner` |
| `AllUplinksDown` | `sum by (instance) (outline_ws_uplink_health_effective) < 1` | 3m | — | critical | `owner` |
| `UplinkCarrierLossHigh` | `outline_ws_uplink_carrier_loss_ratio > 0.05` и плечо активно (`outline_ws_global_active_uplink_info == 1`) | 10m | 30m | warning | `owner` |
| `UplinkFailoverStorm` | больше 20 `outline_ws_uplink_failovers_total` за 15 мин, без `*_shuffle_timer` | 0s | 30m | warning | `owner` |
| `UplinkCertExpiringSoon` | до истечения сертификата меньше 14 дней | 1h | — | info | `owner` |
| `ClientRestarted` | `min by (instance) (time() - outline_ws_start_time_seconds) < 180` | 0s | — | info | `owner-events` |
| `NodeRebooted` | `min by (instance) (time() - node_boot_time_seconds{instance=~"k3s-[0-9]+"}) < 600` | 0s | — | warning | `owner-events` |
| `DeadMansSwitch` | `count(up) >= 1` | 0s | — | none | `heartbeat-observers` |

Аннотации `summary` и `description` не должны содержать `<`, `>`, `&`: получатель Telegram работает с `parse_mode: HTML`, а шаблоны Alertmanager символы не экранируют. Это проверяет `test.sh`.

## Маршруты и получатели

Файл [`alertmanager/alertmanager.yml`](alertmanager/alertmanager.yml). Корневой маршрут: получатель `owner`, `group_by: [alertname, instance]`, `group_wait: 30s`, `group_interval: 5m`, `repeat_interval: 12h`.

| Маршрут (по порядку) | Условие | Получатель | Параметры |
|----------------------|---------|------------|-----------|
| 1 | `alertname="DeadMansSwitch"` | `heartbeat-observers` | `group_wait: 0s`, `group_interval: 1m`, `repeat_interval: 5m` |
| 2 | `shadow="true"` | `blackhole` | уведомления отбрасываются; после снятия метки (2026-11-09) маршрут не срабатывает, оставлен до тех пор, пока переезд не отстоится |
| 3 | `alertname="ClientRestarted"` | `owner-events` | `group_by: [alertname, instance]`, `repeat_interval: 24h` |
| 4 | `alertname="NodeRebooted"` | `owner-events` | `group_by: [alertname]`, `repeat_interval: 24h` |
| корень | всё остальное | `owner` | см. выше |

| Получатель | Каналы | Уведомление о восстановлении (`send_resolved`) |
|------------|--------|-----------------------------------------------|
| `owner` | почта + Telegram | да |
| `owner-events` | почта + Telegram | нет: «восстановлено» для уже прошедшего события читается как второй инцидент |
| `heartbeat-observers` | два webhook'а: `https://relay-a.fleet.example/hb/<токен>` и `https://relay-b.fleet.example/hb/<токен>` | нет |
| `blackhole` | — | — |

`ClientRestarted` группируется по `instance`: при общей группе и окне алерта (3 минуты) короче `group_interval` первое же уведомление поглощало остальные узлы при последовательной выкладке. `NodeRebooted` группируется по `alertname`: три узла k3s, перезагрузившиеся разом, приходят одним письмом, и это признак общего питания. Подробности — в комментариях `alertmanager.yml`.

Адрес получателя почты и `smtp_from` заданы в `alertmanager.yml`; в этом документе они не приводятся.

## Офлайн-проверки

```bash
./ops/alerting/test.sh
```

Нужен только docker, к кластеру скрипт не обращается. Образы `vmalert-tool` и `alertmanager` закреплены по digest. Шаги:

| Шаг | Что проверяет |
|-----|---------------|
| аннотации | в `summary` и `description` нет `<`, `>`, `&` |
| `vmalert-tool unittest` | `vmalert/tests/{uplink,nodes,heartbeat}.yaml`: срабатывание, `for`, `keep_firing_for`, точное совпадение меток и аннотаций |
| рендер | `deploy.sh --render` подставляет фиктивные секреты, плейсхолдеров не остаётся |
| `amtool check-config` | синтаксис и ссылки на получателей в `alertmanager.yml` |
| `amtool config routes test` | каждый алерт попадает к ожидаемому получателю (включая `DeadMansSwitch` с меткой `shadow=true` и произвольный `AlertingSelfTest`) |

Печать `==> all checks passed` в конце означает успех; любой шаг при ошибке завершает скрипт с ненулевым кодом.

Особенность `vmalert-tool unittest`: он считает `time()` от 2000-01-01, поэтому в тестах, где выражение зависит от `time()` (`UplinkCertExpiringSoon`, `ClientRestarted`, `NodeRebooted`), временные метки во входных рядах сдвинуты на 946684800 секунд. Новый тест на `time()` пишите с тем же сдвигом.

## Изменение и раскатка

Любое применение в кластер — действие на проде; выполняйте его только с согласия владельца.

| Что поменяли | Команда | Когда вступает в силу |
|--------------|---------|-----------------------|
| `vmalert/rules.yaml` | `./ops/alerting/deploy.sh` | vmalert перечитывает правила сам (`-configCheckInterval=1m`) после того, как kubelet синхронизирует ConfigMap `vmalert-rules` в под, обычно через 1–2 минуты. Рестарт не нужен |
| `alertmanager/alertmanager.yml` | `./ops/alerting/deploy.sh`, затем reload Alertmanager | после синхронизации Secret (~90 с) и reload |
| манифесты `vmalert.yaml`, `alertmanager.yaml` | `kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/<файл>` | сразу, под пересоздаётся |

`deploy.sh` сам запускает `test.sh`, подставляет секреты в `alertmanager.yml` (рендер лежит во временном каталоге и удаляется; в git он не попадает) и применяет ConfigMap `vmalert-rules`, Secret `alertmanager-config` и Secret `alertmanager-smtp`. Для проверки рендера без обращения к кластеру: `./ops/alerting/deploy.sh --render <существующий каталог>`.

Порядок для изменения правил или маршрутов:

1. Отредактируйте `vmalert/rules.yaml` или `alertmanager/alertmanager.yml`. Для нового правила добавьте тест в `vmalert/tests/`, для нового маршрута — строку `route …` в `test.sh`.
2. Запустите `./ops/alerting/test.sh`. Продолжайте только при `all checks passed`.
3. Получите согласие владельца и выполните:

   ```bash
   export KUBECONFIG=~/.kube/k3s-home.yaml
   ./ops/alerting/deploy.sh
   ```

4. Если менялся `alertmanager.yml`, через ~90 секунд перечитайте конфиг в каждой из трёх реплик, без рестарта подов:

   ```bash
   for i in 0 1 2; do
     kubectl -n monitoring exec alertmanager-$i -- \
       wget -qO- --post-data='' http://127.0.0.1:9093/-/reload
   done
   ```

   busybox `wget` в образе `prom/alertmanager` с пустым `--post-data` шлёт POST, проверено на живом поде 2026-11-09. Конфиг перечитывают все реплики: реплика со старым конфигом продолжит слать уведомления по старым маршрутам. `kubectl -n monitoring rollout restart statefulset/alertmanager` тоже перечитывает конфиг и перезапускает поды по одному; заглушки и журнал отправок при этом сохраняются у соседних реплик.

   Результат в логе каждой реплики:

   ```bash
   for i in 0 1 2; do kubectl -n monitoring logs alertmanager-$i --since=2m | grep -i "completed loading"; done
   ```

5. Для правил проверьте через 2–3 минуты, что vmalert загрузил новую версию (см. «Проверка»).

Токен пульса, токен бота и chat id берутся с машины разработчика и попадают только в Secret `alertmanager-config`. В `alertmanager.yml` стоят плейсхолдеры `__HEARTBEAT_TOKEN__`, `__TELEGRAM_BOT_TOKEN__`, `__TELEGRAM_CHAT_ID__`.

## Проверка

Алерты в Alertmanager (в списке всегда есть `DeadMansSwitch`):

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring exec alertmanager-0 -- amtool alert query --alertmanager.url=http://127.0.0.1:9093
```

Ошибки vmalert и состояние перезагрузки правил:

```bash
kubectl -n monitoring logs deploy/vmalert --since=10m | grep -iE "error|warn" || echo "no errors"
```

Пульс на наблюдателях (на `relay-a` и `relay-b`; имя ssh-хоста — по `FLEET.local.md`). Последние записи должны иметь User-Agent `Alertmanager/0.34.2` и возраст до ~6 минут:

```bash
ssh <relay-a> 'sudo tail -n 5 /var/log/nginx/heartbeat.log'
ssh <relay-b> 'sudo tail -n 5 /var/log/nginx/heartbeat.log'
```

Пульс идёт примерно 20 раз в час суммарно: каждый наблюдатель получает запись примерно раз в 6 минут. Провал больше 15 минут на одном узле — письмо от этого узла, на обоих — письмо от обоих.

Проверка доставки почты и Telegram искусственным алертом (уведомление придёт владельцу; маршрут — корневой `owner`, поэтому отправка идёт и по почте, и в Telegram):

```bash
kubectl -n monitoring exec alertmanager-0 -- amtool alert add alertname=AlertingSelfTest \
  instance=selftest severity=info \
  --annotation=summary='Alertmanager self-test, ignore' \
  --alertmanager.url=http://127.0.0.1:9093
```

Снять алерт:

```bash
kubectl -n monitoring exec alertmanager-0 -- amtool alert add alertname=AlertingSelfTest \
  instance=selftest severity=info --end="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --alertmanager.url=http://127.0.0.1:9093
```

Дашборд `outline alerting` в Grafana (`https://grafana.k3s.fleet.example`): верхний ряд показывает число горящих алертов, число загруженных правил, ошибки вычисления, пропущенные такты vmalert и отправки Alertmanager по каналам; описание панелей — в [`ops/grafana/README.md`](../grafana/README.md). Датасорс Alertmanager в Grafana: `alertmanager-k3s`, `https://alertmanager.k3s.fleet.example`.

## Известные проблемы

- Alertmanager — три реплики (StatefulSet, по одной на узел), объединённые в gossip-кластер; хранилище каждой — `emptyDir`. Заглушки (silences) и журнал уведомлений реплицируются между репликами, поэтому пересозданный под получает их от соседей (проверено 2026-11-09: заглушка пережила удаление пода). Теряются они, только если одновременно пропадут все три пода. PVC не используется намеренно: `local-path` привязал бы под к узлу, NFS — к NAS, то есть к тем доменам отказа, вне которых под должен стоять.
- vmalert шлёт каждый алерт во все три реплики (`-notifier.url` на каждый под). Уведомление отправляет одна реплика, остальные видят его в общем журнале и молчат: на 2026-11-09 пульс шёл только из `alertmanager-2`, у двух других `alertmanager_notifications_total{integration="webhook"}` = 0.
- Искусственный алерт из раздела «Проверка» (`amtool alert add` в `alertmanager-0`) попадает только в эту реплику; отправит его она же.
- После отказа VictoriaMetrics пульс прекращается не сразу. vmalert перестаёт отправлять алерт (в логе `failed to execute query`), а Alertmanager закрывает его по `endsAt`, примерно через четыре интервала вычисления, то есть через ~4 минуты (измерено 2026-11-08 при интервале 10 с; при 1m значение выведено расчётом, а не замерено). Наблюдатели пишут через 15 минут без записей.
- Метрики самого vmalert лежат в VictoriaMetrics. Панель «Ошибок вычисления за 24ч» при её отказе пуста; этот случай ловит только пульс.
- Временные метки в тестах `vmalert-tool unittest` смещены на 946684800 секунд из-за эпохи 2000-01-01 (см. «Офлайн-проверки»). Тест без сдвига для выражения с `time()` даст ложное падение или ложное прохождение.
- Проверка исходящего доступа к SMTP и Telegram с пода подтверждает только узел, на котором он стоит. Реплики стоят на всех трёх узлах, и уведомление может отправить любая из них; если маршрутизация наружу на узлах k3s различается, повторите самопроверку из каждой реплики (`alertmanager-0`, `-1`, `-2`).

## Откат

Условие: вернуть алертинг в Grafana, пока `ops/grafana/alerting/` не удалён из репозитория (удаление — не раньше 2026-11-22). Каждый шаг — действие на проде, только с согласия владельца.

1. Манифеста `grafana.yaml` в дереве больше нет (Grafana работает на NAS, см. [`ops/nas-monitoring/README.md`](../nas-monitoring/README.md)). Верните Grafana в k3s по разделу «Откат в k3s» того README: он берёт манифест из `a6aa553f~1`, последней версии перед удалением, и в ней алертинг Grafana выключен (`GF_UNIFIED_ALERTING_ENABLED=false`, тома `grafana-alerting` нет; проверено). Для отката алертинга возьмите вместо неё версию до переключения: `git show 008e27a2^:ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` (проверено: том `grafana-alerting` на месте; между `008e27a2` и `a6aa553f` файл менялся только удалением) и положите её в `/tmp/rollback/grafana.yaml` после шага 3 отката в k3s (выгрузка манифестов), до шага 5 (применение с `replicas: 0`). Либо оставьте версию `a6aa553f~1`, уберите в ней `GF_UNIFIED_ALERTING_ENABLED=false` и верните том `alerting` из Secret `grafana-alerting` с его `volumeMounts`.
2. Пересоздайте Secret `grafana-alerting`, он был удалён при переключении:

   ```bash
   export KUBECONFIG=~/.kube/k3s-home.yaml
   ./ops/grafana/alerting/deploy.sh --k3s
   ```

3. Примените Deployment и перезапустите Grafana (провижининг алертинга читается только при старте):

   ```bash
   kubectl apply -f /tmp/rollback/grafana.yaml   # манифест из шага 1 и отката в k3s
   kubectl -n monitoring rollout restart deploy/grafana
   ```

4. Остановите vmalert, чтобы не получать дубли: `kubectl -n monitoring scale deploy/vmalert --replicas=0`.

Проверка: в логе Grafana есть `starting to provision alerting` (`kubectl -n monitoring logs deploy/grafana | grep "provision alerting"`), а User-Agent последних записей `heartbeat.log` на наблюдателях начинается с `Grafana`.

## История

| Дата (UTC) | Событие |
|------------|---------|
| 2026-11-08 17:31 | vmalert и Alertmanager выкачены в теневом режиме: vmalert с `-external.label=shadow=true`, Alertmanager отправляет `shadow="true"` в `blackhole`, кроме пульса. Уведомления слала только Grafana |
| 2026-11-08 – 2026-11-09 | Теневой прогон 16 часов: 7 из 7 срабатываний `ClientRestarted` в Grafana совпали с vmalert с точностью до минуты |
| 2026-11-09 09:30 | Переключение: метка `shadow` снята, в Grafana `GF_UNIFIED_ALERTING_ENABLED=false`, том с провижинингом алертинга убран, Secret `grafana-alerting` удалён |

Снятие метки меняет набор меток алертов, поэтому таймеры `for` не восстанавливаются из серий, записанных в теневом режиме: по уже горящим проблемам правила с `for` проходят `pending` заново.

## VictoriaMetrics и Grafana на NAS

С 2026-11-09 VictoriaMetrics и Grafana работают в docker на NAS `198.51.100.105` ([`ops/nas-monitoring`](../nas-monitoring/README.md)). Аргументы vmalert не менялись: `victoria-metrics.monitoring:8428` остался в кластере как Service без селектора, его EndpointSlice `victoria-metrics-nas` указывает на `198.51.100.105:8428`. Датасорс `alertmanager-k3s` в Grafana на NAS ходит на `https://alertmanager.k3s.fleet.example` через Ingress.
