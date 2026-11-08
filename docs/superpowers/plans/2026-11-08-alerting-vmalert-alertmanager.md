# Вынос алертинга из Grafana в vmalert + Alertmanager (k3s): план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Цель:** правила алертов и рассылка уведомлений переезжают из Grafana в отдельные vmalert и Alertmanager в namespace `monitoring` кластера k3s, чтобы Grafana и VictoriaMetrics можно было потом перенести на NAS `198.18.1.105`, не теряя алертинга при отказе NAS.

**Архитектура:** vmalert раз в минуту выполняет 8 существующих правил против VictoriaMetrics и отправляет сработавшие алерты в Alertmanager. Alertmanager повторяет дерево маршрутов из `ops/grafana/alerting/policies.yaml`: почта и Telegram владельцу, пульс dead-man по webhook на cloud1/cloud2. Оба пода без привязки к узлу и без PVC. Переключение идёт через теневой режим: сначала vmalert работает с внешней меткой `shadow="true"`, и Alertmanager глушит всё, кроме пульса. После сверки с Grafana метка снимается, а алертинг Grafana выключается.

**Стек:** vmalert v1.155.0, vmalert-tool v1.155.0 (unit-тесты правил), Alertmanager v0.34.2 (`amtool` для проверки конфига и маршрутов), k3s, docker на маке для тестов.

## Глобальные ограничения

- Образы только по digest (как у остальных манифестов `monitoring`):
  - `victoriametrics/vmalert@sha256:3256cba5ddaca5974eae6141105cec4ce37871f1c213f0a5c267ec0111bc68e1` (v1.155.0)
  - `victoriametrics/vmalert-tool@sha256:b03d29d0a11b906a85879a6a4009c9d0a9d5a8b9a744ebb7dd3a7721f1e78f36` (v1.155.0)
  - `prom/alertmanager@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b` (v0.34.2)
  - Это digest'ы image index, сняты с Docker Hub 2026-11-08. Наличие `linux/arm64` проверяется в задаче 4.
- Секреты не попадают в git: токен пульса, токен бота и chat id Telegram подставляются из `~/.config/outline/{heartbeat-token,telegram-bot-token,telegram-chat-id}` (как в `ops/grafana/alerting/deploy.sh`). Пароль SMTP копируется из существующего Secret `grafana-smtp` (ключ `smtp`).
- Любое `kubectl apply`, рестарт пода или правка живого `scrape.yaml` в PVC — действие на проде. Выполнять только после явного «да» владельца на конкретный шаг (AGENTS.md, «Выкатка на хосты»).
- Коммиты только по команде владельца, только своими путями: `git commit -- <paths>`. Перед push — `git log origin/main..main`.
- Аннотации правил (`summary`, `description`) без символов `<`, `>`, `&`: Telegram-получатель работает с `parse_mode: HTML`, а шаблоны Alertmanager их не экранируют. Проверяется в `ops/alerting/test.sh`.
- Пороги, `for` и `keep_firing_for` всех правил не меняются: они откалиброваны в `docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md`.

## Что проверено до написания плана (2026-11-08, docker на маке)

| Вопрос | Результат |
|---|---|
| vmalert поддерживает `keep_firing_for` | да: `TargetDown` с `for: 5m`, `keep_firing_for: 15m` горит на 20-й минуте после восстановления цели на 7-й и гаснет к 30-й (vmalert-tool unittest) |
| vmalert-tool сверяет аннотации | да, точным совпадением: `exp_annotations` обязательны, иначе тест падает с `Annotations:{}` против фактических |
| Что делает vmalert при недоступной VictoriaMetrics | перестаёт отправлять алерт (в логе `failed to execute query`). Alertmanager снимает его по `endsAt`: при `-evaluationInterval=10s` алерт `DeadMansSwitch` исчез через ~37 с после остановки VM, то есть `endsAt` ≈ 4 интервала оценки. При интервале 1m пульс прекратится через ~4 мин, порог наблюдателя `heartbeat-watch` — 15 мин |
| Приёмник пульса примет webhook Alertmanager | да: `ops/heartbeat/nginx-heartbeat.conf` отвечает `return 204` на `location = /hb/<токен>` при любом методе и теле |
| Внутрикластерные зависимости scrape | одна цель `grafana.monitoring:3000`; остальные — адреса `198.18.1.x` |

Семантика ошибок совпадает с нынешней (`noDataState: OK`, `execErrState: OK`): нет данных — нет алерта, запрос упал — алерт не отправляется.

## Раскладка файлов

| Путь | Что | Статус |
|---|---|---|
| `ops/alerting/vmalert/rules.yaml` | 8 правил в формате vmalert | новый |
| `ops/alerting/vmalert/tests/uplink.yaml` | unit-тесты группы `uplink` | новый |
| `ops/alerting/vmalert/tests/nodes.yaml` | unit-тесты группы `nodes` | новый |
| `ops/alerting/vmalert/tests/heartbeat.yaml` | unit-тест `DeadMansSwitch` | новый |
| `ops/alerting/alertmanager/alertmanager.yml` | конфиг Alertmanager с плейсхолдерами | новый |
| `ops/alerting/deploy.sh` | рендер конфига, проверки, применение ConfigMap/Secret | новый |
| `ops/alerting/test.sh` | все офлайновые проверки в docker | новый |
| `ops/alerting/README.md` | как устроено, как раскатывать, откат | новый |
| `ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml` | Deployment + Service | новый |
| `ops/nanopi-r5c-k3s/apps/monitoring/alertmanager.yaml` | Deployment + Service | новый |
| `ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml` | jobs `vmalert`, `alertmanager` | правка |
| `ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml` | датасорс Alertmanager | правка |
| `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` | выключение unified alerting | правка (задача 7) |
| `ops/grafana/dashboards/outline-alerting.json` | панели здоровья на метрики vmalert/Alertmanager | правка |
| `ops/grafana/README.md`, `ops/heartbeat/README.md` | ссылки на новый алертинг | правка |
| `ops/grafana/alerting/` | старые файлы провижининга Grafana | удаление не раньше 2026-11-22 (задача 9) |

Документация `ops/*` ведётся только на русском (пар `*.ru.md` в `ops/` нет), новый README следует тому же.

---

### Задача 1: правила vmalert и их unit-тесты

**Files:**
- Create: `ops/alerting/test.sh`
- Create: `ops/alerting/vmalert/tests/uplink.yaml`, `ops/alerting/vmalert/tests/nodes.yaml`, `ops/alerting/vmalert/tests/heartbeat.yaml`
- Create: `ops/alerting/vmalert/rules.yaml`

**Interfaces:**
- Produces: группы `uplink`, `nodes`, `heartbeat`; имена алертов `TargetDown`, `AllUplinksDown`, `UplinkCarrierLossHigh`, `UplinkFailoverStorm`, `UplinkCertExpiringSoon`, `ClientRestarted`, `NodeRebooted`, `DeadMansSwitch`; метка `severity` у каждого. Задача 2 маршрутизирует по `alertname`, задача 4 монтирует `rules.yaml` как ConfigMap `vmalert-rules`.

- [ ] **Шаг 1: написать `ops/alerting/test.sh` (пока только правила)**

```bash
#!/usr/bin/env bash
#
# test.sh — offline checks for the vmalert rules and the Alertmanager config.
# Needs only docker. Run from anywhere: ./ops/alerting/test.sh
set -euo pipefail
cd "$(dirname "$0")"

VMALERT_TOOL=victoriametrics/vmalert-tool@sha256:b03d29d0a11b906a85879a6a4009c9d0a9d5a8b9a744ebb7dd3a7721f1e78f36

echo "==> annotations free of < > & (Telegram parse_mode HTML, templates do not escape)"
if grep -nE '^\s+(summary|description):.*[<>&]' vmalert/rules.yaml; then
	echo "annotation contains < > or &" >&2
	exit 1
fi

echo "==> vmalert-tool unittest"
docker run --rm -v "$PWD/vmalert:/w" -w /w "$VMALERT_TOOL" \
	unittest --files=tests/uplink.yaml --files=tests/nodes.yaml --files=tests/heartbeat.yaml

echo "==> all checks passed"
```

`chmod +x ops/alerting/test.sh`.

- [ ] **Шаг 2: написать тесты группы `uplink` — `ops/alerting/vmalert/tests/uplink.yaml`**

```yaml
rule_files: [../rules.yaml]
evaluation_interval: 1m
tests:
  - name: TargetDown fires after 5m, holds 15m, ignores other jobs
    interval: 1m
    input_series:
      - series: 'up{job="rust-ws-exporter",instance="ubuntu"}'
        values: '1 0x6 1x30'
      - series: 'up{job="unbound-exporter",instance="cloud1"}'
        values: '0x40'
      - series: 'up{job="node-exporter",instance="k3s-1"}'
        values: '0x40'
    alert_rule_test:
      - eval_time: 4m
        groupname: uplink
        alertname: TargetDown
        exp_alerts: []
      - eval_time: 7m
        groupname: uplink
        alertname: TargetDown
        exp_alerts:
          - exp_labels: {job: rust-ws-exporter, instance: ubuntu, severity: critical}
            exp_annotations:
              summary: 'ubuntu (rust-ws-exporter) stopped reporting'
              description: 'No successful scrape for five minutes: the process or the path to it is gone.'
          - exp_labels: {job: unbound-exporter, instance: cloud1, severity: critical}
            exp_annotations:
              summary: 'cloud1 (unbound-exporter) stopped reporting'
              description: 'No successful scrape for five minutes: the process or the path to it is gone.'
      - eval_time: 20m
        groupname: uplink
        alertname: TargetDown
        exp_alerts:
          - exp_labels: {job: rust-ws-exporter, instance: ubuntu, severity: critical}
            exp_annotations:
              summary: 'ubuntu (rust-ws-exporter) stopped reporting'
              description: 'No successful scrape for five minutes: the process or the path to it is gone.'
          - exp_labels: {job: unbound-exporter, instance: cloud1, severity: critical}
            exp_annotations:
              summary: 'cloud1 (unbound-exporter) stopped reporting'
              description: 'No successful scrape for five minutes: the process or the path to it is gone.'
      - eval_time: 30m
        groupname: uplink
        alertname: TargetDown
        exp_alerts:
          - exp_labels: {job: unbound-exporter, instance: cloud1, severity: critical}
            exp_annotations:
              summary: 'cloud1 (unbound-exporter) stopped reporting'
              description: 'No successful scrape for five minutes: the process or the path to it is gone.'

  - name: AllUplinksDown fires only when every leg of an instance is unhealthy
    interval: 1m
    input_series:
      - series: 'outline_ws_uplink_health_effective{instance="ubuntu",uplink="a"}'
        values: '0x10'
      - series: 'outline_ws_uplink_health_effective{instance="ubuntu",uplink="b"}'
        values: '0x10'
      - series: 'outline_ws_uplink_health_effective{instance="debian",uplink="a"}'
        values: '0x10'
      - series: 'outline_ws_uplink_health_effective{instance="debian",uplink="b"}'
        values: '1x10'
    alert_rule_test:
      - eval_time: 2m
        groupname: uplink
        alertname: AllUplinksDown
        exp_alerts: []
      - eval_time: 4m
        groupname: uplink
        alertname: AllUplinksDown
        exp_alerts:
          - exp_labels: {instance: ubuntu, severity: critical}
            exp_annotations:
              summary: 'ubuntu has no healthy uplink at all'
              description: 'Every leg on this client is unhealthy, so there is no tunnel.'

  - name: UplinkCarrierLossHigh fires for the active uplink only
    interval: 1m
    input_series:
      - series: 'outline_ws_uplink_carrier_loss_ratio{instance="ubuntu",uplink="a",transport="ws_h2"}'
        values: '0.1x20'
      - series: 'outline_ws_global_active_uplink_info{instance="ubuntu",uplink="a"}'
        values: '1x20'
      - series: 'outline_ws_uplink_carrier_loss_ratio{instance="ubuntu",uplink="b",transport="ws_h2"}'
        values: '0.5x20'
      - series: 'outline_ws_global_active_uplink_info{instance="ubuntu",uplink="b"}'
        values: '0x20'
    alert_rule_test:
      - eval_time: 5m
        groupname: uplink
        alertname: UplinkCarrierLossHigh
        exp_alerts: []
      - eval_time: 11m
        groupname: uplink
        alertname: UplinkCarrierLossHigh
        exp_alerts:
          - exp_labels: {instance: ubuntu, uplink: a, transport: ws_h2, severity: warning}
            exp_annotations:
              summary: 'active uplink a/ws_h2 on ubuntu is losing packets'
              description: 'Carrier loss above 5% for ten minutes on the uplink carrying traffic.'

  - name: UplinkFailoverStorm ignores scheduled shuffle rotations
    interval: 1m
    input_series:
      - series: 'outline_ws_uplink_failovers_total{job="rust-ws-exporter",instance="ubuntu",transport="ws_h2"}'
        values: '0+2x30'
      - series: 'outline_ws_uplink_failovers_total{job="rust-ws-exporter",instance="debian",transport="ws_h2_shuffle_timer"}'
        values: '0+10x30'
    alert_rule_test:
      - eval_time: 16m
        groupname: uplink
        alertname: UplinkFailoverStorm
        exp_alerts:
          - exp_labels: {instance: ubuntu, severity: warning}
            exp_annotations:
              summary: 'ubuntu is churning through uplinks'
              description: 'More than 20 non-scheduled failovers in 15 minutes; shuffle_timer rotations are excluded.'

  - name: UplinkCertExpiringSoon fires under 14 days after 1h
    interval: 5m
    input_series:
      - series: 'outline_ws_uplink_cert_expiry_timestamp_seconds{instance="ubuntu",uplink="near"}'
        values: '864000x30'
      - series: 'outline_ws_uplink_cert_expiry_timestamp_seconds{instance="ubuntu",uplink="far"}'
        values: '3000000x30'
    alert_rule_test:
      - eval_time: 30m
        groupname: uplink
        alertname: UplinkCertExpiringSoon
        exp_alerts: []
      - eval_time: 70m
        groupname: uplink
        alertname: UplinkCertExpiringSoon
        exp_alerts:
          - exp_labels: {instance: ubuntu, uplink: near, severity: info}
            exp_annotations:
              summary: 'certificate for near expires in under 14 days'
              description: 'Seen from ubuntu.'

  - name: ClientRestarted fires while the process is younger than 3 minutes
    interval: 1m
    input_series:
      - series: 'outline_ws_start_time_seconds{instance="ubuntu"}'
        values: '60x20'
    alert_rule_test:
      - eval_time: 2m
        groupname: uplink
        alertname: ClientRestarted
        exp_alerts:
          - exp_labels: {instance: ubuntu, severity: info}
            exp_annotations:
              summary: 'outline-ws-rust restarted on ubuntu'
              description: 'The client process is younger than 3 minutes.'
      - eval_time: 10m
        groupname: uplink
        alertname: ClientRestarted
        exp_alerts: []
```

- [ ] **Шаг 3: написать тесты групп `nodes` и `heartbeat`**

`ops/alerting/vmalert/tests/nodes.yaml`:

```yaml
rule_files: [../rules.yaml]
evaluation_interval: 1m
tests:
  - name: NodeRebooted covers k3s nodes only, for 10 minutes after boot
    interval: 1m
    input_series:
      - series: 'node_boot_time_seconds{instance="k3s-2"}'
        values: '60x30'
      - series: 'node_boot_time_seconds{instance="ubuntu"}'
        values: '60x30'
    alert_rule_test:
      - eval_time: 5m
        groupname: nodes
        alertname: NodeRebooted
        exp_alerts:
          - exp_labels: {instance: k3s-2, severity: warning}
            exp_annotations:
              summary: 'k3s node k3s-2 rebooted'
              description: 'The node kernel is younger than 10 minutes.'
      - eval_time: 15m
        groupname: nodes
        alertname: NodeRebooted
        exp_alerts: []
```

`ops/alerting/vmalert/tests/heartbeat.yaml`:

```yaml
rule_files: [../rules.yaml]
evaluation_interval: 1m
tests:
  - name: DeadMansSwitch fires while any target reports, silent without data
    interval: 1m
    input_series:
      - series: 'up{job="node-exporter",instance="k3s-1"}'
        values: '1x5'
    alert_rule_test:
      - eval_time: 2m
        groupname: heartbeat
        alertname: DeadMansSwitch
        exp_alerts:
          - exp_labels: {severity: none}
            exp_annotations:
              summary: 'pulse from vmalert in k3s, always firing on purpose'
      - eval_time: 30m
        groupname: heartbeat
        alertname: DeadMansSwitch
        exp_alerts: []
```

На 30-й минуте серия `up` закончилась на 5-й, и окна lookback не хватает: это модель «VictoriaMetrics не отдаёт данных», при которой пульс должен замолчать.

- [ ] **Шаг 4: запустить тесты и убедиться, что они падают**

Run: `./ops/alerting/test.sh`
Expected: FAIL — vmalert-tool не находит `../rules.yaml` (файла ещё нет).

- [ ] **Шаг 5: написать `ops/alerting/vmalert/rules.yaml`**

```yaml
# vmalert rules, migrated from ops/grafana/alerting/rules.yaml (Grafana unified
# alerting) on 2026-11-08. Thresholds, `for` and `keep_firing_for` are unchanged;
# the reasoning for each number is in
# docs/superpowers/specs/2026-08-07-uplink-email-alerting-design.md and in the
# comments below, which carry what used to be long `description` annotations.
#
# Grafana wrapped every query as `expr > bool X` plus a threshold above 0. In
# vmalert an alerting rule fires for every series the expression returns, so the
# `bool` is dropped and the comparison filters.
#
# No data means no alert, and a failed query means nothing is sent — the same
# behaviour Grafana had with noDataState/execErrState OK. A dead VictoriaMetrics
# is caught by DeadMansSwitch going silent, not by every rule firing at once.
#
# Annotations must not contain < > & : the Telegram receiver uses parse_mode
# HTML and Alertmanager templates do not escape. test.sh enforces this.
groups:
  - name: uplink
    interval: 1m
    rules:
      # Five minutes is above every ordinary scrape gap seen in a week (1-7
      # minutes) and below the real outages. unbound-exporter is listed because
      # its container on cloud1 once stayed down for three days unnoticed.
      # keep_firing_for: a target on a lossy path flaps; 35 notifications in
      # one night of 2026-08-09 from nuxt2 became one alert per outage.
      - alert: TargetDown
        expr: 'up{job=~"rust-ws-exporter|rust-ss-exporter|unbound-exporter"} < 1'
        for: 5m
        keep_firing_for: 15m
        labels:
          severity: critical
        annotations:
          summary: '{{ $labels.instance }} ({{ $labels.job }}) stopped reporting'
          description: 'No successful scrape for five minutes: the process or the path to it is gone.'

      # Baseline is 12 healthy legs on cloud1/cloud2 and 4 on debian/ubuntu, so
      # zero is unambiguous.
      - alert: AllUplinksDown
        expr: 'sum by (instance) (outline_ws_uplink_health_effective) < 1'
        for: 3m
        labels:
          severity: critical
        annotations:
          summary: '{{ $labels.instance }} has no healthy uplink at all'
          description: 'Every leg on this client is unhealthy, so there is no tunnel.'

      # Restricted to the uplink carrying traffic: a lossy standby leg (senko at
      # 44% on 2026-08-11) affects nobody and stays visible on the dashboard.
      # This also drops disabled uplinks, whose loss ratio freezes at its last
      # value. 5% matches the loss-failover threshold calibrated on .102/.104;
      # the 10m sustain separates this from single-sample spikes of 42%.
      # keep_firing_for 30m: nuxt2 crossed the threshold 59 times in one night.
      - alert: UplinkCarrierLossHigh
        expr: 'outline_ws_uplink_carrier_loss_ratio > 0.05 and on (instance, uplink) outline_ws_global_active_uplink_info == 1'
        for: 10m
        keep_firing_for: 30m
        labels:
          severity: warning
        annotations:
          summary: 'active uplink {{ $labels.uplink }}/{{ $labels.transport }} on {{ $labels.instance }} is losing packets'
          description: 'Carrier loss above 5% for ten minutes on the uplink carrying traffic.'

      # Background shuffle_timer rotations are excluded so that only data-plane
      # failovers and wire exhaustions count. Same flapping shape as the loss
      # rule, hence the same 30m hold.
      - alert: UplinkFailoverStorm
        expr: 'sum by (instance) (increase(outline_ws_uplink_failovers_total{job="rust-ws-exporter",transport!~".*_shuffle_timer"}[15m])) > 20'
        keep_firing_for: 30m
        labels:
          severity: warning
        annotations:
          summary: '{{ $labels.instance }} is churning through uplinks'
          description: 'More than 20 non-scheduled failovers in 15 minutes; shuffle_timer rotations are excluded.'

      # The nearest expiry on 2026-08-07 was 49 days out.
      - alert: UplinkCertExpiringSoon
        expr: '(outline_ws_uplink_cert_expiry_timestamp_seconds - time()) / 86400 < 14'
        for: 1h
        labels:
          severity: info
        annotations:
          summary: 'certificate for {{ $labels.uplink }} expires in under 14 days'
          description: 'Seen from {{ $labels.instance }}.'

      # A restart is an event, not a condition. The window is sized by delivery:
      # 1m evaluation plus 30s group_wait means the alert must outlive ~1.5m or
      # the notification never leaves; 3m is that floor plus slack. min by
      # (instance) so that the freshest start-time series decides. ~13 per week
      # on ubuntu, so the route (owner-events) drops resolved notices.
      - alert: ClientRestarted
        expr: 'min by (instance) (time() - outline_ws_start_time_seconds) < 180'
        labels:
          severity: info
        annotations:
          summary: 'outline-ws-rust restarted on {{ $labels.instance }}'
          description: 'The client process is younger than 3 minutes.'

  - name: nodes
    interval: 1m
    rules:
      # node-exporter starts scraping 30-90s into the boot, so the first sample
      # already shows a minute or two of uptime; 10m leaves slack over the 1m
      # evaluation plus 30s group_wait. All three nodes in one window group into
      # one mail (route groups by alertname), which points at shared power.
      - alert: NodeRebooted
        expr: 'min by (instance) (time() - node_boot_time_seconds{instance=~"k3s-[0-9]+"}) < 600'
        labels:
          severity: warning
        annotations:
          summary: 'k3s node {{ $labels.instance }} rebooted'
          description: 'The node kernel is younger than 10 minutes.'

  - name: heartbeat
    interval: 1m
    rules:
      # Always firing, by design: its notifications are the pulse cloud1 and
      # cloud2 listen for; silence is the signal. The condition goes through
      # the datasource: if VictoriaMetrics dies, the query fails, vmalert stops
      # sending, Alertmanager resolves the alert at its endsAt (about four
      # evaluation intervals, measured 2026-11-08), the pulse stops and both
      # observers mail. vector(1) would keep pulsing over a dead database.
      - alert: DeadMansSwitch
        expr: 'count(up) >= 1'
        labels:
          severity: none
        annotations:
          summary: 'pulse from vmalert in k3s, always firing on purpose'
```

- [ ] **Шаг 6: запустить тесты и убедиться, что проходят**

Run: `./ops/alerting/test.sh`
Expected: `PASS` по каждому файлу и `==> all checks passed`. Если `UplinkFailoverStorm` не срабатывает на 16-й минуте, сверить фактическое значение `increase` в выводе vmalert-tool (VictoriaMetrics считает `increase` без экстраполяции) и поправить входную серию, а не порог.

- [ ] **Шаг 7: коммит (только по команде владельца)**

```bash
git add ops/alerting/test.sh ops/alerting/vmalert
git commit -m "ops(alerting): port Grafana alert rules to vmalert with unit tests" -- ops/alerting/test.sh ops/alerting/vmalert
```

---

### Задача 2: конфиг Alertmanager и тесты маршрутов

**Files:**
- Create: `ops/alerting/alertmanager/alertmanager.yml`
- Create: `ops/alerting/deploy.sh` (в этой задаче — только режим `--render`)
- Modify: `ops/alerting/test.sh`

**Interfaces:**
- Consumes: имена алертов из задачи 1.
- Produces: получатели `owner`, `owner-events`, `heartbeat-observers`, `blackhole`; файл секрета SMTP по пути `/etc/alertmanager/secrets/smtp`; `deploy.sh --render <dir>` пишет `<dir>/alertmanager.yml` с подставленными секретами. Задача 4 монтирует результат как Secret `alertmanager-config`, Secret `alertmanager-smtp` — в `/etc/alertmanager/secrets`.

- [ ] **Шаг 1: дописать в `ops/alerting/test.sh` проверки Alertmanager (перед строкой `echo "==> all checks passed"`)**

```bash
ALERTMANAGER=prom/alertmanager@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/secrets" "$tmp/conf"
echo dummy-heartbeat > "$tmp/secrets/heartbeat-token"
echo 123:dummy-bot   > "$tmp/secrets/telegram-bot-token"
echo 42              > "$tmp/secrets/telegram-chat-id"
echo dummy-smtp      > "$tmp/conf/smtp"

echo "==> render alertmanager.yml with dummy secrets"
OUTLINE_SECRETS_DIR="$tmp/secrets" ./deploy.sh --render "$tmp/conf"

amtool() {
	docker run --rm -v "$tmp/conf:/etc/alertmanager/conf:ro" \
		-v "$tmp/conf:/etc/alertmanager/secrets:ro" \
		--entrypoint amtool "$ALERTMANAGER" "$@"
}

echo "==> amtool check-config"
amtool check-config /etc/alertmanager/conf/alertmanager.yml

route() { # route <expected receiver> <label=value>...
	local want="$1"; shift
	amtool config routes test --config.file=/etc/alertmanager/conf/alertmanager.yml \
		--verify.receivers="$want" "$@" >/dev/null \
		|| { echo "route for $* is not $want" >&2; exit 1; }
	echo "    $* -> $want"
}

echo "==> routing"
route heartbeat-observers alertname=DeadMansSwitch
route heartbeat-observers alertname=DeadMansSwitch shadow=true
route blackhole           alertname=TargetDown shadow=true instance=ubuntu
route owner               alertname=TargetDown instance=ubuntu
route owner               alertname=UplinkCarrierLossHigh instance=ubuntu
route owner-events        alertname=ClientRestarted instance=ubuntu
route owner-events        alertname=NodeRebooted instance=k3s-2
route owner               alertname=AlertingSelfTest instance=selftest
```

Секрет SMTP монтируется из того же каталога `conf/`, поэтому путь `/etc/alertmanager/secrets/smtp` существует при проверке.

- [ ] **Шаг 2: запустить и убедиться, что падает**

Run: `./ops/alerting/test.sh`
Expected: правила проходят, затем FAIL на `./deploy.sh: No such file or directory`.

- [ ] **Шаг 3: написать `ops/alerting/alertmanager/alertmanager.yml`**

```yaml
# Alertmanager config, migrated from ops/grafana/alerting/{policies,contact-points}.yaml
# on 2026-11-08. Placeholders __HEARTBEAT_TOKEN__, __TELEGRAM_BOT_TOKEN__ and
# __TELEGRAM_CHAT_ID__ are substituted by deploy.sh from host-local files; the
# rendered file is applied as the Secret alertmanager-config, never committed.
# The SMTP password is a mounted file (Secret alertmanager-smtp).
global:
  smtp_smarthost: smtp.gmail.com:587
  smtp_from: 'Alertmanager - beerloga.su <balookrd@gmail.com>'
  smtp_auth_username: balookrd@gmail.com
  smtp_auth_password_file: /etc/alertmanager/secrets/smtp
  smtp_require_tls: true

route:
  receiver: owner
  group_by: [alertname, instance]
  group_wait: 30s
  group_interval: 5m
  # Twelve hours: an ongoing problem is one mail a day, not a stream.
  repeat_interval: 12h
  routes:
    # The pulse leaves the tree first, so it keeps flowing in shadow mode too.
    - receiver: heartbeat-observers
      matchers: ['alertname="DeadMansSwitch"']
      group_wait: 0s
      group_interval: 1m
      repeat_interval: 5m

    # Shadow mode: vmalert runs with -external.label=shadow=true while Grafana
    # still owns notifications. Everything except the pulse is dropped here.
    # Harmless once the label is gone; remove after the cut-over settles.
    - receiver: blackhole
      matchers: ['shadow="true"']

    # Client restarts: ~13 per week per client. Event route, no resolved notice.
    # Grouped by instance: with a 3m alert window shorter than group_interval,
    # a shared group swallowed all but the first node of a rolling deploy.
    - receiver: owner-events
      matchers: ['alertname="ClientRestarted"']
      group_by: [alertname, instance]
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 24h

    # Node reboots: grouped by alertname so all three nodes at once arrive as
    # one mail, the signal of shared power. The 10m window outlasts group_interval.
    - receiver: owner-events
      matchers: ['alertname="NodeRebooted"']
      group_by: [alertname]
      group_wait: 30s
      group_interval: 5m
      repeat_interval: 24h

receivers:
  - name: blackhole

  # Telegram reaches a phone; mail is the fallback for the day Telegram is
  # blocked or the bot token is revoked.
  - name: owner
    email_configs:
      - to: balookrd@yandex.ru
        send_resolved: true
    telegram_configs:
      - bot_token: '__TELEGRAM_BOT_TOKEN__'
        chat_id: __TELEGRAM_CHAT_ID__
        parse_mode: HTML
        send_resolved: true

  # Same channels minus the resolved notice: "recovered" for an event already
  # over reads as a second incident.
  - name: owner-events
    email_configs:
      - to: balookrd@yandex.ru
        send_resolved: false
    telegram_configs:
      - bot_token: '__TELEGRAM_BOT_TOKEN__'
        chat_id: __TELEGRAM_CHAT_ID__
        parse_mode: HTML
        send_resolved: false

  # Two independent observers: one mailing means its own path is broken, both
  # mailing means the alerting stack is down.
  - name: heartbeat-observers
    webhook_configs:
      - url: 'https://cloud1.beerloga.su/hb/__HEARTBEAT_TOKEN__'
        send_resolved: false
      - url: 'https://cloud2.beerloga.su/hb/__HEARTBEAT_TOKEN__'
        send_resolved: false
```

- [ ] **Шаг 4: написать `ops/alerting/deploy.sh` с режимом `--render`**

```bash
#!/usr/bin/env bash
#
# deploy.sh — render and push the vmalert rules and the Alertmanager config.
#   ./deploy.sh --render <dir>   # write <dir>/alertmanager.yml, touch nothing else
#   ./deploy.sh                  # apply ConfigMap vmalert-rules and Secrets
#                                # alertmanager-config, alertmanager-smtp
# Secrets come from $OUTLINE_SECRETS_DIR (default ~/.config/outline):
# heartbeat-token, telegram-bot-token, telegram-chat-id. The SMTP password is
# copied from the existing Secret grafana-smtp (key smtp).
set -euo pipefail
cd "$(dirname "$0")"

conf=${OUTLINE_SECRETS_DIR:-$HOME/.config/outline}

require() { [ -s "$1" ] || { echo "missing $1 — $2" >&2; exit 1; }; }
require "$conf/heartbeat-token"    "shared heartbeat token (mode 0600)"
require "$conf/telegram-bot-token" "Telegram bot token from @BotFather (mode 0600)"
require "$conf/telegram-chat-id"   "Telegram chat id"

render() { # render <out dir>
	local token tg_token tg_chat
	token="$(tr -d '\n' < "$conf/heartbeat-token")"
	tg_token="$(tr -d '\n' < "$conf/telegram-bot-token")"
	tg_chat="$(tr -d '\n' < "$conf/telegram-chat-id")"
	case "$tg_chat" in ''|*[!0-9-]*) echo "telegram-chat-id must be an integer" >&2; exit 1 ;; esac
	sed -e "s|__HEARTBEAT_TOKEN__|$token|g" \
		-e "s|__TELEGRAM_BOT_TOKEN__|$tg_token|g" \
		-e "s|__TELEGRAM_CHAT_ID__|$tg_chat|g" \
		alertmanager/alertmanager.yml > "$1/alertmanager.yml"
	if grep -q '__[A-Z_]*__' "$1/alertmanager.yml"; then
		echo "unsubstituted placeholder left in alertmanager.yml" >&2
		exit 1
	fi
}

if [ "${1:-}" = "--render" ]; then
	[ -d "${2:-}" ] || { echo "usage: $0 --render <existing dir>" >&2; exit 1; }
	render "$2"
	exit 0
fi

echo "apply mode is added in task 3" >&2
exit 1
```

`chmod +x ops/alerting/deploy.sh`.

- [ ] **Шаг 5: запустить тесты**

Run: `./ops/alerting/test.sh`
Expected: `Checking '/etc/alertmanager/conf/alertmanager.yml'  SUCCESS`, восемь строк `... -> <receiver>`, `==> all checks passed`.

- [ ] **Шаг 6: коммит (только по команде владельца)**

```bash
git add ops/alerting/alertmanager ops/alerting/deploy.sh ops/alerting/test.sh
git commit -m "ops(alerting): Alertmanager config with routing tests" -- ops/alerting/alertmanager ops/alerting/deploy.sh ops/alerting/test.sh
```

---

### Задача 3: режим применения в `deploy.sh`

**Files:**
- Modify: `ops/alerting/deploy.sh` (заменить заглушку `apply mode is added in task 3`)

**Interfaces:**
- Produces: ConfigMap `monitoring/vmalert-rules` (ключ `rules.yaml`), Secret `monitoring/alertmanager-config` (ключ `alertmanager.yml`), Secret `monitoring/alertmanager-smtp` (ключ `smtp`). Задача 4 на них ссылается.

- [ ] **Шаг 1: заменить последние две строки `deploy.sh` на режим применения**

```bash
command -v kubectl >/dev/null || { echo "kubectl not in PATH" >&2; exit 1; }
: "${KUBECONFIG:?set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)}"

echo "==> offline checks"
./test.sh

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
render "$tmp"

kubectl -n monitoring get secret grafana-smtp -o jsonpath='{.data.smtp}' \
	| base64 -d > "$tmp/smtp"
[ -s "$tmp/smtp" ] || { echo "Secret grafana-smtp has no key smtp" >&2; exit 1; }

kubectl create configmap vmalert-rules -n monitoring \
	--from-file=rules.yaml=vmalert/rules.yaml \
	--dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic alertmanager-config -n monitoring \
	--from-file=alertmanager.yml="$tmp/alertmanager.yml" \
	--dry-run=client -o yaml | kubectl apply -f -
kubectl create secret generic alertmanager-smtp -n monitoring \
	--from-file=smtp="$tmp/smtp" \
	--dry-run=client -o yaml | kubectl apply -f -

cat <<'EOF'

==> applied.
    vmalert re-reads its rules by itself (-configCheckInterval=1m) once the
    kubelet syncs the ConfigMap into the pod, ~1-2 minutes.
    Alertmanager reads its config only on start or on /-/reload. After ~90 s
    (Secret sync) reload it — no restart, notification state is kept:

    kubectl -n monitoring exec deploy/alertmanager -- \
      wget -qO- --post-data='' http://127.0.0.1:9093/-/reload

    and confirm:

    kubectl -n monitoring logs deploy/alertmanager --since=2m | grep -i "completed loading"
EOF
```

- [ ] **Шаг 2: проверить синтаксис и офлайновый путь**

Run: `bash -n ops/alerting/deploy.sh && ./ops/alerting/test.sh`
Expected: без вывода от `bash -n`, затем `==> all checks passed`. Реальный запуск `./ops/alerting/deploy.sh` — в задаче 5, с согласия владельца.

- [ ] **Шаг 3: коммит (только по команде владельца)**

```bash
git commit -m "ops(alerting): deploy.sh applies rules and Alertmanager config to k3s" -- ops/alerting/deploy.sh
```

---

### Задача 4: манифесты k3s, scrape и датасорс Grafana

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml`
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/alertmanager.yaml`
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml` (два новых job в конце)
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml` (второй датасорс)

**Interfaces:**
- Consumes: ConfigMap `vmalert-rules`, Secrets `alertmanager-config`, `alertmanager-smtp` (задача 3).
- Produces: Service `vmalert.monitoring:8880`, Service `alertmanager.monitoring:9093`, датасорс Grafana uid `alertmanager-k3s`.

- [ ] **Шаг 1: убедиться, что у образов есть arm64**

Run:
```bash
docker buildx imagetools inspect victoriametrics/vmalert@sha256:3256cba5ddaca5974eae6141105cec4ce37871f1c213f0a5c267ec0111bc68e1 | grep -c 'linux/arm64'
docker buildx imagetools inspect prom/alertmanager@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b | grep -c 'linux/arm64'
```
Expected: `1` (или больше) для каждого. Если `0` — остановиться и сообщить владельцу: узлы k3s на arm64.

- [ ] **Шаг 2: написать `ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml`**

```yaml
# vmalert: evaluates the alert rules (ops/alerting/vmalert/rules.yaml, applied
# as the ConfigMap vmalert-rules by ops/alerting/deploy.sh) against
# VictoriaMetrics and sends firing alerts to Alertmanager.
#
# No nodeSelector and no volume: it can run on any node, so a dead k3s-1 does
# not take alerting down with VictoriaMetrics. State of `for` timers is restored
# from VictoriaMetrics on start (-remoteRead.url), where vmalert also writes the
# ALERTS series (-remoteWrite.url) that the alerting dashboard reads.
#
# -external.label=shadow=true is the shadow mode of the migration: Alertmanager
# drops everything with that label except the pulse. Removing the flag is the
# cut-over (plan 2026-11-08-alerting-vmalert-alertmanager, task 7).
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vmalert
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels: { app: vmalert }
  template:
    metadata:
      labels: { app: vmalert }
    spec:
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
      containers:
        - name: vmalert
          image: victoriametrics/vmalert@sha256:3256cba5ddaca5974eae6141105cec4ce37871f1c213f0a5c267ec0111bc68e1 # v1.155.0
          args:
            - -rule=/etc/vmalert/rules/*.yaml
            - -configCheckInterval=1m
            - -evaluationInterval=1m
            - -datasource.url=http://victoria-metrics.monitoring:8428
            - -remoteRead.url=http://victoria-metrics.monitoring:8428
            - -remoteWrite.url=http://victoria-metrics.monitoring:8428
            - -notifier.url=http://alertmanager.monitoring:9093
            - -external.label=shadow=true
          ports:
            - { containerPort: 8880, name: http }
          volumeMounts:
            - { name: rules, mountPath: /etc/vmalert/rules, readOnly: true }
          readinessProbe:
            httpGet: { path: /health, port: 8880 }
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests: { cpu: 20m, memory: 32Mi }
            limits:   { memory: 128Mi }
      volumes:
        - name: rules
          configMap: { name: vmalert-rules }
---
apiVersion: v1
kind: Service
metadata:
  name: vmalert
  namespace: monitoring
spec:
  selector: { app: vmalert }
  ports:
    - { port: 8880, targetPort: 8880 }
```

- [ ] **Шаг 3: написать `ops/nanopi-r5c-k3s/apps/monitoring/alertmanager.yaml`**

```yaml
# Alertmanager: groups, deduplicates and delivers alerts from vmalert — mail and
# Telegram to the owner, the dead man's pulse to cloud1/cloud2. Config is the
# Secret alertmanager-config rendered by ops/alerting/deploy.sh.
#
# Storage is emptyDir on purpose. It holds silences and the notification log;
# losing them on a pod restart means at worst one repeated notification and
# forgotten silences. A PVC would pin the pod to a node (local-path) or tie it
# to the NAS (NFS) — exactly the failure domains this pod exists to sit outside.
#
# Single replica, gossip off (--cluster.listen-address=): there is no peer.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: alertmanager
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels: { app: alertmanager }
  template:
    metadata:
      labels: { app: alertmanager }
    spec:
      securityContext:
        runAsUser: 65534
        runAsNonRoot: true
        fsGroup: 65534
      containers:
        - name: alertmanager
          image: prom/alertmanager@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b # v0.34.2
          args:
            - --config.file=/etc/alertmanager/conf/alertmanager.yml
            - --storage.path=/alertmanager
            - --cluster.listen-address=
            - --web.listen-address=:9093
          ports:
            - { containerPort: 9093, name: http }
          volumeMounts:
            - { name: config, mountPath: /etc/alertmanager/conf, readOnly: true }
            - { name: smtp, mountPath: /etc/alertmanager/secrets, readOnly: true }
            - { name: data, mountPath: /alertmanager }
          readinessProbe:
            httpGet: { path: /-/ready, port: 9093 }
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests: { cpu: 20m, memory: 32Mi }
            limits:   { memory: 128Mi }
      volumes:
        - name: config
          secret: { secretName: alertmanager-config }
        - name: smtp
          secret: { secretName: alertmanager-smtp }
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: alertmanager
  namespace: monitoring
spec:
  selector: { app: alertmanager }
  ports:
    - { port: 9093, targetPort: 9093 }
```

- [ ] **Шаг 4: дописать в конец `ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml`**

```yaml
- job_name: vmalert
  static_configs:
  - targets:
    # ClusterIP, not ingress: same hairpin reason as the grafana job above.
    - vmalert.monitoring:8880
- job_name: alertmanager
  static_configs:
  - targets:
    - alertmanager.monitoring:9093
```

Отступы — как у соседних job (два пробела перед `static_configs` нет, список на корневом уровне `scrape_configs`). Сверить с началом файла перед сохранением.

- [ ] **Шаг 5: добавить датасорс в `grafana-provisioning.yaml`, в список `datasources:` после `prometheus`**

```yaml
      - name: alertmanager
        uid: alertmanager-k3s
        type: alertmanager
        access: proxy
        url: http://alertmanager.monitoring:9093
        jsonData:
          implementation: prometheus
          handleGrafanaManagedAlerts: false
```

- [ ] **Шаг 6: офлайновая проверка манифестов**

Run:
```bash
cd ops/nanopi-r5c-k3s/apps/monitoring
KUBECONFIG=~/.kube/k3s-home.yaml kubectl apply --dry-run=server -f vmalert.yaml -f alertmanager.yaml -f grafana-provisioning.yaml
ruby -ryaml -e 'YAML.safe_load(File.read("scrape.yaml")); puts "scrape ok"'
```
Expected: `deployment.apps/vmalert created (server dry run)` и аналогичные строки без ошибок, `scrape ok`. Если k3s недоступен из песочницы (`--request-timeout=10s`), повторить позже; `--dry-run=server` ничего не меняет в кластере.

- [ ] **Шаг 7: коммит (только по команде владельца)**

```bash
git add ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml ops/nanopi-r5c-k3s/apps/monitoring/alertmanager.yaml
git commit -m "ops(k3s): vmalert and Alertmanager in monitoring, shadow mode" -- \
  ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml ops/nanopi-r5c-k3s/apps/monitoring/alertmanager.yaml \
  ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml
```

---

### Задача 5: выкатка в теневом режиме (прод, с согласия владельца)

**Files:** без изменений в репозитории.

Каждый подшаг с `kubectl apply`, рестартом или правкой PVC — после явного «да» владельца.

- [ ] **Шаг 1: применить конфиги и манифесты**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
./ops/alerting/deploy.sh
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/alertmanager.yaml
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml
kubectl -n monitoring rollout status deploy/alertmanager deploy/vmalert --timeout=120s
```
Expected: оба Deployment `successfully rolled out`.

- [ ] **Шаг 2: проверить, что правила загружены и считаются**

```bash
kubectl -n monitoring logs deploy/vmalert --since=5m | grep -iE "error|warn" || echo "no errors"
kubectl -n monitoring exec deploy/alertmanager -- amtool alert query --alertmanager.url=http://127.0.0.1:9093
```
Expected: `no errors`; в списке алертов есть `DeadMansSwitch` (и любые реально горящие алерты — с меткой `shadow="true"`).

- [ ] **Шаг 3: проверить пульс от Alertmanager на cloud1 и cloud2**

```bash
ssh cloud1 'sudo tail -n 20 /var/log/nginx/heartbeat.log | grep -c Alertmanager'
ssh cloud2 'sudo tail -n 20 /var/log/nginx/heartbeat.log | grep -c Alertmanager'
```
Expected: ненулевое число через 5–10 минут после выкатки (User-Agent `Alertmanager/0.34.2`). Пульс Grafana продолжает идти параллельно, это безвредно: наблюдатель смотрит только на свежесть последней записи. Имена ssh-хостов сверить с `FLEET.local.md`.

- [ ] **Шаг 4: самопроверка каналов почты и Telegram**

```bash
kubectl -n monitoring exec deploy/alertmanager -- amtool alert add alertname=AlertingSelfTest \
  instance=selftest severity=info \
  --annotation=summary='Alertmanager self-test, ignore' \
  --alertmanager.url=http://127.0.0.1:9093
```
Expected: через ~30 с письмо на `balookrd@yandex.ru` и сообщение в Telegram. Владелец подтверждает получение. Записать узел, на котором стоит под (`kubectl -n monitoring get pod -l app=alertmanager -o wide`): под без `nodeSelector`, и проверка подтверждает исходящий доступ к SMTP и Telegram только с этого узла. Если исходящая маршрутизация на узлах k3s различается, повторить самопроверку после переезда пода на другой узел. Затем снять алерт:
```bash
kubectl -n monitoring exec deploy/alertmanager -- amtool alert add alertname=AlertingSelfTest \
  instance=selftest severity=info --end="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --alertmanager.url=http://127.0.0.1:9093
```
и дождаться resolved-уведомления. Если почта не пришла — `kubectl -n monitoring logs deploy/alertmanager | grep -i smtp`.

- [ ] **Шаг 5: положить новый `scrape.yaml` в PVC VictoriaMetrics и перечитать**

```bash
pod=$(kubectl -n monitoring get pod -l app=victoria-metrics -o jsonpath='{.items[0].metadata.name}')
kubectl -n monitoring exec "$pod" -- cp /victoria-metrics-data/scrape.yaml /victoria-metrics-data/scrape.yaml.bak-20261108
kubectl -n monitoring cp ops/nanopi-r5c-k3s/apps/monitoring/scrape.yaml "$pod":/victoria-metrics-data/scrape.yaml
kubectl -n monitoring exec "$pod" -- wget -qO- --post-data='' http://127.0.0.1:8428/-/reload
```
Expected: через 1–2 минуты `up{job=~"vmalert|alertmanager"}` равен 1 (проверить в Grafana Explore или `curl https://vm.k3s.beerloga.su/api/v1/query?query=up{job=~"vmalert|alertmanager"}`). Перед `cp` сравнить живой файл с репозиторием (`kubectl exec ... cat` и `diff`): если в живой копии есть то, чего нет в git, сначала перенести это в репозиторий. Откат: вернуть `scrape.yaml.bak-20261108` и тот же `/-/reload`.

- [ ] **Шаг 6: применить датасорс Grafana**

```bash
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml
kubectl -n monitoring rollout restart deploy/grafana
```
Expected: в Grafana **Connections → Data sources** есть `alertmanager`, **Test** проходит. Рестарт Grafana — действие на проде, только с согласия.

---

### Задача 6: теневой прогон и сверка (не меньше 24 часов)

**Files:** без изменений.

- [ ] **Шаг 1: через 24 часа сравнить срабатывания**

Срабатывания vmalert (в VictoriaMetrics):
```bash
curl -s 'https://vm.k3s.beerloga.su/api/v1/query' \
  --data-urlencode 'query=count by (alertname) (count_over_time(ALERTS{alertstate="firing",alertname!="DeadMansSwitch"}[24h]))'
```
Срабатывания Grafana за то же окно: **Alerting → History** в UI или метрика `increase(grafana_alerting_state_history_transitions_total[24h])`.

Expected: одинаковый набор `alertname`/`instance`. Расхождения разобрать до переключения: разница в `increase` (VictoriaMetrics без экстраполяции) или задержка оценки (`-rule.evalDelay`, по умолчанию vmalert сдвигает время запроса назад [проверить значение в `vmalert -help`]) — допустимы, если затрагивают только границу порога. Если за сутки не сработало ни одного алерта, продлить прогон или добавить временное правило-проверку.

- [ ] **Шаг 2: проверить устойчивость пульса**

```bash
ssh cloud1 'sudo grep -c Alertmanager /var/log/nginx/heartbeat.log'
```
Expected: примерно 12 записей в час (repeat 5m) без провалов больше 15 минут.

- [ ] **Шаг 3: доложить владельцу результаты сверки и получить «да» на переключение.**

---

### Задача 7: переключение — снять теневую метку, выключить алертинг Grafana

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml` (удалить строку `- -external.label=shadow=true` и абзац про shadow в шапке)
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` (env `GF_UNIFIED_ALERTING_ENABLED=false`, убрать том `alerting` и его `volumeMounts`)

- [ ] **Шаг 1: правка `vmalert.yaml`** — удалить аргумент `-external.label=shadow=true` и последний абзац комментария в шапке.

- [ ] **Шаг 2: правка `grafana.yaml`**

В `env` добавить:
```yaml
            # Alerting moved to vmalert + Alertmanager (ops/alerting/) on
            # 2026-11-08. Off rather than just unprovisioned: provisioned rules
            # stay in grafana.db and would keep evaluating and mailing.
            - { name: GF_UNIFIED_ALERTING_ENABLED, value: "false" }
```
Удалить из `volumeMounts` строку `- { name: alerting, mountPath: /etc/grafana/provisioning/alerting }` и из `volumes` блок с `secret: { secretName: grafana-alerting }`.

- [ ] **Шаг 3: проверить манифесты**

Run: `KUBECONFIG=~/.kube/k3s-home.yaml kubectl apply --dry-run=server -f ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml -f ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml`
Expected: `configured (server dry run)`, без ошибок.

- [ ] **Шаг 4: применить (прод, с согласия владельца), сначала vmalert, потом Grafana**

```bash
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml
kubectl -n monitoring rollout status deploy/vmalert --timeout=120s
kubectl apply -f ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml
kubectl -n monitoring rollout status deploy/grafana --timeout=180s
```
Такой порядок даёт минуту-две, когда уведомления шлют обе системы (возможен дубль письма), но не оставляет окна без алертинга. Снятие метки `shadow` меняет набор меток каждого алерта, поэтому vmalert не восстановит состояние `for` из старых серий `ALERTS_FOR_STATE`. Правила с `for` (TargetDown, UplinkCarrierLossHigh, UplinkCertExpiringSoon) заново пройдут pending, и по уже горящим проблемам придёт повторное firing без resolved от Grafana. Предупредить владельца заранее.

- [ ] **Шаг 5: проверка после переключения**

```bash
kubectl -n monitoring exec deploy/alertmanager -- amtool alert query --alertmanager.url=http://127.0.0.1:9093 shadow=true
kubectl -n monitoring logs deploy/grafana --since=3m | grep -i "alerting" | head
ssh cloud1 'sudo tail -n 5 /var/log/nginx/heartbeat.log'
```
Expected: алертов с `shadow=true` нет (после `endsAt` старых, ~4 мин); в логе Grafana нет `starting to provision alerting`; последние записи пульса — только `Alertmanager/0.34.2`, свежее 5 минут.

- [ ] **Шаг 6: удалить Secret `grafana-alerting`** (с согласия): `kubectl -n monitoring delete secret grafana-alerting`. Его копия восстанавливается `ops/grafana/alerting/deploy.sh --k3s`, пока каталог не удалён (задача 9).

- [ ] **Шаг 7: коммит (только по команде владельца)**

```bash
git commit -m "ops(k3s): cut alerting over to vmalert, disable Grafana alerting" -- \
  ops/nanopi-r5c-k3s/apps/monitoring/vmalert.yaml ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml
```

---

### Задача 8: дашборд и документация

**Files:**
- Modify: `ops/grafana/dashboards/outline-alerting.json` (ряд «Здоровье алертинга»)
- Create: `ops/alerting/README.md`
- Modify: `ops/grafana/README.md` (раздел «Алертинг» и абзац про `grafana_alerting_*`)
- Modify: `ops/heartbeat/README.md` (источник пульса)

- [ ] **Шаг 1: заменить запросы панелей ряда «Здоровье алертинга»**

| Панель | Было | Стало |
|---|---|---|
| Активных алертов | `grafana_alerting_alerts{state="alerting"}` | `count(ALERTS{alertstate="firing",alertname!="DeadMansSwitch"}) or vector(0)` |
| Правил в работе | `grafana_alerting_schedule_alert_rules` | `sum(vmalert_alerting_rules_last_evaluation_samples >= 0)` [проверить имя метрики на `vmalert.monitoring:8880/metrics`; запасной вариант — `count(vmalert_alerting_rules_errors_total)`] |
| Ошибок вычисления за 24ч | `increase(grafana_alerting_rule_evaluation_failures_total[24h])` | `sum(increase(vmalert_alerting_rules_errors_total[24h]))` |
| Отставание планировщика | `grafana_alerting_scheduler_behind_seconds` | `sum(increase(vmalert_iteration_missed_total[1h]))`, заголовок — «Пропущенных итераций за час» |
| Уведомления по каналам (за час) | `increase(grafana_alerting_notifications_total[1h])` | `sum by (integration) (increase(alertmanager_notifications_total[1h]))`, вторым запросом `sum by (integration) (increase(alertmanager_notifications_failed_total[1h]))` |
| Переходы состояний (за час) | `increase(grafana_alerting_state_history_transitions_total[1h])` | `sum by (alertname) (changes(ALERTS_FOR_STATE[1h]))` [проверить, что vmalert пишет `ALERTS_FOR_STATE` через remoteWrite] |
| Состояние правил (`alertlist`) | панель Grafana-алертов | заменить на `table` с запросом `ALERTS{alertstate="firing"}` в режиме instant |

Перед правкой снять фактические имена метрик: `kubectl -n monitoring exec deploy/vmalert -- wget -qO- http://127.0.0.1:8880/metrics | grep -oE '^vmalert_[a-z_]+' | sort -u`. Раскатить дашборд: `ops/grafana/dashboards/deploy.sh --k3s` (с согласия, нужен рестарт Grafana).

- [ ] **Шаг 2: написать `ops/alerting/README.md`** по `~/.claude/tech-docs-style.md`: что делает каталог, требования (docker, kubectl, `KUBECONFIG`, три файла секретов), раскатка (`./ops/alerting/test.sh`, `./ops/alerting/deploy.sh`, reload Alertmanager), таблица правил (алерт, выражение, `for`, `keep_firing_for`, маршрут), проверка пульса, известные проблемы (emptyDir теряет заглушки при рестарте пода; пульс гаснет через ~4 мин после отказа VictoriaMetrics), раздел «Откат». Имена узлов и домены — условные, как в соседних README (`relay-a`, `fleet.example`).

- [ ] **Шаг 3: обновить `ops/grafana/README.md`** — раздел «Алертинг» сократить до ссылки на `ops/alerting/README.md` с датой переезда; абзацы про `grafana_alerting_*`, **Alerting → History** и `alertlist` заменить описанием новых панелей; убрать упоминание, что «по этому же источнику считаются и алерты».

- [ ] **Шаг 4: обновить `ops/heartbeat/README.md`** — источник пульса: Alertmanager в k3s (маршрут в `ops/alerting/alertmanager/alertmanager.yml`), правило в `ops/alerting/vmalert/rules.yaml`; на схеме `Grafana (k3s)` заменить на `vmalert → Alertmanager (k3s)`. Поправить и текст писем наблюдателя в `ops/heartbeat/heartbeat-watch` (там «home Grafana»), это меняет поведение скрипта на cloud1/cloud2: после правки — `ops/heartbeat/test-heartbeat-watch.sh` и переустановка через `install.sh` с согласия владельца.

- [ ] **Шаг 5: коммит (только по команде владельца)**

```bash
git commit -m "docs(alerting): document vmalert + Alertmanager, rework alerting dashboard" -- \
  ops/alerting/README.md ops/grafana/README.md ops/heartbeat/README.md ops/grafana/dashboards/outline-alerting.json
```

---

### Задача 9: удаление провижининга алертов Grafana (не раньше 2026-11-22)

**Files:**
- Delete: `ops/grafana/alerting/` (`rules.yaml`, `contact-points.yaml`, `policies.yaml`, `deploy.sh`)

- [ ] **Шаг 1:** убедиться, что за две недели не было отката и пульс идёт только от Alertmanager.
- [ ] **Шаг 2:** `git rm -r ops/grafana/alerting` и убрать ссылки на него: `grep -rn "grafana/alerting" ops docs --include=*.md`.
- [ ] **Шаг 3:** коммит (по команде владельца): `git commit -m "ops(grafana): drop the retired alerting provisioning" -- ops/grafana/alerting ops/grafana/README.md ops/heartbeat/README.md`.

---

## Откат

| Момент | Действие |
|---|---|
| Задачи 5–6 (теневой режим) | `kubectl -n monitoring delete deploy/vmalert deploy/alertmanager svc/vmalert svc/alertmanager`; Grafana продолжает алертинг сама, её не трогали |
| После задачи 7 | вернуть `grafana.yaml` из git (`git checkout <коммит до задачи 7> -- ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml`), `ops/grafana/alerting/deploy.sh --k3s`, `kubectl apply -f .../grafana.yaml`, рестарт Grafana; затем `kubectl -n monitoring scale deploy/vmalert --replicas=0`. Проверка: `grep "provision alerting"` в логе Grafana, пульс с User-Agent `Grafana` |
| `scrape.yaml` | вернуть `scrape.yaml.bak-20261108` в PVC и `POST /-/reload` |

## Что делается потом, отдельным планом

Перенос VictoriaMetrics и Grafana на NAS. Для алертинга он меняет только адреса: `-datasource.url`, `-remoteRead.url`, `-remoteWrite.url` у vmalert указывают на `http://198.18.1.105:8428` (по IP, не через `vm.k3s.beerloga.su`: из пода на VIP MetalLB — hairpin, Traefik отвечает 5xx), а датасорс `alertmanager` в Grafana на NAS — на адрес Alertmanager, доступный из домашней сети (Service типа LoadBalancer или Ingress).
