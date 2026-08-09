# Миграция Grafana в k3s: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перенести Grafana с docker-контейнера на `198.18.1.102` в k3s-кластер,
сохранив все дашборды, алерты и пароль, и не трогая VictoriaMetrics.

**Architecture:** Едет только `grafana.db` (после чистки истории версий);
плагины и файлы дашбордов не переносятся. В кластере состояние лежит на
`local-path` (NVMe ноды), конфигурация — в ConfigMap/Secret, дашборды приезжают
из git отдельными ConfigMap'ами, которые генерирует скрипт. Датасорс продолжает
смотреть на VictoriaMetrics по адресу `198.18.1.102:8428`.

**Tech Stack:** k3s v1.36.2 (3 ноды aarch64), Grafana OSS 13.0.2 (unified
storage поверх SQLite), local-path storage, Traefik ingress с готовым wildcard-TLS.

Спека: [`docs/superpowers/specs/2026-08-09-grafana-to-k3s-design.md`](../specs/2026-08-09-grafana-to-k3s-design.md).

## Global Constraints

- Образ строго `grafana/grafana-oss:13.0.2` — версия пинуется, `latest` запрещён.
- Namespace `monitoring`. Имена: Deployment/Service/PVC — `grafana`,
  `grafana`, `grafana-data`.
- **Датасорс обязан иметь UID `adnsc1wi03doga`**, name `prometheus`, type
  `prometheus`, url `http://198.18.1.102:8428`, `isDefault: true`. Дашборды
  ссылаются по UID; другой UID = панели без данных.
- `GF_SECURITY_ADMIN_PASSWORD` **не задаётся** — пароль переезжает внутри БД.
- `GF_PLUGINS_PREINSTALL` **не задаётся** — `marcusolsson-dynamictext-panel`
  отключается как неиспользуемый.
- `securityContext`: `runAsUser: 472`, `fsGroup: 472`; файлы БД с `.102`
  принадлежат uid 1000, поэтому при заливке делается `chown 472:472`.
- Дашборды монтируются в `/etc/grafana/dashboards` (не в `/var/lib/grafana/dashboards`
  — там PVC), провижининг-провайдер указывает туда же.
- Один ConfigMap на дашборд (лимит объекта 1 МиБ, `outline-ws-rust` — 252 КБ),
  собираются в каталог через `projected` volume.
- Управление кластером — с мака: `export KUBECONFIG=~/.kube/k3s-home.yaml`.
  На нодах `helm`/`kubectl` для этого не нужны; `sudo` на нодах без пароля.
- Узел-источник: `ssh mmv@198.18.1.102`, `sudo -n` доступен, docker требует sudo.
- Секреты вне git: `~/.config/outline/{heartbeat-token,telegram-bot-token,telegram-chat-id}`
  на маке, SMTP-пароль — `/opt/grafana/secrets/smtp` на `.102`.
- `/opt/grafana` на `.102` **не удалять** — путь отката.
- Git: коммиты на английском, без Co-Authored-By и Claude-атрибуции, работаем в
  `main`. `git commit` — только по явной команде владельца; шаги «Commit»
  готовят изменения и показывают diff.
- `ops/nanopi-r5c-k3s/` и `ops/grafana/` ведутся по-русски, EN-пары нет.

---

### Task 1: Манифест Grafana и провижининг-ConfigMap'ы

**Files:**
- Modify: `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml` (переписать целиком)
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml`
- Delete: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-admin.secret.example.yaml`

**Interfaces:**
- Produces: Deployment `grafana` (ns `monitoring`), PVC `grafana-data`,
  Service `grafana:3000`, ConfigMap `grafana-datasources`, ConfigMap
  `grafana-dashboard-provider`. Задача 2 создаёт ConfigMap'ы
  `grafana-dashboard-<basename>`, перечисленные в projected volume; Задача 3 —
  Secret `grafana-alerting`; Задача 5 наполняет PVC.

- [ ] **Step 1: Переписать grafana.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/monitoring/grafana.yaml`:

```yaml
# Grafana, migrated off the docker container on 198.18.1.102.
#
# Singleton on local-path: Grafana 13 keeps everything — dashboards included —
# in one SQLite file under unified storage, and SQLite over NFS corrupts on
# network hiccups. The local-path PV carries node affinity, so the pod follows
# its data without a nodeSelector. Durability comes from the nightly backup to
# the NAS, not from the volume.
#
# The admin password is NOT set through the environment on purpose: it lives in
# the migrated database, and GF_SECURITY_ADMIN_PASSWORD would silently reset it
# on every pod start.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana
  namespace: monitoring
spec:
  replicas: 1
  strategy:
    type: Recreate            # SQLite tolerates exactly one writer
  selector:
    matchLabels: { app: grafana }
  template:
    metadata:
      labels: { app: grafana }
    spec:
      securityContext:
        runAsUser: 472        # the image's own uid; migrated files get chowned
        fsGroup: 472
      containers:
        - name: grafana
          image: grafana/grafana-oss:13.0.2
          ports:
            - { containerPort: 3000, name: http }
          env:
            - { name: TZ, value: Europe/Moscow }
            - { name: GF_DATABASE_WAL, value: "true" }
            - { name: GF_SMTP_ENABLED, value: "true" }
            - { name: GF_SMTP_HOST, value: "smtp.gmail.com:587" }
            - { name: GF_SMTP_USER, value: balookrd@gmail.com }
            - { name: GF_SMTP_PASSWORD__FILE, value: /etc/grafana/secrets/smtp }
            - { name: GF_SMTP_FROM_ADDRESS, value: balookrd@gmail.com }
            - { name: GF_SMTP_FROM_NAME, value: "outline alerting" }
          volumeMounts:
            - { name: data, mountPath: /var/lib/grafana }
            - { name: datasources, mountPath: /etc/grafana/provisioning/datasources }
            - { name: dashboard-provider, mountPath: /etc/grafana/provisioning/dashboards }
            - { name: alerting, mountPath: /etc/grafana/provisioning/alerting }
            - { name: dashboards, mountPath: /etc/grafana/dashboards }
            - { name: smtp, mountPath: /etc/grafana/secrets }
          readinessProbe:
            httpGet: { path: /api/health, port: 3000 }
            initialDelaySeconds: 10
            periodSeconds: 10
          resources:
            requests: { cpu: 100m, memory: 256Mi }
            limits:   { memory: 768Mi }
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: grafana-data
        - name: datasources
          configMap: { name: grafana-datasources }
        - name: dashboard-provider
          configMap: { name: grafana-dashboard-provider }
        - name: alerting
          secret: { secretName: grafana-alerting }
        - name: smtp
          secret: { secretName: grafana-smtp }
        # One ConfigMap per dashboard (the 1 MiB object limit rules out a single
        # one — outline-ws-rust alone is 252 KB), projected into one directory.
        # Adding a dashboard means adding a source here; deploy.sh --k3s prints
        # the list it generated.
        - name: dashboards
          projected:
            sources:
              - configMap: { name: grafana-dashboard-outline-alerting }
              - configMap: { name: grafana-dashboard-outline-ss-rust-dashboard }
              - configMap: { name: grafana-dashboard-outline-ws-rust-dashboard }
              - configMap: { name: grafana-dashboard-outline-ws-rust-hang-diagnostics }
              - configMap: { name: grafana-dashboard-unbound-dashboard }
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: grafana-data
  namespace: monitoring
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: local-path
  resources:
    requests:
      storage: 2Gi
---
apiVersion: v1
kind: Service
metadata:
  name: grafana
  namespace: monitoring
spec:
  selector: { app: grafana }
  ports:
    - { port: 3000, targetPort: 3000 }
```

- [ ] **Step 2: Создать grafana-provisioning.yaml**

Полное содержимое `ops/nanopi-r5c-k3s/apps/monitoring/grafana-provisioning.yaml`:

```yaml
# Datasource and dashboard-provider configuration for the cluster Grafana.
#
# The datasource UID is not cosmetic: dashboards reference datasources by UID,
# and the migrated ones all point at adnsc1wi03doga. Change it and every panel
# comes up empty.
#
# VictoriaMetrics stays on 198.18.1.102 — it holds 90 days of history and every
# scrape target of the fleet points at it.
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-datasources
  namespace: monitoring
data:
  datasources.yaml: |
    apiVersion: 1
    datasources:
      - name: prometheus
        uid: adnsc1wi03doga
        type: prometheus
        access: proxy
        url: http://198.18.1.102:8428
        isDefault: true
        jsonData:
          timeInterval: 15s
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboard-provider
  namespace: monitoring
data:
  outline.yaml: |
    apiVersion: 1
    providers:
      - name: outline
        orgId: 1
        type: file
        # A deleted file removes the dashboard, so the directory is the single
        # source of truth rather than an additive overlay. Hand-made dashboards
        # live in the database and belong to no provider — they are untouched.
        disableDeletion: false
        allowUiUpdates: false
        options:
          # NOT /var/lib/grafana/dashboards as on the host: that path is inside
          # the PVC, and a ConfigMap cannot be mounted there.
          path: /etc/grafana/dashboards
          foldersFromFilesStructure: false
```

- [ ] **Step 3: Удалить пример секрета с паролем админа**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git rm ops/nanopi-r5c-k3s/apps/monitoring/grafana-admin.secret.example.yaml
```

Пароль переезжает внутри БД, механизм через env сознательно не используется —
файл описывал бы несуществующую практику.

- [ ] **Step 4: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
ruby -ryaml -e 'ARGV.each { |f| YAML.load_stream(File.read(f)) }; puts "yaml ok"' grafana.yaml grafana-provisioning.yaml
```

Ожидаемо: `yaml ok`.

- [ ] **Step 5: Проверить против кластера, не применяя**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl apply --dry-run=server -f grafana-provisioning.yaml
kubectl apply --dry-run=server -f grafana.yaml
```

Ожидаемо: `configmap/... configured (server dry run)` для первого; для второго —
`deployment.apps/grafana created (server dry run)` и так далее. Ошибка вида
`unknown field` означает опечатку в манифесте, чинить сразу.

- [ ] **Step 6: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/monitoring/
git commit -m "ops(k3s): manifests for Grafana migrated off the gateway node"
```

---

### Task 2: Режим `--k3s` в скрипте дашбордов

**Files:**
- Modify: `ops/grafana/dashboards/deploy.sh`

**Interfaces:**
- Consumes: JSON-файлы `ops/grafana/dashboards/*.json`.
- Produces: ConfigMap'ы `grafana-dashboard-<basename>` в ns `monitoring`
  (`<basename>` — имя файла без `.json`), которые перечислены в projected volume
  из Задачи 1.

- [ ] **Step 1: Добавить режим в deploy.sh**

Заменить в `ops/grafana/dashboards/deploy.sh` блок от `host=${GRAFANA_HOST...}`
до конца файла на:

```bash
host=${GRAFANA_HOST:-mmv@198.18.1.102}
dest=/opt/grafana/data/dashboards

k3s=0
if [ "${1:-}" = "--k3s" ]; then
	k3s=1
	shift
fi

files=("$@")
if [ ${#files[@]} -eq 0 ]; then
	# A bare glob would pass the literal "*.json" through on an empty directory.
	shopt -s nullglob
	files=(*.json)
	if [ "$k3s" = 1 ]; then
		# Binary-specific dashboards live next to their binaries, and in the
		# cluster they must all be deployed together: the provider runs with
		# disableDeletion=false, so a dashboard missing from the mounted
		# directory gets DELETED from the database on the next start.
		files+=(../../../bins/outline-ss-rust/grafana/*.json)
		files+=(../../../bins/outline-ws-rust/grafana/*.json)
	fi
fi
[ ${#files[@]} -gt 0 ] || { echo "no dashboards to deploy" >&2; exit 1; }

for f in "${files[@]}"; do
	[ -f "$f" ] || { echo "missing $f" >&2; exit 1; }
	# A malformed dashboard is skipped silently by the provisioner, leaving the
	# previous version on screen and no error anywhere obvious.
	python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" ||
		{ echo "$f is not valid JSON — refusing to deploy" >&2; exit 1; }
done
echo "==> json ok: ${files[*]}"

if [ "$k3s" = 1 ]; then
	# Cluster mode: each dashboard becomes its own ConfigMap, because a single
	# one would run into the 1 MiB object limit. The manifests are generated
	# rather than committed — otherwise the same JSON would live twice in the
	# repository and the copies would drift.
	command -v kubectl >/dev/null || { echo "kubectl not in PATH" >&2; exit 1; }
	: "${KUBECONFIG:?set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)}"
	for f in "${files[@]}"; do
		name="grafana-dashboard-$(basename "$f" .json)"
		kubectl create configmap "$name" -n monitoring --from-file="$f" \
			--dry-run=client -o yaml | kubectl apply -f -
	done
	cat <<EOF

==> ConfigMaps applied. If you ADDED a dashboard, its ConfigMap is not mounted
    yet — add a source to the projected volume in
    apps/monitoring/grafana.yaml and re-apply the Deployment:

$(for f in "${files[@]}"; do echo "      - configMap: { name: grafana-dashboard-$(basename "$f" .json) }"; done)

    Grafana provisions dashboards at startup, so restart the pod to pick up
    changes (a production action — ask the owner first):

    kubectl -n monitoring rollout restart deploy/grafana
EOF
	exit 0
fi

scp -q "${files[@]}" "$host:/tmp/"
ssh "$host" "
	set -e
	for f in ${files[*]}; do
		sudo install -m 0644 -o 1000 -g 1000 \"/tmp/\$f\" \"$dest/\$f\"
		rm -f \"/tmp/\$f\"
	done
"

cat <<EOF

==> copied, but NOT yet on screen. Restart is a production action, so ask the
    owner first, then:

    ssh $host 'sudo docker restart grafana'

    and confirm it took:

    ssh $host 'sudo docker logs --since 2m grafana 2>&1 | grep "provision dashboards"'
EOF
```

Также обновить шапку скрипта — заменить первые девять строк комментария на:

```bash
#!/usr/bin/env bash
#
# deploy.sh — push the dashboards to Grafana.
# Run from the development machine:
#   ./deploy.sh [file.json ...]         # legacy: copy to the docker Grafana on .102
#   ./deploy.sh --k3s [file.json ...]   # cluster: one ConfigMap per dashboard
#
# With no file arguments every *.json in this directory is used. Copying alone
# changes nothing on screen: Grafana provisions dashboards once at startup, so a
# restart is required afterwards (`updateIntervalSeconds` does not re-read
# anything on 13.0.2 — verified 2026-08-09).
```

- [ ] **Step 2: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/grafana/dashboards
bash -n deploy.sh && echo "bash ok"
```

Ожидаемо: `bash ok`.

- [ ] **Step 3: Проверить, что режим требует KUBECONFIG**

```bash
env -u KUBECONFIG ./deploy.sh --k3s outline-alerting.json; echo "exit=$?"
```

Ожидаемо: сообщение `set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)` и `exit=1`.

- [ ] **Step 4: Проверить генерацию ConfigMap без применения**

```bash
kubectl create configmap grafana-dashboard-outline-alerting -n monitoring \
  --from-file=outline-alerting.json --dry-run=client -o yaml | head -5
```

Ожидаемо: `apiVersion: v1`, `kind: ConfigMap`, `metadata: name: grafana-dashboard-outline-alerting`.

- [ ] **Step 5: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/grafana/dashboards/deploy.sh
git commit -m "ops(grafana): teach the dashboard deployer to target the cluster"
```

---

### Task 3: Режим `--k3s` в скрипте алертинга

**Files:**
- Modify: `ops/grafana/alerting/deploy.sh`

**Interfaces:**
- Consumes: `rules.yaml`, `contact-points.yaml`, `policies.yaml` и токены из
  `~/.config/outline/`.
- Produces: Secret `grafana-alerting` в ns `monitoring` с тремя ключами —
  именно его монтирует Deployment из Задачи 1.

- [ ] **Step 1: Добавить режим в deploy.sh**

В `ops/grafana/alerting/deploy.sh` после строки `cd "$(dirname "$0")"` вставить:

```bash
k3s=0
if [ "${1:-}" = "--k3s" ]; then
	k3s=1
	shift
fi
```

Затем заменить всё от строки `echo "==> copying to $host:$dest"` до конца файла на:

```bash
if [ "$k3s" = 1 ]; then
	# Cluster mode: the three files become one Secret, not a ConfigMap —
	# contact-points.yaml carries the Telegram bot token and the heartbeat
	# token after substitution.
	command -v kubectl >/dev/null || { echo "kubectl not in PATH" >&2; exit 1; }
	: "${KUBECONFIG:?set KUBECONFIG (e.g. ~/.kube/k3s-home.yaml)}"
	kubectl create secret generic grafana-alerting -n monitoring \
		--from-file="$tmp/rules.yaml" \
		--from-file="$tmp/contact-points.yaml" \
		--from-file="$tmp/policies.yaml" \
		--dry-run=client -o yaml | kubectl apply -f -
	cat <<EOF

==> Secret applied, but NOT yet in force. Alerting provisioning runs once at
    startup, so the pod has to restart (a production action — ask the owner
    first):

    kubectl -n monitoring rollout restart deploy/grafana

and confirm it took:

    kubectl -n monitoring logs deploy/grafana --since=2m | grep "provision alerting"
EOF
	exit 0
fi

echo "==> copying to $host:$dest"
scp -q "$tmp"/rules.yaml "$tmp"/contact-points.yaml "$tmp"/policies.yaml "$host:/tmp/"
ssh "$host" "
	set -e
	for f in rules.yaml contact-points.yaml policies.yaml; do
		sudo install -D -m 0640 -o 1000 -g 1000 \"/tmp/\$f\" \"$dest/\$f\"
		rm -f \"/tmp/\$f\"
	done
"

cat <<EOF

==> copied, but NOT yet in force.

Alerting provisioning runs once at startup — unlike dashboards, there is no
poller re-reading the directory. Files dropped in later just sit there (verified
2026-08-07: a copy landing 27 seconds after startup left zero rules in the
database). Restarting is a production action, so ask the owner first, then:

    ssh $host 'sudo docker restart grafana'

and confirm it took:

    ssh $host 'sudo docker logs --since 2m grafana 2>&1 | grep "provision alerting"'
EOF
```

Также в шапке скрипта заменить строку `# Run from the development machine: ./deploy.sh` на:

```bash
# Run from the development machine:
#   ./deploy.sh          # legacy: copy to the docker Grafana on .102
#   ./deploy.sh --k3s    # cluster: one Secret in the monitoring namespace
```

- [ ] **Step 2: Проверить синтаксис**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/grafana/alerting
bash -n deploy.sh && echo "bash ok"
```

Ожидаемо: `bash ok`.

- [ ] **Step 3: Проверить, что подстановка токенов по-прежнему обязательна**

```bash
OUTLINE_SECRETS_DIR=/nonexistent ./deploy.sh --k3s; echo "exit=$?"
```

Ожидаемо: `missing /nonexistent/heartbeat-token — put the shared heartbeat token
there (mode 0600)` и `exit=1` — проверка секретов срабатывает до kubectl.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/grafana/alerting/deploy.sh
git commit -m "ops(grafana): teach the alerting deployer to target the cluster"
```

---

### Task 4: Погасить Grafana на .102 и почистить БД

С этого шага начинается окно без мониторинга: алерты не вычисляются, heartbeat
не идёт, dead-man на cloud1/cloud2 начнёт отсчёт. Задачи 4–6 выполняются подряд.

**Files:** изменений в git нет; на `.102` создаётся
`/opt/grafana/grafana.db.bak-2026-08-09` и `/tmp/grafana-db.tar.gz`.

**Interfaces:**
- Produces: почищенный `grafana.db` и архив с ним — их забирает Задача 5.

- [ ] **Step 1: Остановить контейнер и снять автоперезапуск**

```bash
ssh mmv@198.18.1.102 'sudo -n docker update --restart=no grafana && sudo -n docker stop grafana && sudo -n docker ps -a --filter name=grafana --format "{{.Status}}"'
```

Ожидаемо: `Exited (0) ...`. `--restart=no` обязателен: иначе контейнер вернётся
после перезагрузки узла и начнёт слать вторые алерты параллельно кластерной
Grafana.

- [ ] **Step 2: Снять бэкап БД до чистки**

```bash
ssh mmv@198.18.1.102 'sudo -n cp -a /opt/grafana/data/grafana.db /opt/grafana/grafana.db.bak-2026-08-09 && sudo -n ls -l /opt/grafana/grafana.db.bak-2026-08-09'
```

Ожидаемо: файл ~15 МБ. Чистка необратима, это единственная страховка.

- [ ] **Step 3: Почистить историю версий**

Скрипт удаляет историю семи мёртвых дашбордов и все версии живых, кроме
последней. Работает на остановленной Grafana, поэтому WAL-файлы можно
безопасно слить в основную БД:

```bash
ssh mmv@198.18.1.102 'sudo -n python3 - <<PY
import sqlite3
db = "/opt/grafana/data/grafana.db"
c = sqlite3.connect(db)
c.execute("PRAGMA journal_mode=WAL")

live = {r[0] for r in c.execute("select distinct name from resource where resource=?", ("dashboards",))}
hist = {r[0] for r in c.execute("select distinct name from resource_history where resource=?", ("dashboards",))}
dead = hist - live
print("живых:", len(live), "мёртвых:", len(dead))

for n in sorted(dead):
    c.execute("delete from resource_history where resource=? and name=?", ("dashboards", n))
    print("  удалён:", n)

# У живых оставляем только максимальный resource_version.
c.execute("""
    delete from resource_history
     where resource=?
       and rowid not in (
           select rowid from (
               select rowid, row_number() over (partition by name order by resource_version desc) rn
                 from resource_history where resource=?
           ) where rn = 1
       )
""", ("dashboards", "dashboards"))
c.commit()
print("осталось строк истории:", c.execute("select count(*) from resource_history").fetchone()[0])
c.execute("VACUUM")
c.close()
PY'
```

Ожидаемо: `живых: 10 мёртвых: 7`, перечисление семи UID, и число строк истории
близкое к 10.

- [ ] **Step 4: Проверить результат чистки**

```bash
ssh mmv@198.18.1.102 'sudo -n ls -l /opt/grafana/data/grafana.db*; sudo -n python3 -c "
import sqlite3
c=sqlite3.connect(\"/opt/grafana/data/grafana.db\")
print(\"дашбордов:\", c.execute(\"select count(*) from resource where resource=?\", (\"dashboards\",)).fetchone()[0])
print(\"датасорс:\", c.execute(\"select uid,name from data_source\").fetchall())
"'
```

Ожидаемо: БД заметно меньше 15 МБ, `дашбордов: 10`,
`датасорс: [('adnsc1wi03doga', 'prometheus')]`. Если дашбордов стало меньше
десяти — чистка задела живые данные, восстановить из
`grafana.db.bak-2026-08-09` и остановиться.

- [ ] **Step 5: Упаковать для переноса**

```bash
ssh mmv@198.18.1.102 'cd /opt/grafana/data && sudo -n tar czf /tmp/grafana-db.tar.gz grafana.db && sudo -n chown mmv:mmv /tmp/grafana-db.tar.gz && ls -l /tmp/grafana-db.tar.gz'
```

Ожидаемо: архив в единицы мегабайт. В архиве только `grafana.db` — ни плагинов,
ни `dashboards/`, ни `unified-search/`.

Коммита нет.

---

### Task 5: Создать PVC и залить в него базу

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: `/tmp/grafana-db.tar.gz` с `.102` (Задача 4), манифест PVC (Задача 1).
- Produces: PVC `grafana-data` с файлом `/var/lib/grafana/grafana.db`,
  принадлежащим `472:472` — его монтирует Deployment из Задачи 6.

- [ ] **Step 1: Применить провижининг и секреты**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
kubectl apply -f grafana-provisioning.yaml
ssh mmv@198.18.1.102 'sudo -n cat /opt/grafana/secrets/smtp' > /tmp/smtp
kubectl create secret generic grafana-smtp -n monitoring --from-file=smtp=/tmp/smtp \
  --dry-run=client -o yaml | kubectl apply -f -
rm -f /tmp/smtp
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/grafana/alerting && ./deploy.sh --k3s
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/grafana/dashboards && ./deploy.sh --k3s
```

Ожидаемо: два `configmap ... created`, `secret/grafana-smtp created`,
`secret/grafana-alerting created`, пять `configmap/grafana-dashboard-... created`.

- [ ] **Step 2: Создать PVC**

`local-path` использует `WaitForFirstConsumer`, поэтому том появится только
вместе с первым подом — им и будет helper:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
kubectl apply -f grafana.yaml
kubectl -n monitoring get pvc grafana-data
```

Ожидаемо: PVC в состоянии `Pending` с причиной `WaitForFirstConsumer`, и
Deployment уже создан — под будет падать в `CrashLoopBackOff` или ждать том,
это нормально до заливки данных.

- [ ] **Step 3: Поднять helper-под с тем же PVC**

Deployment уже держит PVC (`ReadWriteOnce`), поэтому сначала убираем его реплики:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/grafana --replicas=0
kubectl -n monitoring run grafana-loader --image=busybox:1.36 --restart=Never \
  --overrides='{"spec":{"containers":[{"name":"grafana-loader","image":"busybox:1.36","command":["sleep","3600"],"volumeMounts":[{"name":"data","mountPath":"/data"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"grafana-data"}}]}}'
kubectl -n monitoring wait --for=condition=Ready pod/grafana-loader --timeout=180s
```

Ожидаемо: `pod/grafana-loader condition met`.

- [ ] **Step 4: Залить базу**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
scp mmv@198.18.1.102:/tmp/grafana-db.tar.gz /tmp/grafana-db.tar.gz
kubectl -n monitoring cp /tmp/grafana-db.tar.gz grafana-loader:/data/grafana-db.tar.gz
kubectl -n monitoring exec grafana-loader -- sh -c 'cd /data && tar xzf grafana-db.tar.gz && rm -f grafana-db.tar.gz && chown -R 472:472 /data && ls -l /data'
```

Ожидаемо: `grafana.db` во владении `472 472`.

- [ ] **Step 5: Убрать helper и временные файлы**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring delete pod grafana-loader
rm -f /tmp/grafana-db.tar.gz
ssh mmv@198.18.1.102 'rm -f /tmp/grafana-db.tar.gz'
```

Коммита нет.

---

### Task 6: Запустить Grafana в кластере и проверить

**Files:** изменений в git нет.

**Interfaces:**
- Consumes: всё из Задач 1–5.
- Produces: работающая Grafana на `https://grafana.k3s.beerloga.su` —
  предусловие Задач 7 и 8.

- [ ] **Step 1: Поднять под**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/grafana --replicas=1
kubectl -n monitoring rollout status deploy/grafana --timeout=300s
```

Ожидаемо: `deployment "grafana" successfully rolled out`. Если под в
`CrashLoopBackOff` — смотреть `kubectl -n monitoring logs deploy/grafana`;
типичная причина — права на `/var/lib/grafana` (должно быть `472:472`).

- [ ] **Step 2: Убедиться, что провижининг отработал**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring logs deploy/grafana | grep -iE "provision (alerting|dashboards)|Starting Grafana" | head -5
```

Ожидаемо: строка `Starting Grafana version=13.0.2` и упоминания провижининга.

- [ ] **Step 3: Проверить HTTPS и здоровье**

```bash
curl -s https://grafana.k3s.beerloga.su/api/health
```

Ожидаемо: JSON с `"database": "ok"` и `"version": "13.0.2"`.

- [ ] **Step 4: Проверить, что данные переехали**

Войти в UI `https://grafana.k3s.beerloga.su` **прежним паролем** (он приехал
внутри БД) и проверить:

- список дашбордов содержит все десять, включая ручные `Power`, `Temperature`,
  `Node Exporter Full`, `Tunnels`, `Outline`, `VictoriaMetrics`, `Xray Dashboard`;
- на любом дашборде рисуются данные — значит датасорс `adnsc1wi03doga` жив и
  ходит на `198.18.1.102:8428`;
- Alerting → Alert rules показывает семь правил;
- Administration → Plugins не содержит `marcusolsson-dynamictext-panel`.

Пустые панели при живом дашборде означают, что UID датасорса разошёлся —
сверить `kubectl -n monitoring get cm grafana-datasources -o yaml` с
`adnsc1wi03doga`.

- [ ] **Step 5: Проверить отправку уведомления**

В UI: Alerting → Contact points → `owner` → Test. Ожидаемо: письмо на
`balookrd@gmail.com` и сообщение в Telegram. Это проверяет и SMTP-секрет, и
подстановку токенов в Secret `grafana-alerting`.

Коммита нет.

---

### Task 7: Перенацелить scrape-job VictoriaMetrics

Пока это не сделано, метрики самой Grafana не собираются, и дашборд
`outline alerting` показывает пустоту.

**Files:** изменений в git нет; на `.102` меняется
`/opt/victoria-metrics/scrape.yaml`.

- [ ] **Step 1: Проверить, что имя резолвится с .102**

```bash
ssh mmv@198.18.1.102 'dig +short grafana.k3s.beerloga.su; curl -s -o /dev/null -w "%{http_code} verify=%{ssl_verify_result}\n" https://grafana.k3s.beerloga.su/metrics'
```

Ожидаемо: `198.18.1.200` и `200 verify=0`. Если резолва нет — узел ходит мимо
Keenetic; тогда добавить запись в `/etc/hosts` узла и отметить это в README.

- [ ] **Step 2: Поправить job**

Меняется и target, и схема: VictoriaMetrics по умолчанию ходит по http, а
ingress отдаёт только https (`web` редиректит на `websecure`, и scrape поймал бы
`308` вместо метрик).

```bash
ssh mmv@198.18.1.102 'sudo -n cp -a /opt/victoria-metrics/scrape.yaml /opt/victoria-metrics/scrape.yaml.bak-2026-08-09 && sudo -n python3 - <<PY
p = "/opt/victoria-metrics/scrape.yaml"
lines = open(p).read().split("\n")
out, i = [], 0
while i < len(lines):
    out.append(lines[i])
    if lines[i].strip() == "job_name: grafana" or lines[i].strip() == "- job_name: grafana":
        indent = " " * (len(lines[i]) - len(lines[i].lstrip()))
        if lines[i].lstrip().startswith("- "):
            indent += "  "
        out.append(indent + "scheme: https")
    i += 1
s = "\n".join(out).replace("    - 127.0.0.1:4000", "    - grafana.k3s.beerloga.su")
open(p, "w").write(s)
print("patched")
PY
sudo -n grep -A7 "job_name: grafana" /opt/victoria-metrics/scrape.yaml'
```

Ожидаемо: `patched`, затем в job'е строка `scheme: https` и target
`grafana.k3s.beerloga.su`. Если `scheme` продублировался (скрипт запускали
дважды) — убрать лишнюю строку и не повторять шаг.

- [ ] **Step 3: Перечитать конфиг без рестарта**

```bash
ssh mmv@198.18.1.102 'curl -s -X POST http://127.0.0.1:8428/-/reload && sleep 5 && curl -s "http://127.0.0.1:8428/api/v1/targets" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d[\"data\"][\"activeTargets\"]:
    if t[\"labels\"].get(\"job\")==\"grafana\": print(t[\"scrapeUrl\"], t[\"health\"], t.get(\"lastError\",\"\"))
"'
```

Ожидаемо: `https://grafana.k3s.beerloga.su/metrics up`. Состояние `down` с
ошибкой TLS или DNS означает, что предыдущий шаг не доделан.

Коммита нет — `/opt/victoria-metrics/` не под git.

---

### Task 8: NFS-клиент на нодах и ночной бэкап на NAS

**Files:**
- Create: `ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml`

**Interfaces:**
- Consumes: PVC `grafana-data`, NAS-экспорт `198.18.1.125:/mnt/HD/HD_a2/k8s`.
- Produces: CronJob `grafana-backup`, кладущий `grafana-YYYYmmdd-HHMM.db.gz`
  в `/mnt/HD/HD_a2/k8s/backup/grafana` и хранящий 7 последних.

- [ ] **Step 1: Поставить nfs-common на три ноды**

```bash
for n in 51 52 53; do
  echo "=== .$n ==="
  ssh mmv@198.18.1.$n 'sudo -n apt-get update -qq && sudo -n DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nfs-common >/dev/null && command -v mount.nfs && echo ok'
done
```

Ожидаемо: на каждой ноде путь к `mount.nfs` и `ok`. Без этого под с `nfs`-томом
навсегда останется в `ContainerCreating`.

- [ ] **Step 2: Создать манифест бэкапа**

Полное содержимое `ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml`:

```yaml
# Nightly Grafana backup to the NAS.
#
# `sqlite3 .backup` rather than cp: it takes a consistent snapshot of a live
# database, WAL included. This matters more than usual here — seven dashboards
# exist only inside this file and in no git repository.
#
# The NFS volume is declared inline instead of going through a StorageClass:
# nfs-provisioner is not deployed, and one CronJob does not justify it. The
# nodes need nfs-common installed.
apiVersion: batch/v1
kind: CronJob
metadata:
  name: grafana-backup
  namespace: monitoring
spec:
  schedule: "30 3 * * *"
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          securityContext:
            runAsUser: 472
            fsGroup: 472
          containers:
            - name: backup
              image: alpine:3.20
              command:
                - /bin/sh
                - -c
                - |
                  set -eu
                  apk add --no-cache sqlite >/dev/null
                  stamp=$(date +%Y%m%d-%H%M)
                  mkdir -p /backup/grafana
                  sqlite3 /data/grafana.db ".backup /tmp/grafana.db"
                  gzip -c /tmp/grafana.db > "/backup/grafana/grafana-$stamp.db.gz"
                  rm -f /tmp/grafana.db
                  # Keep the last seven; ls -1 sorts lexically, which for this
                  # timestamp format is chronological.
                  ls -1 /backup/grafana/grafana-*.db.gz | head -n -7 | xargs -r rm -f
                  ls -l /backup/grafana/
              volumeMounts:
                - { name: data, mountPath: /data, readOnly: true }
                - { name: backup, mountPath: /backup }
          volumes:
            - name: data
              persistentVolumeClaim:
                claimName: grafana-data
                readOnly: true
            - name: backup
              nfs:
                server: 198.18.1.125
                path: /mnt/HD/HD_a2/k8s
```

- [ ] **Step 3: Применить и прогнать вручную**

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
cd /Users/mvmalykh/IdeaProjects/outline-proxy/ops/nanopi-r5c-k3s/apps/monitoring
kubectl apply -f grafana-backup.yaml
kubectl -n monitoring create job grafana-backup-manual --from=cronjob/grafana-backup
kubectl -n monitoring wait --for=condition=complete job/grafana-backup-manual --timeout=300s
kubectl -n monitoring logs job/grafana-backup-manual | tail -5
```

Ожидаемо: job завершается, в логе — листинг с одним файлом
`grafana-<дата>.db.gz`.

Важно: PVC `ReadWriteOnce` и под Grafana держит его на своей ноде. Job должен
попасть на ту же ногу — local-path node affinity об этом позаботится. Если job
висит в `Pending` с `node(s) had volume node affinity conflict`, значит на ноде
не хватило места или под Grafana переехал; смотреть `kubectl -n monitoring
describe pod -l job-name=grafana-backup-manual`.

- [ ] **Step 4: Проверить файл на NAS**

```bash
ssh mmv@198.18.1.102 'ls -l /mnt/nas/k8s/backup/grafana 2>/dev/null || echo "проверить с ноды"'
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring delete job grafana-backup-manual
```

Если на `.102` NAS не смонтирован, достаточно листинга из логов job'а в
предыдущем шаге.

- [ ] **Step 5: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/nanopi-r5c-k3s/apps/monitoring/grafana-backup.yaml
git commit -m "ops(k3s): nightly Grafana backup to the NAS"
```

---

### Task 9: Документация

**Files:**
- Modify: `ops/grafana/README.md`
- Modify: `ops/nanopi-r5c-k3s/apps/README.md`

- [ ] **Step 1: Переписать шапку ops/grafana/README.md**

Заменить первый абзац (строки 1–10, описывающие docker на .102) на (внешний
fence `~~~` — внутри есть вложенный блок кода):

~~~markdown
# Grafana

Grafana OSS 13.0.2 живёт **в k3s-кластере** (`monitoring/grafana`), доступна на
`https://grafana.k3s.beerloga.su`. До 2026-08-09 она работала в docker на
`198.18.1.102`; `/opt/grafana` там оставлен как путь отката, контейнер
остановлен и снят с автозапуска (`docker update --restart=no`).

VictoriaMetrics осталась на `.102` (`:8428`) — датасорс `prometheus`
(uid `adnsc1wi03doga`) смотрит туда по сети. Менять uid нельзя: дашборды
ссылаются на датасорс именно по нему.

Раскатка:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
./dashboards/deploy.sh --k3s     # ConfigMap на каждый дашборд
./alerting/deploy.sh --k3s       # Secret с rules/policies/contact-points
kubectl -n monitoring rollout restart deploy/grafana
```

Провижининг и дашбордов, и алертинга применяется **только при старте** —
рестарт пода обязателен. Добавили новый дашборд? Кроме `deploy.sh --k3s` нужно
добавить его ConfigMap в projected volume в
[`apps/monitoring/grafana.yaml`](../nanopi-r5c-k3s/apps/monitoring/grafana.yaml):
один ConfigMap на дашборд, потому что в один упереться в лимит 1 МиБ.

Состояние (включая семь дашбордов, которых нет в git) лежит в SQLite на
`local-path`; ночной бэкап — CronJob `grafana-backup` на NAS, семь копий.
~~~

- [ ] **Step 2: Дополнить apps/README.md**

В строку про Grafana в таблице сервисов (либо после неё) добавить абзац:

```markdown
Grafana мигрирована с `198.18.1.102` 2026-08-09. Данные — SQLite на
`local-path` (PV несёт node-affinity, поэтому под приколочен к своей ноде);
конфигурация — ConfigMap `grafana-datasources`/`grafana-dashboard-provider`,
дашборды — по ConfigMap на файл, алертинг — Secret `grafana-alerting`.
Пароль администратора живёт в БД: `GF_SECURITY_ADMIN_PASSWORD` намеренно не
задан, иначе он сбрасывался бы при каждом старте пода.
```

- [ ] **Step 3: Проверить ссылки**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
grep -n "grafana-admin" ops/nanopi-r5c-k3s/apps/README.md ops/grafana/README.md || echo "нет ссылок на удалённый пример секрета"
ls ops/nanopi-r5c-k3s/apps/monitoring/
```

Ожидаемо: сообщение об отсутствии ссылок; в каталоге — `grafana.yaml`,
`grafana-provisioning.yaml`, `grafana-backup.yaml`, `victoria-metrics.yaml`.

- [ ] **Step 4: Commit**

```bash
cd /Users/mvmalykh/IdeaProjects/outline-proxy
git add ops/grafana/README.md ops/nanopi-r5c-k3s/apps/README.md
git commit -m "docs(grafana): describe the cluster deployment and its rollout"
```

---

## Порядок и откат

Задачи 1–3 — только репозиторий, безопасны и обратимы. Окно без мониторинга
открывается на Задаче 4 и закрывается на Задаче 6; между ними не отвлекаться —
dead-man на cloud1/cloud2 отсчитывает время без heartbeat.

Откат на любом шаге после Задачи 4:

```bash
export KUBECONFIG=~/.kube/k3s-home.yaml
kubectl -n monitoring scale deploy/grafana --replicas=0
ssh mmv@198.18.1.102 'sudo -n docker update --restart=unless-stopped grafana && sudo -n docker start grafana'
```

Данные на `.102` остаются нетронутыми (кроме почищенной истории версий, для
которой есть `grafana.db.bak-2026-08-09`).

## Известные ограничения

- Под Grafana привязан к одной ноде через local-path. Потеря ноды = развернуть
  PVC заново и восстановить из бэкапа на NAS.
- Семь ручных дашбордов по-прежнему только в БД. Их экспорт в git — отдельная
  задача, здесь не делается.
- VictoriaMetrics остаётся на `.102`, то есть мониторинг всё ещё зависит от этого
  узла.
- `victoria-metrics.yaml` в этом каталоге — незаполненная заготовка с
  `<PLACEHOLDER>`-подобными TODO; она не применяется и в этот план не входит.
