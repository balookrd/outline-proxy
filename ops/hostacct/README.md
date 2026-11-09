# Учёт трафика по хостам на GRE-туннеле

Счётчики байтов и пакетов по каждому LAN-адресу, который Keenetic отправляет на
узел через GRE-туннель `gre1`. Нужны, чтобы по истории в VictoriaMetrics
определить, кто дал всплеск трафика через туннель: в `node_network_*` видна
только сумма по интерфейсу, а Keenetic кладёт в туннель трафик и мимо политик
подключения (маршруты по адресам и доменам).

Узлы: `.104` (NanoPi, node_exporter — systemd) и `.102` (Beelink, node_exporter —
docker-контейнер `node-exporter`). На обоих `gre1` — туннель с Keenetic
`198.18.1.1`, enslaved в VRF `vrf-proxy`.

## Состав

| Файл | Куда ставится | Что делает |
|---|---|---|
| `hostacct.nft` | `/etc/hostacct.nft` | таблица `inet hostacct`: четыре динамических сета со счётчиками (`up4`, `up6`, `down4`, `down6`) |
| `hostacct.service` | `/etc/systemd/system/` | oneshot, загружает таблицу при старте; `stop` удаляет таблицу |
| `hostacct-metrics` | `/usr/local/sbin/` | читает `nft -j list table inet hostacct`, пишет `/run/node_exporter/textfile/hostacct.prom` |
| `hostacct-metrics.timer` | `/etc/systemd/system/` | запускает экспорт раз в 15 с |

Таблица только считает: политика цепочек `accept`, правил с `drop` и
перезаписью пакетов нет.

## Где считается направление

`gre1` входит в VRF `vrf-proxy`. В хуке `forward` у пакетов, пришедших из
`gre1`, `iifname` равен `vrf-proxy`, а не `gre1` (проверено на `.104`,
nftables 1.1.3, ядро 6.1). Поэтому:

- `up` (клиент → интернет) считается в `prerouting` по `iifname "gre1"` и
  адресу источника;
- `down` (интернет → клиент) считается в `forward` по `oifname "gre1"` и
  адресу назначения.

Счётчик считает длину внутреннего IP-пакета, то есть то же, что
`/sys/class/net/gre1/statistics/{rx,tx}_bytes`.

## Метрики

```
hostacct_bytes_total{iface="gre1",dir="down",addr="198.18.1.101",name="spruthub-2-cc09c801edac"}
hostacct_packets_total{...}
```

- `dir` — `up` или `down`, см. выше.
- `name` — PTR-запись адреса у резолвера `198.18.1.1` (Keenetic), кэш на час в
  `/run/hostacct/names.json`; пусто, если PTR нет.
- В сетах встречается `198.18.250.2` (`.104`) / `198.18.251.2` (`.102`) — адрес
  Keenetic на его конце туннеля.

Элементы сетов живут без таймаута, счётчики растут до перезагрузки таблицы
(`systemctl restart hostacct`, ребут). Сброс `rate()` обрабатывает. Лимит —
512 адресов на сет; при переполнении новые адреса не учитываются.

Запрос «кто качал»:

```promql
topk(5, sum by (addr, name)(rate(hostacct_bytes_total{instance="debian",dir="down"}[1m])) * 8)
```

`instance="debian"` — `.104`, `instance="ubuntu"` — `.102`.

Дашборд Grafana «GRE hosts» (uid `hostacct-gre`) —
`ops/grafana/dashboards/hostacct-dashboard.json`, выкладка
`ops/grafana/dashboards/deploy.sh --nas hostacct-dashboard.json` и рестарт
контейнера `grafana` на NAS.

## Установка

На узле, из копии этого каталога:

```bash
sudo ./install.sh
```

Скрипт ставит файлы, загружает таблицу, включает таймер и печатает начало
`hostacct.prom`.

node_exporter должен читать каталог `/run/node_exporter/textfile`:

- `.104`: уже запущен с `--collector.textfile.directory=/run/node_exporter/textfile`.
- `.102`: контейнер монтирует корень хоста в `/rootfs`, нужен флаг
  `--collector.textfile.directory=/rootfs/run/node_exporter/textfile`.
  Флаг добавляется только пересозданием контейнера `node-exporter`.

## Проверка

Суммы по хостам должны совпасть с счётчиками интерфейса:

```promql
sum(rate(hostacct_bytes_total{instance="debian",dir="down"}[5m]))
  / rate(node_network_transmit_bytes_total{instance="debian",device="gre1"}[5m])
```

Значение около `1`. На узле:

```bash
sudo nft list table inet hostacct
systemctl status hostacct-metrics.timer
cat /run/node_exporter/textfile/hostacct.prom
```

## Известные проблемы

- `nft flush ruleset` на узле удаляет и эту таблицу. Тогда `hostacct-metrics`
  падает с `nft failed` в `journalctl -u hostacct-metrics` и удаляет
  `hostacct.prom`, ряды пропадают из VictoriaMetrics. Вернуть:
  `sudo systemctl restart hostacct`.
- На `.104` каталог `/run/node_exporter/textfile` создаёт systemd
  (`RuntimeDirectory`) и удаляет при остановке node_exporter; файл появится
  снова на следующем запуске таймера, через ≤15 с.

## Откат

```bash
sudo systemctl disable --now hostacct-metrics.timer hostacct.service
sudo rm -f /run/node_exporter/textfile/hostacct.prom
```

`stop` у `hostacct.service` удаляет таблицу `inet hostacct`; остальные правила
nftables не затрагиваются.
