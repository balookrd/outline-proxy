# Кластер k3s из 3× NanoPi R5C (RK3568B2)

Развёртывание трёх плат NanoPi R5C под k3s с embedded etcd. Образ — [johang][johang]
(чистый Debian + mainline U-Boot), настройка целиком **по SSH**: ни консоли, ни UART,
ни HDMI не требуется. Физический доступ нужен один раз — вставить microSD.

Конфигурация плат: RK3568B2 (4× Cortex-A55 @2.0), 4 ГБ LPDDR4X, eMMC (у наших плат
**64 ГБ**, `lsblk` показывает 58.2G — бывают и 32 ГБ), NVMe 128 ГБ в M.2 через
переходник E-key→M-key, 2× 2.5GbE, питание 5 В USB-C.

[johang]: https://sd-card-images.johang.se/boards/nanopi_r5c.html

Этот файл — про поднятие кластера (железо + k3s). Нагрузка и её storage вынесены в
[`apps/`](apps/README.md) отдельным деревом манифестов.

## Почему этот образ

| | FriendlyElec | Armbian | **johang / inindev** |
|---|---|---|---|
| Ядро | вендорный BSP 6.1.x | current 6.18.x (rolling) | **stock Debian 6.12 LTS** |
| Обновление ядра | только пересборкой образа через `sd-fuse` | apt из репо Armbian | обычный `apt` из Debian |
| Тир | вендор, конфиг под роутер | Community, `BOARD_MAINTAINER=""` | mainline-only |

FriendlyElec отпадает: FriendlyWrt — это OpenWrt без systemd, FriendlyCore — Ubuntu с
замороженным BSP 6.1, где ядро не обновляется через apt, а `CONFIG_DEBUG_INFO_BTF` и
полный набор cgroup/netfilter-опций у вендорных ядер негарантированы. Armbian рабочий
и даже полезный (см. «Известные риски»), но ядро приходит rolling из стороннего репо —
`apt upgrade` на трёх нодах сразу играет против кворума etcd.

**Ключевое отличие от `.104`:** RK3568 живёт в mainline целиком —
`arch/arm64/boot/dts/rockchip/rk3568-nanopi-r5c.dts` есть в torvalds/linux, U-Boot имеет
`nanopi-r5c-rk3568_defconfig`. Вывод «на NanoPi mainline не грузится», полученный на
RK3528A (см. `ops/nanopi104-backup/`), сюда **не переносится**.

## Что зашито в образ johang

Проверено по `scripts/build-debian` и `2nd-stage-files/` в репозитории johang:

| | значение |
|---|---|
| SSH | `openssh-server` в составе, **`PermitRootLogin yes`**, host-ключи генерятся на первой загрузке |
| Логин | `root`, **пароль = суффикс имени файла** (`…-in3she.bin.gz` → `in3she`) |
| Сеть | systemd-networkd, `Match Name=en*` и `eth*` → **DHCP на обоих портах** |
| Разметка | MBR: `p1` = FAT 28 МиБ (декоративный, «intentionally empty»), `p2` = ext4 rootfs с 32 МиБ; U-Boot на секторе 64 |
| Корень | `root=PARTUUID=${partuuid}` — U-Boot берёт **устройства, с которого загрузился**; в `/etc/fstab` корня нет вообще |
| Ядро | stock Debian `linux-image-arm64` 6.12.95-1; хук `zz-update-uimg` пересобирает `boot.scr` при обновлении |
| Состав | `debootstrap --variant=minbase`: netbase, net-tools, u-boot-tools, initramfs-tools, openssh-server, nano, systemd, e2fsprogs — **и всё** |

Три следствия делают SSH-only реальным: оба порта под DHCP (не надо угадывать, куда
воткнуть кабель), пароль известен до первой загрузки, динамический PARTUUID означает,
что клон на eMMC не перепутает корни.

### Раскладка PCI

Из mainline DTS + конфига inindev. Все три контроллера `status = "okay"`, править DTS
не нужно:

| Контроллер | Базовый адрес | PCI-домен | Что подключено |
|---|---|---|---|
| `pcie2x1` | `0x3c000000` | `0000` | M.2 E-key → **NVMe** (PCIe 2.0 x1, потолок ~400 МБ/с) |
| `pcie3x1` | `0x3c400000` | `0001` | RTL8125BG → LAN |
| `pcie3x2` | `0x3c800000` | `0002` | RTL8125BG → WAN |

## Шаг 1. Скачать образ (на маке)

Сборки перевыпускаются еженедельно, **у каждой свой root-пароль**. Актуальные имена
без браузера:

```bash
curl -s https://cdn.sd-card-images.johang.se/index-boots.js | tr ',' '\n' | grep -A1 nanopi_r5c
curl -s https://cdn.sd-card-images.johang.se/index-debians-arm64.js | tr ',' '\n' | grep -B2 -A6 'debian-trixie'
```

На 2026-07-20 актуальны:

```bash
BASE=https://dl.sd-card-images.johang.se
curl -O $BASE/boots/2026-07-01/boot-nanopi_r5c.bin.gz
curl -O $BASE/debians/2026-07-20/debian-trixie-arm64-in3she.bin.gz   # root password: in3she
```

## Шаг 2. Записать карту

```bash
diskutil list                       # find the card, e.g. disk4
diskutil unmountDisk /dev/disk4
zcat boot-nanopi_r5c.bin.gz debian-trixie-arm64-in3she.bin.gz \
  | sudo dd of=/dev/rdisk4 bs=4m
diskutil eject /dev/disk4
```

Порядок склейки принципиален: boot-образ несёт таблицу разделов и U-Boot, rootfs
ложится следом ровно на 32 МиБ.

## Шаг 3. Первый вход

Кабель — в **любой** из двух портов (оба под DHCP), карта в слот, питание. Через
минуту-полторы (первая загрузка генерит SSH-ключи):

```bash
nmap -sn 198.18.1.0/24 | grep -B2 -i realtek     # or check DHCP leases on the router
ssh root@198.18.1.X                              # password from the image filename
```

**BootROM RK3568 предпочитает SD, а не eMMC** (проверено на плате 2026-07-21: при
полностью залитом eMMC загрузка всё равно ушла на карту). Значит вставленная карта
всегда выигрывает, и содержимое eMMC первому запуску не мешает — кнопка **MASK** не
нужна. Обратная сторона — в шаге 10: чтобы переехать на eMMC, карту придётся физически
вынуть.

## Шаг 4. Пакеты

В `minbase` нет ни `curl`, ни `rsync`, ни `parted`, ни `lspci`, ни `sfdisk`
(последний — в пакете `fdisk`). `sources.list` у johang содержит только `main`:

```bash
sed -i 's/ main$/ main non-free-firmware/' /etc/apt/sources.list
apt update
apt install -y fdisk parted rsync pciutils nvme-cli ethtool chrony fake-hwclock \
               locales dialog firmware-realtek systemd-zram-generator
apt purge -y systemd-timesyncd    # NTP держит chrony; см. шаг 9 про часы
dpkg-reconfigure locales          # silences the perl locale warnings
apt full-upgrade
```

`chrony` не опционален: расхождение часов между нодами разваливает etcd быстрее всего
остального. `fake-hwclock` — тоже: у R5C RTC не держит время без батарейки, а
`systemd-timesyncd` при живом chrony только мешает (подробности и настройка — шаг 9).

## Шаг 5. Прибить MAC и имена портов ⚠️

**Самый важный шаг.** У johang нет `.link`-файлов, тогда как и Armbian, и inindev
задают MAC явно — сильный признак, что у RTL8125 он нестабилен. Проверить на плате:
`ip -br link` → `reboot` → сравнить. Если MAC плавает, DHCP выдаёт новый IP и нода
«пропадает» после каждой перезагрузки. Плюс известная болячка R5C: порты случайно
меняются местами между загрузками (DietPi #7559).

**Мина рядом:** сеть держится на `Match Name=en*`. Переименование в `lan0` ломает
матч, и DHCP исчезает. Поэтому `.link` и `.network` кладутся одним комплектом.

```bash
mkdir -p /root/net-backup && cp -a /etc/systemd/network/*.network /root/net-backup/

udevadm info /sys/class/net/* | grep -E 'INTERFACE=|ID_PATH='   # verify the paths first

cat > /etc/systemd/network/10-name-lan0.link <<'EOF'
[Match]
Path=platform-3c0400000.pcie-pci-0001:01:00.0
[Link]
Name=lan0
MACAddress=02:00:5e:00:01:11
EOF

cat > /etc/systemd/network/10-name-wan0.link <<'EOF'
[Match]
Path=platform-3c0800000.pcie-pci-0002:01:00.0
[Link]
Name=wan0
MACAddress=02:00:5e:00:01:12
EOF

# wan0 — uplink: default route and DNS come from the home DHCP server
cat > /etc/systemd/network/20-wan0.network <<'EOF'
[Match]
Name=wan0
[Network]
DHCP=yes
[DHCP]
UseDNS=true
RouteMetric=100
ClientIdentifier=mac
EOF

# lan0 — cluster interconnect: static, no gateway, no DNS
cat > /etc/systemd/network/20-lan0.network <<'EOF'
[Match]
Name=lan0
[Network]
Address=10.10.10.51/24
IPv6AcceptRA=no
LinkLocalAddressing=no
EOF

update-initramfs -u        # .link files are applied from the initramfs too
```

Адресация парка:

Роли портов: **`wan0` — uplink наружу** (домашняя сеть, интернет, вход по ssh),
**`lan0` — интерконнект внутри кластера** (etcd, трафик подов). Три `lan0` сводятся в
отдельный свитч или изолированный VLAN — с одним портом на ноду кольцо не собрать.

| Нода | hostname | wan0 MAC | wan0 IP (DHCP-резервация) | lan0 IP (статика) |
|---|---|---|---|---|
| 1 | `k3s-1` | `02:00:5e:00:01:12` | `198.18.1.51` | `10.10.10.51/24` |
| 2 | `k3s-2` | `02:00:5e:00:02:12` | `198.18.1.52` | `10.10.10.52/24` |
| 3 | `k3s-3` | `02:00:5e:00:03:12` | `198.18.1.53` | `10.10.10.53/24` |

**MTU — штатные 1500 на обоих портах.** Кластер работает на `--flannel-backend=host-gw`
(шаг 12), инкапсуляции нет, поэтому поды получают полные 1500 без jumbo-кадров и без
требований к свитчу. Если когда-нибудь придётся вернуться на VXLAN — тогда в `.link`
для `lan0` добавляется `MTUBytes=1550` (VXLAN отнимает ровно 50 байт), и свитч обязан
пропускать кадр 1568 байт; задирать выше не стоит, поды с MTU больше 1500 начнут
страдать на пути наружу — TCP спасёт MSS clamping, UDP нет.

MAC-адреса `lan0` — те же с последним байтом `11` (`02:00:5e:00:0N:11`). Номер ноды —
в предпоследнем байте. Резервации на роутере вешаются на **wan0**-MAC; ради их
надёжности MAC и прибивался. Подсеть интерконнекта `10.10.10.0/24` выбрана так, чтобы
не пересечься с дефолтами k3s: `10.42.0.0/16` — поды, `10.43.0.0/16` — сервисы.

> **DNS.** В образе `/etc/resolv.conf` — симлинк на `/run/systemd/resolve/stub-resolv.conf`,
> резолвинг идёт через `systemd-resolved`, а серверы ему отдаёт networkd. Отсюда правило:
> DNS приходит **только с того линка, где `UseDNS=true`**, то есть с `wan0`. Если
> единственный подключённый кабель окажется в порту `lan0`, связь будет, а резолвинга не
> будет вообще — apt свалится с `Temporary failure resolving 'deb.debian.org'`. Лечится
> перетыканием кабеля в `wan0` либо разово `resolvectl dns lan0 <ip>`.

Применять **перезагрузкой**, не `networkctl reload`: переименование живого интерфейса
обрывает сессию на середине. Перед этим — dead-man (урок `.104`: сетевая правка на
удалённом хосте только с авто-откатом):

```bash
systemd-run --on-active=10min --unit=net-rollback /bin/sh -c \
  'rm -f /etc/systemd/network/1*-name-*.link /etc/systemd/network/2*.network; \
   cp -a /root/net-backup/*.network /etc/systemd/network/; reboot'
reboot
```

Зашёл на новый адрес — `systemctl stop net-rollback.timer`, иначе через 10 минут
откатит.

## Шаг 6. Гигиена

```bash
ssh-copy-id root@198.18.1.51        # from the mac, BEFORE disabling passwords
```

```bash
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh

hostnamectl set-hostname k3s-1
timedatectl set-timezone Europe/Moscow
```

## Шаг 7. Проверить железо

```bash
lspci -nn                            # 0000:01:00.0 NVMe, 0001/0002:01:00.0 RTL8125
nvme list
dmesg | grep -iE 'nvme|pcie|link never|timeout'
ip -br link                          # lan0/wan0 with your fixed MACs
ethtool lan0 | grep -i speed
cat /sys/class/thermal/thermal_zone0/temp
```

Когда поднимутся хотя бы две ноды — проверить интерконнект полным кадром без
фрагментации (1472 payload + 8 ICMP + 20 IP = 1500):

```bash
ping -M do -s 1472 -c3 10.10.10.52
```

## Шаг 8. NVMe под данные k3s

Размечаем через `parted` — он уже стоит с шага 4; `sgdisk` жил бы в отдельном пакете
`gdisk`, тянуть его незачем.

```bash
wipefs -a /dev/nvme0n1                  # kills old FS signatures and both GPT copies
parted -s /dev/nvme0n1 mklabel gpt
parted -s -a opt /dev/nvme0n1 mkpart k3s-data ext4 0% 100%
partprobe /dev/nvme0n1
mkfs.ext4 -L k3s-data /dev/nvme0n1p1

mkdir -p /var/lib/rancher
grep -q '/var/lib/rancher' /etc/fstab || \
  echo "LABEL=k3s-data /var/lib/rancher ext4 defaults,noatime,nofail,x-systemd.device-timeout=30s 0 2" >> /etc/fstab
systemctl daemon-reload && mount -a
findmnt /var/lib/rancher
```

Проверка `grep -q` не случайна: повторный прогон шага (например, после клонирования карты)
допишет вторую такую же строку, systemd сгенерирует два `.mount`-юнита на одну точку и
возьмёт последнюю — молча потеряв `nofail`.

`nofail` не даёт упавшему маунту утащить `local-fs.target`, а с ним и всю загрузку в
emergency — без сети и без ssh. Обратная сторона: без диска система поднимется, а k3s
запишет данные на eMMC. Чтобы этого не случилось, привяжем его к маунту явно:

```bash
mkdir -p /etc/systemd/system/k3s.service.d
cat > /etc/systemd/system/k3s.service.d/10-require-data.conf <<'EOF'
[Unit]
RequiresMountsFor=/var/lib/rancher
EOF
systemctl daemon-reload
```

Тогда при недоступном NVMe нода останется живой и доступной по ssh, а k3s просто не
стартует — вместо того чтобы тихо развернуть etcd на eMMC.

`x-systemd.device-timeout` — чтобы медленно поднявшийся PCIe-линк не отправлял загрузку
в emergency shell. На NVMe уедут и etcd, и образы containerd; eMMC останется почти на
чтении. Потолок диска — PCIe 2.0 x1, ~400 МБ/с; для etcd важна не полоса, а
fsync-латентность, и она здесь на порядок лучше eMMC.

## Шаг 9. Подготовка к k3s

```bash
stat -fc %T /sys/fs/cgroup           # expect cgroup2fs

printf 'br_netfilter\noverlay\n' > /etc/modules-load.d/k3s.conf
modprobe br_netfilter overlay

cat > /etc/sysctl.d/99-k3s.conf <<'EOF'
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
vm.swappiness = 100
fs.inotify.max_user_instances = 1024
fs.inotify.max_user_watches = 524288
EOF
sysctl --system

cat > /etc/systemd/zram-generator.conf <<'EOF'
[zram0]
zram-size = ram / 2
compression-algorithm = zstd
EOF
systemctl daemon-reload && systemctl start systemd-zram-setup@zram0
zramctl
```

zram обязателен: 4 ГБ RAM, из которых ~1 ГБ съедают k3s-server и containerd до всякой
нагрузки. Компрессор — **zstd, не lzo-rle**: ядро здесь то же 6.12, на котором
`lzo-rle` местами отсутствует и юнит падает с `EIO` (грабля с парка VPS).

### Гейт по времени ⚠️

**У R5C нет батарейки RTC.** Мягкий `reboot` этого не показывает — RTC переживает
перезагрузку и обнуляется только со снятием питания. После блэкаута часы стартуют не с
текущего времени, а с эпохи: PID 1 поднимает их до mtime `/var/lib/systemd/timesync/clock`
либо до `TIME_EPOCH` сборки, то есть до даты, когда образ собирали или последний раз
синхронизировали. На боевой плате это дало откат **на две недели назад**, причём
воспроизводимо: три холодные загрузки подряд стартовали с одной и той же отметки.

Для k3s это фатально. Он стартует из `multi-user.target` раньше, чем chrony успевает
выправить часы, и упирается в собственные сертификаты, выпущенные «в будущем»:

```
level=error msg="Failed to validate connection to cluster at https://127.0.0.1:6443:
CA cert validation failed: ... x509: certificate has expired or is not yet valid:
current time 2026-07-21T11:54:00+03:00 is before 2026-08-04T08:41:16Z"
```

Дальше сервер не поднимается никогда: даже когда chrony через минуту выправит время,
k3s уже в цикле ожидания и сыпет `Waiting to retrieve agent configuration; server is
not ready`. Юнит при этом остаётся в `activating` — со всеми последствиями из раздела
[«Снос и переустановка»](#снос-и-переустановка-k3s).

Лечение — три независимых слоя, все три нужны:

```bash
# 1. восстановление времени при загрузке. Внимание: legacy-юнит fake-hwclock.service
#    замаскирован САМИМ пакетом (/usr/lib/systemd/system/fake-hwclock.service -> /dev/null),
#    `systemctl unmask` его не снимет — работу делают отдельные load/save-юниты
systemctl enable --now fake-hwclock-load.service fake-hwclock-save.timer

# 2. time-sync.target не достигается, пока chrony реально не синхронизировался
systemctl enable chrony-wait.service

# 3. k3s не стартует раньше этого таргета (каталог drop-in создан на шаге 8)
cat > /etc/systemd/system/k3s.service.d/15-wait-for-time.conf <<'EOF'
[Unit]
After=time-sync.target
Wants=time-sync.target
EOF
systemctl daemon-reload
```

Проверка:

```bash
systemctl is-enabled fake-hwclock-load.service fake-hwclock-save.timer chrony-wait.service
systemctl show chrony-wait.service -p TimeoutStartUSec   # 3min
cat /etc/fake-hwclock.data
```

Почему именно так:

- `systemd-time-wait-sync.service` **не подходит** — он часть `systemd-timesyncd`,
  которого при chrony нет (шаг 4 его сносит). Штатный гейт chrony — `chrony-wait.service`,
  он стоит `Before=time-sync.target` и держит его до первой синхронизации.
- `TimeoutStartUSec=3min` у `chrony-wait` — важная деталь: при мёртвом NTP гейт
  раскроется через три минуты, а не запрёт ноду навсегда. Часы к этому моменту уже
  восстановлены из `fake-hwclock`, то есть отстанут максимум на интервал таймера.
- `apt purge systemd-timesyncd` из шага 4 не косметика: осиротевший
  `/var/lib/systemd/timesync/clock` продолжает задавать стартовые часы, и обновлять его
  уже некому — chrony туда не пишет.

Железная альтернатива — батарейка в RTC-разъём платы; софтверный гейт после неё всё
равно стоит оставить.

**Сколько это стоит на загрузке (k3s-1, замер 2026-08-04):** `8.3s (kernel) + 1min 9s
(userspace)`, из них `chrony-wait` — 33 с, k3s до готовности — 26 с (восстановление WAL
и bbolt), `networkd-wait-online` — 7.6 с. Полторы минуты до `Ready` — норма для этой
платы, а не симптом; `systemd-analyze critical-chain k3s.service` показывает прямую
цепочку `k3s ← time-sync.target ← chrony-wait`.

Полезная деталь для диагностики: `systemd-analyze blame` дал `chrony-wait +33.378s`, а
журнал того же юнита — 55 секунд настенного времени. Расхождение не ошибка, а **прямое
доказательство, что гейт сработал**: systemd меряет монотонными часами, журнал —
настенными, значит chrony шагнул время вперёд на ~22 с (`fake-hwclock` вернул его с
отставанием на интервал сохранения). Этот скачок случился **до** старта k3s — на живом
etcd он был бы куда дороже.

**Пиры по интерконнекту эти 33 секунды не сокращают** — проверено там же: конфиг
`10-cluster.conf` (следующий подраздел) стоял на ноде за полчаса до загрузки, пиры были
живы, гейт всё равно ждал те же 33 с. Упирается он не в скорость источников, а в
собственный критерий: `chronyc waitsync 0 0.1` ждёт, пока остаточная коррекция упадёт
ниже 0.1 с, а после скачка на 22 секунды это требует нескольких циклов опроса, кто бы ни
отвечал. Ослабить критерий можно drop-in'ом к `chrony-wait.service`, но выигрыш — секунды
на загрузке, которая случается раз в месяц; не стоит того.

### Chrony: кластер синхронен и без интернета

etcd разваливает не абсолютная ошибка часов, а **расхождение между членами** — поэтому
ноды должны согласовываться друг с другом, а не только с внешними пулами. Домашний
интернет при этом может пропасть, а кворум обязан продолжать работать.

Схема — симметричный меш по интерконнекту плюс orphan-режим: каждая нода пирится с двумя
соседями, и все три объявляют `local stratum 10 orphan`. Пока пулы доступны, время идёт
от них; когда WAN отваливается, orphan детерминированно выбирает одного «сироту»-лидера
(по наименьшему refid), а остальные следуют за ним. Вариант «нода 1 — NTP-сервер для
двух других» отвергнут: он делает время зависимым от узла, потерю которого кластер с
кворумом 2 из 3 обязан переживать.

Файл одинаковый на всех трёх нодах, меняется только `NODE_IP`:

```bash
grep -n confdir /etc/chrony/chrony.conf      # ожидаем: confdir /etc/chrony/conf.d

NODE_IP=10.10.10.51                          # адрес lan0 ЭТОЙ ноды
{
  echo "# cluster time: symmetric peers over lan0 + orphan mode when the WAN is down"
  for ip in 10.10.10.51 10.10.10.52 10.10.10.53; do
    [ "$ip" = "$NODE_IP" ] || echo "peer $ip iburst"
  done
  echo "allow 10.10.10.0/24"
  echo "local stratum 10 orphan"
} > /etc/chrony/conf.d/10-cluster.conf
systemctl restart chrony
```

Основной `chrony.conf` не трогаем: Debian подключает `confdir /etc/chrony/conf.d`, и
drop-in переживает апгрейд пакета. `allow` открывает NTP только на интерконнект — наружу,
в `wan0`, chrony по-прежнему не отвечает. Дефолтный `makestep 1 3` тоже оставляем: он
разрешает скачок часов только в первых трёх обновлениях после старта, дальше время
подтягивается плавно, и etcd не видит прыжков.

Проверка, когда поднимутся хотя бы две ноды:

```bash
chronyc -n sources     # соседи идут со знаком '=' (peer), внешние пулы — с '^'
chronyc -n tracking    # Leap status: Normal; Stratum 2–3 при живом WAN, 11 в orphan
```

Как выглядит норма (k3s-1, 2026-08-04):

```
^* 92.255.126.22       2   6   377    28   +121us[ +144us] +/- 3388us
=- 10.10.10.52         3   6    17    48   +242us[ +266us] +/-   18ms
=- 10.10.10.53         3   6    17    49   +253us[ +277us] +/-   12ms
```

Минус после `=` — **не поломка**: пир исключён из комбинирования, потому что при живом
WAN внешний пул точнее (3.4 мс против 12–18 мс), и chrony синхронизируется с ним (`^*`).
Соседи держатся в резерве и вступают в игру, когда пулы пропадут, — ровно ради этого они
и заведены. Что важно проверить в этих строках — не выбор источника, а **расхождение
между нодами**: сотни микросекунд, то есть кластер согласован на два порядка точнее, чем
нужно etcd.

## Шаг 10. Клонировать на eMMC

Делается **последним**, чтобы перенести всё настроенное разом. Это единственный шаг,
требующий рук: SD приоритетнее eMMC при загрузке, поэтому переезд завершается
выключением и физическим изъятием карты — одного `reboot` недостаточно.

Голый `dd if=/dev/mmcblk0 of=/dev/mmcblk1` не годится: живая ФС даёт грязный снимок
(журнал в полёте), копируется весь объём карты, и если карта больше 32 ГБ — не влезет.
Загрузчик копируется посекторно, корень — файлами.

```bash
lsblk -o NAME,SIZE,TYPE,MOUNTPOINTS
ls -d /dev/mmcblk*boot0              # the one with boot0/boot1 is the eMMC

# 1. boot area: MBR + idbloader (sector 64) + u-boot.itb (8 MiB) all live below 32 MiB
dd if=/dev/mmcblk0 of=/dev/mmcblk1 bs=1M count=32 conv=fsync

# 2. recreate p2 across the whole eMMC
parted -s /dev/mmcblk1 rm 2
parted -s /dev/mmcblk1 mkpart primary ext2 32MiB 100%
parted -s /dev/mmcblk1 set 2 boot on
partprobe /dev/mmcblk1
mkfs.ext4 -F /dev/mmcblk1p2

# 3. distinct disk signature (optional, cosmetic)
sfdisk --disk-id /dev/mmcblk1 0xc0ffee01

# 4. copy the live root — -x stays on one filesystem
mount /dev/mmcblk1p2 /mnt
rsync -aHAXx --info=progress2 / /mnt/
ls /mnt/boot/boot.scr /mnt/boot/vmlinuz-*
grep rancher /mnt/etc/fstab          # make sure the NVMe line came along
umount /mnt && sync
poweroff
# remove the microSD card, then power on
```

Править после клонирования нечего: `/etc/fstab` на корень не ссылается, PARTUUID
U-Boot вычисляет из устройства загрузки. Флаг `-x` сам исключает `/proc`, `/sys`,
`/dev`, `/run`, `/tmp` и, главное, `/var/lib/rancher` на NVMe — они останутся пустыми
точками монтирования, а строка `LABEL=k3s-data` переедет внутри `/etc/fstab`.

```bash
findmnt /                                   # source should be the eMMC
cat /sys/block/mmcblk0/device/type          # "MMC" = eMMC, "SD" = card
```

**Нумерация `mmcblk` не фиксирована** и меняется в зависимости от порядка probe: без
карты eMMC становится `mmcblk0`, поэтому сам по себе `/dev/mmcblk0p2` в `findmnt`
ничего не доказывает. Однозначные признаки eMMC: `type=MMC`, наличие
`/dev/mmcblkXboot0`/`boot1` и полный размер раздела в `df -h /`.

## Шаг 11. Ноды 2 и 3

Шаги 1–10 со своими MAC/IP/hostname из таблицы.

### Если всё-таки клонировать карту

Соблазн понятен — на карте уже стоит весь софт. Но правок MAC и IP **недостаточно**:
образ несёт ещё три вещи, уникальные для ноды. Обезличивать удобнее всего с уже
работающей ноды 1 — вставить карту в её свободный SD-слот (карта станет `mmcblk0`,
eMMC останется `mmcblk1`):

```bash
mount /dev/mmcblk0p2 /mnt

# 1. machine-id: systemd-networkd выводит из него DHCP DUID, и два клона дерутся
#    за один лиз; пустой файл заставит systemd сгенерировать новый при загрузке
truncate -s0 /mnt/etc/machine-id
rm -f /mnt/var/lib/dbus/machine-id

# 2. hostname
echo k3s-2 > /mnt/etc/hostname
sed -i 's/k3s-1/k3s-2/g' /mnt/etc/hosts

# 3. ssh host keys: сгенерировать СРАЗУ, прямо в образ на карте.
#    Полагаться на sshd-keygen.service нельзя — у него ConditionFirstBoot=yes,
#    то есть он отработает, только если /etc/machine-id пуст на момент загрузки.
#    Разъехался порядок правок — sshd остаётся без ключей и не стартует вовсе,
#    а снаружи это выглядит как ssh: Connection refused при живой сети.
rm -f /mnt/etc/ssh/ssh_host_*
ssh-keygen -A -f /mnt

# 4. MAC и IP интерконнекта под новую ноду
grep -r . /mnt/etc/systemd/network/

# 5. NVMe на новой плате ещё не размечен: без nofail упавший маунт роняет
#    local-fs.target и загрузка уходит в emergency — то есть без sshd
sed -i 's|\(LABEL=k3s-data.*defaults,noatime\)|\1,nofail|' /mnt/etc/fstab

umount /mnt
```

Пропуск любого из пунктов даёт трудноуловимые симптомы: одинаковый machine-id — драку
за DHCP-лиз, отсутствующий `nofail` — emergency mode без сети и ssh. Если после
переноса `ssh` отвечает `Connection refused`, начинать диагностику надо с `arp -n <ip>`:
RST означает, что TCP дошёл, но отвечает либо чужое устройство на этом адресе, либо
машина без запущенного sshd.

## Шаг 12. Установка k3s

```bash
# node 1
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --cluster-init \
  --flannel-backend=host-gw --flannel-iface=lan0 \
  --node-ip=10.10.10.51 --tls-san=198.18.1.51 \
  --kubelet-arg=fail-swap-on=false \
  --kubelet-arg=resolv-conf=/run/systemd/resolve/resolv.conf \
  --disable=traefik --disable=servicelb" sh -
cat /var/lib/rancher/k3s/server/node-token

# nodes 2 and 3 (adjust the IPs per node)
curl -sfL https://get.k3s.io | K3S_TOKEN="<token>" INSTALL_K3S_EXEC="server \
  --server https://10.10.10.51:6443 \
  --flannel-backend=host-gw --flannel-iface=lan0 \
  --node-ip=10.10.10.52 --tls-san=198.18.1.52 \
  --kubelet-arg=fail-swap-on=false \
  --kubelet-arg=resolv-conf=/run/systemd/resolve/resolv.conf \
  --disable=traefik --disable=servicelb" sh -
```

Все три — server-ноды с embedded etcd, кворум 2 из 3. `/var/lib/rancher` должен быть
смонтирован **до** установки (шаг 8).

**`--flannel-backend=host-gw` — без инкапсуляции вообще.** Три ноды сидят в одном L2
(общий свитч интерконнекта), а это ровно то, чего требует host-gw: «IP routes to pod
subnets via node IPs, requires direct layer 2 connectivity». Flannel просто прописывает
маршруты `10.42.N.0/24 via 10.10.10.5N dev lan0`, вместо того чтобы гонять UDP/8472.
Выигрыш против дефолтного VXLAN: у подов честные 1500 без jumbo-кадров, нет software
encap/decap на каждый пакет (заметная доля ядра A55 на 2.5 Гбит/с), работают GRO/GSO,
трафик подов виден в `tcpdump` как обычный IP.

Плата: если появится нода **за маршрутизатором**, а не в общем свитче, host-gw
сломается и придётся вернуться на `vxlan` (плюс `MTUBytes=1550`, см. шаг 5). Backend
меняется только переустановкой k3s — выбирать нужно сразу. IPIP и GRE не рассматриваем:
flannel их не поддерживает вовсе, это опции Calico/OVN, то есть смена CNI.

Остальные флаги сажают кластерный трафик на интерконнект — без них k3s возьмёт адрес
дефолтного маршрута, то есть `wan0`, и репликация etcd вместе с трафиком подов пойдёт
через домашний роутер:

- `--flannel-iface=lan0` — по нему flannel определяет next-hop соседних нод;
- `--node-ip=10.10.10.5N` — InternalIP ноды, по нему же общается etcd;
- `--tls-san=198.18.1.5N` — wan-адрес в сертификате API, иначе `kubectl` с мака
  упрётся в несовпадение имени.

Плюс два kubelet-аргумента:

- `fail-swap-on=false` — иначе kubelet не стартует при включённом zram (шаг 9);
- `resolv-conf=/run/systemd/resolve/resolv.conf` — в `/etc/resolv.conf` лежит stub
  `127.0.0.53` от systemd-resolved, CoreDNS видит в нём себя, срабатывает loop
  detection и под уходит в CrashLoop. Нужен файл с реальными upstream-серверами.

Два `--disable` намеренные, оба нужны из-за перехода на MetalLB:

- `--disable=servicelb` — гасит встроенный k3s ServiceLB (Klipper). Klipper и MetalLB
  оба обслуживают `type: LoadBalancer`; оставить оба — аллокация адресов становится
  недетерминированной. Раз выбрали MetalLB (шаг 13), Klipper обязан уйти.
- `--disable=traefik` — встроенный Traefik ставится в связке с Klipper и стартовал бы
  до MetalLB; свой ставим на шаге 13 через helm, версия и values под контролем.

Вход трафика на bare-metal делает MetalLB (облачного LoadBalancer нет), поэтому голый
k3s тут ещё не обслуживает внешние адреса.

Проверка, что host-gw действительно работает маршрутами, а не туннелем: интерфейса
`flannel.1` быть **не должно**, а подсети соседних нод — видны в таблице маршрутизации
с next-hop на интерконнекте.

```bash
ip route | grep 10.42            # 10.42.1.0/24 via 10.10.10.52 dev lan0
ip link show flannel.1           # must not exist
ip link show cni0 | grep -o 'mtu [0-9]*'    # expect 1500 — ТОЛЬКО там, где есть поды
```

**`cni0` создаётся лениво** — мост появляется на ноде вместе с первым подом, у которого
не `hostNetwork`. Сразу после установки все системные поды сидят на первой ноде, поэтому
на нодах 2 и 3 моста нет, и это не диагноз. Здоровье flannel там смотрят по маршрутам:
`ip route | grep 10.42` показывает подсети соседей через `10.10.10.5N dev lan0`
независимо от наличия подов, плюс `/run/flannel/subnet.env` содержит свой
`FLANNEL_SUBNET`. Проверить мост на всех нодах разом можно временным DaemonSet:

```bash
k3s kubectl apply -f - <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: cni-probe
spec:
  selector:
    matchLabels: {app: cni-probe}
  template:
    metadata:
      labels: {app: cni-probe}
    spec:
      containers:
      - name: pause
        image: registry.k8s.io/pause:3.9
EOF
k3s kubectl get pods -o wide -l app=cni-probe   # по одному на ноду, мосты поднимутся
k3s kubectl delete ds cni-probe                 # мосты остаются, это нормально
```

Главная метрика здоровья на таком железе — `etcd_disk_wal_fsync_duration_seconds`.

### Сколько control plane ест на холостом ходу

Замер на пустом кластере (2026-08-04, все три ноды): `k3s-server` — **0.42–0.50 ядра из
четырёх**, RSS 500–570 МБ. В `top` это выглядит как `88% id` при 4 ядрах, то есть машина
занята на 12–20%. Не пугаться цифры «50%» в `ps`: там среднее за всю жизнь процесса, а не
доля машины.

Это нормальный idle для HA: в одном процессе `k3s-server` живут apiserver,
controller-manager, scheduler, **embedded etcd**, kubelet, kube-proxy и flannel, причём
raft шлёт heartbeat каждые 500 мс, три apiserver'а держат watch'и друг к другу и идёт
периодическая компакция. Цена кворума 2 из 3.

Проверка, что это именно idle, а не бесконечная починка чего-нибудь:

```bash
k3s kubectl get events -A --sort-by=.lastTimestamp | tail -12
curl -s localhost:2381/metrics | grep -E '^etcd_server_proposals_committed_total|^etcd_server_leader_changes_seen_total'
sleep 60   # повторить и посмотреть темп
```

`proposals_committed` на пустом кластере растёт на единицы-десятки в секунду; сотни —
признак того, что кто-то долбит apiserver. `leader_changes_seen_total` должен стоять на
месте: растущий счётчик означает, что etcd переизбирает лидера, и вот это уже проблема
(диск или сеть).

### Флаги после установки: `/etc/rancher/k3s/config.yaml`

Не всё требует переустановки. `--node-ip`, `--tls-san`, `--flannel-backend` и
`--cluster-init` зашиты в сертификаты и bootstrap-данные (см.
[«Снос и переустановка»](#снос-и-переустановка-k3s)), а вот `disable`, `kubelet-arg`,
`etcd-arg` и прочее меняются файлом плюс рестартом.

```bash
install -d -m 0700 /etc/rancher/k3s
cat > /etc/rancher/k3s/config.yaml <<'EOF'
# Options that can be changed with a restart. Keep the full disable list here:
# repeated flags in the file and on the command line do not reliably merge.
disable:
  - traefik
  - servicelb
  - metrics-server
EOF
systemctl restart k3s
```

**Список `disable` дублируется целиком**, вместе с `traefik` и `servicelb` из шага 12 —
иначе есть риск, что файл перекроет флаги командной строки и отключённые компоненты
вернутся.

`metrics-server` выключен намеренно: он опрашивает kubelet всех нод каждые 15 секунд и
на этом железе стоил ~6% ядра, а нужен только для `kubectl top` и HPA. Метрики в этом
парке собирает VictoriaMetrics (шаг 13), которая скрейпит kubelet напрямую и в
metrics-server не нуждается. Если `kubectl top` понадобится — убрать строку и
перезапустить, k3s поставит его обратно.

Раскатывать **по одной ноде**, дожидаясь `Ready` перед переходом к следующей: рестарт
k3s уводит control plane этой ноды, и кворум 2 из 3 держится, только пока соседи живы.

```bash
systemctl restart k3s && sleep 60
systemctl is-active k3s
k3s kubectl get nodes                       # все три Ready
k3s kubectl get deploy -n kube-system       # metrics-server исчез
```

k3s удаляет ресурсы отключённого компонента сам — руками `kubectl delete` не нужно.

## Снос и переустановка k3s

Часть флагов `INSTALL_K3S_EXEC` меняется **только переустановкой с нуля**: `--node-ip`,
`--tls-san`, `--flannel-backend`, `--cluster-init`. Правка юнита и рестарт не помогут —
адреса и SAN уже зашиты в выпущенные сертификаты и в bootstrap-данные etcd. Второй
повод — повреждённые данные после блэкаута.

**Повторный прогон `get.k3s.io` поверх сломанной установки ничего не чинит:** k3s
переиспользует существующие ключи в `/var/lib/rancher/k3s`, а если старый процесс висит
в `activating`, до него даже не доходит рестарт. Сносить нужно явно.

```bash
/usr/local/bin/k3s-killall.sh          # стопает юнит, чистит маунты, netns, iptables-правила
systemctl kill -s SIGKILL k3s.service  # добить залипший процесс, см. грабли ниже
/usr/local/bin/k3s-uninstall.sh
rm -rf /etc/rancher/node /var/lib/rancher/k3s
systemctl list-jobs                    # k3s.service тут быть не должно
ls -la /var/lib/rancher/ /etc/rancher  # ожидаем пусто, кроме lost+found на NVMe
```

Drop-in'ы `10-require-data.conf` (шаг 8) и `15-wait-for-time.conf` (шаг 9) uninstall не
удаляет — он сносит сам `k3s.service`, но каталог `k3s.service.d` оставляет. Проверить,
что оба на месте, и только после этого ставить заново по шагу 12.

Грабли, все проверены на живой ноде:

- **Залипший `activating` глотает рестарты.** Если k3s-server так и не стал ready, юнит
  остаётся в `activating (start)` с незакрытым job'ом, и `systemctl restart` от
  установщика просто встаёт в очередь за ним. Признак: в `systemctl status` есть строка
  `Job: NNN`, а `/proc/<Main PID>/exe` указывает в **старый** распакованный
  `data/<hash>/bin/k3s` — то есть новый бинарь ни разу не запускался. Лечится только
  `systemctl kill -s SIGKILL`.
- **Пропажа питания во время установки уничтожает данные.** ext4 в `data=ordered`
  журналирует метаданные, но не содержимое: файлы остаются на месте с **нулевой
  длиной**. Маркер — `find /var/lib/rancher/k3s -type f -size 0`; штатно нулевые только
  `data/.lock` и `agent/containerd/containerd.log`. Если в списке `server/token` или
  `server/db/etcd/config` — bootstrap-данные не восстановить, только полный снос.
  Симптом в журнале обманчив: `failed to create certificate request ... error loading
  key from ...: <nil>` (пустой PEM) вместо честного «файл пуст».
- **`/etc/rancher/node/password` переживает uninstall** — при переустановке нода может
  получить отказ в регистрации по несовпадению пароля. Отсюда `rm -rf /etc/rancher/node`.
- **Часы.** Если блэкаут был, к моменту переустановки проверить `date` и гейт из
  шага 9 — иначе свежие сертификаты выпустятся с датой эпохи и всё повторится.

Проверка, что установка легла целой:

```bash
systemctl is-active k3s
k3s kubectl get node -o wide
find /var/lib/rancher/k3s -type f -size 0 -printf '%s\t%p\n'   # только .lock и containerd.log
```

Контрольный `reboot` после первой успешной установки обязателен: только он показывает,
что нода поднимается сама — с маунтом NVMe, гейтом по времени и без ручных шагов.

## Шаг 13. Сервисный слой (storage + вход трафика + нагрузка)

Кластер поднят, но пустой. Дальше — отдельное дерево [`apps/`](apps/README.md):
storage (NFS-провижнер + local-path), вход трафика (**MetalLB** пул `198.18.1.200–210`
+ **Traefik** VIP `.200`) и сама нагрузка (VictoriaMetrics, Grafana, mosquitto,
zigbee2mqtt, outline, ocserv). Всё раскатывает идемпотентный
[`apps/deploy.sh`](apps/deploy.sh):

```bash
# helm нужен, но k3s его НЕ ставит — либо доставить на ноду, либо гонять с мака
# с экспортированным /etc/rancher/k3s/k3s.yaml (подменив server: на IP ноды)
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
cd apps
./deploy.sh              # storage → metallb → traefik → workloads → ingress
```

Скрипт пропускает манифесты с незаполненными `<PLACEHOLDER>` и шаблоны секретов
(`*.secret.example.yaml`) — детали, storage-модель и карта адресов в
[`apps/README.md`](apps/README.md).

> **Почему свой Traefik, а не встроенный k3s.** MetalLB в любом случае требует
> `--disable=servicelb` (иначе Klipper дерётся с ним за `type: LoadBalancer`), а
> встроенный Traefik идёт в связке с Klipper и стартует до MetalLB — его Service повис
> бы в `Pending`. Раз «из коробки» всё равно надо переконфигурировать под MetalLB,
> проще поставить свой helm-релизом: чистый порядок (MetalLB → Traefik, VIP сразу),
> обычные values в git вместо `HelmChartConfig` CRD, версия не трогается апгрейдом k3s.
> Если предпочесть встроенный — оставить `--disable=servicelb`, убрать `--disable=traefik`
> и настраивать Traefik через `HelmChartConfig`; выгоды это уже не даёт.

Перед раскаткой:

- исключить пул `198.18.1.200–210` из DHCP роутера (иначе конфликт IP);
- завести DNS `*.k3s.local → 198.18.1.200`;
- создать секреты вне git из `*.secret.example.yaml`.

## Известные риски

- **Питание слота M.2.** В DTS у `&pcie2x1` нет `vpcie3v3-supply` (у обоих RTL-слотов
  прописан `vcc3v3_pcie`) — слот разведён под WiFi-модуль на 1–2 Вт, а не под SSD с
  пиками 3–5 Вт. Брать DRAM-less 2230/2242, следить за `nvme nvme0: I/O tag … timeout,
  reset controller` в dmesg.
- **PCIe-линк на холодную.** Болячка RK3568: `Phy link never came up`, SSD случайно не
  определяется после cold boot (DietPi #7517). Прогнать несколько полных обесточиваний,
  прежде чем считать диск исправным. У Armbian есть патч
  `pcie_dw_rockchip-increase-PCIe-LTSSM-timeout-for-cold-boot`; на чистом mainline его
  нет — если воспроизводится, это повод переехать на Armbian или перенести патч.
- **Загрузка с NVMe невозможна без пересборки U-Boot.** `nanopi-r5c-rk3568_defconfig`
  в mainline не содержит `CONFIG_NVME_PCI` (у R5S — содержит; Armbian берёт ровно этот
  defconfig). Отсюда раскладка «U-Boot и `/boot` на eMMC, данные на NVMe». Если корень
  нужен на NVMe — пересобрать U-Boot с одной строкой `CONFIG_NVME_PCI=y`
  (`CONFIG_PCI` и `CONFIG_PCIE_DW_ROCKCHIP` уже включены).
- **Питание платы.** 5 В USB-C на плату с двумя 2.5GbE и активным NVMe: просадка даёт
  случайные ребуты, а это развал кворума. Отдельный БП ≥3 А на ноду, не хаб на троих.
  **Симптом со стороны диска (k3s-1, 2026-08-04):** под записью контроллер NVMe
  пропадает с шины целиком —

  ```
  nvme nvme0: controller is down; will reset: CSTS=0xffffffff, PCI_STATUS=0x10
  nvme nvme0: Disabling device after reset failure: -19
  Buffer I/O error on dev nvme0n1p1, logical block …, lost async page write
  ```

  `CSTS=0xffffffff` — регистры читаются как все единицы, то есть устройство исчезло, а
  не зависло; `-19` = ENODEV, reset не вернул его. Лечилось **сменой блока питания**.
  Ядро в этом же сообщении предлагает `nvme_core.default_ps_max_latency_us=0 pcie_aspm=off
  pcie_port_pm=off` — это вторая версия (APST/ASPM у DRAM-less SSD), пробовать её стоит
  только если исправный БП не помог.

  Отсюда правило: **после любой замены питания или SSD — нагрузочный тест до установки
  k3s**, иначе отвал диска посреди bootstrap'а даст файлы нулевой длины и неотличимую от
  блэкаута картину (см. [«Снос и переустановка»](#снос-и-переустановка-k3s)):

  ```bash
  fio --name=etcd-like --directory=/var/lib/rancher --size=2G --bs=4k --rw=randwrite \
      --fdatasync=1 --iodepth=1 --numjobs=1 --runtime=600 --time_based --group_reporting
  dmesg -T | grep -icE 'controller is down|I/O error'   # ожидаем 0
  ```

  Смотреть на хвост `fsync/fdatasync` (99-й перцентиль), а не на полосу — для etcd важна
  именно латентность. На парке 2026-08-04 тест прогнан на всех трёх нодах после замены
  БП: отвалов 0.
