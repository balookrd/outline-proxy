# Path-MTU Discovery в TUN UDP

Как TUN UDP engine обрабатывает датаграммы, которые upstream-транспорт
отказывается принять из-за слишком большого размера, и какой
предохранитель не даёт превратить этот сигнал в QUIC-blackhole для
обычных клиентов.

*English version: [TUN-PMTUD.md](TUN-PMTUD.md)*

---

## Когда срабатывает

Для каждого UDP-потока с TUN, который маршрутизируется в туннельный
uplink, engine оборачивает payload в SOCKS5 framing и отдаёт его в
`send_packet` транспорта. Часть транспортов не умеет фрагментировать
oversized payload и отказывает в отправке:

- raw QUIC SS-UDP — `QuicDatagramChannel` ограничен согласованным
  `max_datagram_size` (как правило ~1180 байт);
- VLESS QUIC UDP — тот же QUIC datagram limit плюс 4 байта на
  session-id;
- VLESS-UDP framing — жёсткий потолок 64 KiB на length-prefixed frame;
- Shadowsocks 2022 UDP — отказывает всему, что превышает AEAD record
  limit на uplink leg.

Отказ всплывает как `OversizedUdpDatagram { transport, payload_len,
limit }` либо `Ss2022Error::OversizedUdpUplink`. TUN engine ловит оба
варианта через `is_dropped_oversized_udp_error` и отправляет ошибку в
PMTUD-путь, а не классифицирует её как сбой uplink-а.

## Зачем мы шлём ICMP-сигнал

Отказ транспорта невидим клиенту: отправитель просто ретрансмитит тот
же oversized payload по каждому loss-таймеру. Без in-band сигнала он
никогда не узнает реальный tunnel MTU. Реальный production-кейс —
VoWiFi IKE_AUTH с клиентским сертификатом поверх raw-QUIC uplink-а:
IKE-ретрансмиты копились, сертификатный обмен не завершался, звонок
падал.

Лечение — синтезировать ICMP-ошибку в адрес исходного отправителя,
чтобы сработала его собственная PMTUD state machine:

- **IPv4** — `Destination Unreachable / Fragmentation Needed`
  (Type 3 / Code 4) с advertised Next-Hop MTU во втором слове ICMP
  заголовка (RFC 1191).
- **IPv6** — `Packet Too Big` (Type 2 / Code 0) с advertised MTU во
  втором слове (RFC 4443 §3.2).

Ответ содержит цитату исходного IP-заголовка и UDP-заголовка (8 байт
upper-layer данных), чтобы стек отправителя сопоставил ошибку с
конкретным сокетом — RFC 1812 §4.3.2.3 и RFC 4443 §3.2.

## Advertised Next-Hop MTU

Сообщённый транспортом `limit` (сколько байт SOCKS5-обёрнутого payload
транспорт согласен принять) передаётся в advertised MTU ICMP-ответа с
clamping до протокольного минимума по каждой family:

- IPv4: clamp до `IPV4_MIN_PATH_MTU = 576` (RFC 791);
- IPv6: clamp до `IPV6_MIN_PATH_MTU = 1280` (RFC 8200).

Payload самой ICMPv6 PTB обрезается так, чтобы итоговый пакет не
превышал IPv6 minimum link MTU — RFC 4443 §2.4(c).

## Throttle

Каждому flow разрешён один PTB в секунду — то же значение, что
default `net.ipv4.icmp_ratelimit` в Linux. RFC 4443 §2.4(f) делает
rate-limiting обязательным для ICMPv6; RFC 1812 §4.3.2.8 настоятельно
рекомендует его для IPv4. Бёрсты oversize-ретрансмитов поэтому
производят один PTB в секунду на flow — достаточно, чтобы любая
адекватная PMTUD state machine отреагировала, и недостаточно, чтобы
кривой отправитель устроил ICMP-шторм из TUN-интерфейса.

Состояние throttle живёт в `last_ptb_sent` timestamp на flow, поэтому
после вытеснения flow из таблицы PTB-бюджет сбрасывается вместе с ним.
Для flow, который только что был вытеснен и гоняется с cleanup-путём,
throttle консервативно возвращает «подавить»: пропустить один PTB
лучше, чем выпустить unbounded бёрст во время teardown.

## QUIC floor — почему иногда мы молчим

PTB, рекламирующий path MTU ниже собственного QUIC Initial-datagram
floor, — это проблема, а не лечение. RFC 9000 §14.1 требует от QUIC v1
endpoint-ов отправлять UDP-датаграммы с Initial-пакетами размером не
меньше **1200 байт** UDP payload (IPv6 endpoint-ы дополнительно
соблюдают minimum link MTU 1280 байт). Compliant стек, получив
ICMP-ошибку с заявленным path MTU ниже этого floor, делает вывод что
destination вообще не умеет нести QUIC — и отключает QUIC для
destination, откатываясь на TCP.

Это ровно противоположно тому, чего хочет оператор, гоняющий реальный
QUIC-трафик. Мотивирующий регрессионный кейс: Samsung Smart-TV
YouTube-клиенты отправляли QUIC Initial-датаграммы на 1200 байт через
TUN на googlevideo. SS-over-QUIC datagram channel выдавал
`OversizedUdpDatagram { limit ≈ 1180 }` на framed payload, engine
синтезировал PTB с advertised 1180 байт, и QUIC-стек телевизора
мгновенно отключал HTTP/3 для googlevideo. Сессия оставалась на TCP
навсегда, на дашбордах UDP-трафик с uplink-а пропадал.

Поэтому engine полностью подавляет PTB, когда сообщённый транспортом
limit оказывается ниже QUIC-floor для соответствующей IP family:

| IP family | Floor (байт) | Источник                                          |
| --------- | ------------ | ------------------------------------------------- |
| IPv4      | 1200         | RFC 9000 §14.1 minimum Initial UDP payload         |
| IPv6      | 1280         | RFC 9000 §14.1 + RFC 8200 minimum link MTU         |

Ниже floor oversize-дроп откатывается к pre-PMTUD-поведению: engine
молча дропает датаграмму, отправитель ретраит или таймаутит по
собственному расписанию, и клиенты сохраняют свой QUIC-state. Выше
floor — весь диапазон ~1300–1450 байт, в котором живут реальные
PMTUD-поломки, — PTB по-прежнему уходит без изменений.

`limit == None` (транспорт отказал, не указав конкретный размер)
трактуется permissively: подавлять в этом случае значит заглушить
легитимные PMTUD-сигналы на транспортах, которые просто не
сообщают размер. Clamping до протокольного минимума в ICMP builders
(576 v4 / 1280 v6) всё равно применяется, так что wire-level
advertisement всегда корректен.

## Что видит оператор

Источник истины для диагностики oversize-поведения — счётчики и
дашборды:

- `outline_ws_rust_udp_oversized_dropped_total{direction, cause}` —
  каждый oversize-дроп с разбивкой по причине (`quic_dgram`,
  `vless_quic_dgram`, `vless_udp`, `ss_socket`, …). Всплеск без
  парного PTB на проводе означает что QUIC-floor gate удерживает
  клиента от перехода в TCP fallback.
- `outline_ws_rust_tun_packet_total{direction="upstream_to_tun"}` —
  каждый синтезированный PTB виден здесь как один accepted
  upstream-to-TUN packet на emission.

QUIC-стек, который реально принимает PTB и снижает свой path MTU,
обычно повторно отправляет Initial-датаграммы нового размера; если они
снова oversize для транспорта, цикл сам ограничивается лимитом
1 PTB / sec / flow и виден как стабильный low-rate ряд `quic_dgram`
дропов.

## Surface для тюнинга

Сам QUIC Initial-datagram минимум — протокольная константа из
RFC 9000, она не подлежит negotiation per-deployment. Единственный
user-видимый knob — может ли engine отправлять PTB с advertised path
MTU ниже этого минимума:

```toml
[tun]
# По умолчанию: false. PTB, advertised path MTU которых попадает
# ниже QUIC v1 Initial-datagram минимума (1200 v4 / 1280 v6),
# подавляются — и тем самым удерживают compliant QUIC-клиентов
# на UDP.
pmtud_emit_below_quic_initial = false
```

`pmtud_emit_below_quic_initial = true` возвращает безусловную
отправку PTB для любого oversize-дропа с известным transport limit
(`None`-limit остаётся permissive при обоих настройках — см.
`should_emit_ptb_for_limit`). Используйте на инсталляциях, где
вытеснение QUIC не проблема, а явный PMTUD-сигнал на каждом дропе
важнее: каноничный пример — чистый VoWiFi / IKEv2 концентратор,
который везёт IKE_AUTH с сертификатами поверх узкого raw-QUIC
uplink-а, где PTB — единственный сигнал, позволяющий IKE retransmit
loop узнать реальный tunnel MTU до того, как звонок отвалится по
таймауту.

Trade-off:

| Настройка | sub-минимум дропы `quic_dgram`                   | Сходимость VoWiFi / IKE на узких uplink-ах |
| --------- | ------------------------------------------------ | -------------------------------------------- |
| `false`   | молча (отправитель ретраит по своему таймеру)    | медленнее (нет in-band MTU-подсказки)        |
| `true`    | один PTB / sec / flow                            | быстро (PMTUD реагирует мгновенно)           |

Throttle, builders и clamps до протокольных минимумов (576 v4 /
1280 v6 в самом ICMP заголовке) работают одинаково при обоих
настройках.

Если оператор хочет полностью отключить PMTUD-синтез (точно
воспроизвести pre-bcaf86d поведение), единственный handle — это
сообщаемый транспортом limit: транспорт, который не выдаёт
`OversizedUdpDatagram`, обходит PMTUD-путь целиком.

## Ссылки

- RFC 791 §3.1 — IPv4 minimum datagram size (576 байт)
- RFC 1191 — IPv4 Path MTU Discovery
- RFC 1812 §4.3.2.3, §4.3.2.8 — ICMP error quoting and rate limiting
- RFC 4443 §2.4(c), §2.4(f), §3.2 — ICMPv6 error message rules
- RFC 8200 §5 — IPv6 minimum link MTU (1280 байт)
- RFC 9000 §14.1, §14.2.1 — QUIC datagram size and ICMP handling
- RFC 9221 — Unreliable Datagram Extension for QUIC
