# Email alerting on uplink degradation (design)

Date: 2026-08-07
Status: design agreed in chat; awaiting owner review of this document

## Problem

The fleet has no alerting at all. Degradation is noticed by a human opening
Grafana, which means an uplink can sit lossy for hours before anyone looks —
exactly what happened on 2026-08-02, when `.102` stayed on a lossy `senko` from
03:30 to 10:00 (see `2026-08-03-uplink-loss-signal-design.md`). The loss signal
built after that incident now drives failover, but nothing tells the owner that
it fired, that a client stopped reporting, or that every uplink is down.

The goal is email on real degradation, quiet otherwise.

## Environment (verified 2026-08-07)

On the `.102` gateway (`instance="ubuntu"` in VictoriaMetrics):

- VictoriaMetrics in docker, host network, `:8428`, `-retentionPeriod=90d`,
  scraping from `/victoria-metrics-data/scrape.yaml`.
- Grafana OSS **13.0.2** in docker, `-p 4000:3000`, with
  `/opt/grafana/provisioning` bind-mounted to `/etc/grafana/provisioning`.
  `/opt/grafana/provisioning/alerting/` already exists and is empty.
- No vmalert, no Alertmanager, no MTA — `curl` is the only relevant tool.
- Outbound `smtp.gmail.com:587` and `:465` reachable from `.102`, `cloud1` and
  `cloud2`.
- 21 scrape targets, all `up == 1`. Jobs: `node-exporter`, `oc-exporter`,
  `rust-ss-exporter`, `rust-ws-exporter`, `victoriametrics`. The client
  exporter `rust-ws-exporter` runs on four instances: `cloud1`, `cloud2`,
  `debian`, `ubuntu`. `cloud3`, `cloud4`, `aeza` and `senko` still appear in
  7-day history but are no longer scraped, so they will not produce alerts.
- `cloud1` and `cloud2` both run Ubuntu 24.04 with nginx on 80/443 and python3.
  `.102` reaches both over HTTPS with a valid certificate (`http_code=200`,
  `ssl_verify_result=0`).

Uplink series carry the labels `instance`, `hostname`, `job`, `group`,
`transport` (`tcp`/`udp`) and `uplink`. The `transport` split is why a single
uplink appears twice per instance — it is not duplication, and rules must keep
the dimension rather than collapse it.

## Approach

**Grafana unified alerting**, provisioned from files. Grafana 13 provisions
alert rules, contact points and notification policies from
`/etc/grafana/provisioning/alerting/*.yaml`, which maps onto the workflow the
dashboards already use: the file in the repository is authoritative, the host
copy is a deployment artifact, and the provider re-reads it without a restart.

Rejected alternatives:

- **vmalert + Alertmanager.** Portable rules and `promtool` testing, at the
  price of two new containers and two more configs to keep alive, for one email
  recipient. Grafana already does grouping, deduplication, silences and
  resolved notifications.
- **systemd timer + script.** No new infrastructure, but hysteresis,
  deduplication, resolved notifications and state would all be hand-written —
  which is precisely the work Grafana already did.

## Alert rules

Every rule is evaluated once a minute. Thresholds below are derived from seven
days of fleet data, not chosen a priori.

### Hard outages (critical)

**`TargetDown`** — `up{job=~"rust-ws-exporter|rust-ss-exporter"} == 0` for
**5m**. A client or server stopped reporting. Five minutes clears a restart
(scrape interval plus the binary coming back) without clearing a real death.

**`AllUplinksDown`** — `sum by (instance) (outline_ws_uplink_health_effective)
== 0` for **3m**. Every leg on that client is unhealthy — no tunnel at all.
Current baseline is 12 on `cloud1`/`cloud2` and 4 on `debian`/`ubuntu`, so zero
is unambiguous and needs no per-instance tuning.

### Quality degradation (warning)

**`UplinkCarrierLossHigh`** — `outline_ws_uplink_carrier_loss_ratio > 0.05` for
**10m**, kept split by `(instance, uplink, transport)`. Over seven days the
maxima were 0.42 (`ubuntu`/`nuxt2`), 0.24 (`ubuntu`/`senko`), 0.14
(`cloud1`/`senko`) and 0.077 (`cloud3`/`nuxt`) — all spikes. The 10-minute `for`
is what separates a spike from sustained loss; the 5% threshold matches the
loss-failover threshold already calibrated on `.102` and `.104`.

**`UplinkFailoverStorm`** — `sum by (instance) (increase(
outline_ws_uplink_failovers_total{job="rust-ws-exporter"}[15m])) > 30`.

The threshold had to be set from peaks, not averages. Seven-day totals suggest a
background near 1.5 failovers per 15 minutes, which would make 10 look generous;
in fact the 15-minute peak over the same week reached 63 on `debian`, 50 on
`cloud1`, 28 on `ubuntu` and 24 on `cloud2`. Counting how often each candidate
threshold would have been true (7 days, sampled every 5 minutes, 2016 samples
per instance):

| threshold | ubuntu | debian | cloud1 | cloud2 |
|-----------|--------|--------|--------|--------|
| > 10      | 1051   | 1016   | 330    | 54     |
| > 20      | 80     | 31     | 37     | 26     |
| > 30      | 0      | 3      | 3      | 0      |

At 10 the rule would be true for over half of the week on two nodes — a mail
alarm that is permanently on. At 30 it is roughly one episode per node per week
(overlapping 15-minute windows make three consecutive samples one episode).

The `job` matcher is required — without it the query also picks up series from
`cloud3` and `cloud4`, which ran the client earlier in the same window and are no
longer scraped.

### Hygiene (info)

**`UplinkCertExpiringSoon`** —
`(outline_ws_uplink_cert_expiry_timestamp_seconds - time()) / 86400 < 14` for
**1h**. The nearest expiry today is 49 days out, so this stays silent until it
matters.

**`ClientRestarted`** — `resets(sum by (instance) (
outline_ws_uplink_selected_total)[1h:1m]) > 0`. The client exports no
`process_start_time_seconds`, so a restart is detected as a counter reset
instead. `outline_ws_uplink_selected_total` is the right carrier for it: it
increases on all four clients (551–21302 over six hours) and its 24-hour reset
count was 1 on both `debian` and `ubuntu`, matching known restarts. This catches
watchdog-driven restarts, which are otherwise invisible.

### Deliberately excluded

- **Per-uplink `health == 0`.** On a four-leg fleet where one leg failing is
  routine and covered, this would be the dominant source of noise. Single-leg
  degradation still surfaces through the loss and failover rules.
- **A latency rule.** `outline_ws_uplink_effective_latency_seconds` currently
  spans 0.03–0.28 s across uplinks and transports with no established baseline;
  any threshold now would be a guess. Revisit once there is a calibrated normal.

## Notification policy

Default route: `group_by [alertname, instance]`, `group_wait 30s`,
`group_interval 5m`, `repeat_interval 12h`, resolved notifications on.

The long `for` durations and the 12-hour repeat both follow from a rule the
fleet has already taught us: a spike right after a restart is not a regression.
A single transient must not produce mail, and a genuine ongoing problem must not
produce mail every five minutes.

## Dead man's switch

Grafana alerting cannot report its own death, nor the death of `.102` or the
home uplink. Two independent observers cover that.

**On `.102`:** an always-firing rule `DeadMansSwitch` with the expression
`count(up) >= 1`. The condition deliberately runs *through* the datasource
rather than using `vector(1)`: if VictoriaMetrics dies, the query stops
returning data, the rule stops firing, and the heartbeat goes silent. That
extends coverage from "Grafana is alive" to "VictoriaMetrics, Grafana, the host
and the home link are all alive". It routes through its own notification policy
(matcher `alertname = DeadMansSwitch`) to a contact point holding **two** webhook
integrations, `https://cloud1.beerloga.su/hb/<token>` and
`https://cloud2.beerloga.su/hb/<token>`, with `repeat_interval 5m` and resolved
notifications off.

**On `cloud1` and `cloud2`, independently:** an nginx `location = /hb/<token>`
that logs to a dedicated `heartbeat.log` and returns 204, plus a systemd timer
running every 5 minutes. If the log's mtime is older than **15 minutes**, the
watcher sends mail through the same Gmail SMTP account using python3 `smtplib` —
no package to install — and records state so the message goes out once rather
than every five minutes. Recovery sends a matching "resolved" message.

Two observers exist because a single one cannot distinguish its own isolation
from the gateway's death: aeza and senko are, as of today, fully blocked from
Russian networks, and any single observer could end up on the wrong side of such
a block. Mail from one node means that node's path is probably broken; mail from
both means `.102` is genuinely down. The observer's hostname therefore goes in
the subject line. The cost is duplicate mail during a real outage — an
acceptable trade against silence.

## Secrets

Nothing secret enters the repository.

- **SMTP password** — a Gmail app password (16 characters, requires 2FA on the
  account). Stored on `.102` at `/opt/grafana/secrets/smtp`, mode `0600`, owner
  `1000:1000` to match the container user, written without a trailing newline.
  `grafana.sh` gains `-v /opt/grafana/secrets:/etc/grafana/secrets:ro` and
  `GF_SMTP_PASSWORD__FILE=/etc/grafana/secrets/smtp`, alongside
  `GF_SMTP_ENABLED`, `GF_SMTP_HOST=smtp.gmail.com:587`, `GF_SMTP_USER` and
  `GF_SMTP_FROM_ADDRESS`.
- **Heartbeat token** — the repository holds the provisioning file with a
  `__HEARTBEAT_TOKEN__` placeholder; the deploy script substitutes the real
  token from a host-local file. This avoids depending on whether `$__file{}`
  interpolation is supported in alerting provisioning, which datasource
  provisioning supports but alerting provisioning is not documented to.

The same app password is also needed on `cloud1` and `cloud2`: their watchers
send mail themselves, without going through Grafana — that independence is the
whole point of the dead man's switch. Each stores it in
`/etc/heartbeat-watch/smtp.env`, mode `0600`, owner `root`, alongside the
recipient address and the heartbeat token.

The owner creates the app password and writes the secret files on all three
hosts; no secret is ever transmitted through the session.

## Files and deployment

New in the repository:

- `ops/grafana/alerting/rules.yaml` — the six alert rules plus `DeadMansSwitch`.
- `ops/grafana/alerting/contact-points.yaml` — the email contact point and the
  two-webhook heartbeat contact point (token placeholder).
- `ops/grafana/alerting/policies.yaml` — default route and the `DeadMansSwitch`
  route.
- `ops/grafana/README.md` — extended with the alerting deployment procedure.
- `ops/heartbeat/nginx-heartbeat.conf` — the `location` snippet.
- `ops/heartbeat/heartbeat-watch` — the python3 watcher.
- `ops/heartbeat/heartbeat-watch.service` / `.timer` — systemd units.
- `ops/heartbeat/install.sh` — installer, modelled on `ops/watchdog/install.sh`.

Deployment order: heartbeat receivers on `cloud1` and `cloud2` first (so the
switch has somewhere to report), then the Grafana alerting files, then the
`grafana.sh` change for SMTP.

**Only the last step needs a container restart**, because SMTP is configured
through environment variables; the alerting files are picked up live. That
restart, and the `nginx -s reload` on both cloud nodes, will be requested
explicitly rather than performed as part of the rollout.

## Validation

1. Grafana's "Test" button on the email contact point — proves SMTP end to end.
2. A temporary rule with an always-true condition — proves the rule → policy →
   email path, then is removed.
3. `curl` to each heartbeat URL — proves nginx logging and the 204.
4. Heartbeat silence test: pause the `DeadMansSwitch` rule and confirm both
   observers mail after 15 minutes, then confirm the resolved message when it
   resumes. This is the only test that exercises the failure path itself.
5. Rule queries are replayed against the last 7 days of VictoriaMetrics data
   before rollout, confirming each would have fired only on real events. Done
   during design for three of them:
   - `UplinkCarrierLossHigh` with the 10-minute sustain would have been true for
     5 series and 1–14 samples each over the week — a handful of episodes across
     the whole fleet.
   - `UplinkFailoverStorm` at 30, as tabulated above.
   - `TargetDown` with `for 5m` would have discarded the short scrape gaps
     (1–7 minutes on `ubuntu`, `debian`, `nuxt`, `nuxt2`) and kept the real ones:
     `cloud3` 21 min, `debian` 19 min, and `cloud4` 1271 min — the last being the
     decommissioned node, since removed from `scrape.yaml`.

   `ClientRestarted` would have fired twice in the last 24 hours — one counter
   reset each on `debian` and `ubuntu` — which is the intended behaviour, not
   noise. `AllUplinksDown` and `UplinkCertExpiringSoon` had no positive samples
   in the window: no client lost every leg, and the nearest certificate expiry is
   49 days out.

## What actually happened on rollout (2026-08-07)

Deployed to `cloud1`, `cloud2` and `.102` the same day. Confirmed working:
receivers answer 204 on the right token and 404 on a wrong one; both watchers run
on their timers reporting `state=up`; all seven rules are in Grafana's database;
and the pulse reaches both nodes every minute
(`"POST /hb/<token>" 204 "Grafana"`). Both observers sent real mail, delivered to
the owner's mailbox — the observer path is proven end to end.

The mail path through Grafana and the dead man's switch were both validated the
same evening, in one cycle: a temporary always-true rule went in while the
heartbeat webhook URL was deliberately pointed at a wrong token, so the observers
faced a real delivery failure rather than a simulated one.

```
21:15:40  last pulse before the break
21:17     self-test rule live, webhook broken     → self-test mail delivered
21:31     cloud1 → down                           → mail delivered
21:36     cloud2 → down                           → mail delivered
21:38:14  configuration restored, pulse resumes
21:41     both observers → up                     → resolved mail delivered
```

The five minutes between the two observers are worth remembering when reading a
real alert: their timers are not synchronised, so one node's mail routinely
arrives up to five minutes before the other's. That is timer phase, not evidence
that one path is worse.

Six things the design got wrong, all found by verification:

- **"Grafana re-reads provisioning, no restart needed" was false for alerting.**
  Dashboards have a file provider with `updateIntervalSeconds`; alerting is
  provisioned once at startup. Files copied 27 seconds after startup left zero
  rules in the database. Every alerting deploy needs a restart.
- **The installer's backup broke nginx's config.** `nginx.conf` includes
  `sites-enabled/*` by bare glob, so a backup written next to the original was
  loaded as a second config: `conflicting server name "*.beerloga.su", ignored`.
  Caught by `nginx -t` before the reload. Backups now live in
  `/etc/nginx/heartbeat-backups/`.
- **`--dry-run` was not dry.** It persisted state, so a diagnostic run marked the
  outage "already notified" and would have swallowed the next real alert. Split
  into `--dry-run` (touches nothing) and `--simulate` (for tests).
- **The sending account is `balookrd@gmail.com`, not the address in the user
  profile.** The app password authenticates only against the account it was
  created for; the mismatch surfaced as `535 BadCredentials` with a
  correctly-formatted 16-character password, which reads as a broken secret
  rather than a wrong username.
- **`docker restart` does not pick up launcher edits.** It restarts the container
  with the environment it was *created* with, so provisioning files are re-read
  but a changed `GF_SMTP_USER` is not. Environment changes need the full
  re-create through `grafana.sh`; provisioning changes only need a restart.
- **Deleting a rule from the file does not delete it from Grafana.** Alerting
  provisioning adds and updates only, and provisioned rules cannot be removed
  through the UI either. Removal takes an explicit `deleteRules:` entry — unlike
  dashboards, where deleting the file removes the dashboard.

One measurement changed a rule: client restarts run ~13 per week on `ubuntu` and
~12 on `debian`, far too often for the default route, so `ClientRestarted` got its
own daily-digest route. `resets` also had to move off the aggregated `sum`, where
a series appearing or disappearing counts as a reset.

## Telegram as a second channel (added 2026-08-08)

Every Grafana alert now goes to Telegram as well as mail, through a single
contact point `owner` carrying both integrations. Telegram is the channel that
actually reaches a phone; mail stays as the fallback for a blocked Telegram or a
revoked bot token. Validated the same way as mail, with a temporary self-test
rule: both channels delivered, no integration errors.

**The dead man's switch stays mail-only, and that is forced.**
`api.telegram.org` answers from `.102` — including from inside the Grafana
container — but times out from both `cloud1` and `cloud2`, which is exactly where
the observers live. Routing them through a node's own tunnel would make the most
important alert depend on the thing it is watching, so the observers keep mail.

Two mechanical differences from the SMTP secret are worth remembering. Grafana
reads the SMTP password from a file (`GF_SMTP_PASSWORD__FILE`), but a bot token
can only be a setting value — so it is substituted by `deploy.sh` from
`~/.config/outline/telegram-bot-token` and ends up inside
`contact-points.yaml` on the node. And `chat_id` cannot be discovered without the
user first messaging the bot: Telegram withholds the id until then and forbids
bots from writing first.

## Risks and known limits

- **App passwords may be unavailable.** Accounts under Google Advanced
  Protection cannot create them; that would force a different mailbox.
- **Decommissioned nodes ring forever.** `TargetDown` fires until the target is
  removed from `scrape.yaml` — as would have happened with `cloud4`, retired on
  2026-08-06. Removing a node from the fleet now includes removing its scrape
  entry.
- **A single observer can cry wolf.** Mail from one cloud node may mean only
  that the path to that node is blocked. The subject line names the observer so
  this is visible immediately.
- **Gmail sending limits** (~500/day) are far above any plausible alert volume,
  but a rule flapping at `repeat_interval 5m` would be visible as unusual
  traffic on the account.
- **Grafana's alert state lives in its sqlite database** under `/opt/grafana/data`.
  Losing that volume loses silences and alert history, not the rules.
