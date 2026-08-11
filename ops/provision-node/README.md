# provision-node — clone a configured fleet node onto a fresh host

Three scripts that take a working node (the *reference*) and reproduce it on an
empty one: packages, `/opt`, binaries, systemd units, nginx, sysctl, docker
workloads, root crontab and the secrets that tie them together.

What "the node" contains differs by node family, so all of it lives in a
**profile** under `profiles/`. The scripts themselves hold no per-family
knowledge, and the chosen profile is copied into the bundle — a bundle is
self-describing on the target.

| Profile | Family | Shape |
|---|---|---|
| `cloud1` | entry node | ss+ws, ocserv, unbound+dnsproxy, ddns as a container, netplan, IPv4 |
| `nuxt` | exit node | ss-rust, dumbproxy, unbound, ddns as a container, IPv6 `/64` + ndppd |

Both were built against live nodes (Ubuntu 24.04, x86_64); nothing is hardcoded
to those hostnames.

| Script | Runs on | Touches |
|---|---|---|
| `collect-from-reference.sh` | workstation | reads the reference over ssh, writes a bundle locally |
| `install.sh` | the new node, as root | everything on that node |
| `register-uplink-user.sh` | workstation | creates one user on each peer via its control API |

## Sequence

```bash
# 1. Snapshot the reference (read-only; restarts nothing there)
./collect-from-reference.sh --reference sysadm@cloud1.beerloga.su \
    --profile cloud1 --out ./bundle-cloud1

# 2. Announce the node to the peers it dials through
./register-uplink-user.sh --user cloud2 --template cloud1 --out ./cloud2-uplink-creds \
    --peer nuxt:sysadm@nuxt.beerloga.su \
    --peer senko:sysadm@senko.beerloga.su \
    --peer aeza:sysadm@aeza.beerloga.su \
    --alias-cidr 87.242.85.181/32 \
    --alias-peer mmv@198.18.1.104:cloud \
    --alias-peer mmv@198.18.1.102:cloud

# 3. Ship bundle + scripts to the new node
rsync -a --delete ./bundle-cloud1/ sysadm@cloud2.beerloga.su:/tmp/provision-bundle/
rsync -a ./ sysadm@cloud2.beerloga.su:/tmp/provision-node/
rsync -a ./cloud2-uplink-creds sysadm@cloud2.beerloga.su:/tmp/

# 4. Dry-run, then install
ssh sysadm@cloud2.beerloga.su 'sudo /tmp/provision-node/install.sh \
    --bundle /tmp/provision-bundle --host cloud2 \
    --uplink-creds /tmp/cloud2-uplink-creds \
    --shared-uplink beerloga-1 --shared-uplink beerloga-2 --dry-run'

ssh sysadm@cloud2.beerloga.su 'sudo /tmp/provision-node/install.sh \
    --bundle /tmp/provision-bundle --host cloud2 \
    --uplink-creds /tmp/cloud2-uplink-creds \
    --shared-uplink beerloga-1 --shared-uplink beerloga-2'
```

Step 2 is entry-node-only. An exit node dials no peers, so cloning `nuxt` is
just collect → ship → install:

```bash
./collect-from-reference.sh --reference sysadm@nuxt.beerloga.su \
    --profile nuxt --out ./bundle-nuxt

ssh sysadm@<new-node> 'sudo /tmp/provision-node/install.sh \
    --bundle /tmp/provision-bundle --host nuxt2 \
    --ipv6-prefix 2a0f:cdc6:500:XXX::/64'
```

`--ipv6-prefix` is what makes a dual-stack clone its own node: it rewrites
`ndppd.conf` and `[outbound] ipv6_prefix` in the ss-rust config, which otherwise
still name the reference's `/64`. Without it the install warns and leaves them
alone.

ss-rust probes the prefix at startup and logs either `outbound IPv6 startup
probe succeeded` or `… failed for all attempts; disabling random outbound IPv6
source`. When it fails, check in this order:

1. **`/etc/ndppd.conf` and `[outbound] ipv6_prefix` — do they name *this* node's
   `/64`?** If either still carries the reference's prefix, ndppd answers
   neighbour solicitations for someone else's subnet and every address in the
   real `/64` is unreachable. This is the likely cause after a partial re-run —
   see "Re-running" below.
2. Only then suspect the hosting: some providers route just the single assigned
   address rather than the whole prefix. The server falls back to the default
   source and keeps working, but the rotation stays dead until the prefix is
   routed.

Either way the check is the same — take an address from the prefix and send
from it:

```bash
ip -6 addr add <prefix-with-random-suffix>/128 dev lo
ping6 -c3 -I <that-address> 2606:4700:4700::1111
ip -6 addr del <prefix-with-random-suffix>/128 dev lo
```

One thing the reference has is deliberately outside the clone: the **GRE/BGP
tunnels** `bgp0`/`bgp1`. Because those tunnels are defined in the reference's
`/etc/network/interfaces`, this profile collects no network configuration at
all — the new node's interfaces are set up before install runs.

Two hooks in that file are not about addressing, though, and a clone is broken
without them:

```
post-up /opt/network/ipset-init.sh            # → iptables-init.sh → the whole
                                              #   firewall, incl. v4/v6 MASQUERADE
up ip -6 route add local <prefix> dev lo      # accept the entire routed /64
```

So `install.sh` re-expresses them as a generated `post-up.service` (oneshot,
before `outline-ss-rust`) with this node's own prefix substituted in. The unit
also exports `WAN_V6_PREFIX`, because `network-online.target` can be satisfied
by IPv4 alone: without it the firewall script may run before any IPv6 address
exists, silently skip the v6 MASQUERADE rule, and leave it missing for the whole
uptime — which is exactly what happened on the reference, where the same hook
sits in the ifupdown `inet` section and runs before the `inet6` one. On a
netplan/networkd host the ifupdown hooks would never have fired anyway. Without
this the node comes up with no firewall and no NAT — an exit node that neither
filters nor forwards.

The firewall scripts themselves need no rewriting: `iptables-init.sh` derives
the WAN interface, its address and the routed `/64` at run time, and re-running
it is a no-op (every rule is added through `-C || -A`). The mesh allow-list in
`iptables-update.sh` is left alone on purpose — see "Announcing the node to the
mesh" below. The `--ipv4`, `--wan-if` and `--ipv6-prefix` flags exist for a
reference that still hardcodes its own identity, and to override a wrong guess.

## Two peer conventions

The fleet identifies a client node in two different ways, so the registration
script has two modes:

- **Per-node account** (`--peer`, the `main` group: nuxt, senko, aeza). The peer
  keeps one user per node. The new node gets its own account cloned from the
  reference's — same secret paths and `fwmark`, fresh `vless_id`/password. Those
  credentials land in the creds file and `install.sh` swaps them into the
  matching `[[outline.uplinks]]` block.
- **Shared account plus alias** (`--alias-peer`, the `russia` group: `.104`,
  `.102`). Every cloud node dials as the same `cloud` user; nodes are told apart
  by `[users.aliases]`, which relabels accounting by source address. Nothing is
  created — the new node's `/32` is merged into that map. Credentials stay
  shared, so those uplinks are declared with `--shared-uplink <name>` and keep
  the reference's values.

Without `--shared-uplink`, `install.sh` refuses to proceed when an uplink has no
credentials of its own — a typo in an uplink name fails loudly instead of
silently leaving the reference's identity in place.

The `--peer` key is the uplink `name` in the new node's ws-rust config, not a
hostname. `--alias-peer` takes `<ssh-target>:<shared-user>`, and the alias map
is read, merged and written back whole, because the control API replaces it.

## What the repo owns rather than the reference

Almost everything a new node gets is a copy of what the reference had. A few
files are the other way round: they live in `assets/`, they are identical on
every node of a family, and `install.sh` writes them over whatever the bundle
carried. A profile lists them in `ASSET_FILES`, and `%HOST%` / `%DOMAIN%` in an
asset expand to the node being installed — which is how one file can carry
per-node certificate paths.

Today that is the **unbound stack**, and it is there because collecting it from
a reference is exactly how the four live nodes drifted apart without anything
noticing (found and repaired by hand on 2026-08-08):

- `cloud1`/`cloud2` ran `unbound-exporter` with no `restart: unless-stopped`, so
  the container died at the first reboot of the node and never came back. Nobody
  saw it: unbound itself kept resolving, and the only symptom was a gap in a
  Grafana row.
- `nuxt`/`nuxt2` had no exporter service at all, `control-enable: no` in
  `unbound.conf` — which would have starved one anyway — and no
  `/unbound-exporter/metrics` location in nginx, so even a working exporter
  could not have been scraped through 443.
- All four had `extended-statistics` off, so even where the exporter did run it
  answered with 27 metric families instead of 56 and 13 of the 21 panels in the
  Unbound dashboard stayed empty.

| Asset | Installed as | Used by |
|---|---|---|
| `assets/unbound/unbound.conf` | `/opt/unbound/unbound.conf` | both profiles |
| `assets/unbound/docker-compose.entry.yml` | `/opt/unbound/docker-compose.yml` | `cloud1` — unbound, unbound-exporter, dnsproxy |
| `assets/unbound/docker-compose.exit.yml` | `/opt/unbound/docker-compose.yml` | `nuxt` — unbound, unbound-exporter |

The resolver config is one file for both families. Compared to what the exit
nodes run today it adds a single line, `cache-max-negative-ttl: 60`, which the
entry nodes already had: without it an NXDOMAIN sticks for `cache-max-ttl`, an
hour, so a name that starts resolving stays broken long after the authoritative
side is fixed. A reprovisioned exit node picks that up.

Two of its settings are there for the dashboard rather than for the resolver, so
change them only together with
[`ops/grafana/README.md`](../grafana/README.md#unbound): `extended-statistics:
yes`, without which `unbound-control stats_noreset` returns 93 lines instead of
195 and 13 of the 21 panels of `unbound-dashboard.json` (uid `9FQf4fEWz`) have
nothing to draw, and the absence of `statistics-cumulative`, which the exporter
does not want — it polls `stats_noreset`, and the counters rise monotonically
downstream anyway.

The exporter binds `127.0.0.1:9167` and is scraped through nginx on 443, so the
site file needs a matching `location`. That file comes from the reference, so a
profile declares the location instead and `install.sh` inserts it into the last
`server` block when it is missing:

```
NGINX_LOCATIONS=( "/unbound-exporter/metrics:http://127.0.0.1:9167/metrics" )
```

The `verify` phase checks both halves — that the exporter answers on 9167 and
that the site actually serves the location — because the second one is invisible
from the node itself: everything local looks healthy while the scrape 404s.

`assets/victoria-metrics/scrape-unbound-exporter.yaml` is the fourth piece and
the only one nothing applies: the scrape config lives on `.102`, not on the node
being provisioned. See "Deliberately not automated" below.

## What the bundle holds

```
MANIFEST            profile, reference host/os/arch/addresses/machine-id, binary versions, access-keys dir
profile.conf        the profile this bundle was collected with
assets/             the repo-owned files above, copied in so the bundle stays self-describing
SHA256SUMS          verified by install.sh --only preflight
packages.list       deliberately installed packages (docker-ce set, nginx, jq, ipset, …)
docker-images.list  images to pull
crontab.root        root crontab of the reference
ocserv-run.sh       regenerated from the *running* container, not from the stale
                    update-ocserv.sh on disk
payload/            /opt whitelist, binaries, units, nginx, sysctl, docker daemon.json,
                    daemon configs (ndppd), and — where a profile collects them —
                    network files, which are staged and never applied
secrets/            0700: service configs, users.txt, ACME material, ocserv passwords
```

Dormant material on the reference is not collected: `accel-ppp`, `wireguard`,
`ping-check`, `*.bak*`, `*-old.sh`, `__pycache__`, the ddns venv (rebuilt on the
target) and the reference's own host certificate (the new node issues its own).

**The bundle contains live secrets. Do not commit it.**

## Phases

`install.sh` runs these in order; `--only` / `--skip` take any subset, and every
phase is safe to re-run.

| Phase | Does |
|---|---|
| `preflight` | root, arch match, bundle checksums, does `<host>.beerloga.su` point here, uplink creds present |
| `identity` | what a disk-image clone kept and no bundle carries: machine-id (regenerated when it is still the reference's), hostname, the `/etc/hosts` line |
| `packages` | docker apt repo + packages, `daemon.json` (restarts docker only if it changed) |
| `users` | `outline-ss-rust`, group `certs`, state/log directories — plus `outline-ws` and its directories on profiles that carry the client (`INSTALL_WS_RUST=1`, entry only) |
| `files` | `/opt`, `/usr/local/{bin,sbin}`, units, nginx site, sysctl, `occtl` symlink, and the generated `post-up.service` where the profile defines one. Then the repo-owned files (`ASSET_FILES`) over the top, and any missing `NGINX_LOCATIONS` into the site |
| `secrets` | service configs with owners and modes, `users.txt`, ocserv passwords, ACME material, then `permission-certs.sh` (needs the `users` phase to have created `outline-ss-rust`) |
| `rehost` | rewrites every reference-host reference: cert paths, ddns cron, dnsproxy flags, ocserv `SRV_CN`, and the IPv6 `/64` when `--ipv6-prefix` is given. Adds the profile's `COMPOSE_REQUIRED_ARGS`, then audits itself: nothing may still name the reference, and every cert/key path it names must exist here |
| `uplinks` | swaps this node's own `vless_id`/`password` into each `[[outline.uplinks]]` block |
| `network` | unpacks the reference's interface definitions into `/root/provision-network-<host>` and stops. Never applied — see below |
| `ddns` | rebuilds the python venv, or builds the container image, per the profile |
| `certs` | issues `<host>.beerloga.su` via lego, re-runs `permission-certs.sh`, repoints the `/opt/ddns/certs` symlinks at the new host certificate |
| `cron` | installs the root crontab |
| `services` | enables and starts units, pulls images, starts node-exporter / ocserv / unbound+dnsproxy, regenerates access keys |
| `verify` | units, timers, `/metrics`, listening ports, containers, the `NGINX_LOCATIONS` the exporters are scraped through; asks this node's own resolver for its own name (`VERIFY_SELF_DNS`); and — on dual-stack profiles — the IPv6 default route, ndppd, the `local` route for the `/64` and the MASQUERADE rule |

### What a disk-image clone brings that no bundle does

These scripts assume a fresh host. When the "fresh host" is instead a copy of
the reference's disk (how `cloud2` and `nuxt2` were made), it arrives carrying
identity the bundle never mentions, so nothing in `files`/`secrets`/`rehost`
would ever look at it. The `identity` phase does:

- **`/etc/machine-id`.** Two live hosts sharing one means a shared journal id
  and DHCP DUID, and any metric labelled by it silently merges the two.
  Regenerated when it still matches the reference's (recorded in the MANIFEST);
  already-running services keep the old id until the node reboots.
- **Hostname and `/etc/hosts`.** Ubuntu's `127.0.1.1 <fqdn>` line names the
  reference on a clone. Beyond the confusion, a resolver running on this host
  may serve that line to the whole network: on 2026-08-08 `dnsproxy` (hosts
  files on by default, `network_mode: host`, so docker hands it a copy of
  `/etc/hosts`) answered `cloud2.beerloga.su → 127.0.1.1` for the fleet, and
  every node that dialled cloud2 by name hit its own port 443 instead. That is
  what `--hosts-file-enabled=false` in the dnsproxy asset and the
  `VERIFY_SELF_DNS` check now cover.

What still has no automatic answer is anything the *peers* hold: `shard_id`,
`[cluster] peers` and the mesh allow-list — see below.

### Deliberately not automated

- **Joining `cloud.beerloga.su`.** The cron line that adds the node to the
  shared round-robin record is installed commented out. Joining is what sends
  live client traffic here, so it stays a separate decision — pass
  `--join-shared-dns` when you mean it.
- **Restarting peers.** `register-uplink-user.sh` uses the control API, which
  applies users live.
- **Scraping the new node.** The exporters answer, nginx serves them and nothing
  collects them: the scrape config is `/opt/victoria-metrics/data/scrape.yaml`
  on `.102`, a different host from the one being installed. Add a target block
  per job — `assets/victoria-metrics/scrape-unbound-exporter.yaml` is the
  `unbound-exporter` one, kept here as the reference shape — then reload rather
  than restart:
  ```bash
  curl -s http://127.0.0.1:8428/-/reload
  ```
  The `verify` phase says so at the end of a run. A node missing from that file
  is not broken in any way it can detect: it simply never appears in Grafana.
- **Announcing the node to the mesh.** `/opt/network/iptables-update.sh` holds
  the peer allow-list for the QUIC mesh port (9443) as literal addresses, and
  the same file is rolled out to every edge node — that is what keeps the list
  identical everywhere. It is therefore never rehosted, and a new node is not
  reachable on 9443 until its address is added to that file **on every edge
  node**. The same goes for `[cluster] peers` in each node's ss-rust config, and
  for the clone's own `shard_id`, which arrives as a copy of the reference's and
  must be made unique — the install warns about it but cannot choose a value.
  Fleet-wide edit, not part of an install.
- **Applying network configuration.** The `network` phase only unpacks the
  reference's `interfaces`/`interfaces.d` for a human to merge. Bringing an
  interface down over ssh on a host with no console is how a node gets
  reinstalled from scratch; if you do merge them, do it under a dead-man:
  `systemd-run --on-active=5min systemctl restart networking`.

### Guard worth knowing about

`register-uplink-user.sh` refuses to write to a peer whose `outline-ss-rust`
predates the control-API persistence fix (`b48525b5`): an older build rewrites
`config.toml` on user creation and drops the other users with it. The check
greps the binary for `failed to serialize user entry as TOML`; a peer that
fails it is skipped with a warning, not silently written to.

## Re-running

Every phase is idempotent, but a full re-run is a *restore from the bundle*, not
a merge: the `secrets` phase overwrites `/etc/outline-{ss,ws}-rust/config.toml`
with the reference's copy, and `rehost` / `uplinks` then re-apply this node's
identity on top. Anything changed on the node afterwards — users added through
the control API or the dashboard, hand edits — is lost. To re-run one part
without that, scope it: `--only rehost`, `--only uplinks`, `--skip secrets`.

**`files` and `secrets` restore the reference's own values; `rehost` is what
makes them this node's.** Running the first without the second — say
`--only files` to refresh one unit — silently puts back the reference's ndppd
prefix, `[outbound] ipv6_prefix`, certificate paths and cert domains. The
install warns when it notices this and prints the `--only rehost` command to
fix it, but the warning is the only sign: nothing else complains, and a node in
that state looks healthy while advertising the wrong `/64`.

Without `--yes` the script asks for confirmation before the first phase, and a
non-interactive run (ssh with no tty) aborts rather than proceeding silently.

## Limitations

- `packages.list` is filtered through the profile's `PACKAGES_ALLOW_RE`. A
  package installed on the reference outside that pattern is not carried over —
  extend it when a node family grows a new dependency.
- **A locally built image on a node that cannot reach pypi.org.** The ddns
  responder is built from a Dockerfile whose `pip install` needs pypi.org, and
  some hosting cannot reach it (files.pythonhosted.org may still work, which
  makes the failure look odd). Carry the image over instead — the ddns phase
  skips the build when `DDNS_IMAGE` is already loaded:
  ```bash
  ssh <reference> 'sudo docker save update_domain:latest' | ssh <new-node> 'sudo docker load'
  ```
- `docker-images.list` holds only images backing a *running* container, minus
  the profile's `DOCKER_IMAGE_EXCLUDE_RE`, and pulling is best-effort: a locally
  built image (nuxt's ddns responder) has no registry, and the ddns phase builds
  it instead.
- `--peer` specs split on `:`, so an ssh target with a port does not parse. Use
  a host alias in `~/.ssh/config` instead.
- The bundle pins the reference's binaries by content. It does not build them —
  use `ops/deploy/deploy-binary.sh` for upgrades afterwards.

## Adding a profile

Copy the closest existing profile and adjust the lists. The variables split into
collection (`OPT_PATHS`, `UNIT_PATHS`, `SECRET_TARS`, `PACKAGES_ALLOW_RE`, …) and
installation (`ENABLE_UNITS`, `DOCKER_START`, `DDNS_MODE`, `VERIFY_*`, …); every
one has a default, so a profile only states what it has.

Rules worth keeping:

- **Anything holding a credential belongs in `SECRET_TARS`, not the payload.**
  Check where a service actually reads its config from rather than where the
  package puts it: on this fleet the live file is regularly the one in `/opt`,
  not the stock path under `/etc` or `/usr/local/etc`, and it is the live one
  that carries the keys. Collecting it as ordinary payload puts credentials in
  the non-secret half of the bundle.
- **List a file in `REHOST_FILES` if it names the reference host.** Each
  `rehost_file` call reports how many occurrences it replaced and warns when a
  file names neither the old nor the new host, so a drifted reference surfaces
  instead of silently producing a node that points at its template. The audit at
  the end of the phase is the backstop: it fails loudly on a leftover mention
  and on any `.crt`/`.key`/`.pem` path that does not exist on this node.
- **`ASSET_FILES` is for a file no reference should be the source of.** Use it
  when every node of a family should hold the same content and drift between
  them is a bug rather than local tuning — and exclude the same path in
  `OPT_EXCLUDES`, so the bundle does not also carry the reference's copy for the
  asset to overwrite a moment later. Anything genuinely per-node goes in as
  `%HOST%` / `%DOMAIN%`; anything secret does not belong in an asset at all,
  because `assets/` is committed.
- **`NGINX_LOCATIONS` is for a route the site file must have**, written as
  `<location>:<proxy_pass URL>` and inserted into the last `server` block when
  missing. It is how an exporter reaches the scrape: a node whose site file
  predates the exporter answers on loopback and 404s on 443, and nothing on the
  node notices.
- **`COMPOSE_REQUIRED_ARGS` is for a flag the reference predates**, written as
  `<compose-file>:<service>:<flag>` and inserted at the head of that service's
  `command:` list. Use it when the fix belongs on every clone rather than on the
  reference alone; a service whose `command:` is inline (`["-d", "-c", …]`)
  is reported instead of rewritten.
- **Set `VERIFY_SELF_DNS=1` on a family that runs a resolver.** The check asks
  the node's own resolver for the node's own name and fails on a loopback
  answer — the shape a leaked hosts entry takes.
