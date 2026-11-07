# Browser fingerprint drift monitor

Russian version: [README.ru.md](README.ru.md).

`outline-ws-rust` imitates browsers on every layer a DPI box can see: the TCP
and QUIC ClientHello, QUIC transport parameters, the HTTP/2 preface and the
request headers. The profiles (`crates/outline-transport/src/fingerprint_profile.rs`
and the tables next to it) were tuned against Chrome 157 and Firefox 159
(`tests/data/versions.json`). `cargo test` catches regressions of our code
against those captures, but not browsers moving on. This monitor covers that:
`.github/workflows/fingerprint-drift.yml` (Mondays at 06:00 UTC and on manual
dispatch) captures fresh Chrome stable and Firefox release, compares them with
`baseline/*.json` and keeps one `fingerprint-drift` issue open while they
differ.

Only browsers are compared, never our client: the baseline is what the
browser sent when the profiles were tuned.

## Files

| File | Role |
|---|---|
| `capture.sh` | Installs the browsers (`--install`), runs the scenarios, writes `versions.json` and a gzipped Chrome net-log per scenario |
| `tls_sink.py` | Records each ClientHello, terminates TLS, answers h2/h1, records the requests |
| `../quic-initial-sink.py` | Records QUIC Initial datagrams |
| `ca.sh`, `page.html` | Throwaway CA for `localtest.me`; a page doing fetch GET/POST and a WebSocket |
| `pcapwrite.py` | Writes the bytes the sinks received into a pcap as synthetic IPv4/TCP packets |
| `pcapread.py` | Reads the pcaps through tshark (QUIC Initial decryption, CRYPTO/TCP reassembly, JA4, HPACK) |
| `hello.py` | Parses a ClientHello into comparable fields |
| `normalize.py` | pcap → snapshot JSON; the only place that decides what is noise. Fails when the UA major disagrees with `versions.json` |
| `compare.py` | Snapshot vs baseline → Markdown report; exit 0 match, 1 drift, 2 incomplete, 3 drift beside an incomplete one. Lists show what was added and removed |
| `issue.sh` | Opens, refreshes or closes the `fingerprint-drift` issue |
| `baseline/` | The reference snapshots (generated from `tests/data/`, never edited by hand) |

Scenarios, all against `localtest.me`: the page over h2 (port 8443), the page
over http/1.1 only (8444; Chrome opens its WebSocket connection there with an
`http/1.1`-only hello), the QUIC Initial (8445; Chrome is forced with
`--origin-to-force-quic-on`, Firefox follows the page's `Alt-Svc`). Browsers
run under Xvfb, not headless.

## What counts as noise

GREASE values, the extension order (random everywhere except Firefox over
TCP), the transport-parameter order (random in Chrome), the source connection
ID value, reserved QUIC versions, JA4's c-part (its inputs are compared one by
one), lengths, and the values of `host`/`:authority`, `origin`, `referer`,
`sec-websocket-key`, `accept-language` (the header itself, its name and
position, still counts). The platform in `user-agent` and
`sec-ch-ua-platform` is masked: the baseline was taken on macOS, CI runs on
Linux. The sink issues no TLS session tickets (`num_tickets = 0` in
`tls_sink.py`), so later connections are not resumed: a resumed hello adds
`pre_shared_key`.

## Running locally

Linux (or Docker) with the browsers installed:

```bash
scripts/fingerprint-drift/capture.sh --install /tmp/cap      # drop --install if the browsers are present
python3 scripts/fingerprint-drift/normalize.py /tmp/cap /tmp/snap
python3 scripts/fingerprint-drift/compare.py scripts/fingerprint-drift/baseline /tmp/snap /tmp/report.md
```

`CHROME=` and `FIREFOX=` pick other binaries (defaults `google-chrome` and
`firefox`), e.g. `CHROME=chromium` on arm64: Google Chrome has no linux/arm64
build, and Chrome crashes under the QEMU emulation of Docker on Apple silicon.

Unit tests:

```bash
python3 -m unittest discover -s scripts/fingerprint-drift/tests -t scripts/fingerprint-drift/tests
```

## When a run fails

An incomplete snapshot ("Snapshot lacks layers") is a partial capture, not
drift: the job fails, and the issue is touched only if the other browser
drifted. A capture that fails outright (no ClientHello at all) stops the job
in `capture.sh` / `normalize.py`, before anything is compared.

Before suspecting the browser, look at the Chrome net-logs in the run artifact
(`*.netlog.json.gz`; the JSON ends unclosed because Chrome is killed by the
timeout). A fresh Google Chrome rebuilds its cert verifier in its first
moments and drops every connection, which is why `page.html` waits 2 s before
the first request.

## When the issue opens

1. Read the report: a new major means new UA and `sec-ch-ua` strings; a hello,
   preface or header change means the profile tables need the same change.
2. Re-measure and update `PROFILES` and the tables. The refresh checklist is
   in the comment on `PROFILES_REFRESHED_AT_UNIX`
   (`crates/outline-transport/src/fingerprint_profile.rs`).
3. Put the browser directories and `versions.json` from the new capture in
   `tests/data/` (layout as `capture.sh` writes it; the CI artifact has it).
   Do not copy the `ca/` directory: it holds a throwaway private key.
4. Rebuild the baseline:

   ```bash
   python3 scripts/fingerprint-drift/normalize.py scripts/fingerprint-drift/tests/data scripts/fingerprint-drift/baseline
   ```

5. Run `cargo test -p outline-transport`: the test
   `drift_baselines_describe_the_profiled_browser_majors` checks that the
   baseline majors match `PROFILES`.
6. The next scheduled run closes the issue.
