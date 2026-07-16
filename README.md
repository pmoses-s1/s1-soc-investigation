# s1-soc-investigation

> **Disclaimer.** Community-supported tool, not an official SentinelOne product and not covered by
> SentinelOne support. Review what it runs and test against a non-production tenant first.

An execution engine for running a standard forensic / insider-threat query catalog across long
(90+ day) lookbacks over the SentinelOne Singularity Data Lake, without the timeouts, rate limits,
and silently-skipped queries that break notebook automation. It runs as a local, hardened Docker web
app: pick a catalog, an entity, and a lookback, hit Start, and watch every query complete slice by
slice, with a verification report at the end that proves nothing was skipped.

## The core idea

The unit of work is **one query for one time-slice**, not one query over the whole window. A 40-query
catalog over 90 days becomes 3,600 small, independent jobs instead of 40 giant ones that each either
finish or die. That single decomposition is what makes long lookbacks tractable:

- Each Long Running Query (LRQ) scans a bounded range, so the backend stops timing out.
- Each job is idempotent and individually retryable, so a failure costs one slice, not the run.
- Nothing is silently skipped: every slice ends in an auditable terminal state (`done`, `failed`,
  `permanent`), and the post-run verification confirms full coverage per query.
- A past calendar day's result never changes, so the slice key is a stable cache key: resuming a
  run, or a second overlapping investigation, re-executes only the missing slices.

## What is built (Phase 0 + Phase 1)

**Phase 0, resilient execution.** UTC day-slicing (configurable slice size), a durable SQLite job
ledger with a full state machine, resume after interruption, retry with error classification, and
merge-aware reassembly of sliced results.

**Phase 1, throughput.** The proper LRQ v2 async lifecycle (launch, poll, cancel with the
`X-Dataset-Query-Forward-Tag`), a per-token token-bucket rate governor (~2.5 rps under the 3 rps
per-user cap), a worker pool that round-robins across multiple service-user tokens to multiply the
budget, and an AIMD concurrency controller that shrinks on 429s and grows on sustained success, so it
self-tunes to whatever the backend tolerates.

Plus: a structured **activity log** of every execution, a post-run **verification** report, and a
hardened **web UI** with a user-selectable output folder.

## Quickstart

### Docker (recommended)

```bash
cp .env.example .env      # fill in S1_CONSOLE_URL and S1_LRQ_TOKENS
docker compose up --build
# then open http://localhost:8901
```

Or without compose, publishing to the host loopback and mounting your output folder:

```bash
docker build -t s1-soc-investigation .
docker run --rm -p 127.0.0.1:8901:8801 \
  -v "$PWD/investigations:/data" --env-file .env s1-soc-investigation
```

Publishing to `127.0.0.1:8901` (not `8901`) keeps the port reachable only from this machine. The app
drives privileged SDL queries with your token and is unauthenticated by default, so to serve it to
other hosts you must opt in and set a token:

```bash
docker run --rm -p 8901:8801 -e S1IE_BIND_ALL=1 -e S1IE_AUTH_TOKEN=<strong-secret> \
  -v "$PWD/investigations:/data" --env-file .env s1-soc-investigation
# then open  http://<host>:8901/?token=<strong-secret>
```

The server refuses to start network-exposed without a token, and every request must carry it.

### Local (no Docker)

```bash
pip install -r requirements.txt
set -a; source .env; set +a
python app/server.py       # then open http://localhost:8801
```

### CLI (headless / scriptable)

```bash
# Live 90-day run, 1-day slices, resumable
python -m s1engine.cli run --case CASE-1234 --entity user@corp.com \
  --catalog catalogs/insider_threat.yaml --lookback 90 -v

# Offline dry run against the built-in mock backend (no tenant needed)
python -m s1engine.cli run --case DEMO --entity alice@corp.com \
  --catalog catalogs/insider_threat.yaml --lookback 7 --mock -v

# Resume an interrupted run (same run id -> same ledger + output dir; cached slices skipped)
python -m s1engine.cli run --case CASE-1234 --entity user@corp.com \
  --catalog catalogs/insider_threat.yaml --lookback 90 --run-id CASE-1234-20260716T0900Z

# Coverage of an existing run
python -m s1engine.cli status --run-dir investigations/CASE-1234/CASE-1234-20260716T0900Z
```

## Using the UI

1. **Connect.** Paste your console URL and one or more service-user tokens (one per line for
   round-robin). Tokens are held in the server process only; the browser never receives them.
2. **Run.** Enter the case id and entity, pick a catalog, set the lookback and slice size, and choose
   an output folder (blank uses the default base, which is the mounted `/data` in Docker). Start.
3. **Watch.** The activity log streams every event: slices submitted, completed, retried, throttled,
   subdivided, or failed, with the live AIMD concurrency limit and which token ran each slice.
4. **Verify.** When the run finishes, the verification panel shows a per-query PASS / FAILED /
   INCOMPLETE table and an overall verdict. The run passes only when every slice of every query
   completed. Results, ledger, activity log, and manifest are written to your output folder.

## Credentials

The LRQ v2 API needs your tenant **console host** (`https://your-tenant.sentinelone.net`, not the
`xdr.*` V1 host) and one or more console service-user JWTs. Provide them via the in-UI Connect panel,
a mounted `.env`, or exported environment variables. Two tokens with distinct `sub` claims roughly
double the per-user rate budget. Every key is documented in `.env.example`.

## Output layout

Everything for a run lands under `<output>/<case>/<run_id>/`:

```
ledger.db          durable job ledger (state per query x slice; the resume source of truth)
activity.jsonl     append-only structured log of every execution event
slices/<query>/    per-slice result cache (immutable for past days)
results/<query>.csv + .json   merged, reassembled result per query
manifest.json      run manifest: coverage and gaps per query per day, warnings
```

## Verification and activity logging

Every execution event is written to `activity.jsonl` as it happens, so the run is fully auditable
after the fact. After each run the engine verifies that every slice of every query reached a
successful terminal state and presents the result. A query passes only when all its slices are `done`
(or were subdivided into children that all completed); the run passes only when every query passes. If
anything is incomplete, re-running with the same run id retries just the outstanding slices.

## Catalog format

A catalog is your standard query set. Each entry carries the PowerQuery body and a `merge` strategy
so sliced results reassemble correctly (count/sum are additive, min/max reduce, and
`estimate_distinct` is flagged approximate because it is not additive). `{{entity}}` is substituted
per investigation. See `catalogs/insider_threat.yaml` for a worked example and replace the bodies with
your real query set.

## Security and hardening

- Tokens are never written to disk by the app and never sent to the browser. Every SDL call is made
  server-side by the engine.
- The UI binds to `127.0.0.1` by default. Network exposure requires `S1IE_BIND_ALL=1` and a strong
  `S1IE_AUTH_TOKEN`; the server refuses to start exposed without one and enforces it on every `/api`
  call (header `X-Auth-Token` or `?token=`).
- Cross-origin POSTs are rejected unless from localhost or an allowlisted origin.
- The container runs as a non-root user, ships a healthcheck, and mounts your output folder as a
  volume. `.env` and `credentials.json` are git-ignored and docker-ignored. Never commit a token.

## Roadmap

Phase 0 and 1 are implemented. Later phases build on the same slice/ledger foundation:

- **Phase 2, content-addressed cache.** Key immutable past-day slices by content hash so re-runs and
  overlapping investigations are near-instant; the ledger and slice store already make this a small
  addition.
- **Phase 3, workbook export.** A per-case `.xlsx` workbook (one tab per query) plus the coverage
  manifest, for direct hand-off into the case folder.
- **Phase 4, orchestration.** Priority lane so an analyst's interactive queries preempt the background
  batch, and job dedupe across concurrent investigations.

## Layout

```
s1engine/
  slicing.py       UTC day-slicing + adaptive sub-slicing
  ledger.py        durable SQLite job ledger + resume + coverage
  catalog.py       query catalog model, {{entity}} templating, merge specs
  merge.py         re-aggregate sliced results (sum/min/max, distinct flagged approximate)
  rate_limiter.py  token bucket + AIMD concurrency controller
  lrq_client.py    LRQ v2 async client (launch/poll/cancel) + pluggable transport
  engine.py        orchestrator: plan -> run (pool, round-robin, retry) -> finalize
  activity.py      structured activity log (JSONL + live tail)
  verify.py        post-run verification report
  config.py        credential + console-host resolution
  cli.py           headless CLI
  testing.py       in-memory FakeTransport for offline runs and tests
app/
  server.py        hardened stdlib web server (loopback default, token, origin checks)
  index.html       single-file UI
catalogs/          example query catalog(s)
tests/             unit + end-to-end suite (run_tests.py, or pytest)
Dockerfile, docker-compose.yml, .env.example
```

## Testing

```bash
python run_tests.py      # stdlib runner, no dependencies
# or, if you have pytest:
pytest -q
```

The suite covers slicing, the ledger state machine and resume, merge correctness, the rate limiter and
AIMD, and end-to-end runs proving throttle absorption, permanent-error handling, and resume, all
offline against the mock backend.

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).
