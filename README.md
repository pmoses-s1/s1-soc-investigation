# s1-soc-investigation

> **Disclaimer.** Community-supported tool, not an official SentinelOne product and not covered by
> SentinelOne support. Review what it runs and test against a non-production tenant first.

An execution engine for running a standard forensic / insider-threat query catalog across long
(90+ day) lookbacks over the SentinelOne Singularity Data Lake, without the timeouts, rate limits,
and silently-skipped queries that break notebook automation. It runs as a local, hardened Docker web
app: pick a catalog, an entity, and a lookback, hit Start, watch every query complete slice by slice,
and get a verification report that proves nothing was skipped, plus a workbook and downloadable logs.

## Install and run (Docker, one command)

```bash
docker run --rm -p 127.0.0.1:8901:8801 \
  -v "$PWD/investigations:/data" \
  ghcr.io/pmoses-s1/s1-soc-investigation:latest
```

Then open **http://localhost:8901**. `docker run` pulls the image automatically the first time, so
there is no separate `docker pull`. The `-v` mount is your output folder: everything the engine writes
lands in `./investigations` on your machine. Enter credentials in the Connect panel, or preload them:

```bash
cp .env.example .env      # fill in S1_CONSOLE_URL and S1_LRQ_TOKENS, then:
docker run --rm -p 127.0.0.1:8901:8801 -v "$PWD/investigations:/data" \
  --env-file .env ghcr.io/pmoses-s1/s1-soc-investigation:latest
```

Convenience wrapper (loads `.env`, mounts `./investigations`, publishes to loopback):

```bash
./run.sh                  # http://localhost:8901
```

Publishing to `127.0.0.1:8901` (not `8901`) keeps the port reachable only from this machine. The app
drives privileged SDL queries with your token and is unauthenticated by default, so to serve it to
other hosts you must opt in and set a token:

```bash
docker run --rm -p 8901:8801 -e S1IE_BIND_ALL=1 -e S1IE_AUTH_TOKEN=<strong-secret> \
  -v "$PWD/investigations:/data" --env-file .env ghcr.io/pmoses-s1/s1-soc-investigation:latest
# then open  http://<host>:8901/?token=<strong-secret>
```

The server refuses to start network-exposed without a token, and every request must carry it. Build
locally instead of pulling with `docker build -t s1-soc-investigation .` or `docker compose up --build`.

## The core idea

The unit of work is **one query for one time-slice**, not one query over the whole window. A 40-query
catalog over 90 days becomes 3,600 small, independent jobs instead of 40 giant ones that each either
finish or die. That decomposition is what makes long lookbacks tractable:

- Each Long Running Query scans a bounded range, so the backend stops timing out.
- Each job is idempotent and individually retryable, so a failure costs one slice, not the run.
- Nothing is silently skipped: every slice ends in an auditable terminal state, and the post-run
  verification confirms full coverage per query.
- A past UTC day's result never changes, so it is cached and reused across runs and investigations;
  only the volatile current day re-runs.

## What it does

**Resilient execution.** UTC day-slicing, a durable SQLite job ledger with resume, retry with error
classification (429 backs off, 5xx/timeout retries then subdivides, 400 syntax is permanent), and
merge-aware reassembly (count/sum additive, min/max reduce, estimate_distinct flagged approximate).

**Throughput.** The LRQ v2 async lifecycle (launch/poll/cancel with the forward tag), a per-token
token-bucket rate governor (~2.5 rps under the 3 rps per-user cap), a worker pool that round-robins
across multiple service-user tokens, and an AIMD controller that shrinks concurrency on 429s and grows
on success, self-tuning to whatever the backend tolerates.

**Content-addressed cache.** Immutable past-day slices are keyed by hash(query + window + scope) and
reused across runs, so re-running an investigation, or a second overlapping one, executes only the new
or changed days.

**Verification and activity logging.** Every event is written to `activity.jsonl` as it happens; after
each run a verification report confirms every slice of every query completed and is presented in the
UI. Download the raw activity log, or a zip of the results, from the UI or the API.

**Workbook export.** Each run produces a per-case `.xlsx`: a Summary sheet with the verification verdict
and coverage, then one sheet per query with its merged results, alongside the CSV/JSON and manifest.

**Catalog management.** Edit, add to, import, and export the query catalog from the UI. Saved catalogs
persist in the output volume. **Validate against SDL** launches each query over a short window to
confirm the engine accepts it (catching syntax errors) before you run a 90-day investigation.

## Using the UI

1. **Connect.** Console URL and one or more service-user tokens (one per line to round-robin). Tokens
   stay in the server process; the browser never receives them. Every field has a `?` with guidance.
2. **Catalog.** Pick one, or Edit / New / Import / Export it, and Validate vs SDL.
3. **Run.** Case id, entity, lookback, slice size, output folder, then Start.
4. **Watch and verify.** The activity log streams live; the verification panel shows per-query
   PASS / FAILED / INCOMPLETE and download buttons for the activity log and result zips.

## Credentials

The LRQ v2 API needs your tenant **console host** (`https://your-tenant.sentinelone.net`, not the
`xdr.*` V1 host) and one or more console service-user JWTs. Two tokens with distinct `sub` claims
roughly double the per-user rate budget. Provide them via the Connect panel or a mounted `.env`; every
key is documented in `.env.example`.

## Output layout

Everything for a run lands under `<output>/<case>/<run_id>/`:

```
ledger.db                    durable job ledger (state per query x slice; the resume source of truth)
activity.jsonl               append-only structured log of every execution event
slices/<query>/              per-slice results for this run
results/<query>.csv + .json  merged, reassembled result per query
<case>_<run_id>.xlsx         workbook: Summary + one sheet per query
manifest.json                coverage and gaps per query per day, warnings
```

The shared cache lives at `<output>/.slice_cache/` and is reused across runs.

## Security and hardening

- Tokens are never written to disk by the app and never sent to the browser. Every SDL call is made
  server-side by the engine.
- The UI binds to `127.0.0.1` by default. Network exposure requires `S1IE_BIND_ALL=1` and a strong
  `S1IE_AUTH_TOKEN`; the server refuses to start exposed without one and enforces it on every `/api`
  call. Cross-origin POSTs are rejected unless from localhost or an allowlisted origin.
- The container runs as a non-root user, ships a healthcheck, and mounts your output folder as a volume.
  `.env` and `credentials.json` are git- and docker-ignored. Never commit a token.

## Command line (inside the image)

The same engine has a headless CLI, useful for scripting and CI:

```bash
docker run --rm -v "$PWD/investigations:/data" --env-file .env \
  ghcr.io/pmoses-s1/s1-soc-investigation:latest \
  python -m s1engine.cli run --case CASE-1234 --entity user@corp.com \
    --catalog catalogs/insider_threat.yaml --lookback 90 --out /data -v

# dry run offline (no tenant), resume with the same --run-id, export a run:
python -m s1engine.cli run --case DEMO --entity a@corp.com --catalog catalogs/insider_threat.yaml --lookback 7 --mock
python -m s1engine.cli export --run-dir /data/CASE-1234/<run_id> --kind results
```

## Roadmap

- **Orchestration.** A priority lane so an analyst's interactive queries preempt the
  background batch, and job dedupe across concurrent investigations.

## Layout

```
s1engine/   slicing, ledger, catalog, merge, rate_limiter, lrq_client, engine,
            cache, workbook, activity, verify, validate, export, config, cli, testing
app/        server.py (hardened stdlib web server) + index.html (single-file UI)
catalogs/   example query catalog(s)
tests/      unit + end-to-end suite (run_tests.py, or pytest)
Dockerfile, docker-compose.yml, run.sh, .env.example
```

## Testing

```bash
python run_tests.py      # stdlib runner, no dependencies; or: pytest -q
```

Covers slicing, the ledger and resume, merge correctness, the rate limiter and AIMD, and end-to-end
runs proving throttle absorption, permanent-error handling, and resume, all offline against the mock
backend.

## License

GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).
