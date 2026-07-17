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
docker run --rm --pull=always -p 127.0.0.1:8901:8801 \
  -v "$PWD/investigations:/data" \
  ghcr.io/pmoses-s1/s1-soc-investigation:latest
```

Then open **http://localhost:8901**. The `--pull=always` flag makes Docker fetch the newest published
image every time; without it, `docker run` reuses whatever `:latest` you already have cached and never
picks up new builds. The `-v` mount is your output folder: everything the engine writes lands in
`./investigations` on your machine. Enter credentials in the Connect panel, or preload them:

```bash
cp .env.example .env      # fill in S1_CONSOLE_URL and S1_LRQ_TOKENS, then:
docker run --rm --pull=always -p 127.0.0.1:8901:8801 -v "$PWD/investigations:/data" \
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
docker run --rm --pull=always -p 8901:8801 -e S1IE_BIND_ALL=1 -e S1IE_AUTH_TOKEN=<strong-secret> \
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

## What you can achieve

The point of the tool is a completed, provable investigation over a window too long to run by hand.
Concretely, it lets you:

- **Reconstruct long-lookback activity for a subject.** Run a full DFIR / insider-threat catalog across
  identity, endpoint, web, cloud, SaaS, and exfil sources over 90+ days (or a fixed window like all of
  April) in a single pass, instead of babysitting queries that time out on wide ranges.
- **Scope an incident and go straight to the findings.** The verification panel sorts queries with hits
  to the top with row counts, so you see which of a large catalog actually matched for this entity, host,
  IP, or session, and can click through to preview the rows.
- **Prove completeness for audit or handoff.** The per-query, per-day verification report and the durable
  ledger show every slice reached a terminal state, so you can demonstrate nothing was silently dropped.
- **Triage many subjects at once.** Batch mode runs the same catalog across a CSV of users and rolls up
  per-user status and hit counts, so you can compare who warrants a closer look.
- **Standardise and reuse a hunt.** A versioned catalog plus template variables makes the same
  investigation repeatable for any subject, refreshable from the repo without rebuilding the image.
- **Walk away with evidence.** Every run yields an `.xlsx` workbook (one tab per query, each showing its
  PowerQuery), the raw per-day slice JSON, merged CSV/JSON per query, a manifest, and a downloadable
  activity log, all under one case folder.

## How it works, end to end

1. **Plan.** The chosen catalog is expanded against the lookback or From/To window into one job per query
   per day-slice. Queries whose required variables are unset are skipped up front, and the cost preview
   shows the resulting job count before you commit.
2. **Execute.** Jobs run through the LRQ v2 async lifecycle (launch, poll, cancel) across a worker pool
   that round-robins your service-user tokens, paced by a per-token rate governor and an AIMD controller
   that tunes concurrency to what the backend tolerates.
3. **Adapt.** Rate limits back off, timeouts and 5xx retry and then subdivide the day into smaller
   windows, and query-syntax errors are marked permanent. Every state change is recorded in the SQLite
   ledger, which is also the resume source of truth.
4. **Cache.** Immutable past-day results are content-addressed and reused, so a re-run or an overlapping
   second investigation executes only the new or changed days.
5. **Merge.** Per-day results are reassembled into one result per query (count/sum additive, min/max
   reduce, `estimate_distinct` flagged approximate).
6. **Verify and export.** Coverage is checked per query per day, the verdict is presented findings-first
   in the UI, and the run is written out as the workbook, CSV/JSON results, manifest, and activity log.

## What it does

**Resilient execution.** UTC day-slicing, a durable SQLite job ledger with resume, retry with error
classification (429 backs off, 5xx/timeout retries then subdivides, 400 syntax is permanent), and
merge-aware reassembly (count/sum additive, min/max reduce, estimate_distinct flagged approximate).

**Throughput.** The LRQ v2 async lifecycle (launch/poll/cancel with the forward tag), a per-token
token-bucket rate governor (~2.5 rps under the 3 rps per-user cap), a worker pool that round-robins
across multiple service-user tokens, and an AIMD controller that shrinks concurrency on 429s and grows
on success, self-tuning to whatever the backend tolerates. The UI auto-sizes the worker pool to
tokens x 3 as you add tokens, and shows the resulting aggregate rate; type a pool value to override, or
clear it to auto-size again.

**Content-addressed cache.** Immutable past-day slices are keyed by hash(query + window + scope) and
reused across runs, so re-running an investigation, or a second overlapping one, executes only the new
or changed days.

**Live progress and verification.** A progress bar tracks completed slices against the planned total
with a running throughput and time-to-finish estimate, and live tiles show done / cached / failed /
throttled / retried counts as they change. Every event is written to `activity.jsonl` as it happens;
after each run a verification report confirms every slice of every query completed and is presented in
the UI, findings first (queries with hits sorted to the top). Click any query to preview its merged
results inline. Download the raw activity log, or a zip of the results, from the UI or the API.

**Single and batch investigations.** Run one entity, or a batch from a single CSV whose columns are the
same variables as single mode (email plus hostname, agent_uuid, ip, username, sf_user_id, session), one
row per user. Datatables stay global. The batch view rolls up per-user status and hit counts. Investigate
a rolling lookback (e.g. last 90 days) or a fixed date window (e.g. all of April) via From/To dates.

**Plan before you run.** A live cost preview estimates the job count (runnable queries x slices, with
skipped-query count) as you change the catalog, query subset, lookback, dates, or variables. A **Test
connection** button confirms the token authenticates before you start a long run. **Recent runs** lists
past investigations (surviving restarts) and reopens any of them; an incomplete or cancelled run can be
resumed from where it stopped.

**Workbook export.** Each run produces a per-case `.xlsx`: a Summary sheet with the verification verdict
and coverage, then one sheet per query with its merged results. Each query tab shows the exact
PowerQuery that produced it at the top. The CSV/JSON results and `manifest.json` also carry the PQ.

**Catalog management.** Edit, add to, import, and export the query catalog from the UI. Saved catalogs
persist in the output volume. **Validate against SDL** launches each query over a short window to
confirm the engine accepts it (catching syntax errors) before you run a 90-day investigation.

## DFIR catalogs and variables

The bundled `catalogs/` include a DFIR insider-threat set converted from a real investigation
workbook: eight domain catalogs (`dfir_identity_access`, `dfir_endpoint`, `dfir_collab_storage`,
`dfir_web_network`, `dfir_cloud`, `dfir_saas_apps`, `dfir_exfil_dlp`, `dfir_correlation`) plus a
master `dfir_insider_threat_full` for a one-click full sweep. Pick a domain catalog per phase, or the
master to run everything the provided variables allow.

Every environment- or subject-specific value in a query is a template variable, not a hardcoded string.
The **Variables** popup groups them:

- **Investigation subject** (`{{hostname}}`, `{{agent_uuid}}`, `{{ip}}`, `{{username}}`, `{{sf_user_id}}`,
  `{{session}}`, `{{app_name}}`, `{{domain}}`, `{{login_key}}`, `{{file_or_title}}`). `{{entity}}` (the
  subject) is set on the run form. A query whose subject variables are not all set is **skipped, not
  failed**, so you run the identity phase first, fill in what you discover, and re-run to light up the
  endpoint and network queries.
- **Config datatables** (`dt_*`) for the identity-mapping queries: set the ones your tenant has.
- **Data source names** (`src_*`): the SDL `serverHost` sources each query reads from (zia, okta,
  slack, salesforce, …). These carry a default (the source's name in the reference workbook) using the
  `{{var|default}}` syntax, so queries run out of the box; override one only if your tenant ingests that
  source under a different name.

Every field has a `?` tooltip. **Import / Export variables** saves the whole set to a JSON file (or loads
one), so you can reuse a configuration across cases or share it with a teammate. The catalog dropdown
shows which variables each catalog needs and which are still unset.

**Refresh catalogs from the repo.** The **Refresh from repo** button pulls the latest `catalogs/`
from GitHub into the persisted catalogs folder at runtime, so query updates do not require rebuilding
the image. Point it at a different repo/branch with `S1IE_CATALOG_REPO` / `S1IE_CATALOG_REPO_REF`.

## Using the UI

The [step-by-step user guide](docs/user-guide.md) walks through the whole flow with screenshots:
connect, choose and validate a catalog, configure and start the run, watch the live activity log, and
read the verification panel and downloads. In short:

1. **Connect.** Console URL and one or more service-user tokens (one per line to round-robin). Tokens
   stay in the server process; the browser never receives them. Every field has a `?` with guidance.
   Use **Test connection** to confirm the token authenticates before a long run.
2. **Catalog.** Pick one, or Edit / New / Import / Export it, and Validate vs SDL. Optionally use
   **Select queries** to run only a subset, and open **Variables** to set the template vars and datatables.
3. **Run.** Choose Single or Batch, set case id and entity (or upload the batch CSV), a rolling lookback
   or a From/To date window, output folder, then Start. The cost preview estimates the job count first.
4. **Watch and verify.** The progress bar, ETA, and live tiles track execution while the activity log
   streams; the verification panel shows per-query PASS / FAILED / INCOMPLETE / SKIPPED, findings first,
   with hit counts. Click a query to preview its results. Download the activity log or result zips, or
   Resume an incomplete run. **Recent runs** reopens any past investigation.

The header shows the active build version (the running image's git sha), so you can confirm which
build you are on. Once connected, the Connect panel collapses to a summary with an **Edit** button.

## Credentials

The LRQ v2 API needs your tenant **console host** (`https://your-tenant.sentinelone.net`, not the
`xdr.*` V1 host) and one or more console service-user JWTs. Two tokens with distinct `sub` claims
roughly double the per-user rate budget. Provide them via the Connect panel or a mounted `.env`; every
key is documented in `.env.example`.

## Output layout

Everything for a run lands under `<output>/<case>/<run_id>/`:

```
ledger.db                    durable job ledger (state per query x slice; the resume source of truth)
activity.jsonl               append-only structured log of every execution event (the raw run trace)
slices/<query>/<slice>.json  RAW per-slice output from SDL for each day (the raw logs)
results/<query>.csv + .json  merged, reassembled result per query (also carries the pq used)
<case>_<run_id>.xlsx         workbook: Summary + one tab per query, each tab showing its PowerQuery
manifest.json                coverage and gaps per query per day, warnings, and the pq used
```

**Where are the raw logs?** The raw, unmerged output SDL returned for each day is in
`slices/<query_id>/<slice>.json` (columns + values). For row-style queries (a `| columns … | limit N`
body) these are the raw event rows with every projected field; for aggregate queries they are the
per-day grouped numbers before merging. Note the LRQ engine returns only the columns your query
projects, so for full-fidelity event capture use a row-style query rather than an aggregate. The raw
execution trace (launches, polls, cache hits, retries, verdicts) is `activity.jsonl`.

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

- **Case report export.** Generate a formatted per-case report (findings, timeline, coverage, IOCs) as
  a document from a completed run, not just the raw workbook and result zips.
- **Timeline view.** A cross-query, cross-source chronological timeline of the entity's activity built
  from the merged results, for faster storyline reconstruction.
- **Scheduled sweeps.** Recurring runs of a catalog against a saved entity or user list, so a standard
  hunt executes on a cadence and flags new findings between runs.
- **Saved scenarios.** Named bundles of catalog + query subset + variables + lookback that an analyst
  can reuse and share, instead of re-entering the run configuration each time.
- **Orchestration.** A priority lane so an analyst's interactive queries preempt the background batch,
  and job dedupe across concurrent investigations.

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
