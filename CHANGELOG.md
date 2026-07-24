# Changelog

## v0.4.2

Query scope enforcement (stop investigations pulling the whole tenant), faster
handling of heavy slices, and resilient run status. Every query-syntax claim was
verified live against a tenant before shipping.

### Subject scoping (no more tenant-wide leaks)

- **Every query now has a `scope`:** `subject` (must filter to the investigated
  person/endpoint), `pivot` (scoped by a discovered domain/file/app/session/login
  key), `environment` (intentionally tenant-wide: Top/Unique/totals/rankings/
  inventory), or `coverage` (source/schema presence). See the catalog guide.
- **The engine hard-skips a subject/pivot query that has no matching filter set**,
  so a single-subject investigation never silently returns every employee. Skips
  are reported with a clear reason (`no_subject_value`), never failed.
- **Rewrote the mis-scoped detail panels** (the reported leak, e.g. `zia-dlp-26`
  "All ZIA Raw Activity" filtered only on the source) to filter to the subject:
  ZIA on `event.user`/`event.deviceowner`, EDR on `agent.uuid`/`endpoint.name`/
  `src.process.user`, oplockdown `owner`, prompt-security `log.user`, Google
  Workspace `actor.email`/`event.owner`, Salesforce `username`/`UserId`. The
  multi-source correlation panels get a trailing subject filter on their unified
  user column. True fleet-wide panels stay `environment`, labelled so analysts
  know the results are not subject-specific.
- **Scope audit** (`s1engine/lint.py` + `cli validate`) flags any subject/pivot
  query that lacks its filter; a bundled-catalog regression test fails the build
  if the leak is ever reintroduced.
- New `catalogs/dfir_location_compliance.yaml` (63 subject-scoped queries).
- New `catalogs/dfir_itm_detections.yaml` (92 queries) mapped to
  [Insider Threat Matrix](https://insiderthreatmatrix.org/detections) detection IDs (anti-forensics,
  browser/OS artifacts, USB, registry, DNS/proxy/VPN, cloud resource deletion, M365/Entra). Query
  bodies were live-validated and kept exactly as authored; each is scope-labelled (87 subject, 5
  aggregate volume timelines as environment). Merged into the master `dfir_insider_threat_full`
  de-duplicated by body (7 exact-body duplicates skipped); the master is now 725 queries.

### Execution reliability

- **Wall timeouts subdivide immediately** instead of retrying the same-size slice
  up to `max_attempts` times (which just times out again). A genuine transient
  error still retries first. At the smallest window a timeout fails with a "scope
  to a subject or shorten the lookback" hint.
- **Run status is always persisted and recoverable.** A crashed or interrupted run
  no longer reopens as `unknown`: the terminal status is written in a `finally`,
  and on reopen the verdict is recomputed from the ledger DB, so the run shows an
  accurate, resumable status. Existing interrupted runs remain fully resumable.

### UI

- Query-selection list shows a colour-coded **scope tag** per query; the Variables
  popup gains a **Clear variables** button; skip and timeout reasons read clearly
  in the activity log.

## v0.4.1

Catalog library expansion, a query test harness, and cost-saving execution controls.
Every change was verified against the test suite, and every query-syntax claim was
verified live against a tenant before shipping.

### Catalogs

- **Merged the SOC Investigation Library v2.** 483 new DFIR queries folded into the
  `dfir_*` catalogs (matched by body, 152 duplicates skipped, 0 failed), normalized for
  SDL and linted. New categories `dfir_ai_prompt` and `dfir_coverage_identity`. ~1,289
  queries total, de-duplicated.
- **Fixed `psc-02`** (removed the `obj['Sensitive Data']` sub-index that returned
  `Expected ")"`), verified live.
- New [catalog guide](docs/catalog-guide.md) documenting each catalog and a logical run
  order for DFIR.

### Query test harness

- **Static linter** (`s1engine/lint.py`) flags the syntax pitfalls SDL rejects, verified
  live: `field == null` (500), `obj['key']` / `obj."key"` sub-indexing (400), `| head`
  (400), `sort field desc|asc` (400), and un-converted placeholders. Verified valid and
  therefore NOT flagged: `!= null`, `field = *`, top-level `"quoted fields"`, bare
  case-sensitive `contains`, and `nolimit`.
- **`python -m s1engine.cli validate`** lints and (optionally) launches each query with
  dummy variables against SDL; `--lint-only` needs no tenant. A pytest fails the build if
  any bundled catalog regresses.

### Execution controls

- **Per-day source-existence pre-check.** For a query anchored to a single source, the
  engine probes that source once per day (lazy: one cached probe in the common case,
  shared across all its queries) and skips the day as empty if there is no data. Checks
  both `serverHost` and `dataSource.name`, and warns when a source's data lives under the
  other field than the query uses. Toggle: **Skip empty source-days**.
- **Configurable source field.** Force every source-anchor predicate to `serverHost` or
  `dataSource.name`, or leave queries as written. Run-form dropdown **Source field**.
- **Audit log** highlights a one-time per-day **NO DATA** line when a source is empty.

### UX

- **Inline fix loop:** open a failed query to edit its template, **Test vs SDL**, **Save
  to catalog**, and **Save & re-run** from the same popup.
- Query-selection modal gains a **search** filter and a **select-all** checkbox with a
  live count.

## v0.4.0

A large round of reliability, variable, and UX work (tagged `v0.4.0`).

- **Broken-query circuit breaker.** Trips on an outright rejection (400 syntax) or a
  repeated failure that survives retries and subdivision (a 500 from a bad query), aborts
  that query's remaining slices, and flags it as needing a fix. Toggle: **Stop query on
  permanent error**.
- **Removed all hardcoding.** Every environment/subject value is a template variable:
  new subject placeholders (`app_name`, `domain`, `login_key`, `file_or_title`), and
  `serverHost` sources became overridable `{{src_*|default}}` via new `{{var|default}}`
  template support.
- **Foolproof output-volume permissions.** The Docker container makes a mounted `/data`
  bind mount writable for its non-root user automatically; otherwise it prints clear
  remediation and exits instead of crashing. Hardened directory scans (fixes a `scandir`
  crash) and cross-OS `_safe()` names.
- **UX:** live progress bar with ETA and a **running** (in-parallel) tile; cost preview;
  **Recent runs** (reopen and resume); **Test connection** (tests the typed credentials);
  findings-first verification with the exact per-query error and click-to-preview; batch
  CSV covering every subject variable; **Import / Export variables**; auto-sized worker
  pool; date-range vs lookback; header "DFIR ..." with a clean version + build date; a
  "Crafted with by SentinelOne GSA Team" footer; refreshed
  [user guide](docs/user-guide.md) with screenshots.

## v0.3.0

Initial public engine: LRQ v2 async execution with UTC day-slicing, durable SQLite
ledger and resume, retry/subdivide with error classification, content-addressed slice
cache, per-run verification, xlsx workbook export, hardened Docker web UI, and GHCR
publishing.
