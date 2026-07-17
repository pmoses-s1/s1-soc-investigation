# Changelog

## v0.4.0

A large round of reliability, catalog, UX, and tooling work. Highlights below;
every change was verified against the test suite, and query-syntax claims were
verified live against a tenant before shipping.

### Reliability and engine

- **Broken-query circuit breaker.** A query that is deterministically broken no
  longer re-fails on every day-slice. It trips on an outright rejection (400 syntax)
  or on a repeated failure that survives retries and subdivision (a 500 from a bad
  query), aborts that query's remaining slices, and flags it as needing a fix. Other
  queries keep running. Toggle: **Stop query on permanent error**.
- **Per-day source-existence pre-check.** For a query anchored to a single source,
  the engine probes that source once per day and skips the query's slice as empty if
  the source has no data that day (one cached probe serves all that source's queries).
  Probing is lazy (one probe in the common case). It checks both `serverHost` and
  `dataSource.name`, and warns when a source's data lives under the other field than
  the query uses. Toggle: **Skip empty source-days**.
- **Configurable source field.** Force every source-anchor predicate to `serverHost`
  or `dataSource.name` (some tenants populate one, some the other), or leave queries
  as written. Run-form dropdown **Source field**.
- **Foolproof output-volume permissions.** In Docker the container now makes the
  mounted `/data` folder writable for its non-root runtime user automatically (root
  entrypoint that drops privileges via gosu); if it still cannot write it prints a
  clear remediation and exits instead of crashing.
- **Hardened directory scans.** Run-history and run-lookup tolerate case folders that
  vanish or are inaccessible mid-scan (fixes a `scandir` crash), and `_safe()` names
  are cross-OS (reserved names, trailing dots/spaces, length, never empty).

### Catalogs

- **Removed all hardcoding.** Every environment/subject value is a template variable:
  subject placeholders (`app_name`, `domain`, `login_key`, `file_or_title`, plus the
  existing set), and `serverHost` sources became overridable `{{src_*|default}}` via
  new `{{var|default}}` template support. Fixed the `psc-02` bracket sub-index that
  returned `Expected ")"`.
- **Merged the SOC Investigation Library v2.** 483 new DFIR queries folded into the
  `dfir_*` catalogs (matched by body, 152 duplicates skipped, 0 failed), normalized
  for SDL and linted. New categories `dfir_ai_prompt` and `dfir_coverage_identity`.
  ~1,289 queries total across catalogs, de-duplicated.

### Query test harness

- **Static linter** (`s1engine/lint.py`) flags the syntax pitfalls SDL rejects,
  verified live: `field == null` (500), `obj['key']` / `obj."key"` sub-indexing (400),
  `| head` (400), `sort field desc|asc` (400), and un-converted placeholders. Verified
  valid and therefore NOT flagged: `!= null`, `field = *`, top-level `"quoted fields"`,
  bare case-sensitive `contains`, and `nolimit`.
- **`python -m s1engine.cli validate`** lints and (optionally) launches each query
  against SDL with dummy variables; `--lint-only` needs no tenant. A pytest fails the
  build if any bundled catalog regresses.

### UX

- Live progress bar with ETA and a **running** (in-parallel) tile; cost preview before
  a run; **Recent runs** (reopen and resume); **Test connection** (tests the typed
  credentials); findings-first verification with the exact per-query error and
  click-to-preview results.
- **Inline fix loop:** open a failed query to edit its template, **Test vs SDL**,
  **Save to catalog**, and **Save & re-run** from the same popup.
- **Batch mode** CSV now covers every single-mode subject variable; **Import / Export
  variables** as JSON; dynamic Variables popup (subject, datatables, source overrides).
- Query-selection modal gains a **search** filter and a **select-all** checkbox with a
  live count. Worker pool auto-sizes to tokens x 3. Audit log highlights a per-day
  **NO DATA** line when a source is empty.
- Header reads "DFIR Long-lookback ...", shows a clean version plus build date (no git
  hash), links the user guide, and has a "Crafted with by SentinelOne GSA Team" footer.

### Docs

- Refreshed [user guide](docs/user-guide.md) with current screenshots and a new
  [catalog guide](docs/catalog-guide.md). README updated throughout. Tagged `v0.4.0`.

## v0.3.0

Initial public engine: LRQ v2 async execution with UTC day-slicing, durable SQLite
ledger and resume, retry/subdivide with error classification, content-addressed slice
cache, per-run verification, xlsx workbook export, hardened Docker web UI, and GHCR
publishing.
