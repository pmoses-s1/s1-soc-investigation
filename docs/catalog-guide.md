# Catalog guide

The bundled `catalogs/` are a DFIR / insider-threat query library for the SentinelOne
Singularity Data Lake, organized by investigation domain so you can run one phase at a
time or the whole sweep. Every query is written in the engine's template form
(`{{entity}}` plus the variables in the [Variables popup](user-guide.md#4-set-investigation-variables))
and is validated by the [test harness](#validating-the-catalogs) before shipping.

Sources: a real DFIR investigation workbook plus the SOC Investigation Library v2
(coverage, identity, endpoint, collaboration, web/DLP, SaaS, GenAI, and cross-source
pivots). On import, queries were normalized for SDL (`== null` -> `!field`,
`!= null` -> `field = *`, placeholders -> `{{var}}`, `serverHost` -> overridable
`{{src_*|default}}`), de-duplicated by body, and linted; nothing invalid ships.

## Query scope (subject vs tenant-wide)

Every query carries a `scope` so an investigation of one person never silently
returns the whole tenant:

- **`subject`** must filter to the investigated person or endpoint (`{{entity}}`,
  `{{username}}`, `{{hostname}}`, `{{agent_uuid}}`, `{{ip}}`, `{{sf_user_id}}`).
  The engine skips a subject query (reason `no_subject_value`, not a failure) until
  at least one of its subject values is set, so it can never run fleet-wide.
- **`pivot`** is scoped by a discovered value (`{{domain}}`, `{{file_or_title}}`,
  `{{app_name}}`, `{{session}}`, `{{login_key}}`) and is gated the same way.
- **`environment`** is intentionally tenant-wide: Top Users, Unique Users, totals,
  rankings, and software inventory. These run fleet-wide by design and are labelled
  so analysts know the results are not subject-specific.
- **`coverage`** is a tenant-wide source/schema presence check.

The UI tags each query with its scope, and `python -m s1engine.cli validate`
reports the scope mix per catalog and flags any subject/pivot query that lacks its
filter (a build-failing regression test guards the bundled catalogs).

## Domain catalogs

Pick the catalog for the phase you are working, or the master for everything the
variables allow. Query counts below are as of v0.4.2; the catalog dropdown in the UI shows the live count.

| Catalog | Queries | Focus | What it covers |
|---|---:|---|---|
| `dfir_coverage_identity` | 291 | Coverage & identity | Which sources hold data for the subject; first/last seen, countries, IPs; identity baselining. Run this first to see what telemetry exists before concluding absence. |
| `dfir_identity_access` | 32 | Identity & access | Okta, Azure/Entra, JumpCloud, 1Password, secrets. Logins, MFA, lifecycle, privilege changes, impossible travel. |
| `dfir_endpoint` | 22 | Endpoint / EDR | SentinelOne EDR plus software inventory (oplockdown): USB writes, archive/exfil tooling, large-file staging, logins, print/screenshot artifacts, installed software. |
| `dfir_collab_storage` | 78 | Collaboration & storage | Google Workspace, Slack, OneDrive/Box: file downloads, sharing, deletions, channel joins, mass access. |
| `dfir_web_network` | 52 | Web & network | Zscaler ZIA web proxy, DNS: destinations, uploads, blocked/allowed categories, DLP-relevant web activity. |
| `dfir_saas_apps` | 37 | SaaS & apps | Salesforce (realtime/event/audit), GitHub, Snyk, Navan travel, misc SaaS: logins, report/SOQL volume, config changes, session pivots. |
| `dfir_ai_prompt` | 65 | AI & Prompt Security | GenAI / Prompt Security (prompt-security): data-laundering and policy violations, secrets/sensitive content sent to AI tools, shadow-AI usage. |
| `dfir_exfil_dlp` | 48 | Exfil & DLP | Cross-source exfiltration and data-loss signals (endpoint + web + SaaS staging and transfer). |
| `dfir_cloud` | 3 | Cloud | Cloud control-plane activity (e.g. AWS). |
| `dfir_correlation` | 15 | Cross-source correlation | Quick pivots and multi-source stitching (session keys, login keys, IOC sweeps). |
| `dfir_location_compliance` | 63 | Location / residency | Where was the subject working from? Okta, ZPA, ZIA, EDR LAN evidence, OS timezone/WiFi artifacts, badge access, travel (Navan), and multi-source daily country evidence for remote-work / residency compliance cases. All subject-scoped. |
| `dfir_itm_detections` | 92 | Insider Threat Matrix | Daily-count feasibility timelines mapped to [Insider Threat Matrix](https://insiderthreatmatrix.org/detections) detections (dt IDs): anti-forensics (history/log clearing, VSS delete), browser and OS artifacts, USB/removable media, registry persistence, DNS/proxy/VPN, cloud resource deletion (AWS/GCP/Azure/OCI), and M365/Entra identity and mailbox activity. 87 subject-scoped; 5 aggregate volume timelines are `environment`. |
| `dfir_insider_threat_full` | 725 | Master (full sweep) | Every domain query in one catalog, de-duplicated by body, for a one-click full investigation (now includes the ITM detections). |
| `insider_threat` | 6 | Minimal example | A tiny sample for demos and smoke tests. |

The master `dfir_insider_threat_full` (725 queries) is the de-duplicated-by-body union of the domain catalogs, including `dfir_location_compliance` and `dfir_itm_detections`. When the ITM detections were merged in, 7 queries whose bodies exactly matched an existing query were skipped (different ITM detection IDs that reduce to the same telemetry query); the standalone `dfir_itm_detections` keeps all 92 for the full detection mapping.

## How to run a case logically

1. **Coverage first.** Run `dfir_coverage_identity` to confirm which sources have data
   for the subject and to baseline identity. Empty sources are a finding too.
2. **Identity phase.** Run `dfir_identity_access` to establish logins, MFA, geography,
   and privilege changes. Fill in the `hostname` / `agent_uuid` you discover.
3. **Endpoint and web.** With the host/agent set, run `dfir_endpoint` and
   `dfir_web_network` for on-device staging and web/DLP activity.
4. **Collaboration, SaaS, AI.** Run `dfir_collab_storage`, `dfir_saas_apps`, and
   `dfir_ai_prompt` for cloud-app data movement and GenAI exposure.
5. **Correlate.** Use `dfir_correlation` to stitch sessions and pivot IOCs across
   sources, or run `dfir_insider_threat_full` to sweep everything at once.

A query whose required subject variables are unset is **skipped, not failed**, so you
can run the coverage/identity phases first and re-run later phases once you have filled
in the host, agent, IP, or app you discovered.

## Variables and data-source overrides

Queries reference subject variables (`{{entity}}`, `{{hostname}}`, `{{agent_uuid}}`,
`{{ip}}`, `{{username}}`, `{{sf_user_id}}`, `{{session}}`, `{{app_name}}`, `{{domain}}`,
`{{login_key}}`, `{{file_or_title}}`), optional config datatables (`dt_*`), and
data-source names (`src_*`). Source names carry a default (e.g. `{{src_zia|zia}}`), so
queries run out of the box; override one in **Variables** only if your tenant ingests
that source under a different `serverHost`. See the
[user guide](user-guide.md#4-set-investigation-variables).

## Validating the catalogs

The repo ships a query test harness. Lint every catalog offline (no tenant), or
validate against SDL with dummy variables:

```bash
# static lint only (catches == null, obj['key'], | head, sort desc, placeholders)
python -m s1engine.cli validate --lint-only --dir catalogs

# lint + launch each query over a short window with dummy vars (needs credentials)
python -m s1engine.cli validate --dir catalogs

# offline against the fake backend
python -m s1engine.cli validate --dir catalogs --mock
```

The linter's rules are all verified against a live tenant: `field == null` (HTTP 500),
`obj['key']` / `obj."key"` sub-indexing (HTTP 400), `| head` (HTTP 400), and
`sort field desc|asc` (HTTP 400) are rejected; while `field != null`, `field = *`,
top-level `"quoted fields"`, bare case-sensitive `contains 'x'`, and `nolimit` are
valid and are not flagged. `pytest tests/test_catalog_lint.py` fails the build if any
bundled catalog regresses.

## Linting a raw list of PowerQueries from the CLI

To check ad-hoc queries (not a catalog), put them in a plain text file, **one query per
block, separated by a blank line**, and pass `--pq-file`. Each block may span multiple
lines; template variables like `{{entity}}` are fine (dummy values are used).

```text
# queries.txt
serverHost='okta' actor.alternateId='{{entity}}' | limit 1 | columns actor.alternateId

serverHost='oplockdown' | filter owner == null | limit 1

event.type='Process Creation' | head 5 | columns endpoint.name
```

```bash
# static lint only, no tenant needed (fast, CI-friendly)
python -m s1engine.cli validate --pq-file queries.txt --lint-only

# also launch each query over a short window with dummy vars (needs credentials)
python -m s1engine.cli validate --pq-file queries.txt

# offline against the fake backend
python -m s1engine.cli validate --pq-file queries.txt --mock
```

Queries are reported as `q1`, `q2`, ... in file order. Example output for the file above:

```text
== queries.txt  (3 queries) ==
  LINT  q2: `== null` is rejected by SDL (HTTP 500); use `!field` for empty/absent
  LINT  q3: `| head` is invalid; use `| limit N`

=== validation summary ===
lint issues : 2
```

The command exits non-zero when there are lint issues (or, without `--lint-only`, any
query SDL rejects), so it drops straight into a CI check or a pre-commit hook. Running
inside the published image works too: `docker run --rm -v "$PWD:/work"
ghcr.io/pmoses-s1/s1-soc-investigation:latest python -m s1engine.cli validate
--pq-file /work/queries.txt --lint-only`.
