# User guide

A step-by-step walkthrough of the s1-soc-investigation web UI: launch it, connect to your tenant,
choose and validate a catalog, run an investigation over a long lookback, watch it complete, and pull
back verified results. For the concepts behind it (slicing, the cache, verification) see the
[README](../README.md).

---

## 1. Launch

Run the published image, publishing to the host loopback and mounting a folder for output:

```bash
docker run --rm --pull=always -p 127.0.0.1:8901:8801 \
  -v "$PWD/investigations:/data" \
  ghcr.io/pmoses-s1/s1-soc-investigation:latest
```

Open **http://localhost:8901**. The header shows the active build version, so you can confirm which
image you are on. `--pull=always` ensures you are always on the newest published build.

Every field in the UI has a **?** next to it. Hover it for a plain-language explanation of what the
field does.

---

## 2. Connect

![Connect panel](images/01-connect.png)

Enter your tenant's **Console URL** (the console host for the LRQ v2 API, for example
`https://your-tenant.sentinelone.net`, not the `xdr.*` V1 host) and one or more **service-user
tokens**. Put one token per line to round-robin across identities, which roughly doubles the ~3
requests/sec per-user rate budget.

- **Rate (rps):** per-token request rate. Keep at or below ~2.5 to stay under the 3 rps per-user cap.
- **Account IDs:** optional. Set comma-separated account IDs to scope the query (this switches the
  query to `tenant=false`); leave blank to query tenant-wide.

Click **Connect**. Tokens stay in the server process and are never sent back to the browser. Once
connected, this panel collapses to a one-line summary with an **Edit** button to reopen it.

---

## 3. Choose and validate the catalog

![Run investigation panel](images/02-run.png)

Pick a **query catalog** (your standard investigation query set). The buttons below it let you manage
it without leaving the UI:

- **Edit** the selected catalog, or **New** to start one from a template. Each query has an `id`,
  `title`, `pq` (the PowerQuery), and a `merge` block that tells the engine how to reassemble sliced
  results. `{{entity}}` is substituted per run.
- **Import** a catalog file from disk, or **Export** the selected one.
- **Validate vs SDL** launches every query over a short recent window against your tenant and reports
  each as **valid**, **invalid** (a real syntax error such as an unknown function), or **unknown** (a
  transient condition). Run this before a 90-day investigation so a bad query is caught in seconds
  instead of mid-run. Saved catalogs persist in your output folder.

---

## 4. Configure and start the run

In the same panel, set:

- **Case ID** and **Entity** (the subject of the investigation: user, host, or IP). The entity fills
  in `{{entity}}` in every query.
- **Lookback (days)** and **Slice size (days).** 90+ day lookbacks with 1-day slices are the norm.
- **Output folder.** Blank uses the default base (the mounted `/data` folder in Docker).
- **Worker pool** (blank = tokens × 3; the engine auto-tunes it) and **Max attempts** per slice.
- **Priority**, and the checkboxes: **Adaptive sub-slice** (split a slow slice and retry the pieces),
  **Use cache** (reuse immutable past-day results from earlier runs), and **Dry run (offline mock)**
  to try the flow with no tenant.

Click **Start investigation**.

---

## 5. Watch it run

![Activity log](images/03-activity-log.png)

The **Activity log** streams every event live: the plan (queries × slices), each slice completing
(with row count, elapsed time, which token ran it, and the current concurrency limit `gov=`), cache
hits, retries, adaptive sub-slicing, and throttles. The concurrency limit rises and falls on its own
as the engine adapts to what the backend tolerates. The full trace is also written to
`activity.jsonl` in the run folder.

---

## 6. Verify and download

![Verification panel](images/04-verification.png)

When the run finishes, the **Verification** panel gives the verdict: it passes only when every slice
of every query completed. The per-query table shows status (**pass / failed / incomplete**) with
done / failed / permanent / pending counts and the merged row count, and flags approximations (for
example distinct counts summed across slices). The run stats line shows done, cached, failed, retries,
throttles, and subdivided totals.

Download buttons give you:

- **Activity log (.jsonl):** the raw execution trace.
- **Results (.zip):** the merged results, workbook, manifest, and logs.
- **Everything (.zip):** the above plus the raw per-slice output.

Each run also writes a per-case `.xlsx` workbook (a Summary sheet plus one tab per query, each tab
showing the exact PowerQuery used). All outputs land under `<output>/<case>/<run_id>/`; see the
[output layout](../README.md#output-layout) for what each file contains and where the raw logs are.

---

## Tips

- **Resume:** if a run is interrupted or some slices fail, run it again with the same run id. Only the
  outstanding and volatile (current-day) slices re-run; completed past days are served from cache.
- **Offline demo:** tick **Dry run** to exercise the whole flow against a built-in fake backend with
  no tenant or credentials.
- **Serving to other hosts:** the UI is loopback-only by default. To expose it, set `S1IE_BIND_ALL=1`
  and a strong `S1IE_AUTH_TOKEN`, then open `http://<host>:8901/?token=<secret>`. See the
  [README security section](../README.md#security-and-hardening).
