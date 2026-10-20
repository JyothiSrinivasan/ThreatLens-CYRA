# ThreatLens — VirusTotal Enrichment Analysis

## Dataset and coverage
- Total indicators: 150
- Successful VirusTotal lookups: 38
- Indicators with no VirusTotal report returned: 12
- Indicators not yet submitted for lookup: 100
- Unique type/value pairs: 150

## Successful lookups by indicator type
- domain: 3
- hostname: 7
- md5: 5
- sha1: 6
- sha256: 7
- url: 10

## Indicators with at least 10 malicious detections

| Type | Indicator | Malicious | Suspicious | Harmless | Undetected |
|---|---|---:|---:|---:|---:|
| sha1 | `5d8d9ce63d63f5d89b3774215830751de6efced2` | 54 | 0 | 0 | 16 |
| sha1 | `b9601e60f87545441bf8579b2f62668c56507f4a` | 52 | 0 | 0 | 19 |
| md5 | `c24e99f9437feacaa63766a3cde3fe3d` | 48 | 0 | 0 | 22 |
| md5 | `1dcafb7f8448683281106b06dd22409a` | 46 | 0 | 0 | 25 |
| sha1 | `7c049c51338b6485abb8368e32b0b09041d3e1d2` | 44 | 0 | 0 | 27 |
| sha256 | `cd147efe37003399e174951927e5fe727a4481756b116f0204a14a64cc62b059` | 41 | 0 | 0 | 30 |
| sha1 | `c491d477dbe0ae04e9aed9dbe237144c03f73ec4` | 39 | 0 | 0 | 24 |
| sha1 | `ddd07abb4c1077a6b6e54d61a8f6026360ac6379` | 37 | 0 | 0 | 24 |
| sha256 | `001337488c32d8610c2aef6f9330acca825f0afacd071bf6ebfc06b5a1a69f09` | 33 | 0 | 0 | 33 |
| sha256 | `85b5e95cbb5103202abebf8f84b91a286994e61b33ddef53355ab0df2a2b6d9a` | 30 | 0 | 0 | 32 |
| md5 | `c6832aa04d5c56d3953aa0671cc07902` | 29 | 0 | 0 | 38 |
| sha1 | `c8cb3f6d5b90c46686d2bf531dc1a5786e27edc5` | 27 | 0 | 0 | 28 |
| sha256 | `20675a659c338f7267fd09bacb431f4491f061d3acf42d07aca2dec3d25fa549` | 26 | 0 | 0 | 44 |
| sha256 | `321e1fb01eb3462b48ff6ccdef132acc1182e3f7456548439f0d4ead12fd98bf` | 24 | 0 | 0 | 38 |
| sha256 | `41d922a220ac28a4af8cbed3ffff517bfc5087f11c52801a1be0353e22a71fe0` | 22 | 0 | 0 | 45 |
| url | `http://snake.zooparkko.com/collect` | 17 | 3 | 44 | 29 |
| domain | `neeitoerw.my` | 14 | 1 | 45 | 32 |
| url | `https://nsseo.vip/` | 13 | 2 | 45 | 33 |
| url | `http://creainovada.xyz/instructions/` | 13 | 1 | 48 | 30 |
| hostname | `www.maxintora.com` | 13 | 2 | 42 | 35 |
| hostname | `hpn.bandhiem.com` | 12 | 0 | 46 | 34 |
| url | `https://www.incofar.it/js/jquery/plugins/ajaxfileupload/mag.txt` | 12 | 1 | 49 | 29 |
| url | `https://proof.gitprogram.com/a4/j8` | 12 | 0 | 49 | 30 |
| hostname | `drive.worksplace.cloud` | 10 | 0 | 47 | 35 |

## Interpretation and limitations
- VirusTotal lookup success means a report was returned; it does not itself establish maliciousness.
- Vendor detection counts are evidence for triage, not a calibrated probability of compromise.
- A not-found result means no report was returned for that lookup; it does not mean the indicator is safe.
- Not-attempted indicators have not yet been checked through this batch workflow.
- The indicators were selected from a threat-intelligence dataset, so the results are not representative of all internet indicators.
- This report summarizes VirusTotal results; it does not independently confirm live activity or attribute indicators to a campaign.

## Consolidated Enrichment Dataset — 18 October 2026

A separate consolidated dataset was created at:

`data/processed/misp_enrichment_150_with_vt_urlscan_consolidated.json`

The original 150-record VirusTotal batch dataset was preserved.

### Validation results

- Total records: 150.
- Unique type/value pairs: 150.
- All records retain their source URLs.
- VirusTotal lookup success: 38 records.
- VirusTotal not found: 12 records.
- VirusTotal not attempted in the original batch results: 100 records.
- URLScan enrichment attached by exact type/value match: 1 record.
- URLScan-enriched indicator: `https://nsseo.vip/`.
- URLScan result: `https://urlscan.io/result/01a14b86-4f6f-74f8-b907-b5ca7c943356/`.
- The matched record retains its VirusTotal lookup status and `source_reported_unverified` validation status.

### Interpretation and limitations

Source-context enrichment is distinct from external reputation enrichment. A VirusTotal `not_found` response does not establish that an indicator is benign, and a `not_attempted` status means no lookup result is recorded for that indicator in this dataset.

The URLScan result reported no malicious verdict in its URLScan verdict object, while the corresponding VirusTotal batch reported 13 malicious detections. This disagreement warrants further investigation; neither result alone proves that the URL is safe or malicious.

All 150 indicators remain source-reported and unverified. The dataset demonstrates a reproducible enrichment workflow and coverage accounting, not 150 independently confirmed malicious indicators.
