# ThreatLens — Collection Layer Report

Generated (UTC): 2026-10-15T08:35:17.366988+00:00

## Collection counts

| Dataset | Records |
|---|---:|
| CIS and Cisco Talos RSS articles | 65 |
| CERT-In public advisories | 45 |
| Cisco Talos UAT-11985 IOC file | 8 |
| AlienVault OTX pulses | 200 |
| AlienVault OTX indicator candidates | 5893 |
| Unified candidate records | 6655 |

## Source coverage and limitations

- **RSS:** 65 entries were collected from the configured CIS advisories and Cisco Talos feeds.
- **CERT-In:** the collector checked one listing page for each of 2024, 2025 and 2026. It saved 45 advisories with zero parse failures and zero request failures in the last run. This is not full historical archive coverage.
- **Cisco Talos:** the UAT-11985 IOC file supplied 8 source-reported entries. These are campaign-specific, not a complete Talos IOC feed.
- **AlienVault OTX:** the collector retrieved 200 subscribed pulses from the first 20 pages. The API reported 9,214 available pulses during a diagnostic request, so the current dataset is a bounded sample rather than a complete collection.

## Data quality

- Unified records: 6655
- Distinct canonical type/value pairs: 6411
- Repeated pairs across records: 160
- Records missing source URLs: 0
- Records missing values: 0
- Records missing types: 0

### Canonical type counts

| Type | Count |
|---|---:|
| cve | 732 |
| url | 585 |
| domain | 1143 |
| md5 | 976 |
| sha256 | 1647 |
| email | 3 |
| hostname | 527 |
| ipv4 | 340 |
| sha1 | 699 |
| yara | 3 |

## Interpretation and limitations

- Extracted records are candidates, not automatically confirmed malicious indicators.
- CVEs are vulnerability references and must not be counted as confirmed malicious IoCs.
- URLs and domains can be legitimate references in vendor advisories or articles.
- Source-reported metadata is retained for traceability; it is not equivalent to independent validation.
- Repeated type/value pairs are reported for review and are not automatically removed from the provenance-preserving dataset.

## Reproducibility

Run the existing source collectors and parsers to refresh the datasets. Then run `python collectors\merge_candidate_datasets.py`, `python collectors\audit_collection.py`, and this report generator in that order.

## Verified OSINT source inventory

The following public source endpoints are configured in the project collectors:

| Source | Endpoint | Collection evidence |
|---|---|---|
| CERT-In | https://www.cert-in.org.in/s2cMainServlet | 45 public advisories recorded in the collection report |
| CIS Security | https://www.cisecurity.org/feed/advisories | Included in the combined total of 65 RSS entries |
| Cisco Talos RSS | https://feeds.feedburner.com/feedburner/Talos | Included in the combined total of 65 RSS entries |
| Cisco Talos IOC repository | https://raw.githubusercontent.com/Cisco-Talos/IOCs/ | 8 UAT-11985 source-reported entries |
| AlienVault OTX | https://otx.alienvault.com/api/v1/pulses/subscribed | 200 subscribed pulses recorded |

These are public OSINT endpoints configured in the project. Collection was bounded and does not establish complete coverage of any source. The combined RSS count is not broken down by feed in the current report. Source terms, API conditions, and applicable usage restrictions should be reviewed before operational use. Collection alone does not independently validate indicator maliciousness.

