# ThreatLens — MISP Verification Evidence

**Verification date:** 18 October 2026  
**Verification method:** Read-only PyMISP queries against the local MISP instance.

## 1. Event-level results

The read-only event inspection returned three MISP events:

| Event | Description | Reported attributes |
|---|---|---:|
| 1 | CERT-In SHA-256 Source-Reported Candidates | 2 |
| 2 | Cisco Talos UAT-11985 Source-Reported Candidates | 8 |
| 3 | OTX Context-Enriched Candidate Indicators (Unverified) | 150 |
| **Total** | **3 events** | **160** |

## 2. Pilot matching check

A separate read-only duplicate check reported:
- Pilot records: 150
- Unique pilot type/value pairs: 150
- Pilot indicators already present in the returned MISP attributes: 150
- Pilot indicators not found in the returned attributes: 0
- Existing attributes returned by that query: 160

## 3. Interpretation

The results provide evidence that the MISP instance is populated beyond the project minimum of 100 indicators. All 150 unique pilot type/value pairs matched attributes returned by the MISP query.

The reported total of 160 is an attribute count, not a claim that 160 indicators have been independently confirmed malicious. Source-reported candidates remain unverified unless corroborated by appropriate evidence.

The event inspection used metadata counts. A complete paginated audit of unique MISP attribute type/value pairs has not yet been documented.

## 4. Limitations and security note

The Python client emitted `InsecureRequestWarning` because HTTPS certificate verification was disabled for the local MISP host. The read-only queries succeeded, but certificate verification should be configured appropriately before operational deployment.

## 5. Safety and scope

These checks were read-only. No MISP events or attributes were created or modified during verification.


## 6. Final paginated attribute audit

**Audit method:** Read-only PyMISP search with a page size of 100.

| Check | Verified result |
|---|---:|
| Page 1 attributes retrieved | 100 |
| Page 2 attributes retrieved | 60 |
| Total attributes retrieved | 160 |
| Unique normalized type/value pairs | 160 |
| Unique pilot type/value pairs | 150 |
| Pilot pairs found in MISP | 150 |
| Pilot pairs not found | 0 |

The audit explicitly retrieved two pages. All 160 retrieved attributes had unique normalized type/value pairs. All 150 unique pilot pairs matched attributes returned by MISP.

**Conclusion:** The read-only audit supports the project requirement for at least 100 indicators in the MISP instance. Uniqueness does not establish maliciousness or independent verification; the indicators remain source-reported candidates unless corroborated.

No MISP events or attributes were created, modified, or deleted during this audit.

