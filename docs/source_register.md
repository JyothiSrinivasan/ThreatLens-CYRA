# ThreatLens — OSINT Source Register

**Project:** ThreatLens — GenAI-Powered OSINT Threat Intelligence for BFSI  
**Project mode:** Individual  
**Document date:** 15 October 2026  
**Project code:** CAP-TIE-3W

## 1. Purpose

This register documents the public intelligence sources used by ThreatLens, their intended purposes, implementation status, collection outputs and limitations.

ThreatLens supports a simulated consortium of Indian regional banks requiring a low-cost, shared Cyber Threat Intelligence (CTI) capability without a commercial threat-intelligence platform.

The primary threat priorities are ATM jackpotting, SWIFT-related malware, UPI fraud kits and politically motivated DDoS. Ransomware, data theft and actively exploited vulnerabilities are supporting intelligence areas.

## 2. Source Register

| Source | URL | Intended use | Recorded status |
|---|---|---|---|
| Center for Internet Security (CIS) Advisories | https://www.cisecurity.org/feed/advisories | Public security advisories and vulnerability information | RSS collection tested; 50 entries collected in a recorded run |
| CERT-In | https://www.cert-in.org.in/ | Indian cybersecurity advisories and relevant vulnerability or threat reports | Collector tested; 45 advisory records collected in a later recorded run |
| Cisco Talos | https://blog.talosintelligence.com/ | Vendor threat research, malware reports and campaign context | RSS feed tested; separate UAT-11985 indicator collection implemented |
| AlienVault OTX | https://otx.alienvault.com/ | Community threat intelligence, pulse metadata and reported indicators | API collection and enrichment pipeline tested; bounded collection of 200 pulses |
| National Vulnerability Database (NVD) | https://nvd.nist.gov/ | CVE details and vulnerability context | CVE enrichment implemented; 76 CVE references processed, including one without a matching record |

**Interpretation:** The counts above represent different collection activities and outputs. They must not be added together as unique indicators. Advisory records, OTX pulses, CVE references and IoCs are different data categories.

## 3. Recorded Collection Outputs

### 3.1 CIS Advisories

- Source type: RSS feed.
- Feed URL: https://www.cisecurity.org/feed/advisories
- Recorded test: Successful.
- Recorded output: 50 entries in an earlier run.
- Output file: `data/raw/rss_entries.json`
- Limitation: RSS entries are advisory/report records, not confirmed IoCs.

### 3.2 CERT-In

- Source type: Public advisory listing and individual advisory pages.
- Website: https://www.cert-in.org.in/
- Recorded later output: 45 advisory records.
- Output file: `data/raw/certin_advisories.json`
- Additional processing: Cleaned advisory text is available at `data/processed/certin_advisories_cleaned.json`.
- Limitation: Collection covered the implemented listing pages for 2024, 2025 and 2026; it is not a complete historical archive. Advisory records and extracted candidates are not automatically verified malicious indicators.

### 3.3 Cisco Talos

- Source type: RSS and public threat-research material.
- RSS URL: https://feeds.feedburner.com/feedburner/Talos
- Recorded RSS test: HTTP 200, valid XML and 15 entries.
- Combined RSS output: `data/raw/rss_entries.json`
- Separate indicator collection: UAT-11985, with eight source-reported candidates.
- Processed output: `data/processed/talos_uat_11985_candidates.json`
- Limitation: Research reports and extracted candidates require contextual assessment. Extraction does not independently establish maliciousness.

### 3.4 AlienVault OTX

- Source type: Public threat-intelligence API.
- Website: https://otx.alienvault.com/
- Recorded collection: Bounded sample of 200 pulses.
- Candidate extraction output: `data/processed/otx_enriched_indicators.json`
- Unified candidate output: `data/processed/unified_candidate_iocs.json`
- MISP pilot output: `data/processed/misp_enrichment_pilot_diverse_ready.json`
- MISP ingestion: 150 attributes added to Event ID 3, `ThreatLens - OTX Context-Enriched Candidate Indicators (Unverified)`.
- Limitation: OTX pulse context provides source-context enrichment, not independent validation. The imported indicators remain marked `source_reported_unverified`, with IDS disabled.

### 3.5 National Vulnerability Database

- Source type: Public vulnerability database.
- Website: https://nvd.nist.gov/
- Recorded processing: 76 CVE references processed; 75 matched records and one did not.
- Output file: `data/processed/cve_enriched.json`
- Limitation: A CVE reference is a vulnerability identifier, not itself a malicious IoC. Exploitation claims require supporting evidence.

## 4. Collection and OPSEC Controls

1. Collect only from publicly accessible sources and permitted APIs.
2. Respect source terms, rate limits and access restrictions.
3. Preserve source URLs, publication dates and collection timestamps where available.
4. Record collection timestamps in UTC where supported.
5. Deduplicate indicators while retaining source provenance.
6. Distinguish reported facts, source-context enrichment and analytical assessments.
7. Do not classify an indicator as malicious solely because it appears in a report or community feed.
8. Verify LLM-generated claims against source material and trusted references.
9. Do not conduct unauthorised scanning, exploitation, credential testing or access to real-world targets.
10. Keep API keys and credentials out of source code, public reports and version-controlled repositories.

## 5. Relevance to Consortium Priorities

The source register identifies collection capabilities, but the presence of a source does not prove coverage of every priority.

| Priority | Evidence required in collected material |
|---|---|
| ATM jackpotting | Reports identifying relevant ATM malware, jackpotting tools, campaigns or behaviours |
| SWIFT-related malware | Reports relevant to SWIFT or interbank payment environments |
| UPI fraud kits | Evidence of UPI-related fraud infrastructure, phishing or credential-theft campaigns |
| Politically motivated DDoS | Reports of politically motivated campaigns relevant to Indian financial institutions |
| Supporting priorities | Relevant ransomware, data-theft and actively exploited vulnerability reporting |

Coverage must be demonstrated from collected records and their source URLs. Missing evidence must be reported as a gap rather than assumed.

## 6. Known Limitations and Follow-up

- Collection counts come from recorded runs and may change between runs.
- RSS entries, advisories, CVE references, pulses and IoCs must be counted separately.
- The OTX dataset is bounded rather than exhaustive.
- Source-reported indicators have not all been independently validated.
- The relevance of collected records to the four primary consortium priorities requires evidence-based assessment.
- End-to-end collection, deduplication and output consistency should be verified before the final report is submitted.

## 7. Status Summary

The CIS, CERT-In, Cisco Talos, OTX and NVD components have recorded implementation or testing evidence. This register documents those results and their limitations; it does not claim complete coverage of all four threat priorities or independent validation of every indicator.

**Document status:** Updated source register for the individual ThreatLens capstone prototype.