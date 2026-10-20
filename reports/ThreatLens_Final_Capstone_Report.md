# ThreatLens — GenAI-Powered OSINT Threat Intelligence for BFSI
## Final Capstone Project Report

**Implementation/platform name:** CYRA — AI-Driven Threat Detection and Risk Analytics  
**Project type:** Individual capstone  
**Report date:** 18 October 2026  
**Status:** Evidence-based implementation report; see limitations and submission checklist.

## Abstract

ThreatLens is an OSINT-based cyber threat intelligence (CTI) project focused on the information needs of the banking, financial services and insurance (BFSI) sector. CYRA is the implementation/platform name used for threat-detection, risk-analytics and GenAI-assisted investigation components. The project collects public threat information, extracts candidate entities, preserves source provenance, enriches selected indicators, organizes campaign intelligence, produces STIX 2.1 output, and demonstrates detection logic in SIEM lab environments.

The collection report records 45 CERT-In public advisories, 65 combined CIS Security and Cisco Talos RSS entries, eight Cisco Talos UAT-11985 source-reported entries, and 200 AlienVault OTX subscribed pulses. It records 6,655 unified candidate records and 6,411 distinct canonical type/value pairs. These are collection and processing counts, not counts of confirmed malicious indicators. A read-only paginated MISP audit retrieved 160 attributes with 160 unique normalized type/value pairs; all 150 unique pilot type/value pairs were found.

A pilot NLP evaluation compared a regular-expression (regex) baseline with GLiNER on five manually labelled CERT-In advisories. Regex achieved 95.35% precision, recall and F1 on the saved evaluation; GLiNER achieved 50.85% precision, 23.26% recall and 31.91% F1. The evaluation is small and depends on a non-exhaustive reference set, so these results are not production performance guarantees.

The project also includes ASK CYRA, a local retrieval-augmented generation (RAG) question-answering pipeline; an enhanced STIX 2.1 bundle for the UAT-11985 case study; two Sigma rules tested against synthetic Splunk events; and a synthetic SSH authentication-failure event detected by Wazuh. The evidence demonstrates a functioning prototype and controlled lab workflows. It does not establish that all collected indicators are malicious, that the campaign targeted Indian banks, or that detections are production-ready.

## 1. Introduction and objectives

### 1.1 Background

Financial organizations need timely information about phishing, malware, ransomware, digital-payment threats, vulnerability exploitation, denial-of-service activity and credential theft. Public reporting can provide useful leads, but raw reports often contain a mixture of indicators, vulnerability references, benign URLs, descriptive text and claims requiring analyst verification.

ThreatLens explores a reproducible workflow for turning public reporting into structured, traceable threat intelligence for BFSI analysts. CYRA adds local AI-assisted search and analysis so an analyst can query collected knowledge while retaining source references.

### 1.2 Objectives

1. Define priority intelligence requirements (PIRs) for a BFSI consortium.
2. Collect public OSINT from multiple configured sources.
3. Normalize, deduplicate and preserve provenance for candidate records.
4. Populate and inspect a MISP instance.
5. Compare rule-based and model-based entity extraction on a small labelled dataset.
6. Analyze one public threat case using the Diamond Model and MITRE ATT&CK references.
7. Produce a STIX 2.1 bundle for machine-readable sharing.
8. Convert two intelligence items into Sigma hunting rules and test them in Splunk.
9. Demonstrate a controlled log-ingestion and alerting path in Wazuh.
10. Implement ASK CYRA, a local RAG pipeline that answers questions from project knowledge with source references.
11. Produce a strategic intelligence brief and document limitations, safe-use boundaries and GenAI usage.

### 1.3 Scope boundaries

The project uses public OSINT, locally stored analysis and controlled synthetic lab events. It does not claim to have tested against real financial institutions, performed unauthorized scanning, or observed a live attack in the lab. Source-reported indicators are not automatically treated as confirmed malicious. Candidate counts can include CVEs, legitimate references and other entities that are not confirmed IoCs.

## 2. Priority Intelligence Requirements

The project PIR document defines five BFSI-oriented requirements:

| PIR | Intelligence topic | Priority |
|---|---|---|
| PIR-01 | Banking malware, including ATM and SWIFT-related threats | High |
| PIR-02 | UPI and digital-payment threats | High |
| PIR-03 | Ransomware and data theft | High |
| PIR-04 | DDoS and hacktivism | Medium |
| PIR-05 | Exploited vulnerabilities | High |

The PIR document also records intended users, required information, defensive use, collection and validation principles, operational-security boundaries, intelligence products and review considerations. These requirements guide collection and dissemination, but the current collected sample does not provide evidence for every PIR equally.

## 3. Architecture and CTI lifecycle

The implementation follows a practical CTI workflow:

1. **Direction:** Define BFSI PIRs and intended defensive users.
2. **Collection:** Retrieve public advisories, RSS articles, threat-intelligence pulses and campaign-specific public IOC material.
3. **Processing:** Parse and normalize records, extract candidate entities, retain source URLs and deduplicate canonical type/value pairs.
4. **Enrichment:** Query available threat-intelligence services for selected indicator batches and preserve lookup statuses.
5. **Analysis:** Evaluate extraction methods, review a public campaign, map reported behavior to ATT&CK and use Diamond Model concepts.
6. **Dissemination:** Produce a strategic weekly brief, STIX 2.1 bundle, Sigma rules and supporting evidence reports.
7. **Feedback and review:** Identify missing source coverage, require analyst validation, and use future analyst feedback to revise PIRs, rules and collection priorities.

### 3.1 Main components

- **Collectors and processing scripts:** Python scripts under `collectors/` and supporting scripts under `analysis/`.
- **Data and provenance:** Raw and processed files under `data/`.
- **Threat-intelligence platform:** Local MISP instance at the configured `misp.local` host.
- **AI/NLP:** Regex extraction, GLiNER pilot evaluation, Sentence Transformers embeddings, FAISS retrieval and Qwen2.5:3b served locally through Ollama.
- **Detection testing:** Sigma CLI, Splunk Enterprise in Docker and Wazuh in Docker.
- **Outputs:** Markdown evidence reports, a three-page weekly brief, a STIX 2.1 JSON bundle, Sigma rules and the campaign analysis.

## 4. OSINT collection and data quality

### 4.1 Configured sources

| Source | Configured endpoint | Reported collection evidence |
|---|---|---|
| CERT-In public advisories | `https://www.cert-in.org.in/s2cMainServlet` | 45 advisories |
| CIS Security RSS | `https://www.cisecurity.org/feed/advisories` | Included in combined 65-entry RSS total |
| Cisco Talos RSS | `https://feeds.feedburner.com/feedburner/Talos` | Included in combined 65-entry RSS total |
| Cisco Talos UAT-11985 IOC repository | `https://raw.githubusercontent.com/Cisco-Talos/IOCs/` | Eight source-reported entries in the UAT-11985 case file |
| AlienVault OTX subscribed pulses | `https://otx.alienvault.com/api/v1/pulses/subscribed` | 200 subscribed pulses |

These are five identifiable endpoints across four source organizations/services. The combined RSS count is not broken down by individual feed in the current report. The source inventory documents configured endpoints and reported collection results; it is not, by itself, a comprehensive legal review of each source's terms. API terms, rate limits, attribution requirements and applicable restrictions should be reviewed before operational deployment.

### 4.2 Collection counts

| Dataset | Records |
|---|---:|
| CIS and Cisco Talos RSS articles | 65 |
| CERT-In public advisories | 45 |
| Cisco Talos UAT-11985 IOC file | 8 |
| AlienVault OTX pulses | 200 |
| AlienVault OTX indicator candidates | 5,893 |
| Unified candidate records | 6,655 |
| Distinct canonical type/value pairs | 6,411 |

The OTX collector retrieved 200 pulses from the first 20 pages. A diagnostic request reported 9,214 available pulses, so the dataset is a bounded sample, not a complete collection. CERT-In collection checked one listing page for each of 2024, 2025 and 2026 and saved 45 advisories in the reported run, with zero parse failures and zero request failures in that run. This does not establish complete historical coverage.

### 4.3 Data quality and interpretation

The collection report records no unified records missing source URLs, values or types. Canonical entity counts include CVEs, URLs, domains, hashes, email addresses, hostnames, IPv4 addresses and YARA-related values. The project preserves source-reported metadata and does not automatically equate an extracted value with a confirmed IoC.

- CVEs are vulnerability references, not confirmed malicious IoCs.
- URLs and domains can be legitimate references within advisories or articles.
- Duplicate type/value pairs across sources are useful for correlation and are not necessarily discarded from provenance-preserving records.
- A source's report of an indicator is not equivalent to independent validation.
- A bounded sample cannot establish complete source coverage or sector-wide prevalence.

### 4.4 Operational security

The collection workflow is limited to public sources and configured APIs. API credentials are stored locally in environment configuration and must not be included in reports, screenshots, source-control commits or LLM prompts. Collection should respect service terms, rate limits and access controls. No unauthorized scanning or exploitation is claimed in this project.

## 5. MISP population and verification

MISP was inspected through read-only PyMISP queries. Event metadata reported three events:

| Event | Description | Reported attributes |
|---|---|---:|
| 1 | ThreatLens — CERT-In SHA-256 Source-Reported Candidates | 2 |
| 2 | ThreatLens — Cisco Talos UAT-11985 Source-Reported Candidates | 8 |
| 3 | ThreatLens — OTX Context-Enriched Candidate Indicators (Unverified) | 150 |
| **Total** | **Three events** | **160** |

A separate paginated audit requested attributes in pages of 100. Page 1 returned 100 attributes and page 2 returned 60. Across the retrieved attributes, the audit found 160 unique normalized type/value pairs. The pilot file contained 150 unique normalized type/value pairs; all 150 were found in the returned MISP attributes, and zero were missing.

This provides evidence that the MISP instance exceeds the project minimum of 100 unique attribute type/value pairs. It does not prove that all 160 values are malicious or independently confirmed. The event labels explicitly describe source-reported candidates or unverified enrichment.

### 5.1 MISP audit limitation

The local MISP client emitted `InsecureRequestWarning` because HTTPS certificate verification was disabled for the local host. The read-only queries succeeded, but certificate verification should be configured appropriately before operational use. The audit made no changes to MISP events or attributes.

## 6. Enrichment and source corroboration

The project includes VirusTotal and URLScan enrichment attempts for a selected indicator sample. The saved batch analysis records 50 unique VirusTotal lookup attempts: 38 successful results and 12 not-found results; 100 of the 150-record dataset were not attempted in those batches. The consolidated file retains lookup status for each record rather than implying every indicator was checked.

The VirusTotal analysis report records 24 indicators with at least 10 malicious detections among the successfully returned sample; 37 of 38 successful results had at least one malicious detection, 14 had at least one suspicious detection, and 13 had both malicious and suspicious detections. This is a threat-intelligence-biased sample, not a representative prevalence estimate.

For one URL submitted to URLScan, the saved result reported a score of zero, empty categories, `malicious:false`, and `has_verdicts:false`, with limited browser activity observed. VirusTotal had 13 malicious detections for the same URL. These sources produced different signals. The URLScan result is not proof of safety, and the disagreement should be treated as a reason for cautious analyst review rather than an automatic verdict.

Enrichment status, source and timestamp should be preserved in downstream use. Not found, not attempted and no verdict are different states and should not be merged into a single “clean” classification.

## 7. NLP entity extraction and pilot evaluation

### 7.1 Objective and methods

The evaluation compares a regex baseline with `urchade/gliner_small-v2.1` for identifying cybersecurity entities in five manually labelled CERT-In advisories. The notebook combines predictions from both methods in a hybrid extraction stage, records provenance and deduplicates entity values.

### 7.2 Saved evaluation results

| Metric | Regex baseline | GLiNER |
|---|---:|---:|
| True positives | 123 | 30 |
| False positives | 6 | 29 |
| False negatives | 6 | 99 |
| Precision | 95.35% | 50.85% |
| Recall | 95.35% | 23.26% |
| F1-score | 95.35% | 31.91% |

On this pilot dataset, regex outperformed GLiNER on precision, recall and F1. Regex is suitable for predictable formats such as many hashes, IP addresses, domains and CVE strings. A model-based extractor may complement patterns by identifying contextual entities, but the saved results do not show better performance for GLiNER on this sample.

### 7.3 Annotation and metric caveats

The notebook constructs 131 raw gold labels. Evaluation normalizes entity text and labels and compares sets within each advisory, producing 129 unique normalized gold annotations. The PAN-OS advisory contributes 12 raw labels but 10 unique normalized labels. Both methods therefore have TP + FN = 129.

The report's earlier description of “exact-span evaluation” is not accurate for the final documented method: the evaluation compares normalized entity values and labels, not exact character offsets. The saved metrics have not been independently recomputed as part of this report. The reference set is not exhaustive, so an entity missing from the gold set can be counted as a false positive even if it is valid. GLiNER confidence scores are not calibrated probabilities of correctness.

The results are pilot estimates from five advisories, not generalizable production accuracy. Extraction does not establish maliciousness, attribution or campaign involvement. The regex baseline evaluated in the notebook is not necessarily identical to the production collection pipeline.

### 7.4 Conclusion

The current evidence supports retaining regex as the primary extractor for predictable indicators and treating GLiNER as a complementary experimental component. A larger, diverse, independently labelled dataset and a clearly versioned evaluation procedure are needed before making production-performance claims.

## 8. CYRA and ASK CYRA: local LLM-assisted RAG

### 8.1 Purpose

ASK CYRA is the question-answering component of CYRA. It retrieves passages from a project knowledge base and passes them to a locally hosted language model to produce an answer grounded in retrieved source material. This is separate from the regex-versus-GLiNER entity-extraction evaluation.

### 8.2 Knowledge base and retrieval

The recorded build produced 193 chunks: 176 chunks from CERT-In advisories and 17 from the UAT-11985 campaign analysis. The source knowledge base includes 45 cleaned CERT-In advisories and the campaign analysis. The recorded build had 193 unique chunk IDs, no missing source URLs and no empty text fields.

The vector index uses `sentence-transformers/all-MiniLM-L6-v2` with normalized embeddings and a FAISS `IndexFlatIP` index. Because vectors are normalized, inner-product ranking corresponds to cosine-similarity ranking. The retrieval test retrieved relevant source material for the UAT-11985 campaign and a Veeam vulnerability query. Similarity values are retrieval-ranking scores, not factual confidence or answer-accuracy percentages.

### 8.3 Local language model and answer generation

Ollama was installed locally with `qwen2.5:3b`. The ASK CYRA script loads the FAISS index and metadata, embeds the question, retrieves the top three passages, and sends the retrieved context to Qwen through the local Ollama API. The prompt requests evidence-based answers, uncertainty where evidence is insufficient and source citations. The answer output includes source titles, URLs and excerpts, and notes that similarity is not factual confidence.

A functional UAT-11985 test produced a coherent answer summarizing the reported phishing workflow, fake Google sign-in pages, obfuscated JavaScript, HTTP POST, WebSocket-based synchronization, and possible credential or session-token capture. The answer cited retrieved campaign-analysis material. This demonstrates that the end-to-end local retrieval-and-generation pipeline ran successfully for this test query.

### 8.4 Limitations

This was a functional test, not a comprehensive evaluation of answer correctness, citation faithfulness, retrieval recall, hallucination rate or performance across a benchmark set. Similarity scores must not be interpreted as probabilities. The source analysis itself remains source-reported intelligence, and the answer cannot turn unverified reporting into confirmed fact. ASK CYRA is an analyst-assistance prototype, not an autonomous decision-maker. Analysts must inspect cited source material before acting on an answer.

### 8.5 GenAI disclosure

The implementation uses a locally hosted Qwen2.5:3b model via Ollama for contextual extraction and ASK CYRA answer generation, and `urchade/gliner_small-v2.1` for the documented GLiNER entity-extraction evaluation. Sentence Transformers `all-MiniLM-L6-v2` is used to create retrieval embeddings. Deterministic regex processing is also used for structured indicators. LLM outputs are treated as candidate analysis and checked against retrieved context and source material; the report does not claim independent validation of all generated statements. No real customer records, passwords, API keys or other secrets should be submitted to the model.

## 9. UAT-11985 campaign analysis

### 9.1 Source and indicator scope

The case study is based on public Cisco Talos reporting and its public UAT-11985 IOC file. The project recorded eight source-reported entries: five URLs and three email addresses. These entries are retained as unverified; they have not been independently validated by ThreatLens.

### 9.2 Reported behavior

The source describes phishing emails leading to fake Google sign-in pages, obfuscated JavaScript, HTTP POST activity, WebSocket-based authentication/MFA state synchronization, and possible credential or session-token capture that could support account takeover. The actor is unknown in the project analysis. The case study does not establish that Indian banks were targeted or that the reported activity affected an Indian BFSI organization.

### 9.3 Diamond Model

The campaign analysis uses the Diamond Model to structure relationships among adversary, capability, infrastructure and victim. Where the source does not identify an actor or a confirmed victim, the analysis preserves uncertainty rather than inventing attribution. Infrastructure and capabilities are documented as source-reported information, and the victim context is not assumed to be Indian BFSI.

### 9.4 MITRE ATT&CK mapping

The STIX bundle includes ATT&CK references T1557 and T1566.002. These mappings are analytical mappings to reported behaviors, not observations of a live attack within the ThreatLens lab. ATT&CK mappings should be treated as hypotheses grounded in cited reporting and revised if source evidence changes.

## 10. STIX 2.1 intelligence sharing

The enhanced bundle is `stix/uat11985_enhanced_bundle.json`, generated by `stix/build_uat11985_enhanced_bundle.py`. Its inventory contains 23 objects:

| Object type | Count |
|---|---:|
| Identity | 1 |
| Campaign | 1 |
| Attack Pattern | 2 |
| Indicator | 8 |
| Relationship | 10 |
| Report | 1 |
| **Total** | **23** |

The validation report records that all 23 objects declare STIX 2.1, all object IDs are unique, and all relationship source/target references resolve to existing objects. All eight indicators retain the `unverified` label. The bundle contains a campaign object and a threat report, and the original bundle was preserved.

These checks establish structural consistency, not factual accuracy or independent indicator validation. The eight indicators remain source-reported. A SOC consuming this bundle should review source, confidence, timestamp and unverified status; correlate indicators against its own telemetry; and apply local policy before using them for blocking or alerting. Import should be tested in a non-production or staging instance first.

## 11. Sigma rules and Splunk testing

### 11.1 Test environment and method

Two experimental Sigma rules associated with the UAT-11985 case were converted to Splunk SPL using the installed Sigma CLI and Splunk backend. The generated SPL was executed in Splunk Search & Reporting against synthetic events created with `makeresults`. The test events were not persisted to a Splunk index.

### 11.2 Phishing-domain rule

Rule: `sigma_rules/google_auth_phishing_hunt.yml`

Expected behavior:
- Match `google.morelessty.com`.
- Match `jmlh.morelessty.com`.
- Exclude the benign control domain `example.org`.

Observed result: two expected matches; the benign control was excluded.

### 11.3 Email-indicator rule

Rule: `sigma_rules/uat11985_email_indicator_hunt.yml`

Expected behavior:
- Match `hoangthikieuanh254@gmail.com`.
- Match `chenzhengyu1989@gmail.com`.
- Exclude the benign control sender `normal-user@example.com`.

Observed result: two expected matches; the benign control was excluded.

### 11.4 Interpretation

Both rules passed the synthetic search-logic tests. This demonstrates expected matching and benign-control exclusion in controlled test data. It does not demonstrate end-to-end detection from persisted proxy or email telemetry, and the source-reported indicators have not been independently validated by this project. Operational use requires validation against representative, authorized data and review of false positives.

## 12. Wazuh controlled ingestion test

### 12.1 Setup

The Wazuh 4.14.9 Docker environment used a registered agent named `threatlens-linux-agent`, ID `001`. A synthetic SSH authentication-failure line was written to `/tmp/threatlens-ssh-test.log` inside the agent container. The manager alert output was `/var/ossec/logs/alerts/alerts.json`.

### 12.2 Test event and observed alert

The test record was:

`Oct 16 20:35:00 threatlens-lab sshd[4321]: Failed password for invalid user testuser from 198.51.100.25 port 2222 ssh2`

The address `198.51.100.25` is reserved for documentation and was used only for this controlled test.

Wazuh recorded an alert with:
- Agent `threatlens-linux-agent`, ID `001`
- Rule ID `5710`
- Rule description `sshd: Attempt to login using a non-existent user`
- Severity level 5
- Source IP `198.51.100.25`
- Username `testuser`
- Decoder `sshd`
- Log source `/tmp/threatlens-ssh-test.log`
- Rule-reported ATT&CK mappings T1110.001 and T1021.004

### 12.3 Interpretation and limitations

The evidence supports that a synthetic record was forwarded from the monitored file through the agent to the manager, parsed, evaluated by built-in rule 5710 and written as an alert. This verifies the tested file-to-agent-to-manager path.

It was not an actual SSH login attempt or evidence of a real attack. It does not show that real Windows or WSL authentication logs were monitored. The report explicitly notes that this event matched built-in rule 5710 and does not establish that custom rule 100001 generated the alert. The agent's container has its own view of system data.

## 13. Strategic weekly intelligence brief

The project includes `ThreatLens_Weekly_Threat_Brief_2026-10-15.pdf`, a three-page executive-facing brief. It summarizes bounded collection and highlights a key analytical caveat: the collected sample does not establish activity against the specific Indian BFSI priorities of ATM jackpotting, SWIFT malware, UPI fraud kits or politically motivated DDoS. UAT-11985 is presented as a supporting identity-phishing case study, not proof of targeting of Indian banks.

This is an important negative finding. A threat-intelligence product should distinguish “not observed in this sample” from “does not exist.” The current dataset is bounded and may not cover all sources, sectors or historical periods.

## 14. Analyst feedback and operational use

A practical feedback mechanism for a SOC analyst using this prototype should capture:
- Whether an item is relevant to a defined PIR.
- Whether an indicator was independently corroborated and by which source.
- Whether a candidate was a false positive, benign reference or duplicate.
- Whether an ATT&CK mapping is supported by source behavior.
- Whether a Sigma rule produced a true or false positive on authorized telemetry.
- Whether ASK CYRA retrieved relevant evidence and whether each citation supported its answer.
- Whether the item should be retained, downgraded, escalated or excluded from operational use.

Feedback should be versioned with analyst, timestamp, source reference and rationale. A future iteration can use this feedback to prioritize collection and improve labelled evaluation data. The current project documents this design direction; it does not claim a fully deployed analyst-feedback workflow unless separately evidenced.

## 15. Safety, ethics and confidentiality

1. All offensive activity, scanning and exploitation must remain confined to authorized lab environments. No real-world target testing is claimed in this report.
2. Public OSINT collection must respect applicable law, source terms, API conditions, rate limits and attribution requirements.
3. No API keys, passwords, real customer data or secrets should be included in reports, screenshots, source control or LLM prompts.
4. GenAI output is treated as an analyst aid and checked against source material. It is not a substitute for independent validation.
5. All project evidence and logs should be treated as confidential and shared only with authorized evaluators or reviewers.
6. Source-reported indicators remain unverified until corroborated. No automated blocking or attribution should be based solely on an unverified candidate.
7. The local MISP HTTPS certificate-verification warning should be addressed before operational deployment.
8. The prototype is for educational and defensive use, not a production security service.

## 16. Limitations and future work

The principal limitations are:

- Collection is bounded; OTX retrieval covers a sample of available pulses, and the RSS counts are not broken down by individual feed.
- Source terms and usage restrictions should be reviewed before operational use.
- Candidate entity counts include values that are not confirmed malicious IoCs, including CVEs and potentially legitimate URLs or domains.
- The MISP audit establishes unique normalized type/value pairs, not independent maliciousness.
- The NLP evaluation uses five advisories and a non-exhaustive reference set; its saved metrics were not independently recomputed during this report assembly.
- ASK CYRA passed a functional test, but there is no comprehensive benchmark for answer accuracy, citation faithfulness, retrieval recall or hallucination rate.
- The STIX bundle was structurally validated, but its intelligence remains source-reported.
- Sigma rules were tested with synthetic, non-persisted events rather than production logs.
- Wazuh was tested with a synthetic event in a container-level lab, not real host authentication telemetry.
- The UAT-11985 analysis does not establish Indian BFSI targeting.
- The local MISP client was configured without HTTPS certificate verification during these checks.

Future work should prioritize a larger independently labelled extraction benchmark, a repeatable ASK CYRA evaluation set, individual RSS feed collection counts, review of source terms, correction of certificate verification, testing detection rules against authorized indexed telemetry, and analyst feedback on retrieval relevance and intelligence utility.

## 17. Conclusion

ThreatLens demonstrates an end-to-end educational CTI prototype for BFSI-oriented analysis. It combines public OSINT collection, provenance-preserving candidate processing, MISP population and verification, pilot NLP evaluation, enrichment, campaign analysis, ATT&CK mapping, STIX 2.1 output, Sigma/Splunk logic tests, Wazuh ingestion testing and a local LLM-assisted RAG workflow through ASK CYRA.

The evidence is strongest where specific read-only counts and controlled tests are documented: 160 unique MISP attribute type/value pairs retrieved, 150 of 150 pilot pairs matched, two Sigma rules passing synthetic search tests, one synthetic Wazuh event detected, and a 23-object STIX bundle passing documented structural checks. The NLP report provides pilot metrics, while ASK CYRA has functional evidence but not a comprehensive accuracy score.

The project should therefore be presented as a functioning prototype with measured pilot results and explicit limitations—not as a production-ready platform or proof that all candidate indicators are malicious. Its principal value is the traceable workflow from public reporting to analyst-oriented outputs, with uncertainty retained and human validation kept in the loop.

## References and project artifacts

### Project documents and reports
- `docs/PIR_Document.md`
- `reports/collection_report.md`
- `reports/MISP_Verification_Evidence.md`
- `reports/ThreatLens_NLP_Evaluation.md`
- `reports/ThreatLens_VirusTotal_Enrichment_Analysis.md`
- `reports/Sigma_Splunk_Test_Evidence.md`
- `reports/STIX_Enhanced_Bundle_Validation.md`
- `reports/Wazuh_Live_Ingestion_Test.md`
- `ThreatLens_Weekly_Threat_Brief_2026-10-15.pdf`
- `analysis/UAT-11985_Diamond_Model.md`
- `analysis/ask_cyra_rag.py`
- `analysis/cyra_llm_extraction.py`
- `stix/uat11985_enhanced_bundle.json`
- `stix/build_uat11985_enhanced_bundle.py`
- `sigma_rules/google_auth_phishing_hunt.yml`
- `sigma_rules/uat11985_email_indicator_hunt.yml`

### Public source endpoints
- CERT-In: https://www.cert-in.org.in/s2cMainServlet
- CIS Security advisories RSS: https://www.cisecurity.org/feed/advisories
- Cisco Talos RSS: https://feeds.feedburner.com/feedburner/Talos
- AlienVault OTX subscribed pulses API: https://otx.alienvault.com/api/v1/pulses/subscribed
- Cisco Talos UAT-11985 analysis: https://blog.talosintelligence.com/uat-11985/
- Cisco Talos IOC repository path used for the case: https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/10/uat-11985.txt

### GenAI and retrieval components
- GLiNER model used in pilot evaluation: `urchade/gliner_small-v2.1`
- Sentence Transformers embedding model: `sentence-transformers/all-MiniLM-L6-v2`
- Local generation model: `qwen2.5:3b` served by Ollama

---

## Submission checklist (complete before final hand-in)

- [ ] Confirm the final report title page and required course metadata.
- [ ] Re-open the generated report and check formatting, tables, links and encoding.
- [ ] Verify that all referenced artifacts are included in the submission package.
- [ ] Include source code and related project files, excluding `.env`, API keys, passwords, tokens and other secrets.
- [ ] Include the weekly brief PDF, STIX bundle, Sigma rules, evaluation report and evidence screenshots/logs.
- [ ] Prepare the presentation deck or submit the report if that satisfies the course's stated choice.
- [ ] Record and review the required 15-minute video presentation.
- [ ] Check that the video and slides distinguish synthetic tests from real telemetry and source-reported intelligence from verified indicators.
- [ ] Ensure the final package contains no credentials, sensitive logs or unapproved personal/customer data.
