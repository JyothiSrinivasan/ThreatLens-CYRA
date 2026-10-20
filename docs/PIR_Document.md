\# ThreatLens — Priority Intelligence Requirements (PIRs)



\*\*Project:\*\* ThreatLens — GenAI-Powered OSINT Threat Intelligence for BFSI

\*\*Programme:\*\* IIT Roorkee × Futurense PG Certificate in AI/GenAI-Powered Cybersecurity

\*\*Project Code:\*\* CAP-TIE-3W

\*\*Project Mode:\*\* Individual

\*\*Version:\*\* 1.0

\*\*Date:\*\* 1 October 2026



\## 1. Purpose



ThreatLens aims to provide a low-cost Cyber Threat Intelligence (CTI) capability for a simulated consortium of Indian regional banks. It collects legally accessible, publicly available threat intelligence, extracts relevant indicators and threat behaviours, and produces actionable intelligence for defensive security operations.



\## 2. Intelligence Scope



\- Sector: Banking, Financial Services and Insurance (BFSI)

\- Geography: India, with relevant global campaigns affecting BFSI

\- Collection method: Public OSINT sources and permitted feeds

\- Reporting period: The preceding 30 days where source data permits

\- Intended users: SOC analysts, CTI analysts and banking security decision-makers

### 2.1 Consortium Mission and Threat Priorities

ThreatLens supports a simulated consortium of Indian regional banks that requires a low-cost, shared Cyber Threat Intelligence (CTI) capability without reliance on a commercial threat-intelligence platform.

The prototype prioritises four threat areas:

1. **ATM jackpotting:** Publicly reported tools, malware families, campaigns and behaviours associated with attacks against ATM infrastructure.
2. **SWIFT-related malware:** Malware and campaigns relevant to interbank payment environments and financial messaging operations.
3. **UPI fraud kits:** Publicly reported phishing infrastructure, malicious domains, fraud-enabling tools and credential-theft behaviours targeting UPI and digital-payment users.
4. **Politically motivated DDoS:** Campaigns, reported targets, attack methods and relevant infrastructure affecting Indian financial institutions.

Ransomware, data theft and actively exploited vulnerabilities are retained as supporting intelligence areas where they are relevant to the consortium's exposure and defensive priorities.

ThreatLens will use legally accessible public intelligence sources, preserve source provenance, distinguish reported information from analytical assessments, and produce a weekly threat brief intended to support defensive prioritisation and information sharing among participating banks.


\## 3. Priority Intelligence Requirements



\### PIR-01 — Banking Malware



\*\*Priority:\*\* High



\*\*Question:\*\* Which malware families and campaigns are reported to target banking systems, ATMs or SWIFT-related environments?



\*\*Information required:\*\*

\- Malware and campaign names

\- Reported targets and affected technologies

\- Associated IP addresses, domains and file hashes

\- Reported attacker behaviours and MITRE ATT\&CK techniques

\- Source publication date and confidence



\*\*Defensive use:\*\* Support threat hunting, intelligence sharing and risk assessment.



\### PIR-02 — UPI and Digital Payment Threats



\*\*Priority:\*\* High



\*\*Question:\*\* What publicly reported phishing infrastructure, malicious domains and fraud-enabling tools target UPI users, digital payment services or financial institutions?



\*\*Information required:\*\*

\- Relevant phishing and fraud campaign reports

\- Reported malicious domains and URLs

\- Associated IP addresses and file hashes, where available

\- Reported delivery and credential-theft behaviours

\- Potential relevance to Indian digital payments



\*\*Defensive use:\*\* Inform fraud prevention, domain monitoring and security awareness.



\### PIR-03 — Ransomware and Data Theft



\*\*Priority:\*\* High



\*\*Question:\*\* Which ransomware and data-theft campaigns are reported to target financial services, and what techniques do they use?



\*\*Information required:\*\*

\- Threat group and campaign names, where reliably attributed

\- Reported victim sectors and incident dates

\- Associated indicators and vulnerabilities

\- Initial-access, persistence and exfiltration behaviours

\- Supporting source references and confidence



\*\*Defensive use:\*\* Improve defensive monitoring and incident preparedness.



\### PIR-04 — DDoS and Hacktivism



\*\*Priority:\*\* Medium



\*\*Question:\*\* Which politically motivated DDoS or hacktivist campaigns are reported to target Indian financial institutions?



\*\*Information required:\*\*

\- Campaign and group names, where supported by evidence

\- Reported target sector and timeframe

\- Publicly reported infrastructure and attack methods

\- Relevant ATT\&CK mappings where applicable

\- Source reliability and attribution confidence



\*\*Defensive use:\*\* Improve situational awareness and availability planning.



\### PIR-05 — Exploited Vulnerabilities



\*\*Priority:\*\* High



\*\*Question:\*\* Which disclosed vulnerabilities relevant to banking infrastructure are reported as actively exploited and may require defensive attention?



\*\*Information required:\*\*

\- CVE identifiers and affected products

\- Publication and disclosure dates

\- Evidence of exploitation in the wild

\- Reported attacker behaviours and available mitigations

\- Source references and confidence



\*\*Defensive use:\*\* Support vulnerability prioritisation and remediation decisions.



\## 4. Collection and Validation Principles



1\. Use legal, publicly accessible sources and comply with their terms.

2\. Preserve source URLs, publication dates and collection timestamps where available.

3\. Deduplicate indicators and retain provenance.

4\. Distinguish observed facts from analytical assessments.

5\. Do not treat an indicator as malicious solely because it appears in a report.

6\. Verify LLM-generated claims against the source and trusted references.

7\. Do not conduct unauthorised scanning, exploitation or access to real-world targets.

### OPSEC Boundaries

ThreatLens operates as a passive, defensive intelligence-collection prototype. Collection is restricted to publicly accessible reports, permitted feeds and authorised APIs. The project will not conduct unauthorised scanning, exploitation, credential testing or access to bank systems, suspected attacker infrastructure or third-party services. Collection credentials and API keys must be stored securely and excluded from published reports and source-code repositories. Any future active validation must be separately authorised and conducted within a documented scope.

\## 5. Intelligence Products



ThreatLens will produce:

\- Tactical intelligence: Structured indicators and STIX 2.1 output.

\- Operational intelligence: Campaign analysis and ATT\&CK mapping.

\- Strategic intelligence: A weekly BFSI threat brief.



\## 6. Review



These PIRs will guide source selection, collection, processing, analysis and reporting. Relevance and usefulness should be reviewed as part of the CTI feedback mechanism.



\*\*Document status:\*\* Initial requirements for the individual capstone prototype.

