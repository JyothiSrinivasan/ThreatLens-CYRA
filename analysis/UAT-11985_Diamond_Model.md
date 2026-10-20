\# ThreatLens Campaign Analysis: UAT-11985



\*\*Project:\*\* ThreatLens — GenAI-Powered OSINT Threat Intelligence for BFSI  

\*\*Platform:\*\* CYRA — AI-Driven Threat Intelligence, Detection \& Risk Analytics  

\*\*Analysis type:\*\* Diamond Model with MITRE ATT\&CK overlay  

\*\*Primary source:\*\* Cisco Talos, UAT-11985 campaign analysis  

\*\*Source article:\*\* https://blog.talosintelligence.com/uat-11985/  

\*\*IOC repository:\*\* https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/10/uat-11985.txt  

\*\*Analysis status:\*\* Source-based assessment; indicators not independently verified



\## 1. Executive Summary



Cisco Talos describes UAT-11985 as a phishing campaign using an adversary-in-the-middle (AitM) framework to target Google-account authentication. The attack begins with a malicious URL delivered through phishing email. A fake Google sign-in page relays authentication interactions to the legitimate service while communicating with attacker-controlled infrastructure.



The reported kit uses obfuscated JavaScript, HTTP POST requests, and a persistent WebSocket connection to coordinate authentication challenges. The campaign's described objective is to capture credentials and authenticated session tokens, potentially enabling account takeover and bypassing certain multi-factor authentication protections.



This campaign is relevant to the banking consortium's broader identity-security and account-takeover concerns. However, the supplied Talos excerpt does not establish that Indian banks, UPI systems, ATM infrastructure, or SWIFT systems were direct targets.



\## 2. Campaign Overview



\### Reported attack chain



1\. A victim receives a phishing email containing a malicious URL.

2\. The URL opens a replica of the Google sign-in page.

3\. Obfuscated JavaScript collects browser information and relays authentication inputs.

4\. The operator's infrastructure forwards authentication interactions to the legitimate Google service.

5\. HTTP POST transmits identifiers, credentials, challenge submissions, and related session data.

6\. WebSocket messages synchronize the phishing page with authentication-state changes and MFA prompts.

7\. The operator may capture an authenticated session and take over the account.



The chain above summarizes the behavior described by Cisco Talos. The document does not independently reproduce or execute the campaign.



\## 3. Diamond Model



\### 3.1 Adversary



\*\*Assessment:\*\* Unknown operator associated with the UAT-11985 campaign.



Talos reports that the phishing kit's localization architecture and terminology suggest, with moderate confidence, that its interface was originally authored by a Simplified Chinese speaker. This is a linguistic assessment and does not establish the operator's identity, nationality, physical location, or organizational affiliation.



\*\*Confidence:\*\* Low for operator attribution; moderate for the source's stated localization assessment.



\### 3.2 Capability



The reported capabilities include:



\- AitM phishing and authentication relaying.

\- A replica Google sign-in interface supporting Simplified Chinese, Traditional Chinese, and English.

\- Obfuscated JavaScript using string rotation and control-flow obfuscation.

\- HTTP POST-based transmission of authentication inputs and browser information.

\- WebSocket-based real-time synchronization of authentication challenges.

\- Credential and authenticated session-token capture.



\*\*Confidence:\*\* High that these behaviors are described in the supplied Talos report; not independently validated by this project.



\### 3.3 Infrastructure



The project collected eight indicators from the public Cisco Talos UAT-11985 IOC repository. The records preserve their original defanged values and source provenance in `data/processed/unified\_candidate\_iocs.json`.



The indicators are recorded as `source\_reported\_unverified`. They have not been independently validated, and the analysis does not activate them as detection indicators.



\*\*Primary sources:\*\*



\- Campaign analysis: https://blog.talosintelligence.com/uat-11985/

\- IOC repository: https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/10/uat-11985.txt



\### 3.4 Victim



The source describes Google-account users interacting with the phishing page. The supplied excerpt does not establish a specific victim organization, Indian bank, or geographic victim concentration.



For the banking consortium, the relevant risk is transferable: a similar authentication-relay approach could threaten users of financial or enterprise services if adapted to those services. This is a defensive risk assessment, not a claim that such adaptation was observed in UAT-11985.



\## 4. MITRE ATT\&CK Overlay



| Observed behavior | ATT\&CK technique | Evidence and caveat |

|---|---|---|

| Phishing email delivers a malicious URL | T1566 — Phishing | Supported by the reported initial access chain; sub-technique requires further validation. |

| AitM authentication relay | T1557 — Adversary-in-the-Middle | Explicitly referenced in the supplied Talos analysis. |

| Fake sign-in page collects authentication input | T1056.003 — Web Portal Capture | Candidate mapping; verify the technique definition and scope before finalizing. |

| HTTP POST and WebSocket communications | Command-and-control or web-protocol behavior | Do not assign a specific technique solely from the protocol; additional evidence is needed. |

| Obfuscated JavaScript | Defense-evasion behavior may be relevant | A specific ATT\&CK mapping requires validation against the implementation details. |



The ATT\&CK mappings are analytical candidates, not a claim that every technique has been independently confirmed. Before publication, verify technique names, identifiers, and applicability against the current MITRE ATT\&CK knowledge base.



\## 5. Defensive Detection Opportunities



The supplied Talos report lists the following detection references:



\- \*\*ClamAV:\*\* `Html.Phishing.UAT11985-10060614-0`

\- \*\*Snort 2:\*\* SID `67198`

\- \*\*Snort 3:\*\* SID `31`



These are source-reported detection references. ThreatLens has not yet tested their availability, compatibility, or effectiveness in its own environment.



Potential defensive monitoring opportunities include:



\- Detection of phishing URLs and fake authentication portals.

\- Review of unusual authentication flows and suspicious session behavior.

\- Investigation of authentication events where user interaction and session activity are inconsistent.

\- Review of suspicious outbound HTTP and persistent WebSocket activity in relevant endpoint or network telemetry.



These are proposed defensive use cases, not validated detections produced by this capstone.



\## 6. Relevance to the BFSI Consortium



UAT-11985 is useful as an identity-security case study because credential theft and authenticated-session compromise can create risks for organizations that rely on web authentication.



The campaign does not, based on the supplied excerpt, satisfy the consortium's four primary threat priorities directly:



\- ATM jackpotting tools

\- SWIFT-related malware

\- UPI fraud kits

\- Politically motivated DDoS



It should therefore be presented as a supporting authentication-threat case study, not as proof of direct targeting of the consortium or as a substitute for evidence covering those four priorities.



\## 7. Limitations and Confidence



1\. The analysis is based on the supplied Cisco Talos campaign report and the project's collected IOC records.

2\. The eight indicators are source-reported and unverified.

3\. The campaign operator's identity is unknown.

4\. Direct targeting of Indian banks is not established by the supplied source excerpt.

5\. ATT\&CK mappings beyond the explicitly referenced T1557 are candidates pending technique-level validation.

6\. Detection references have not been tested in the ThreatLens environment.

7\. No active scanning, connection attempts, or execution of the campaign infrastructure was performed for this analysis.



\## 8. Sources



1\. Cisco Talos, UAT-11985 campaign analysis: https://blog.talosintelligence.com/uat-11985/

2\. Cisco Talos public IOC repository: https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/10/uat-11985.txt

3\. MITRE ATT\&CK, T1557 — Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/



\*\*Status:\*\* Initial source-based campaign analysis. Ready for evidence review and integration into the final capstone report after ATT\&CK mappings and source-reported indicators are validated.


## Framework Alignment: MITRE ATT&CK, NIST CSF 2.0 and OWASP

### 1. MITRE ATT&CK Mapping

The UAT-11985 reporting describes an adversary-in-the-middle (AitM) phishing operation involving a fake Google sign-in page, obfuscated JavaScript, HTTP POST requests, WebSocket communication, and the potential capture of credentials and session tokens.

| Observed or reported behaviour | ATT&CK mapping | Confidence and limitation |
|---|---|---|
| Phishing through a fake Google sign-in page | T1566 — Phishing | Plausible mapping; the specific sub-technique requires further evidence. |
| Adversary-in-the-middle activity | T1557 — Adversary-in-the-Middle | Supported by the campaign reporting; validate the exact technique details against MITRE ATT&CK. |
| Potential credential capture through a web portal | T1056.003 — Web Portal Capture | Candidate mapping requiring further validation against the reported implementation. |

These mappings are analytical classifications, not proof that every technique was observed in a victim environment. They should be validated against the official MITRE ATT&CK knowledge base before operational use.

**Threat-hunting application:** A SOC analyst could investigate suspicious authentication pages, unusual sign-in activity, unexpected session changes, and relevant proxy or endpoint telemetry. The eight campaign-associated indicators in this project remain source-reported and unverified; they must not be treated as confirmed malicious activity.

### 2. NIST Cybersecurity Framework 2.0 Alignment

ThreatLens supports selected cybersecurity activities aligned with the NIST Cybersecurity Framework (CSF) 2.0:

- **Govern:** Define collection boundaries, permitted sources, confidence labels, and rules against automatically blocking unverified indicators.
- **Identify:** Record threat intelligence sources, affected assets and potential risks relevant to the financial-services environment.
- **Detect:** Develop and validate candidate Sigma rules for hunting relevant authentication and email indicators.
- **Respond:** Provide a campaign analysis, investigation leads, and a STIX 2.1 bundle that a SOC analyst can review.
- **Protect:** Recommend appropriate authentication controls and secure configurations based on validated findings.
- **Recover:** Treat recovery as a downstream incident-response activity; this campaign analysis does not demonstrate recovery testing or implementation.

This is a project-level alignment, not a claim of full NIST CSF implementation or certification.

### 3. OWASP Security Relevance

The campaign provides a useful defensive case study for two risks in the OWASP Top 10 for Web Application Security:

- **A07:2025 — Authentication Failures:** Relevant to investigating phishing-enabled credential theft and possible session compromise. This is a defensive relevance mapping, not evidence that a particular Google service has this vulnerability.
- **A09:2025 — Security Logging and Alerting Failures:** Relevant to ensuring authentication events, suspicious session activity, and investigation evidence are logged and reviewed appropriately.

For the future GenAI-assisted enrichment workflow, ThreatLens should also treat external threat reports and indicator descriptions as untrusted input. Model-generated classifications must be reviewed, traceable to their sources, and prevented from directly triggering blocking actions. This is a design safeguard, not a claim that a generative LLM is currently implemented.

### 4. Scope and Evidence Limitations

The UAT-11985 case is used to demonstrate the campaign-analysis and threat-hunting workflow. The available evidence does not establish that this campaign targeted Indian banks or that the campaign indicators are currently active. The analysis must not be presented as proof of a current threat to the consortium.

**References**

- MITRE ATT&CK: https://attack.mitre.org
- NIST Cybersecurity Framework 2.0: https://www.nist.gov/cyberframework
- OWASP Top 10: https://owasp.org/www-project-top-ten/

