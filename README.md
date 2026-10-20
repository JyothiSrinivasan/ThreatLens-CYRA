\# ThreatLens — GenAI-Powered OSINT Threat Intelligence for BFSI



\*\*CYRA — AI-Driven Threat Detection and Risk Analytics\*\*



An individual capstone project developed for the IIT Roorkee × Futurense AI/GenAI-powered cybersecurity program.



\## Overview



ThreatLens is a threat-intelligence prototype that collects and analyzes public cybersecurity information, extracts indicators of compromise (IoCs), organizes campaign intelligence, and uses generative AI to support analyst investigation.



CYRA is the interactive interface, including \*\*ASK CYRA\*\*, a retrieval-augmented generation (RAG) assistant that answers questions using retrieved project knowledge and source references.



\## Key capabilities



\- \*\*OSINT collection:\*\* Public security advisories, RSS feeds, and threat-intelligence sources.

\- \*\*Indicator extraction and enrichment:\*\* Candidate IP addresses, domains, URLs, hashes, CVEs, and other indicators.

\- \*\*Threat analysis:\*\* UAT-11985 campaign case study, Diamond Model analysis, and MITRE ATT\&CK mapping.

\- \*\*GenAI and RAG:\*\* Local Qwen2.5:3b via Ollama, Sentence Transformers embeddings, and FAISS retrieval.

\- \*\*Threat sharing:\*\* STIX 2.1 bundles and MISP integration evidence.

\- \*\*Detection engineering:\*\* Two Sigma rules tested against synthetic Splunk events.

\- \*\*Evaluation and reporting:\*\* NLP evaluation, validation evidence, and a weekly threat brief.



\## Technology stack



Python · Streamlit · Ollama · Qwen2.5:3b · FAISS · Sentence Transformers · GLiNER · MISP · STIX 2.1 · Sigma · Splunk · Wazuh



\## Repository structure



\- `app.py` — Streamlit CYRA dashboard.

\- `analysis/` — ASK CYRA RAG, campaign analysis, and supporting scripts.

\- `collectors/` — OSINT collection, parsing, and enrichment scripts.

\- `docs/` — Priority Intelligence Requirements (PIRs) and source register.

\- `notebooks/` — NLP evaluation notebook.

\- `reports/` — Final report, weekly brief, and implementation evidence.

\- `sigma\_rules/` — Sigma detection rules.

\- `stix/` — STIX bundles and generation scripts.



\## Run locally



This prototype depends on local model and knowledge-base resources. A GitHub checkout alone does not include every generated local data artifact.



1\. Install Python and Git.

2\. Clone this repository.

3\. Install the project's Python dependencies.

4\. Configure the local knowledge index and required data resources.

5\. Install Ollama and obtain the `qwen2.5:3b` model.

6\. Start the Streamlit application with `streamlit run app.py`.



The exact dependencies and local resource paths must be configured for the environment in which the application is run.



\## Current demo status



ASK CYRA was functionally tested in the local environment. \*\*A public, hosted ASK CYRA demo is not yet available.\*\* The repository currently provides source code and project evidence, not a live hosted AI service.



\## Evaluation and limitations



\- NLP metrics are pilot results from a limited labelled dataset.

\- Sigma tests used synthetic Splunk events.

\- STIX structural validation does not independently verify every indicator.

\- Collected indicators are not automatically confirmed malicious.

\- AI-generated answers and cited evidence require human verification.

\- This project is an analyst-assistance prototype, not a production SOC platform.



\## Responsible use



Uses public threat-intelligence sources for defensive analysis. Do not submit secrets, credentials, or confidential customer data to the AI assistant. Verify source material before taking action based on generated answers.



\## Project deliverables



See `reports/` for the final capstone report, collection evidence, MISP verification, NLP evaluation, Sigma testing, STIX validation, Wazuh testing, and weekly threat brief.

