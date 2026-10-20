# Sigma Detection Testing — Splunk Enterprise

**Project:** ThreatLens — CYRA: AI-Driven Threat Detection and Risk Analytics  
**Test date:** 16 October 2026  
**Platform:** Splunk Enterprise running in Docker  
**Test type:** Synthetic-event detection logic validation

## 1. Objective

Validate the detection logic of two experimental Sigma rules associated with the Cisco Talos UAT-11985 threat-intelligence case by converting the rules to Splunk SPL and testing them against controlled synthetic events.

## 2. Phishing-Domain Detection

**Rule file:** `sigma_rules/google_auth_phishing_hunt.yml`

**Expected behaviour:**
- Match `google.morelessty.com`.
- Match `jmlh.morelessty.com`.
- Exclude the benign control domain `example.org`.

**Observed result:** 2 expected matches. The benign control domain was excluded.

**Status:** PASS — synthetic search-logic test.

## 3. Email-Indicator Detection

**Rule file:** `sigma_rules/uat11985_email_indicator_hunt.yml`

**Expected behaviour:**
- Match `hoangthikieuanh254@gmail.com`.
- Match `chenzhengyu1989@gmail.com`.
- Exclude the benign control sender `normal-user@example.com`.

**Observed result:** 2 expected matches. The benign control sender was excluded.

**Status:** PASS — synthetic search-logic test.

## 4. Test Method

Both Sigma rules were converted using the installed Sigma CLI and the Splunk backend. The resulting SPL was executed in Splunk Search & Reporting against synthetic events generated with `makeresults`.

The searches ran successfully and returned the expected results.

## 5. Limitations

- Test events were generated at search time and were not persisted to a Splunk index.
- No real proxy logs or live malicious activity were used.
- These tests validate matching logic, not end-to-end detection from a production data source.
- The indicators remain source-reported and have not been independently validated by this project.

## 6. Evidence

Attach or reference the following screenshots:
1. Three synthetic events created in Splunk.
2. Phishing-domain search returning two results.
3. Email-indicator search returning two results.

Retain the terminal output showing successful conversion of both Sigma rules to Splunk SPL.

## 7. Conclusion

Both experimental Sigma rules produced the expected results against controlled synthetic data in a running Splunk Enterprise instance. Further validation against indexed proxy or email telemetry is required before operational deployment.
