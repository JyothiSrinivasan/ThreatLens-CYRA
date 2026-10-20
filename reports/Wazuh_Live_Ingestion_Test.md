# Wazuh Live-Ingestion Test — ThreatLens / CYRA

**Test date:** 16 October 2026  
**Platform:** Wazuh 4.14.9 running in Docker  
**Test type:** Controlled synthetic-event ingestion and detection

## Objective
Verify that a log record written to a monitored file on a registered Wazuh agent is forwarded to the Wazuh manager, parsed, evaluated by a detection rule, and recorded as an alert.

## Setup
- Manager: `wazuh.manager`
- Agent name: `threatlens-linux-agent`
- Agent ID: `001`
- Test log: `/tmp/threatlens-ssh-test.log` inside the agent container
- Manager alert output: `/var/ossec/logs/alerts/alerts.json`

## Test event
A synthetic SSH authentication-failure record was written to the agent's dedicated test log:

`Oct 16 20:35:00 threatlens-lab sshd[4321]: Failed password for invalid user testuser from 198.51.100.25 port 2222 ssh2`

The source IP `198.51.100.25` is reserved for documentation and was used only for this controlled test.

## Observed result
Wazuh recorded the event in `alerts.json` with these fields:
- Agent: `threatlens-linux-agent` (ID `001`)
- Rule ID: `5710`
- Rule description: `sshd: Attempt to login using a non-existent user`
- Severity level: `5`
- Source IP: `198.51.100.25`
- Source username: `testuser`
- Decoder: `sshd`
- Log source: `/tmp/threatlens-ssh-test.log`
- MITRE ATT&CK mappings reported by the rule: `T1110.001` (Password Guessing) and `T1021.004` (SSH)

## Result
**PASS — synthetic event successfully ingested and detected.**

The manager's alert record identifies agent `001`, includes the original test log, extracts the source IP and username, and records rule `5710`.

## Limitations
- The event was generated synthetically inside the lab; it was not an actual SSH login attempt or evidence of a real attack.
- This test verifies the file-to-agent-to-manager detection path. It does not demonstrate monitoring of the Windows host's or WSL host's real authentication logs.
- The event matched built-in rule `5710`; it does not establish that custom rule `100001` generated this alert.
- The agent runs in a Docker container and has its own container-level view of system data.

## Evidence to retain
Save the terminal output showing:
1. Agent `001` active in `agent_control -l`.
2. Agent connection and startup logs.
3. The test record in `/tmp/threatlens-ssh-test.log`.
4. The corresponding JSON alert in the manager's `alerts.json`.

## Conclusion
The controlled test demonstrates that Wazuh can receive a synthetic SSH authentication-failure record from a registered agent, parse it, apply a detection rule, and write an alert. This provides a verified live-ingestion demonstration for the ThreatLens/CYRA lab.
