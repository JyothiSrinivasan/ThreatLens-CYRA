# ThreatLens — Enhanced STIX Bundle Validation

## Artifact
- File: `stix/uat11985_enhanced_bundle.json`
- Format: STIX 2.1 JSON bundle
- Case study: UAT-11985
- Validation date: 18 October 2026

## Object inventory
| Object type | Count |
|---|---:|
| Identity | 1 |
| Campaign | 1 |
| Attack Pattern | 2 |
| Indicator | 8 |
| Relationship | 10 |
| Report | 1 |
| **Total** | **23** |

## Validation results
- All 23 objects declare STIX version 2.1.
- All object IDs are unique.
- All relationship source and target references resolve to existing objects.
- All eight indicators retain the `unverified` label.
- MITRE ATT&CK references included: T1557 and T1566.002.
- The bundle includes a campaign object and a threat report.
- The original STIX bundle was preserved.

## Evidence limitations
The bundle represents source-reported intelligence from Cisco Talos. The eight indicators have not been independently validated by ThreatLens. ATT&CK mappings represent analysis of the reported behaviors, not observations from a live attack in the ThreatLens lab. This case study does not establish that Indian banks were targeted.

## Reproducibility
Builder: `stix/build_uat11985_enhanced_bundle.py`

The builder parses the generated bundle as STIX 2.1 after writing it. Structural checks were also run separately to confirm object counts, unique IDs, valid relationship references, indicator labels, and object version declarations.
