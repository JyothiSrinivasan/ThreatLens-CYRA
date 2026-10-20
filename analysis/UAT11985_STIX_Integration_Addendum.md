# ThreatLens — UAT-11985 STIX Integration Addendum

**Related analysis:** `analysis/UAT-11985_Diamond_Model.md`  
**STIX bundle:** `stix/uat11985_enhanced_bundle.json`  
**Builder:** `stix/build_uat11985_enhanced_bundle.py`  
**Validation evidence:** `reports/STIX_Enhanced_Bundle_Validation.md`

## 1. Integration Summary

The enhanced STIX 2.1 bundle represents the UAT-11985 case study using a campaign object, source-reported indicators, ATT&CK attack-pattern objects, relationships, and a threat report.

| STIX object type | Count |
|---|---:|
| Identity | 1 |
| Campaign | 1 |
| Attack Pattern | 2 |
| Indicator | 8 |
| Relationship | 10 |
| Report | 1 |
| **Total** | **23** |

## 2. Technique Mapping

- **T1557 — Adversary-in-the-Middle:** Included based on the authentication-relaying behavior described in the source reporting.
- **T1566.002 — Spearphishing Link:** Included based on the reported phishing emails and deceptive links.
- **T1056.003 — Web Portal Capture:** Retained as a candidate in the existing campaign analysis; it is not included as an attack-pattern object in this enhanced bundle.

These are source-based analytical mappings. They do not constitute independent observation of the campaign in the ThreatLens lab.

## 3. Validation Results

The generated bundle was parsed as STIX 2.1. Separate structural checks confirmed:

- 23 objects declare STIX version 2.1.
- Object IDs are unique.
- Relationship source and target references resolve to existing objects.
- All eight indicators retain the `unverified` label.
- The bundle contains one campaign, two attack-pattern objects, ten relationships, and one report.
- The original STIX bundle remains unchanged.

Structural validation confirms bundle consistency; it does not independently validate the threat indicators or the reported campaign behavior.

## 4. Evidence Limitations

The eight indicators remain source-reported and unverified by ThreatLens. No claim is made that the campaign targeted Indian banks, UPI, ATM infrastructure, or SWIFT systems. The reported Talos detection references have not been independently tested in the ThreatLens environment.

## 5. Relationship to the Main Analysis

Use this addendum alongside `analysis/UAT-11985_Diamond_Model.md`. The Diamond Model remains the primary campaign analysis; this document records how the case study was represented and structurally validated in STIX 2.1.
