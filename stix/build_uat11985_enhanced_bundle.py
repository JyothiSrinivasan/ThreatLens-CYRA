import json
from datetime import datetime, timezone
from pathlib import Path

from stix2 import (
    AttackPattern,
    Bundle,
    Campaign,
    ExternalReference,
    Identity,
    Indicator,
    Relationship,
    Report,
    parse,
)

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data" / "processed" / "talos_uat_11985_candidates.json"
OUTPUT = ROOT / "stix" / "uat11985_enhanced_bundle.json"

if OUTPUT.exists():
    raise SystemExit(f"Refusing to overwrite existing file: {OUTPUT}")

records = json.loads(INPUT.read_text(encoding="utf-8"))
if len(records) != 8:
    raise SystemExit(f"Expected 8 source indicators, found {len(records)}")

created = datetime.now(timezone.utc)

talos_article = ExternalReference(
    source_name="Cisco Talos campaign analysis",
    url="https://blog.talosintelligence.com/uat-11985/",
)
talos_ioc_source = ExternalReference(
    source_name="Cisco Talos public IOC repository",
    url="https://raw.githubusercontent.com/Cisco-Talos/IOCs/main/2026/10/uat-11985.txt",
)

creator = Identity(
    name="ThreatLens",
    identity_class="organization",
    description="ThreatLens capstone threat-intelligence project",
    created=created,
)

campaign = Campaign(
    name="UAT-11985 Google Adversary-in-the-Middle Phishing Campaign",
    description=(
        "Campaign represented from Cisco Talos public reporting. "
        "Talos describes spear-phishing lures, a spoofed Google sign-in "
        "interface and real-time authentication relaying. This is a "
        "source-based representation; ThreatLens has not independently "
        "validated the reported indicators. The available evidence does "
        "not establish targeting of Indian banks."
    ),
    created=created,
    created_by_ref=creator.id,
    external_references=[talos_article],
    labels=["source-reported", "ThreatLens-case-study", "UAT-11985"],
)

# Technique mappings are limited to behaviors described by the source.
attack_patterns = [
    AttackPattern(
        name="Adversary-in-the-Middle",
        description=(
            "Talos describes the phishing infrastructure relaying "
            "authentication between the victim and the legitimate service."
        ),
        created=created,
        created_by_ref=creator.id,
        external_references=[
            ExternalReference(
                source_name="mitre-attack",
                external_id="T1557",
                url="https://attack.mitre.org/techniques/T1557/",
            ),
            talos_article,
        ],
        labels=["source-supported-mapping"],
    ),
    AttackPattern(
        name="Spearphishing Link",
        description=(
            "Talos describes spear-phishing emails containing deceptive "
            "links that direct recipients to phishing infrastructure."
        ),
        created=created,
        created_by_ref=creator.id,
        external_references=[
            ExternalReference(
                source_name="mitre-attack",
                external_id="T1566.002",
                url="https://attack.mitre.org/techniques/T1566/002/",
            ),
            talos_article,
        ],
        labels=["source-supported-mapping"],
    ),
]

objects = [creator, campaign, *attack_patterns]
indicator_ids = []

for record in records:
    value = record["value"]
    kind = record["type"].lower()

    if kind == "url":
        pattern_value = (
            value.replace("https[:]", "https:")
                 .replace("http[:]", "http:")
                 .replace("[.]", ".")
        )
        pattern = f"[url:value = '{pattern_value}']"
    elif kind == "email":
        pattern_value = value.replace("[.]", ".")
        pattern = f"[email-addr:value = '{pattern_value}']"
    else:
        raise SystemExit(f"Unsupported indicator type: {kind}")

    indicator = Indicator(
        name=f"UAT-11985 source-reported {kind} indicator",
        description=(
            f"Original reported value: {value}. "
            "Validation status: source_reported_unverified. "
            "Collected from the Cisco Talos public IOC repository. "
            "Not independently validated by ThreatLens."
        ),
        pattern=pattern,
        pattern_type="stix",
        pattern_version="2.1",
        valid_from=created,
        created=created,
        created_by_ref=creator.id,
        external_references=[talos_ioc_source, talos_article],
        labels=["source-reported", "unverified", "UAT-11985"],
        confidence=20,
        indicator_types=["malicious-activity"],
    )
    objects.append(indicator)
    indicator_ids.append(indicator.id)

    # The source associates this indicator with UAT-11985;
    # the relationship does not independently validate the indicator.
    objects.append(
        Relationship(
            relationship_type="indicates",
            source_ref=indicator.id,
            target_ref=campaign.id,
            description=(
                "Source-reported association with UAT-11985; "
                "indicator remains unverified by ThreatLens."
            ),
            created=created,
            created_by_ref=creator.id,
            external_references=[talos_ioc_source, talos_article],
        )
    )

for attack_pattern in attack_patterns:
    objects.append(
        Relationship(
            relationship_type="uses",
            source_ref=campaign.id,
            target_ref=attack_pattern.id,
            description=(
                "Technique mapping based on behavior described in "
                "the Cisco Talos report; not independently observed "
                "in the ThreatLens environment."
            ),
            created=created,
            created_by_ref=creator.id,
            external_references=[talos_article],
        )
    )

report = Report(
    name="ThreatLens UAT-11985 Campaign Analysis",
    description=(
        "Source-based campaign analysis using Cisco Talos reporting and "
        "eight source-reported indicators. Technique mappings are linked "
        "to the source report. Indicators remain unverified by ThreatLens. "
        "No claim is made that Indian banks were targeted."
    ),
    report_types=["threat-report"],
    published=created,
    created=created,
    created_by_ref=creator.id,
    object_refs=[obj.id for obj in objects],
    external_references=[talos_article, talos_ioc_source],
)
objects.append(report)

bundle = Bundle(objects=objects)
OUTPUT.write_text(bundle.serialize(pretty=True), encoding="utf-8")

# Parse the saved file to verify that it can be read as STIX 2.1.
saved = parse(OUTPUT.read_text(encoding="utf-8"), version="2.1")

print("Enhanced STIX bundle created:", OUTPUT.relative_to(ROOT))
print("Total STIX objects:", len(saved.objects))
print("Indicators:", sum(o.type == "indicator" for o in saved.objects))
print("Campaigns:", sum(o.type == "campaign" for o in saved.objects))
print("Attack patterns:", sum(o.type == "attack-pattern" for o in saved.objects))
print("Relationships:", sum(o.type == "relationship" for o in saved.objects))
print("Reports:", sum(o.type == "report" for o in saved.objects))
print("Original STIX bundle unchanged.")
