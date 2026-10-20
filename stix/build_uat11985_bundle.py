
import json
from pathlib import Path
from datetime import datetime, timezone

from stix2 import (
    Bundle,
    Identity,
    Indicator,
    Report,
    ExternalReference,
    Malware,
    parse,
)

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data" / "processed" / "talos_uat_11985_candidates.json"
OUTPUT = ROOT / "stix" / "uat11985_bundle.json"

records = json.loads(INPUT.read_text(encoding="utf-8"))

creator = Identity(
    name="ThreatLens",
    identity_class="organization",
    description="ThreatLens capstone threat-intelligence project",
)

created = datetime.now(timezone.utc)
objects = [creator]
indicator_ids = []

for record in records:
    value = record["value"]
    kind = record["type"].lower()

    # Preserve the original defanged value in the description.
    # Convert only the value used in the STIX pattern.
    if kind == "url":
        pattern_value = (
            value.replace("https[:]", "https:")
                 .replace("http[:]", "http:")
                 .replace("[.]", ".")
        )
        pattern = f"[url:value = '{pattern_value}']"
        indicator_type = "malicious-activity"
    elif kind == "email":
        pattern_value = value.replace("[.]", ".")
        pattern = f"[email-addr:value = '{pattern_value}']"
        indicator_type = "malicious-activity"
    else:
        print(f"Skipping unsupported type: {kind}")
        continue

    source_url = record.get("source_url")
    article_url = record.get("article_url")
    references = []

    if source_url:
        references.append(
            ExternalReference(
                source_name="Cisco Talos public IOC repository",
                url=source_url,
            )
        )
    if article_url:
        references.append(
            ExternalReference(
                source_name="Cisco Talos campaign analysis",
                url=article_url,
            )
        )

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
        created_by_ref=creator.id,
        external_references=references,
        labels=["source-reported", "unverified", "UAT-11985"],
        confidence=20,
        indicator_types=[indicator_type],
    )
    objects.append(indicator)
    indicator_ids.append(indicator.id)

campaign_report = Report(
    name="ThreatLens UAT-11985 Campaign Indicator Report",
    description=(
        "A source-based bundle of eight indicators reported by Cisco Talos "
        "for UAT-11985: five URLs and three email addresses. "
        "All indicators remain source-reported and unverified. "
        "This report does not assert that the indicators are independently "
        "confirmed malicious or that Indian banks were targeted."
    ),
    report_types=["threat-report"],
    published=created,
    created_by_ref=creator.id,
    object_refs=[creator.id] + indicator_ids,
    external_references=[
        ExternalReference(
            source_name="Cisco Talos campaign analysis",
            url="https://blog.talosintelligence.com/uat-11985/",
        ),
        ExternalReference(
            source_name="Cisco Talos public IOC repository",
            url=(
                "https://raw.githubusercontent.com/Cisco-Talos/IOCs/"
                "main/2026/10/uat-11985.txt"
            ),
        ),
    ],
)

objects.append(campaign_report)

bundle = Bundle(objects=objects)
OUTPUT.write_text(bundle.serialize(pretty=True), encoding="utf-8")

# Parse the saved bundle to confirm that it is valid STIX JSON.
saved = parse(OUTPUT.read_text(encoding="utf-8"), version="2.1")
print("STIX 2.1 bundle created:", OUTPUT)
print("Objects in bundle:", len(saved.objects))
print("Indicators:", sum(obj.type == "indicator" for obj in saved.objects))
print("Reports:", sum(obj.type == "report" for obj in saved.objects))
print("All source indicators remain unverified.")
