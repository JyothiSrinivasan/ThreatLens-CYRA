
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent, MISPAttribute

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "processed" / "talos_uat_11985_candidates.json"

load_dotenv(ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_API_KEY")
VERIFY_CERT = os.getenv("MISP_VERIFY_CERT", "true").lower() == "true"

if not MISP_URL or not MISP_KEY:
    raise SystemExit("Missing MISP_URL or MISP_API_KEY in .env")

records = json.loads(DATA_FILE.read_text(encoding="utf-8"))

records = [
    r for r in records
    if r.get("type") in {"url", "email"}
    and r.get("validation_status") == "source_reported_unverified"
]

if not records:
    raise SystemExit("No eligible Talos candidates found.")

misp = PyMISP(
    MISP_URL,
    MISP_KEY,
    ssl=VERIFY_CERT,
    tool="ThreatLens",
)

event = MISPEvent()
event.info = "ThreatLens - Cisco Talos UAT-11985 Source-Reported Candidates"
event.distribution = 0
event.threat_level_id = 3
event.analysis = 0

created = misp.add_event(event, pythonify=True)

if isinstance(created, dict) and created.get("errors"):
    raise SystemExit(f"MISP event creation failed: {created['errors']}")

event_id = str(created.id)
print("Created local MISP event ID:", event_id)

added = 0

for record in records:
    raw_value = record["value"]
    attribute_type = record["type"]

    # Normalize defanged syntax only for the MISP attribute value.
    # The source-preserved value remains unchanged in the JSON file.
    if attribute_type == "url":
        normalized_value = raw_value.replace("https[:]", "https:").replace(
            "http[:]", "http:"
        ).replace("[.]", ".")
        misp_type = "url"
    else:
        normalized_value = raw_value.replace("[.]", ".")
        misp_type = "email-src"

    attribute = MISPAttribute()
    attribute.type = misp_type
    attribute.value = normalized_value
    attribute.to_ids = False
    attribute.comment = (
        "Source-reported and not independently verified; detection disabled. "
        f"Campaign: {record.get('campaign', 'UAT-11985')}. "
        f"Source: {record.get('source_url', '')}. "
        f"Article: {record.get('article_url', '')}. "
        f"Original defanged value: {raw_value}"
    )

    result = misp.add_attribute(event_id, attribute, pythonify=True)

    if isinstance(result, dict) and result.get("errors"):
        print("Attribute import failed:", result["errors"])
        continue

    added += 1

print(f"Import complete: {added} attributes added.")
print("All imported attributes have to_ids=False.")
print("Original defanged values remain preserved in the source JSON.")
