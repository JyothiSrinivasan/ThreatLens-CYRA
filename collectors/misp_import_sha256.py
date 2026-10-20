
import json
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent, MISPAttribute
import os

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "processed" / "sha256_review_queue.json"

load_dotenv(PROJECT_ROOT / ".env")

MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_API_KEY")
VERIFY_CERT = os.getenv("MISP_VERIFY_CERT", "true").lower() == "true"

if not MISP_URL or not MISP_KEY:
    raise SystemExit("Missing MISP_URL or MISP_API_KEY in .env")

records = json.loads(DATA_FILE.read_text(encoding="utf-8"))
records = [
    r for r in records
    if r.get("type") == "sha256"
    and r.get("validation_status") == "source_reported_unverified"
]

if not records:
    raise SystemExit("No eligible SHA-256 records found.")

misp = PyMISP(
    MISP_URL,
    MISP_KEY,
    ssl=VERIFY_CERT,
    tool="ThreatLens",
)

event = MISPEvent()
event.info = "ThreatLens - CERT-In SHA-256 Source-Reported Candidates"
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
    attribute = MISPAttribute()
    attribute.type = "sha256"
    attribute.value = record["value"]
    attribute.to_ids = False
    attribute.comment = (
        "Source-reported, not independently verified. "
        f"Source: {record.get('source_url', '')}. "
        f"Context: {record.get('context', '')}"
    )

    result = misp.add_attribute(event_id, attribute, pythonify=True)

    if isinstance(result, dict) and result.get("errors"):
        print("Attribute import failed:", result["errors"])
        continue

    added += 1

print(f"Import complete: {added} SHA-256 attributes added.")
print("All imported attributes have to_ids=False.")

