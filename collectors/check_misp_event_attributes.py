
import json
import os
from pathlib import Path
from dotenv import load_dotenv
from pymisp import PyMISP

load_dotenv()

INPUT_FILE = Path(
    "data/processed/misp_enrichment_pilot_diverse_ready.json"
)

url = os.getenv("MISP_URL")
key = os.getenv("MISP_API_KEY")
verify = os.getenv("MISP_VERIFY_CERT", "false").lower() == "true"

if not url or not key:
    raise SystemExit("MISP_URL or MISP_API_KEY is missing from .env")

pilot = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

def norm(value):
    return str(value or "").strip().lower()

pilot_keys = {
    (norm(r.get("type")), norm(r.get("value")))
    for r in pilot
    if norm(r.get("type")) and norm(r.get("value"))
}

misp = PyMISP(url, key, ssl=verify)

event_ids = ["1", "2"]
existing = set()

for event_id in event_ids:
    print(f"\nChecking MISP event {event_id}...")
    response = misp.get_event(event_id)

    if isinstance(response, dict):
        event = response.get("Event", response)
    else:
        event = response

    attributes = event.get("Attribute", []) if isinstance(event, dict) else []

    print("Attributes returned:", len(attributes))

    for attr in attributes:
        if isinstance(attr, dict):
            attr_type = norm(attr.get("type"))
            value = norm(attr.get("value"))
            if attr_type and value:
                existing.add((attr_type, value))
                print(f"  Existing: {attr_type} | {value}")

duplicates = pilot_keys & existing

print("\n=== Event-by-Event Duplicate Results ===")
print("Pilot indicators:", len(pilot_keys))
print("Existing attributes checked:", len(existing))
print("Duplicates found:", len(duplicates))
print("Not matched:", len(pilot_keys - existing))

if duplicates:
    print("\nMatching indicators:")
    for attr_type, value in sorted(duplicates):
        print(f"- {attr_type} | {value}")

print("\nRead-only check complete. No MISP changes made.")
