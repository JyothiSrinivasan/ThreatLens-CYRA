
import json
import os
from pathlib import Path
from collections import Counter
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

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

def normalize(value):
    return str(value or "").strip().lower()

pilot_keys = {
    (normalize(r.get("type")), normalize(r.get("value")))
    for r in records
    if normalize(r.get("type")) and normalize(r.get("value"))
}

print("Pilot records:", len(records))
print("Unique pilot type/value pairs:", len(pilot_keys))
print("Connecting to MISP...")

misp = PyMISP(url, key, ssl=verify)

# Fetch existing attributes without changing MISP.
response = misp.search(
    controller="attributes",
    return_format="json",
    limit=10000,
    page=1,
)

if isinstance(response, dict):
    attributes = response.get("Attribute", [])
else:
    attributes = response

if not isinstance(attributes, list):
    raise SystemExit(
        "Unexpected MISP response. No changes were made. "
        f"Response type: {type(response).__name__}"
    )

existing_keys = {
    (normalize(a.get("type")), normalize(a.get("value")))
    for a in attributes
    if isinstance(a, dict)
    and normalize(a.get("type"))
    and normalize(a.get("value"))
}

duplicates = pilot_keys & existing_keys
new_candidates = pilot_keys - existing_keys

print("\n=== Duplicate Check Results ===")
print("Existing attributes returned:", len(attributes))
print("Pilot indicators already in MISP:", len(duplicates))
print("Pilot indicators not found in returned attributes:", len(new_candidates))

if duplicates:
    print("\nMatching pilot indicators (up to 20):")
    for indicator_type, value in sorted(duplicates)[:20]:
        print(f"- {indicator_type}: {value}")

print("\nRead-only check complete. No events or attributes created.")
