
import json
from collections import Counter
from pathlib import Path

path = Path("data/processed/misp_enrichment_pilot_diverse_ready.json")
records = json.loads(path.read_text(encoding="utf-8"))

keys = [
    (str(r.get("type", "")).strip().lower(),
     str(r.get("value", "")).strip().lower())
    for r in records
]

pulse_ids = [str(r.get("pulse_id", "")).strip() for r in records]

print("=== Diversified Pilot Audit ===")
print("Total records:", len(records))
print("Unique type/value pairs:", len(set(keys)))
print("Distinct pulse IDs:", len(set(pulse_ids)))
print("Duplicate type/value pairs:", len(keys) - len(set(keys)))
print("Missing values:", sum(not r.get("value") for r in records))
print("Missing source URLs:", sum(not r.get("source_url") for r in records))
print("Missing pulse IDs:", sum(not r.get("pulse_id") for r in records))
print("Missing descriptions:", sum(
    not str(r.get("indicator_description", "")).strip()
    for r in records
))
print("Incorrect validation labels:", sum(
    r.get("validation_status") != "source_reported_unverified"
    for r in records
))
print("Detection enabled:", sum(r.get("to_ids") is True for r in records))

print("\nFirst 5 records:")
for r in records[:5]:
    print({
        "type": r.get("type"),
        "value": r.get("value"),
        "pulse_name": r.get("pulse_name"),
        "source_url": r.get("source_url"),
        "validation_status": r.get("validation_status"),
    })

print("\nAudit only: no changes and no MISP import performed.")
