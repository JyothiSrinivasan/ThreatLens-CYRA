
import json
from collections import Counter
from pathlib import Path

path = Path("data/processed/misp_enrichment_pilot.json")
records = json.loads(path.read_text(encoding="utf-8"))

print("Total records:", len(records))
print("Types:", dict(Counter(r["type"] for r in records)))
print("Missing source URL:", sum(not r.get("source_url") for r in records))
print("Missing pulse ID:", sum(not r.get("pulse_id") for r in records))
print("Missing pulse name:", sum(not r.get("pulse_name") for r in records))
print("Records with tags:", sum(bool(r.get("pulse_tags")) for r in records))
print("Records with descriptions:", sum(
    bool(r.get("indicator_description")) for r in records
))
print("Validation statuses:", dict(Counter(
    r.get("validation_status", "missing") for r in records
)))
print("Enrichment statuses:", dict(Counter(
    r.get("enrichment_status", "missing") for r in records
)))

print("\nFirst 3 records:")
for record in records[:3]:
    print(json.dumps(record, indent=2, ensure_ascii=False)[:1200])
    print("-" * 40)
