
import json
from collections import Counter
from pathlib import Path

INPUT_FILE = Path("data/processed/misp_enrichment_pilot_ready.json")

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

pulse_ids = Counter(str(r.get("pulse_id", "")).strip() for r in records)
pulse_names = Counter(str(r.get("pulse_name", "")).strip() for r in records)
indicator_types = Counter(str(r.get("type", "")).strip() for r in records)
sources = Counter(str(r.get("source", "")).strip() for r in records)

print("=== MISP Pilot Diversity Audit ===")
print("Total records:", len(records))
print("Distinct pulse IDs:", len(pulse_ids))
print("Distinct pulse names:", len(pulse_names))
print("Indicator types:", dict(indicator_types))
print("Distinct source labels:", len(sources))

print("\nTop 10 pulses by indicator count:")
for pulse_id, count in pulse_ids.most_common(10):
    matching = next(
        (r.get("pulse_name", "") for r in records
         if str(r.get("pulse_id", "")).strip() == pulse_id),
        ""
    )
    print(f"- {pulse_id}: {count} indicators | {matching}")

print("\nRecords with missing pulse IDs:",
      sum(not str(r.get("pulse_id", "")).strip() for r in records))
print("Records with missing source URLs:",
      sum(not str(r.get("source_url", "")).strip() for r in records))
print("Records with missing descriptions:",
      sum(not str(r.get("indicator_description", "")).strip()
          for r in records))
print("Records marked source_reported_unverified:",
      sum(r.get("validation_status") == "source_reported_unverified"
          for r in records))

print("\nAudit only: no records changed and no MISP import performed.")
