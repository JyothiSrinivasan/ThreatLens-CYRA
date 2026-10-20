
import json
from pathlib import Path

INPUT_FILE = Path("data/processed/misp_enrichment_pilot.json")
OUTPUT_FILE = Path("data/processed/misp_enrichment_pilot_ready.json")

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
enriched = []

for record in records:
    item = dict(record)
    tags = item.get("pulse_tags") or []
    pulse_name = item.get("pulse_name", "").strip()

    if not item.get("indicator_description"):
        context_parts = []

        if pulse_name:
            context_parts.append(f"OTX pulse: {pulse_name}")

        if tags:
            context_parts.append("Source tags: " + ", ".join(tags[:8]))

        item["indicator_description"] = (
            "Context derived from source metadata; not independently verified. "
            + " ".join(context_parts)
        )

        item["description_enrichment_method"] = (
            "generated_from_source_pulse_metadata"
        )

    enriched.append(item)

OUTPUT_FILE.write_text(
    json.dumps(enriched, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("Input records:", len(records))
print("Output records:", len(enriched))
print(
    "Descriptions populated:",
    sum(bool(r.get("indicator_description")) for r in enriched),
)
print(
    "Generated contextual descriptions:",
    sum(
        r.get("description_enrichment_method")
        == "generated_from_source_pulse_metadata"
        for r in enriched
    ),
)
print(
    "Still source-reported/unverified:",
    sum(
        r.get("validation_status") == "source_reported_unverified"
        for r in enriched
    ),
)
print("Output:", OUTPUT_FILE)
print("MISP import performed: No")
