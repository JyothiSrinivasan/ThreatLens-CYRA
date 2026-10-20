
import json
from pathlib import Path

INPUT_FILE = Path("data/processed/misp_enrichment_pilot_diverse.json")
OUTPUT_FILE = Path("data/processed/misp_enrichment_pilot_diverse_ready.json")

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
updated = []
generated = 0

for record in records:
    item = dict(record)

    pulse_name = str(item.get("pulse_name") or "").strip()
    tags = item.get("pulse_tags") or []

    # Keep an existing description if one is already present.
    description = str(item.get("indicator_description") or "").strip()

    if not description:
        context_parts = []

        if pulse_name:
            context_parts.append(f"OTX pulse: {pulse_name}")

        if tags:
            tag_names = [
                str(tag).strip()
                for tag in tags
                if str(tag).strip()
            ]
            if tag_names:
                context_parts.append(
                    "Source tags: " + ", ".join(tag_names[:8])
                )

        if context_parts:
            item["indicator_description"] = (
                "Source-context enrichment only; not independently "
                "verified. " + " ".join(context_parts)
            )
            item["description_enrichment_method"] = (
                "generated_from_source_pulse_metadata"
            )
            generated += 1
        else:
            item["indicator_description"] = (
                "Source-reported indicator candidate; context unavailable; "
                "not independently verified."
            )
            item["description_enrichment_method"] = (
                "fallback_missing_source_context"
            )

    item["validation_status"] = "source_reported_unverified"
    item["enrichment_status"] = "source_context_enriched"
    item["to_ids"] = False

    updated.append(item)

OUTPUT_FILE.write_text(
    json.dumps(updated, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("Input records:", len(records))
print("Output records:", len(updated))
print("Descriptions populated:", sum(
    bool(str(r.get("indicator_description") or "").strip())
    for r in updated
))
print("Descriptions generated from metadata:", generated)
print("Still source-reported/unverified:", sum(
    r.get("validation_status") == "source_reported_unverified"
    for r in updated
))
print("Output:", OUTPUT_FILE)
print("MISP import performed: No")
