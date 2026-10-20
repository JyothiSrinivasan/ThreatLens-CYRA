
import json
from pathlib import Path
from collections import Counter

INPUT_FILE = Path("data/processed/otx_enriched_indicators.json")
OUTPUT_FILE = Path("data/processed/misp_enrichment_pilot.json")
TARGET_COUNT = 150

# Only use types that can be mapped safely to MISP attributes.
TYPE_MAP = {
    "filehash-md5": "md5",
    "filehash-sha1": "sha1",
    "filehash-sha256": "sha256",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
}

def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_FILE}")

    records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    selected = []
    seen = set()
    skipped = Counter()

    for record in records:
        original_type = str(record.get("type", "")).strip()
        value = str(record.get("value", "")).strip()
        mapped_type = TYPE_MAP.get(original_type.lower())

        if not mapped_type:
            skipped["unsupported_type"] += 1
            continue

        if not value or not record.get("source_url") or not record.get("pulse_id"):
            skipped["missing_required_provenance"] += 1
            continue

        # Preserve the original value for the output.
        # Use a case-insensitive key for deduplication in this pilot.
        key = (mapped_type, value.lower())
        if key in seen:
            skipped["duplicate_type_value"] += 1
            continue

        seen.add(key)

        tags = record.get("pulse_tags") or []
        selected.append({
            "type": mapped_type,
            "value": value,
            "source_type_original": original_type,
            "source": record.get("source", "AlienVault OTX"),
            "source_url": record["source_url"],
            "pulse_id": record["pulse_id"],
            "pulse_name": record.get("pulse_name", ""),
            "pulse_tags": tags,
            "indicator_description": record.get(
                "indicator_description", ""
            ),
            "indicator_created": record.get("indicator_created"),
            "indicator_expiration": record.get("indicator_expiration"),
            "validation_status": "source_reported_unverified",
            "enrichment_status": "source_context_enriched",
            "record_category": "threat_indicator_candidate",
            "to_ids": False,
        })

        if len(selected) >= TARGET_COUNT:
            break

    if len(selected) < TARGET_COUNT:
        raise ValueError(
            f"Only {len(selected)} eligible records found; "
            f"target is {TARGET_COUNT}. Output not written."
        )

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(selected, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Pilot preparation complete.")
    print("Selected records:", len(selected))
    print("Unique type/value pairs:", len({
        (x["type"], x["value"].lower()) for x in selected
    }))
    print("Types:", dict(Counter(x["type"] for x in selected)))
    print("Missing source URLs:", sum(not x["source_url"] for x in selected))
    print("Missing pulse IDs:", sum(not x["pulse_id"] for x in selected))
    print("Validation statuses:", dict(Counter(
        x["validation_status"] for x in selected
    )))
    print("Skipped:", dict(skipped))
    print("Output:", OUTPUT_FILE)
    print("MISP import performed: No")

if __name__ == "__main__":
    main()
