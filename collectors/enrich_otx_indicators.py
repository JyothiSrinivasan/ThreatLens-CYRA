
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INPUT = ROOT / "data" / "processed" / "otx_indicator_candidates.json"
OUTPUT = ROOT / "data" / "processed" / "otx_enriched_indicators.json"


def main():
    records = json.loads(INPUT.read_text(encoding="utf-8"))
    enriched = []

    for record in records:
        item = dict(record)

        # Explicitly record what source context is available.
        available_context = []

        if item.get("pulse_name"):
            available_context.append("pulse_name")
        if item.get("pulse_tags"):
            available_context.append("pulse_tags")
        if item.get("indicator_description"):
            available_context.append("indicator_description")
        if item.get("source_url"):
            available_context.append("source_url")
        if item.get("pulse_created"):
            available_context.append("pulse_created")
        if item.get("pulse_modified"):
            available_context.append("pulse_modified")

        item["available_context_fields"] = available_context
        item["enrichment_status"] = (
            "source_context_enriched"
            if len(available_context) >= 3
            else "limited_source_context"
        )
        item["validation_status"] = "source_reported_unverified"

        # CVEs remain vulnerability references, not malicious IoCs.
        if item.get("type", "").upper() == "CVE":
            item["record_category"] = "vulnerability_reference"
        else:
            item["record_category"] = "threat_indicator_candidate"

        enriched.append(item)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(enriched, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Records processed:", len(enriched))
    print(
        "Enrichment statuses:",
        dict(Counter(x["enrichment_status"] for x in enriched)),
    )
    print(
        "Record categories:",
        dict(Counter(x["record_category"] for x in enriched)),
    )
    print("Output:", OUTPUT)


if __name__ == "__main__":
    main()
