
import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INPUT = ROOT / "data" / "raw" / "talos_uat_11985_iocs.json"
OUTPUT = ROOT / "data" / "processed" / "talos_uat_11985_candidates.json"

URL_RE = re.compile(r"^https?\[\:\]\s*//", re.IGNORECASE)
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\[\.\][A-Za-z]{2,}$"
)


def classify_indicator(value):
    if URL_RE.match(value):
        return "url"

    if EMAIL_RE.match(value):
        return "email"

    return "unclassified"


def main():
    source_data = json.loads(INPUT.read_text(encoding="utf-8"))
    candidates = []

    for item in source_data["indicators"]:
        raw_value = item["raw_value"]
        indicator_type = classify_indicator(raw_value)

        candidates.append({
            "value": raw_value,
            "type": indicator_type,
            "campaign": source_data["campaign"],
            "source": source_data["source"],
            "source_url": source_data["source_url"],
            "article_url": source_data["article_url"],
            "validation_status": "source_reported_unverified",
            "collected_at_utc": source_data["collected_at_utc"],
            "extracted_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(candidates, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    counts = {}
    for candidate in candidates:
        kind = candidate["type"]
        counts[kind] = counts.get(kind, 0) + 1

    print("Campaign:", source_data["campaign"])
    print("Total candidates:", len(candidates))
    print("Types:", counts)
    print("Output:", OUTPUT)


if __name__ == "__main__":
    main()
