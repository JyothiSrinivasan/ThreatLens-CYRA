
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "processed" / "unified_candidate_iocs.json"
OUTPUT = ROOT / "data" / "processed" / "collection_quality_audit.json"

TYPE_MAP = {
    "cve": "cve",
    "md5": "md5",
    "filehash-md5": "md5",
    "sha1": "sha1",
    "filehash-sha1": "sha1",
    "sha256": "sha256",
    "filehash-sha256": "sha256",
    "url": "url",
    "domain": "domain",
    "hostname": "hostname",
    "ipv4": "ipv4",
    "email": "email",
    "yara": "yara",
}


def main():
    records = json.loads(INPUT.read_text(encoding="utf-8"))

    canonical_counts = Counter()
    status_counts = Counter()
    source_counts = Counter()
    missing_source_url = 0
    missing_value = 0
    missing_type = 0
    unmapped_types = Counter()
    indicators_by_key = defaultdict(list)

    for record in records:
        original_type = str(record.get("type", "")).strip()
        value = str(record.get("value", "")).strip()
        source_url = str(record.get("source_url", "")).strip()
        source = str(record.get("source", "")).strip()
        status = record.get("validation_status", "missing")

        canonical_type = TYPE_MAP.get(original_type.lower())

        if canonical_type:
            canonical_counts[canonical_type] += 1
        else:
            unmapped_types[original_type or "(missing)"] += 1

        status_counts[status] += 1
        source_counts[source or "(missing source)"] += 1

        if not source_url:
            missing_source_url += 1
        if not value:
            missing_value += 1
        if not original_type:
            missing_type += 1

        if canonical_type and value:
            key = (canonical_type, value.casefold())
            indicators_by_key[key].append({
                "source": source,
                "source_url": source_url,
                "source_file": record.get("source_file", ""),
                "validation_status": status,
            })

    repeated = {
        f"{kind}:{value}": occurrences
        for (kind, value), occurrences in indicators_by_key.items()
        if len(occurrences) > 1
    }

    audit = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_file": str(INPUT.relative_to(ROOT)),
        "total_records": len(records),
        "canonical_type_counts": dict(canonical_counts),
        "validation_status_counts": dict(status_counts),
        "source_counts": dict(source_counts),
        "records_missing_source_url": missing_source_url,
        "records_missing_value": missing_value,
        "records_missing_type": missing_type,
        "unmapped_type_counts": dict(unmapped_types),
        "distinct_canonical_type_value_pairs": len(indicators_by_key),
        "pairs_repeated_across_records": len(repeated),
        "repeated_pairs_sample": dict(list(repeated.items())[:50]),
        "note": (
            "Repeated values are retained to preserve source provenance. "
            "Source-reported or enriched records are not automatically "
            "independently verified as malicious."
        ),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(audit, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Collection quality audit completed.")
    print("Total records:", len(records))
    print("Canonical type counts:", dict(canonical_counts))
    print("Distinct type/value pairs:", len(indicators_by_key))
    print("Repeated pairs across records:", len(repeated))
    print("Missing source URLs:", missing_source_url)
    print("Missing values:", missing_value)
    print("Missing types:", missing_type)
    print("Unmapped types:", dict(unmapped_types))
    print("Audit report:", OUTPUT)


if __name__ == "__main__":
    main()

