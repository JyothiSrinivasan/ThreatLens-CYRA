
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INPUT_FILES = [
    ROOT / "data" / "processed" / "candidate_iocs.json",
    ROOT / "data" / "processed" / "talos_uat_11985_candidates.json",
    ROOT / "data" / "processed" / "otx_enriched_indicators.json",
]

OUTPUT = ROOT / "data" / "processed" / "unified_candidate_iocs.json"


def load_records(path):
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list in {path.name}")

    records = []

    
    for item in data:
        record = dict(item)
        record.setdefault("source_file", path.name)

        if not record.get("source"):
            if path.name == "candidate_iocs.json":
                record["source"] = "CERT-In"

        record.setdefault(
            "context",
            "Candidate collected from public source",
        )
        records.append(record)


    return records


def main():
    combined = []
    seen = set()
    input_counts = {}

    for path in INPUT_FILES:
        if not path.exists():
            raise FileNotFoundError(f"Missing input file: {path}")

        records = load_records(path)
        input_counts[path.name] = len(records)

        for record in records:
            value = str(record.get("value", "")).strip()
            record_type = str(record.get("type", "")).strip()
            source_url = str(record.get("source_url", "")).strip()

            # Preserve records from distinct sources, but remove
            # duplicates within the same source and type.
            key = (
                record_type.lower(),
                value.lower(),
                source_url.lower(),
            )

            if not value or not record_type or key in seen:
                if key in seen:
                    continue
                # Keep malformed records out of the main dataset.
                continue

            seen.add(key)
            combined.append(record)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(combined, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Unified dataset created.")
    print("Input record counts:", input_counts)
    print("Unique type/value/source records:", len(combined))
    print(
        "Types:",
        dict(Counter(r.get("type", "unknown") for r in combined)),
    )
    print(
        "Validation statuses:",
        dict(
            Counter(
                r.get("validation_status", "missing")
                for r in combined
            )
        ),
    )
    print(
        "Records with source URLs:",
        sum(bool(r.get("source_url")) for r in combined),
    )
    print("Output:", OUTPUT)


if __name__ == "__main__":
    main()
