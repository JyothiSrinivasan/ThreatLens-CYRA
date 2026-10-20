
import json
from pathlib import Path

files = [
    "data/processed/otx_enriched_indicators.json",
    "data/processed/cve_enriched.json",
    "data/processed/talos_uat_11985_candidates.json",
    "data/processed/candidate_iocs.json",
]

for filename in files:
    path = Path(filename)
    print(f"\n{'=' * 60}")
    print(f"FILE: {filename}")
    print(f"Exists: {path.exists()}")

    if not path.exists():
        continue

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Could not read file: {exc}")
        continue

    print("Record count:", len(data))

    if isinstance(data, list) and data:
        print("Sample fields:", list(data[0].keys())
              if isinstance(data[0], dict) else type(data[0]).__name__)
        print("Sample record:")
        print(json.dumps(data[0], indent=2)[:700])
    else:
        print("Top-level format:", type(data).__name__)
