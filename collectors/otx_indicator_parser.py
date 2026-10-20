
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "raw" / "otx_pulses.json"
OUTPUT = ROOT / "data" / "processed" / "otx_indicator_candidates.json"


def main():
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    candidates = []
    seen = set()

    for pulse in data.get("pulses", []):
        pulse_name = pulse.get("name", "Unnamed pulse")
        pulse_id = pulse.get("id")
        pulse_tags = pulse.get("tags", [])
        pulse_created = pulse.get("created")
        pulse_modified = pulse.get("modified")

        for indicator in pulse.get("indicators", []):
            value = str(indicator.get("indicator", "")).strip()
            indicator_type = str(indicator.get("type", "unknown")).strip()

            if not value:
                continue

            # Keep an indicator from each distinct pulse so its provenance
            # is not lost when the same value appears in multiple pulses.
            key = (
                indicator_type.lower(),
                value.lower(),
                str(pulse_id or pulse_name),
            )

            if key in seen:
                continue

            seen.add(key)

            candidates.append({
                "type": indicator_type,
                "value": value,
                "otx_indicator_id": indicator.get("id"),
                "indicator_created": indicator.get("created"),
                "indicator_expiration": indicator.get("expiration"),
                "indicator_active": indicator.get("is_active"),
                "indicator_title": indicator.get("title", ""),
                "indicator_content": indicator.get("content", ""),
                "indicator_role": indicator.get("role"),
                "source": "AlienVault OTX",
                "source_url": (
                    f"https://otx.alienvault.com/pulse/{pulse_id}"
                    if pulse_id else ""
                ),
                "pulse_id": pulse_id,
                "pulse_name": pulse_name,
                "pulse_tags": pulse_tags,
                "pulse_created": pulse_created,
                "pulse_modified": pulse_modified,
                "indicator_description": indicator.get("description", ""),
                "validation_status": "source_reported_unverified",
                "enrichment_status": "source_context_collected",
            })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(candidates, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("OTX pulses processed:", len(data.get("pulses", [])))
    print("Indicator candidates:", len(candidates))
    print(
        "Types:",
        dict(Counter(item["type"] for item in candidates)),
    )
    print("Output:", OUTPUT)


if __name__ == "__main__":
    main()
