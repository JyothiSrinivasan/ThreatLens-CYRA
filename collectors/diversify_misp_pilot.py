
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

INPUT_FILE = Path("data/processed/otx_enriched_indicators.json")
OUTPUT_FILE = Path("data/processed/misp_enrichment_pilot_diverse.json")

TARGET_COUNT = 150
MIN_PULSES = 10
RANDOM_SEED = 42

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

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

# Group eligible indicators by OTX pulse.
by_pulse = defaultdict(list)
seen = set()
skipped = Counter()

for record in records:
    original_type = str(record.get("type", "")).strip().lower()
    mapped_type = TYPE_MAP.get(original_type)

    value = str(record.get("value", "")).strip()
    pulse_id = str(record.get("pulse_id", "")).strip()
    source_url = str(record.get("source_url", "")).strip()

    if not mapped_type:
        skipped["unsupported_type"] += 1
        continue
    if not value or not pulse_id or not source_url:
        skipped["missing_required_field"] += 1
        continue

    key = (mapped_type, value.lower())
    if key in seen:
        skipped["duplicate_type_value"] += 1
        continue
    seen.add(key)

    item = dict(record)
    item["type"] = mapped_type
    item["validation_status"] = "source_reported_unverified"
    item["enrichment_status"] = "source_context_enriched"
    item["record_category"] = "threat_indicator_candidate"
    item["to_ids"] = False

    by_pulse[pulse_id].append(item)

# Randomize deterministically within each pulse.
rng = random.Random(RANDOM_SEED)
for pulse_records in by_pulse.values():
    rng.shuffle(pulse_records)

# Round-robin across pulses to avoid taking nearly everything
# from whichever pulse appears first in the input file.
pulse_ids = sorted(by_pulse)
selected = []

while len(selected) < TARGET_COUNT:
    added_this_round = False
    for pulse_id in pulse_ids:
        if by_pulse[pulse_id]:
            selected.append(by_pulse[pulse_id].pop())
            added_this_round = True
            if len(selected) == TARGET_COUNT:
                break
    if not added_this_round:
        break

if len(selected) < TARGET_COUNT:
    raise SystemExit(
        f"Only {len(selected)} eligible unique indicators available; "
        f"expected {TARGET_COUNT}. No output written."
    )

OUTPUT_FILE.write_text(
    json.dumps(selected, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

pulse_counts = Counter(str(r.get("pulse_id", "")) for r in selected)
type_counts = Counter(r["type"] for r in selected)

print("Diversified pilot preparation complete.")
print("Input records:", len(records))
print("Output records:", len(selected))
print("Distinct pulses:", len(pulse_counts))
print("Indicator types:", dict(type_counts))
print("Top 10 pulse counts:", pulse_counts.most_common(10))
print("Missing source URLs:", sum(not r.get("source_url") for r in selected))
print("Unverified records:", sum(
    r.get("validation_status") == "source_reported_unverified"
    for r in selected
))
print("Skipped during eligibility/deduplication:", dict(skipped))
print("Output:", OUTPUT_FILE)
print("MISP import performed: No")
