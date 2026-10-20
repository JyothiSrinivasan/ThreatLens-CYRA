import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data/processed/misp_enrichment_150_with_vt_batch_results_v2.json"
URLSCAN = ROOT / "data/processed/urlscan_normalized_enrichment.json"
OUTPUT = ROOT / "data/processed/misp_enrichment_150_with_vt_urlscan_consolidated.json"

if OUTPUT.exists():
    raise SystemExit(f"Output already exists; refusing to overwrite: {OUTPUT}")

records = json.loads(INPUT.read_text(encoding="utf-8"))
urlscan = json.loads(URLSCAN.read_text(encoding="utf-8"))

matches = [
    r for r in records
    if r.get("type") == urlscan.get("indicator_type")
    and r.get("value") == urlscan.get("indicator_value")
]

if len(matches) > 1:
    raise SystemExit(f"Found {len(matches)} exact matches; review before merging.")

for record in records:
    status = record.get("virustotal_status")
    if not status:
        record["virustotal_status"] = "not_attempted"

if matches:
    record = matches[0]
    record["urlscan_status"] = "lookup_success"
    record["urlscan_enrichment"] = urlscan
else:
    print("WARNING: No exact URL type/value match; URLScan result not attached.")

OUTPUT.write_text(json.dumps(records, indent=2), encoding="utf-8")

saved = json.loads(OUTPUT.read_text(encoding="utf-8"))
print("Created:", OUTPUT.relative_to(ROOT))
print("Records:", len(saved))
print("Unique type/value pairs:", len({(r.get("type"), r.get("value")) for r in saved}))
print("VirusTotal statuses:", {
    status: sum(r.get("virustotal_status") == status for r in saved)
    for status in sorted({r.get("virustotal_status") for r in saved})
})
print("Exact URLScan matches:", len(matches))
print("URLScan-enriched records:", sum("urlscan_enrichment" in r for r in saved))
print("Original input unchanged.")
