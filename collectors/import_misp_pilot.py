
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent, MISPAttribute

load_dotenv()

INPUT_FILE = Path(
    "data/processed/misp_enrichment_pilot_diverse_ready.json"
)
EVENT_NAME = (
    "ThreatLens - OTX Context-Enriched Candidate Indicators (Unverified)"
)
ALLOWED_TYPES = {"md5", "sha1", "sha256", "domain", "hostname", "url"}

url = os.getenv("MISP_URL")
key = os.getenv("MISP_API_KEY")
verify = os.getenv("MISP_VERIFY_CERT", "false").lower() == "true"

if not url or not key:
    sys.exit("ERROR: MISP_URL or MISP_API_KEY is missing from .env")

if not INPUT_FILE.exists():
    sys.exit(f"ERROR: Input file not found: {INPUT_FILE}")

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))

if len(records) != 150:
    sys.exit(f"STOP: Expected 150 records; found {len(records)}.")

# Validate the complete input before making any changes.
seen = set()

for index, record in enumerate(records, start=1):
    attr_type = str(record.get("type") or "").strip().lower()
    value = str(record.get("value") or "").strip()

    if attr_type not in ALLOWED_TYPES or not value:
        sys.exit(f"STOP: Invalid type/value at record {index}.")

    if (attr_type, value.lower()) in seen:
        sys.exit(f"STOP: Duplicate indicator in input at record {index}.")

    seen.add((attr_type, value.lower()))

    if record.get("validation_status") != "source_reported_unverified":
        sys.exit(f"STOP: Unexpected validation status at record {index}.")

    if not record.get("source_url") or not record.get("pulse_id"):
        sys.exit(f"STOP: Missing provenance at record {index}.")

    if record.get("to_ids") is True:
        sys.exit(f"STOP: Detection enabled in input at record {index}.")

print("Input validation passed:", len(records), "records")
print("Connecting to MISP...")

misp = PyMISP(url, key, ssl=verify)


def as_dict(obj):
    if isinstance(obj, dict):
        return obj
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    return {}


def event_dict(response):
    data = as_dict(response)
    return data.get("Event", data)


def norm(value):
    return str(value or "").strip().lower()


# Read all existing events and their attributes before importing.
response = misp.search(
    controller="events",
    return_format="json",
    metadata=True,
)

if isinstance(response, dict):
    events = response.get("response", response.get("Event", []))
else:
    events = response

if not isinstance(events, list):
    sys.exit("STOP: Unexpected MISP event-list response. No import performed.")

existing_pairs = set()
target_event_id = None

for item in events:
    data = event_dict(item)
    event_id = data.get("id")
    if not event_id:
        continue

    if data.get("info") == EVENT_NAME:
        target_event_id = str(event_id)

    full_response = misp.get_event(str(event_id))
    full_event = event_dict(full_response)

    for attr in full_event.get("Attribute", []):
        if isinstance(attr, dict):
            attr_type = norm(attr.get("type"))
            value = norm(attr.get("value"))
            if attr_type and value:
                existing_pairs.add((attr_type, value))

print("Existing event attributes checked:", len(existing_pairs))

# Create the target event only if it does not already exist.
if target_event_id is None:
    event = MISPEvent()
    event.info = EVENT_NAME
    event.distribution = 0
    event.threat_level_id = 4
    event.analysis = 0

    created = misp.add_event(event)
    created_data = event_dict(created)
    target_event_id = str(created_data.get("id") or "")

    if not target_event_id:
        nested = created_data.get("Event", {})
        target_event_id = str(nested.get("id") or "")

    if not target_event_id:
        print("STOP: Event creation response had no event ID.")
        print("Inspect MISP before rerunning; do not blindly retry.")
        sys.exit(1)

    print("Created MISP event ID:", target_event_id)
else:
    print("Reusing existing target event ID:", target_event_id)

added = 0
skipped = 0
failed = 0

for index, record in enumerate(records, start=1):
    attr_type = norm(record["type"])
    value = str(record["value"]).strip()
    pair = (attr_type, norm(value))

    if pair in existing_pairs:
        skipped += 1
        continue

    pulse_name = str(record.get("pulse_name") or "").strip()
    pulse_id = str(record.get("pulse_id") or "").strip()
    source_url = str(record.get("source_url") or "").strip()
    description = str(record.get("indicator_description") or "").strip()

    comment = (
        "ThreatLens validation_status=source_reported_unverified; "
        "enrichment_status=source_context_enriched; "
        f"OTX pulse={pulse_name}; pulse_id={pulse_id}; "
        f"source_url={source_url}; context={description}"
    )

    attribute = MISPAttribute()
    attribute.type = attr_type
    attribute.value = value
    attribute.comment = comment
    attribute.to_ids = False
    attribute.distribution = 0

    try:
        result = misp.add_attribute(target_event_id, attribute)
        result_data = as_dict(result)

        # Detect API error responses where possible.
        if result_data.get("errors"):
            failed += 1
            print(f"FAILED record {index}: API returned an error.")
            continue

        added += 1
        existing_pairs.add(pair)

        if added % 25 == 0:
            print(f"Progress: {added} new attributes added.")

    except Exception as exc:
        failed += 1
        print(f"FAILED record {index}: {type(exc).__name__}: {exc}")

print("\n=== Import Summary ===")
print("Target event ID:", target_event_id)
print("Input records:", len(records))
print("New attributes added:", added)
print("Already present and skipped:", skipped)
print("Failed additions:", failed)
print("Detection enabled for imported attributes: No")
print("Validation status: source_reported_unverified")
print("Review the event in MISP before considering this milestone complete.")
