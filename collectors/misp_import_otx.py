
import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from pymisp import PyMISP

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

INPUT = ROOT / "data" / "processed" / "otx_enriched_indicators.json"

MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_API_KEY")
VERIFY_CERT = os.getenv("MISP_VERIFY_CERT", "true").lower() == "true"

if not MISP_URL or not MISP_KEY:
    raise SystemExit("MISP_URL or MISP_API_KEY is missing in .env")

TYPE_MAP = {
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "URL": "url",
    "domain": "domain",
    "hostname": "hostname",
    "IPv4": "ip-src",
}

def main():
    records = json.loads(INPUT.read_text(encoding="utf-8"))

    candidates = []
    seen = set()

    for item in records:
        source_type = item.get("type", "")
        misp_type = TYPE_MAP.get(source_type)
        value = str(item.get("value", "")).strip()

        # CVEs are vulnerability references, not threat indicators.
        if not misp_type or not value:
            continue

        key = (misp_type, value.lower())
        if key in seen:
            continue
        seen.add(key)

        candidates.append((item, misp_type, value))

    print("Input records:", len(records))
    print("Supported non-CVE candidates:", len(candidates))
    print("All imported attributes will use to_ids=False.")

    confirmation = input(
        "Type IMPORT to create a new MISP event and continue: "
    )
    if confirmation != "IMPORT":
        print("Cancelled. No event created.")
        return

    misp = PyMISP(
        MISP_URL,
        MISP_KEY,
        ssl=VERIFY_CERT,
        tool="ThreatLens",
    )

    event_result = misp.add_event({
        "info": "ThreatLens - AlienVault OTX Source-Reported Candidates",
        "distribution": 0,
        "threat_level_id": 3,
        "analysis": 0,
    })

    if isinstance(event_result, dict) and event_result.get("errors"):
        raise RuntimeError(f"MISP event creation failed: {event_result['errors']}")

    event_data = event_result.get("Event", event_result)
    event_id = event_data.get("id")

    if not event_id:
        raise RuntimeError(
            "Could not determine the new MISP event ID. "
            "Check MISP before attempting another import."
        )

    print("Created MISP event ID:", event_id)

    imported = 0
    failed = 0

    for index, (item, misp_type, value) in enumerate(candidates, start=1):
        pulse_name = item.get("pulse_name", "Unknown OTX pulse")
        source_url = item.get("source_url", "")
        status = item.get("validation_status", "source_reported_unverified")

        comment = (
            f"Source: AlienVault OTX; Pulse: {pulse_name}; "
            f"Validation: {status}; Source URL: {source_url}"
        )

        attribute = {
            "type": misp_type,
            "value": value,
            "to_ids": False,
            "comment": comment,
        }

        try:
            result = misp.add_attribute(event_id, attribute)
            if isinstance(result, dict) and result.get("errors"):
                failed += 1
                print(f"Failed attribute {index}: MISP returned an error.")
            else:
                imported += 1
        except Exception as exc:
            failed += 1
            print(f"Failed attribute {index}: {type(exc).__name__}")

        if index % 25 == 0:
            print(f"Processed {index}/{len(candidates)} candidates")
            time.sleep(0.5)

    print("\nImport summary")
    print("MISP event ID:", event_id)
    print("Successfully submitted:", imported)
    print("Failed submissions:", failed)
    print("Detection enabled: No (to_ids=False)")
    print("Review the event in MISP before considering further enrichment.")

if __name__ == "__main__":
    main()
