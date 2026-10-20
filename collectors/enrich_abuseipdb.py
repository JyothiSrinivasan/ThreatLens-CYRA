
import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

API_KEY = os.getenv("ABUSEIPDB_API_KEY")

INPUT = ROOT / "data" / "processed" / "virustotal_enrichment_pilot.json"
OUTPUT = ROOT / "data" / "processed" / "abuseipdb_enrichment_pilot.json"

API_URL = "https://api.abuseipdb.com/api/v2/check"


def main():
    if not API_KEY:
        raise SystemExit("ABUSEIPDB_API_KEY is missing from .env")

    if not INPUT.exists():
        raise SystemExit(f"Input file not found: {INPUT}")

    records = json.loads(INPUT.read_text(encoding="utf-8"))

    candidate = next(
        (
            item for item in records
            if item.get("type") == "IPv4"
            and item.get("validation_status") == "source_reported_unverified"
            and str(item.get("value", "")).strip()
        ),
        None,
    )

    if not candidate:
        raise SystemExit("No eligible source-reported IPv4 candidate found.")

    # This sends the selected IP to a third-party reputation service.
    # Use only an indicator suitable for external lookup.
    response = requests.get(
        API_URL,
        headers={
            "Key": API_KEY,
            "Accept": "application/json",
        },
        params={
            "ipAddress": candidate["value"],
            "maxAgeInDays": 90,
        },
        timeout=20,
    )

    result = dict(candidate)
    result["abuseipdb_status"] = "lookup_error"
    result["abuseipdb_lookup"] = None

    if response.status_code == 200:
        data = response.json().get("data", {})

        result["abuseipdb_status"] = "lookup_success"
        result["abuseipdb_lookup"] = {
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "num_distinct_users": data.get("numDistinctUsers"),
            "last_reported_at": data.get("lastReportedAt"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "isp": data.get("isp"),
            "is_public": data.get("isPublic"),
        }
    elif response.status_code == 429:
        result["abuseipdb_status"] = "rate_limited"
    elif response.status_code in (401, 403):
        result["abuseipdb_status"] = "authentication_or_permission_error"
    else:
        result["abuseipdb_status"] = f"http_error_{response.status_code}"

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps([result], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("Records enriched:", 1)
    print("AbuseIPDB status:", result["abuseipdb_status"])
    print("Original validation status preserved:", result.get("validation_status"))
    print("Output:", OUTPUT)


if __name__ == "__main__":
    main()
