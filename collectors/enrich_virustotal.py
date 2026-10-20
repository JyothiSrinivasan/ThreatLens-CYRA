
import json
import os
import time
from collections import Counter
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

INPUT = ROOT / "data" / "processed" / "unified_candidate_iocs.json"
OUTPUT = ROOT / "data" / "processed" / "virustotal_enrichment_pilot.json"

BASE_URL = "https://www.virustotal.com/api/v3"
MAX_LOOKUPS = 5
REQUEST_DELAY_SECONDS = 16



def get_vt_path(record):
    """Map ThreatLens indicator types to VirusTotal API endpoints."""
    indicator_type = str(record.get("type", "")).strip().lower()
    value = str(record.get("value", "")).strip()

    if not value:
        return None

    hash_types = {
        "md5", "sha1", "sha256",
        "filehash-md5", "filehash-sha1", "filehash-sha256",
        "file_hash",
    }

    if indicator_type in hash_types:
        return f"files/{value}"

    if indicator_type in {"domain", "hostname"}:
        return f"domains/{value}"

    if indicator_type in {"ipv4", "ip", "ip-src", "ip-dst"}:
        return f"ip_addresses/{value}"

    # URL lookup will be added after the initial pilot.
    return None


def main():
    if not API_KEY:
        raise SystemExit("VIRUSTOTAL_API_KEY is missing from .env")

    if not INPUT.exists():
        raise SystemExit(f"Input file not found: {INPUT}")


    records = json.loads(INPUT.read_text(encoding="utf-8"))

    # Select one source-reported candidate for each supported type.
    wanted_types = [
        "FileHash-MD5",
        "FileHash-SHA1",
        "FileHash-SHA256",
        "IPv4",
        "domain",
    ]

    selected = []
    seen_values = set()

    for wanted_type in wanted_types:
        match = next(
            (
                record for record in records
                if str(record.get("type", "")).strip() == wanted_type
                and record.get("validation_status") == "source_reported_unverified"
                and str(record.get("value", "")).strip()
                and str(record.get("value", "")).lower() not in seen_values
            ),
            None,
        )

        if match:
            selected.append(match)
            seen_values.add(str(match["value"]).lower())

    if len(selected) != 5:
        raise SystemExit(
            f"Expected 5 diverse candidates; found {len(selected)}. "
            "No API requests made."
        )

    results = []
    session = requests.Session()
    session.headers.update({"x-apikey": API_KEY})

    for index, record in enumerate(selected):
        item = dict(record)
        path = get_vt_path(item)

        item["virustotal_status"] = "skipped_unsupported_type"
        item["virustotal_lookup"] = None

        if not path:
            results.append(item)
            continue

        try:
            response = session.get(
                f"{BASE_URL}/{path}",
                timeout=20,
            )

            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})

                item["virustotal_status"] = "lookup_success"
                item["virustotal_lookup"] = {
                    "malicious": stats.get("malicious"),
                    "suspicious": stats.get("suspicious"),
                    "harmless": stats.get("harmless"),
                    "undetected": stats.get("undetected"),
                    "last_analysis_date": data.get("last_analysis_date"),
                    "reputation": data.get("reputation"),
                }
            elif response.status_code == 404:
                item["virustotal_status"] = "not_found"
            elif response.status_code == 429:
                item["virustotal_status"] = "rate_limited"
            elif response.status_code in (401, 403):
                item["virustotal_status"] = "authentication_or_permission_error"
            else:
                item["virustotal_status"] = f"http_error_{response.status_code}"

        except requests.RequestException:
            item["virustotal_status"] = "request_error"
        except (ValueError, TypeError):
            item["virustotal_status"] = "invalid_response"

        results.append(item)

        print(
            f"Lookup {index + 1}/5:",
            item.get("type"),
            "->",
            item["virustotal_status"],
        )

        if index < len(selected) - 1:
            time.sleep(REQUEST_DELAY_SECONDS)


    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


    print("Input records:", len(records))
    print("Unique lookups attempted:", len(selected))
    print(
        "VirusTotal statuses:",
        dict(Counter(x["virustotal_status"] for x in results)),
    )
    print("Output:", OUTPUT)
    print("Original validation labels preserved.")


if __name__ == "__main__":
    main()
