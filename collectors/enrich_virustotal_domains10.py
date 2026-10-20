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
INPUT = ROOT / "data/processed/misp_enrichment_pilot_diverse_ready.json"
OUTPUT = ROOT / "data/processed/virustotal_domains_batch10.json"
BASE_URL = "https://www.virustotal.com/api/v3"
DELAY = 16

def main():
    if not API_KEY:
        raise SystemExit("VIRUSTOTAL_API_KEY missing from .env")
    if not INPUT.exists():
        raise SystemExit("Input file not found")
    if OUTPUT.exists():
        raise SystemExit("Output exists; refusing to overwrite")

    records = json.loads(INPUT.read_text(encoding="utf-8"))
    selected = []
    seen = set()

    for record in records:
        kind = str(record.get("type", "")).strip().lower()
        value = str(record.get("value", "")).strip().rstrip(".")
        if kind not in {"domain", "hostname"} or not value:
            continue
        if value.lower() in seen:
            continue
        seen.add(value.lower())
        selected.append(dict(record))
        if len(selected) == 10:
            break

    if not selected:
        raise SystemExit("No domain/hostname indicators found")

    session = requests.Session()
    session.headers.update({"x-apikey": API_KEY})
    results = []

    for i, item in enumerate(selected, 1):
        value = str(item["value"]).strip().rstrip(".")
        item["virustotal_status"] = "request_error"
        item["virustotal_lookup"] = None

        try:
            response = session.get(
                f"{BASE_URL}/domains/{value}",
                timeout=25,
            )
            if response.status_code == 200:
                attrs = response.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                item["virustotal_status"] = "lookup_success"
                item["virustotal_lookup"] = {
                    "malicious": stats.get("malicious"),
                    "suspicious": stats.get("suspicious"),
                    "harmless": stats.get("harmless"),
                    "undetected": stats.get("undetected"),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "reputation": attrs.get("reputation"),
                }
            elif response.status_code == 404:
                item["virustotal_status"] = "not_found"
            elif response.status_code == 429:
                item["virustotal_status"] = "rate_limited"
            elif response.status_code in (401, 403):
                item["virustotal_status"] = "authentication_or_permission_error"
            else:
                item["virustotal_status"] = f"http_error_{response.status_code}"
        except requests.RequestException as exc:
            item["virustotal_status"] = "request_error"
            print("  Network error:", type(exc).__name__)
        except (ValueError, TypeError):
            item["virustotal_status"] = "invalid_response"

        results.append(item)
        print(f"Lookup {i}/{len(selected)}: {item['virustotal_status']}")

        if i < len(selected):
            time.sleep(DELAY)

    OUTPUT.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print("\nStatuses:", dict(Counter(r["virustotal_status"] for r in results)))
    print("Output:", OUTPUT)
    print("Original 150-record dataset and previous pilots were not modified.")

if __name__ == "__main__":
    main()
