import json
import os
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SOURCE = ROOT / "data/processed/virustotal_sha256_batch10.json"
OUTPUT = ROOT / "data/processed/virustotal_sha256_retry.json"

if not API_KEY:
    raise SystemExit("VIRUSTOTAL_API_KEY missing from .env")
if not SOURCE.exists():
    raise SystemExit("Original batch file not found")
if OUTPUT.exists():
    raise SystemExit("Retry output already exists; refusing to overwrite")

records = json.loads(SOURCE.read_text(encoding="utf-8"))
failed = [
    r for r in records
    if r.get("virustotal_status") == "request_error"
]

if len(failed) != 1:
    raise SystemExit(
        f"Expected exactly one request_error record; found {len(failed)}"
    )

item = dict(failed[0])
url = "https://www.virustotal.com/api/v3/files/" + item["value"]

try:
    response = requests.get(
        url,
        headers={"x-apikey": API_KEY},
        timeout=30,
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
    print("Network error:", type(exc).__name__)
except (ValueError, TypeError):
    item["virustotal_status"] = "invalid_response"

OUTPUT.write_text(
    json.dumps([item], indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("Retry status:", item["virustotal_status"])
if isinstance(item.get("virustotal_lookup"), dict):
    print("Detection counts:", {
        k: item["virustotal_lookup"].get(k)
        for k in ("malicious", "suspicious", "harmless", "undetected")
    })
print("Retry output:", OUTPUT)
