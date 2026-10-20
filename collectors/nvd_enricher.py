
import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
INPUT_FILE = ROOT / "data" / "processed" / "cve_inventory.json"
OUTPUT_FILE = ROOT / "data" / "processed" / "cve_enriched.json"

load_dotenv(ROOT / ".env")

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")

headers = {"User-Agent": "ThreatLens-CVE-Enricher/1.0"}
if API_KEY:
    headers["apiKey"] = API_KEY

records = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
session = requests.Session()
session.headers.update(headers)

results = []
success = 0

for index, record in enumerate(records, start=1):
    cve_id = record["cve"]
    item = dict(record)
    item["nvd_status"] = "not_checked"
    item["description"] = None
    item["cvss_score"] = None
    item["cvss_severity"] = None
    item["nvd_published"] = None
    item["nvd_last_modified"] = None
    item["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    try:
        response = session.get(
            API_URL,
            params={"cveId": cve_id},
            timeout=30,
        )

        if response.status_code == 404:
            item["nvd_status"] = "not_found"
        else:
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])

            if not vulnerabilities:
                item["nvd_status"] = "no_record_returned"
            else:
                cve = vulnerabilities[0]["cve"]
                descriptions = cve.get("descriptions", [])
                english = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    None,
                )

                item["description"] = english
                item["nvd_published"] = cve.get("published")
                item["nvd_last_modified"] = cve.get("lastModified")
                item["nvd_status"] = "enriched"

                metrics = cve.get("metrics", {})
                for metric_name in (
                    "cvssMetricV40",
                    "cvssMetricV31",
                    "cvssMetricV30",
                    "cvssMetricV3",
                    "cvssMetricV2",
                ):
                    entries = metrics.get(metric_name, [])
                    if entries:
                        data = entries[0].get("cvssData", {})
                        item["cvss_score"] = data.get("baseScore")
                        item["cvss_severity"] = (
                            data.get("baseSeverity")
                            or entries[0].get("baseSeverity")
                        )
                        break

                success += 1

    except requests.RequestException as exc:
        item["nvd_status"] = "request_error"
        item["nvd_error"] = str(exc)[:300]

    results.append(item)
    print(f"[{index}/{len(records)}] {cve_id}: {item['nvd_status']}")

    # Public NVD API: stay below its no-key rate limit.
    if index < len(records):
        time.sleep(6)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(
    json.dumps(results, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("\nEnrichment finished.")
print("Input CVEs:", len(records))
print("NVD records enriched:", success)
print("Output file:", OUTPUT_FILE)
