
import json
from datetime import datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "raw" / "talos_uat_11985_iocs.json"

IOC_URL = (
    "https://raw.githubusercontent.com/Cisco-Talos/IOCs/"
    "main/2026/10/uat-11985.txt"
)
ARTICLE_URL = "https://blog.talosintelligence.com/uat-11985/"

response = requests.get(
    IOC_URL,
    timeout=30,
    headers={"User-Agent": "ThreatLens-OSINT-Collector/1.0"},
)
response.raise_for_status()

lines = [
    line.strip()
    for line in response.text.splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]

result = {
    "source": "Cisco Talos public IOC repository",
    "source_url": IOC_URL,
    "article_url": ARTICLE_URL,
    "campaign": "UAT-11985",
    "collected_at_utc": datetime.now(timezone.utc).isoformat(),
    "indicator_count": len(lines),
    "indicators": [
        {
            "raw_value": line,
            "validation_status": "source_reported_unverified",
        }
        for line in lines
    ],
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(
    json.dumps(result, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("Source: Cisco Talos IOC repository")
print("Campaign: UAT-11985")
print("Lines collected:", len(lines))
print("Output:", OUTPUT)
print("Values remain in their original defanged form.")
