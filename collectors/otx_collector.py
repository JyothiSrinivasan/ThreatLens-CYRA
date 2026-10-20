
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "data" / "raw" / "otx_pulses.json"

load_dotenv(ROOT / ".env")
API_KEY = os.getenv("OTX_API_KEY")

if not API_KEY:
    raise SystemExit("OTX_API_KEY is missing from .env")

API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"
PAGE_SIZE = 10
MAX_PAGES = 20  # Safety limit: at most 200 pulses per run

headers = {
    "X-OTX-API-KEY": API_KEY,
    "User-Agent": "ThreatLens-OSINT-Collector/1.0",
}

all_pulses = []
seen_ids = set()
page_results = []
session = requests.Session()

try:
    for page in range(1, MAX_PAGES + 1):
        params = {"limit": PAGE_SIZE, "page": page}

        response = session.get(
            API_URL,
            headers=headers,
            params=params,
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()

        pulses = payload.get("results", [])
        if not isinstance(pulses, list):
            raise ValueError("Unexpected OTX results format")

        page_results.append({
            "page": page,
            "returned": len(pulses),
        })

        added_this_page = 0

        for pulse in pulses:
            pulse_id = pulse.get("id")
            identity = str(pulse_id) if pulse_id else json.dumps(
                pulse, sort_keys=True
            )

            if identity not in seen_ids:
                seen_ids.add(identity)
                all_pulses.append(pulse)
                added_this_page += 1

        print(
            f"Page {page}: {len(pulses)} returned, "
            f"{added_this_page} new pulses"
        )

        if not pulses or len(pulses) < PAGE_SIZE:
            break

        time.sleep(0.3)

except requests.RequestException as exc:
    raise SystemExit(
        f"OTX request failed: {type(exc).__name__}. "
        "Existing output was not overwritten."
    ) from None
except (ValueError, json.JSONDecodeError):
    raise SystemExit(
        "OTX returned invalid JSON or an unexpected response format. "
        "Existing output was not overwritten."
    ) from None
finally:
    session.close()

result = {
    "source": "AlienVault Open Threat Exchange",
    "endpoint": API_URL,
    "collected_at_utc": datetime.now(timezone.utc).isoformat(),
    "page_size": PAGE_SIZE,
    "max_pages": MAX_PAGES,
    "pages_checked": len(page_results),
    "page_results": page_results,
    "pulse_count": len(all_pulses),
    "pulses": all_pulses,
}

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(
    json.dumps(result, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("\nOTX collection complete.")
print("Pages checked:", len(page_results))
print("Unique pulses collected:", len(all_pulses))
print("Output:", OUTPUT)

if len(page_results) == MAX_PAGES and page_results[-1]["returned"] == PAGE_SIZE:
    print(
        "WARNING: The page safety limit was reached. "
        "More subscribed pulses may remain."
    )
