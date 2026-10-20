
import json
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_FILE = OUTPUT_DIR / "rss_entries.json"

# Add only verified, publicly accessible RSS/Atom feed URLs here.

FEED_URLS = [
    "https://www.cisecurity.org/feed/advisories",
    "https://feeds.feedburner.com/feedburner/Talos",
]


def collect_feed(url):
    """Fetch and parse one public RSS/Atom feed."""
    response = requests.get(
        url,
        timeout=20,
        headers={"User-Agent": "ThreatLens-CTI-Student-Project/1.0"},
    )
    response.raise_for_status()

    feed = feedparser.parse(response.content)

    if feed.bozo and not feed.entries:
        raise ValueError("Feed could not be parsed successfully")

    records = []

    for entry in feed.entries:
        records.append({
            "source_url": url,
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "published": entry.get("published", ""),
            "summary": entry.get("summary", ""),
            "collected_at_utc": datetime.now(
                timezone.utc
            ).isoformat(),
        })

    return records


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    all_records = []

    for url in FEED_URLS:
        try:
            records = collect_feed(url)
            all_records.extend(records)
            print(f"Collected {len(records)} entries from {url}")
        except (requests.RequestException, ValueError) as exc:
            print(f"Feed collection failed for {url}: {exc}")

    # Deduplicate entries by link.
    unique_records = {}
    for record in all_records:
        key = record["link"] or (
            record["source_url"] + "|" + record["title"]
        )
        unique_records[key] = record

    OUTPUT_FILE.write_text(
        json.dumps(
            list(unique_records.values()),
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"Unique entries saved: {len(unique_records)}")
    print(f"Output file: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
