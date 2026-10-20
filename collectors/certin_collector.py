
import json
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import requests

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT / "data" / "raw"
OUTPUT_FILE = OUTPUT_DIR / "certin_advisories.json"
SUMMARY_FILE = OUTPUT_DIR / "certin_collection_summary.json"

YEARS = [2024, 2025, 2026]
MAX_LISTING_PAGES_PER_YEAR = 30
DELAY_SECONDS = 0.4

BASE_URL = "https://www.cert-in.org.in/s2cMainServlet"
HEADERS = {"User-Agent": "ThreatLens-CTI-Student-Project/1.0"}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.links = []

    def handle_data(self, data):
        value = data.strip()
        if value:
            self.text_parts.append(value)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href:
                self.links.append(href)


def fetch_page(session, url):
    response = session.get(url, headers=HEADERS, timeout=25)
    response.raise_for_status()
    parser = PageParser()
    parser.feed(response.text)
    return parser


def listing_year(url):
    query = parse_qs(urlparse(url).query)
    if query.get("pageid", [""])[0] != "PUBADVLIST02":
        return None
    try:
        return int(query.get("year", [""])[0])
    except (ValueError, TypeError):
        return None


def collect_listing_links(session, year, summary):
    start_url = (
        f"{BASE_URL}?pageid=PUBADVLIST02&year={year}"
    )
    queue = [start_url]
    visited = set()
    advisory_urls = set()

    while queue and len(visited) < MAX_LISTING_PAGES_PER_YEAR:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            parser = fetch_page(session, url)
        except requests.RequestException as exc:
            summary["listing_errors"].append({
                "year": year,
                "url": url,
                "error_type": type(exc).__name__,
            })
            continue

        for href in parser.links:
            absolute_url = urljoin(url, href)
            parsed = urlparse(absolute_url)
            query = parse_qs(parsed.query)

            advisory_code = query.get("VLCODE", [""])[0]
            if re.fullmatch(r"CIAD-\d{4}-\d{4}", advisory_code):
                if advisory_code.startswith(f"CIAD-{year}-"):
                    advisory_urls.add(absolute_url)

            # Follow only listing pages for the same year.
            if listing_year(absolute_url) == year:
                if absolute_url not in visited and absolute_url not in queue:
                    queue.append(absolute_url)

        time.sleep(DELAY_SECONDS)

    if queue:
        summary["listing_limit_warnings"].append({
            "year": year,
            "limit": MAX_LISTING_PAGES_PER_YEAR,
            "unvisited_listing_pages": len(queue),
        })

    summary["listing_pages_checked"][str(year)] = len(visited)
    return advisory_urls


def extract_record(session, url):
    parser = fetch_page(session, url)
    text = " ".join(parser.text_parts)


    match = re.search(
        r"(CIAD-\d{4}-\d{4})\s+(.*?)"
        r"\s+Original Issue Date:\s*"
        r"([A-Za-z]+\s+\d{1,2},\s+\d{4})",
        text,
        re.IGNORECASE,
    )

    if not match:
        print("Could not extract advisory fields:", url)
        return None

    advisory_id, title, issue_date = (
        value.strip() for value in match.groups()
    )

    severity_match = re.search(
        r"\bSeverity Rating:\s*(Critical|High|Medium|Low)\b",
        text,
        re.IGNORECASE,
    )
    severity = severity_match.group(1).title() if severity_match else "Unknown"


    return {
        "source": "CERT-In",
        "advisory_id": advisory_id,
        "title": title,
        "original_issue_date": issue_date,
        "severity": severity,
        "source_url": url,
        "text": text,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    summary = {
        "source": "CERT-In public advisory listing",
        "collection_started_at_utc": datetime.now(timezone.utc).isoformat(),
        "years_requested": YEARS,
        "listing_pages_checked": {},
        "listing_errors": [],
        "listing_limit_warnings": [],
        "advisory_pages_attempted": 0,
        "advisory_pages_failed": [],
        "parse_failures": [],
    }

    records_by_id = {}

    with requests.Session() as session:
        advisory_urls = set()

        for year in YEARS:
            urls = collect_listing_links(session, year, summary)
            advisory_urls.update(urls)
            print(f"{year}: discovered {len(urls)} advisory links")

        print("Unique advisory links discovered:", len(advisory_urls))

        for url in sorted(advisory_urls):
            summary["advisory_pages_attempted"] += 1
            try:
                record = extract_record(session, url)
                if not record:
                    summary["parse_failures"].append(url)
                    print("Parse failed:", url)
                else:
                    records_by_id[record["advisory_id"]] = record
            except requests.RequestException as exc:
                summary["advisory_pages_failed"].append({
                    "url": url,
                    "error_type": type(exc).__name__,
                })
                print("Request failed:", url, type(exc).__name__)

            time.sleep(DELAY_SECONDS)

    # Preserve previous results if this run returns no records.
    if not records_by_id:
        print("No advisories extracted. Existing output was not overwritten.")
        summary["collection_finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        summary["records_saved"] = 0
        SUMMARY_FILE.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        raise SystemExit(1)

    records = sorted(
        records_by_id.values(),
        key=lambda item: item["advisory_id"],
    )

    OUTPUT_FILE.write_text(
        json.dumps(records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    summary["collection_finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    summary["advisory_links_discovered"] = len(advisory_urls)
    summary["records_saved"] = len(records)
    summary["parse_failure_count"] = len(summary["parse_failures"])
    summary["request_failure_count"] = len(summary["advisory_pages_failed"])

    SUMMARY_FILE.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\nCERT-In collection finished.")
    print("Listing pages checked:", summary["listing_pages_checked"])
    print("Advisory links discovered:", len(advisory_urls))
    print("Unique advisories saved:", len(records))
    print("Parse failures:", summary["parse_failure_count"])
    print("Request failures:", summary["request_failure_count"])
    print("Advisory output:", OUTPUT_FILE)
    print("Run summary:", SUMMARY_FILE)


if __name__ == "__main__":
    main()
