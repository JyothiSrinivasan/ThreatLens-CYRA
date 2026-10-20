
import json
import re
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_FILE = PROJECT_ROOT / "data" / "processed" / "candidate_iocs.json"

PATTERNS = {
    "cve": re.compile(
        r"\bCVE-\d{4}-\d{4,}\b",
        re.IGNORECASE,
    ),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "ipv4": re.compile(
        r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])"
    ),
    "url": re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE),
    "domain": re.compile(
        r"(?<![\w.-])"
    	r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    	r"(?:com|org|net|edu|gov|mil|int|in|uk|io|co|ai|biz|info|"
    	r"dev|app|cloud|tech|online|site|xyz|me|us|ca|au|de|fr|jp|"
    	r"ru|cn|br|eu|tv|gg|ly|onion)"
    	r"(?![\w.-])",
    	re.IGNORECASE,
    ),
}


def load_text_records(path):
    if not path.exists():
        print("File not found:", path)
        return []

    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, list):
        print("Expected a JSON list in:", path)
        return []

    return data



def record_text(record):
    # Search content, not metadata URLs.
    fields = ["title", "summary", "text"]
    parts = []

    for field in fields:
        value = str(record.get(field, ""))
        # Remove HTML tags, including links embedded in RSS markup.
        value = re.sub(r"<[^>]*>", " ", value)
        parts.append(value)

    return " ".join(parts)



def valid_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.version == 4
    except ValueError:
        return False


def extract_from_record(record, source_file):
    text = record_text(record)
    source_url = record.get("source_url", "")
    if not source_url:
        source_url = record.get("link", "")

    found = []

    for kind in ("cve", "md5", "sha1", "sha256", "ipv4"):
        for value in PATTERNS[kind].findall(text):
            if kind == "ipv4" and not valid_ipv4(value):
                continue

            found.append({
                "type": kind,
                "value": value.upper() if kind == "cve" else value,
                "source_url": source_url,
                "source_file": source_file,
                "context": "Candidate extracted from public threat content",
                "validation_status": "unvalidated",
            })

    # Extract URLs and their hostnames.
    for value in PATTERNS["url"].findall(text):
        value = value.rstrip(".,;:!?) ]}")
        found.append({
            "type": "url",
            "value": value,
            "source_url": source_url,
            "source_file": source_file,
            "context": "Candidate extracted from public threat content",
            "validation_status": "unvalidated",
        })

        hostname = urlsplit(value).hostname
        if hostname:
            found.append({
                "type": "domain",
                "value": hostname.lower(),
                "source_url": source_url,
                "source_file": source_file,
                "context": "Hostname extracted from a URL",
                "validation_status": "unvalidated",
            })

    # Find other domain-like strings in the text.
    for value in PATTERNS["domain"].findall(text):
        found.append({
            "type": "domain",
            "value": value.lower(),
            "source_url": source_url,
            "source_file": source_file,
            "context": "Candidate extracted from public threat content",
            "validation_status": "unvalidated",
        })

    return found


def main():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    inputs = [
        ("rss_entries.json", "RSS"),
        ("../processed/certin_advisories_cleaned.json", "CERT-In"),
    ]

    all_candidates = []

    for filename, source_label in inputs:
        path = RAW_DIR / filename
        records = load_text_records(path)
        print(f"{source_label} records loaded:", len(records))

        for record in records:
            all_candidates.extend(
                extract_from_record(record, filename)
            )

    # Deduplicate by indicator type, value and source URL.
    unique = {}
    for item in all_candidates:
        key = (
            item["type"],
            item["value"].lower(),
            item["source_url"],
        )
        unique[key] = item

    results = list(unique.values())

    OUTPUT_FILE.write_text(
        json.dumps(results, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print("\nCandidate occurrences:", len(all_candidates))
    print("Unique type/value/source records:", len(results))
    print("Output file:", OUTPUT_FILE)
    print("\nCounts by type:")

    for kind in sorted({item["type"] for item in results}):
        count = sum(1 for item in results if item["type"] == kind)
        print(f"{kind}: {count}")

    print("\nReminder: all extracted candidates are unvalidated.")


if __name__ == "__main__":
    main()
