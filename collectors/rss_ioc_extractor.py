
import html
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "raw" / "rss_entries.json"
OUTPUT = ROOT / "data" / "processed" / "rss_candidate_iocs.json"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
DOMAIN_RE = re.compile(
    r"(?<![@\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}\b"
)

def clean_html(value):
    value = re.sub(r"<[^>]+>", " ", value or "")
    return html.unescape(value)

def add_candidate(results, seen, kind, value, record, context):
    article_url = record.get("link", "")
    key = (kind, value.lower(), article_url)
    if key in seen:
        return

    seen.add(key)
    results.append({
        "type": kind,
        "value": value,
        "source": record.get("source_url", "unknown"),
        "source_url": article_url,
        "title": record.get("title", ""),
        "published": record.get("published", ""),
        "context": context,
        "validation_status": "unvalidated",
    })

records = json.loads(INPUT.read_text(encoding="utf-8"))
results = []
seen = set()

total_text_length = 0
for record in records:
    text = clean_html(
        (record.get("title") or "") + " " + (record.get("summary") or "")
    )
    total_text_length += len(text)
    if record is records[0]:
        print("First cleaned text:", repr(text[:500]))
        print("CVE matches:", CVE_RE.findall(text)[:5])
        print("URL matches:", URL_RE.findall(text)[:5])
        print("Domain matches:", DOMAIN_RE.findall(text)[:5])

    for cve in CVE_RE.findall(text):
        add_candidate(
            results, seen, "cve", cve.upper(), record,
            "CVE reference extracted from RSS title/summary"
        )

    for value in HASH_RE.findall(text):
        kind = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
        add_candidate(
            results, seen, kind, value.lower(), record,
            "Hash-shaped string; requires source-context review"
        )

    for value in IP_RE.findall(text):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue

        add_candidate(
            results, seen, "ip", value, record,
            "IPv4 candidate extracted from RSS text; unverified"
        )

    for value in URL_RE.findall(text):
        value = value.rstrip(".,;:!?)" + "]}")
        add_candidate(
            results, seen, "url", value, record,
            "URL extracted from RSS text; not presumed malicious"
        )

        host = urlsplit(value).hostname
        if host:
            add_candidate(
                results, seen, "domain", host.lower(), record,
                "Hostname extracted from RSS URL; not presumed malicious"
            )

    for value in DOMAIN_RE.findall(text):
        add_candidate(
            results, seen, "domain", value.lower(), record,
            "Domain-shaped string; requires source-context review"
        )

print("Total cleaned text characters:", total_text_length)
print("Candidate insertion count:", len(results))
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(
    json.dumps(results, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print("RSS articles processed:", len(records))
print("Candidate records extracted:", len(results))
print("Counts by type:", dict(Counter(x["type"] for x in results)))
print("Output:", OUTPUT)
print("All candidates remain unvalidated.")
