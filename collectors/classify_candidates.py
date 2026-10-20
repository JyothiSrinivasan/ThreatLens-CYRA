
import json
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
INPUT = ROOT / "data" / "processed" / "unified_candidate_iocs.json"
OUTPUT = ROOT / "data" / "processed" / "classified_candidates.json"

records = json.loads(INPUT.read_text(encoding="utf-8"))

reference_domains = {
    "cert-in.org.in",
    "oracle.com",
    "apple.com",
    "sap.com",
    "microsoft.com",
    "ic3.gov",
    "huntress.com",
    "bleepingcomputer.com",
    "veeam.com",
    "dlink.com",
    "notion.site",
    "example.com",
}

def root_domain(host):
    host = (host or "").lower().strip(".")
    for domain in reference_domains:
        if host == domain or host.endswith("." + domain):
            return domain
    return None

classified = []

for record in records:
    item = dict(record)
    value = str(item.get("value", "")).strip()
    raw_kind = str(item.get("type", "")).strip()
    kind_lower = raw_kind.lower()

    if kind_lower.startswith("filehash-"):
        kind = kind_lower.removeprefix("filehash-")
    else:
        kind = kind_lower

    if kind == "ipv4":
        kind = "ip"

    if (
        item.get("campaign") == "UAT-11985"
        and "Cisco Talos" in item.get("source", "")
    ):
        item["classification"] = "campaign_indicator_source_reported"
        item["classification_reason"] = (
            "Published in the Cisco Talos UAT-11985 campaign IOC file; "
            "not independently verified."
        )
    elif kind in ("domain", "url"):    
        if kind in ("domain", "url"):
            host = (
                urlsplit(value).hostname
                if kind == "url"
                else value
            )
        known_reference = root_domain(host)

        if known_reference:
            item["classification"] = "likely_reference"
            item["classification_reason"] = (
                f"Host belongs to known vendor/security reference domain: "
                f"{known_reference}"
            )
        else:
            item["classification"] = "needs_review"
            item["classification_reason"] = (
                "Not on the reference-domain list; this is not proof "
                "that the domain or URL is malicious."
            )
   
    elif kind == "cve":
        item["classification"] = "vulnerability_reference"
        item["classification_reason"] = (
            "CVE identifiers are vulnerability references, not malicious IoCs."
        )
    elif kind in ("md5", "sha1", "sha256"):
        item["classification"] = "source_reported_unverified"
        item["classification_reason"] = (
            "Hash was reported in source material; independently unverified."
        )
    else:
        item["classification"] = "needs_review"
        item["classification_reason"] = "Unrecognized candidate type."


    classified.append(item)

OUTPUT.write_text(
    json.dumps(classified, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

from collections import Counter

print("Records classified:", len(classified))
print("Classification totals:", dict(Counter(
    item["classification"] for item in classified
)))
print("Output:", OUTPUT)
