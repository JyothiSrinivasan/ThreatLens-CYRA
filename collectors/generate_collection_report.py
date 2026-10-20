
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
REPORT = ROOT / "reports" / "collection_report.md"


def read_json(path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def count_records(data, list_key=None):
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict) and list_key:
        value = data.get(list_key, [])
        return len(value) if isinstance(value, list) else 0
    return 0


def main():
    rss = read_json(RAW / "rss_entries.json")
    certin = read_json(RAW / "certin_advisories.json")
    certin_summary = read_json(RAW / "certin_collection_summary.json")
    talos = read_json(PROCESSED / "talos_uat_11985_candidates.json")
    otx = read_json(RAW / "otx_pulses.json")
    unified = read_json(PROCESSED / "unified_candidate_iocs.json")
    quality = read_json(PROCESSED / "collection_quality_audit.json")

    sources = [
        ("CIS and Cisco Talos RSS articles",
         count_records(rss)),
        ("CERT-In public advisories",
         count_records(certin)),
        ("Cisco Talos UAT-11985 IOC file",
         count_records(talos)),
        ("AlienVault OTX pulses",
         count_records(otx, "pulses")),
        ("AlienVault OTX indicator candidates",
         count_records(read_json(PROCESSED / "otx_indicator_candidates.json"))),
        ("Unified candidate records",
         count_records(unified)),
    ]

    lines = [
        "# ThreatLens — Collection Layer Report",
        "",
        f"Generated (UTC): {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Collection counts",
        "",
        "| Dataset | Records |",
        "|---|---:|",
    ]

    for name, count in sources:
        lines.append(f"| {name} | {count} |")

    lines.extend([
        "",
        "## Source coverage and limitations",
        "",
        "- **RSS:** 65 entries were collected from the configured CIS "
        "advisories and Cisco Talos feeds.",
        "- **CERT-In:** the collector checked one listing page for each "
        "of 2024, 2025 and 2026. It saved 45 advisories with zero "
        "parse failures and zero request failures in the last run. "
        "This is not full historical archive coverage.",
        "- **Cisco Talos:** the UAT-11985 IOC file supplied 8 source-reported "
        "entries. These are campaign-specific, not a complete Talos IOC feed.",
        "- **AlienVault OTX:** the collector retrieved 200 subscribed pulses "
        "from the first 20 pages. The API reported 9,214 available pulses "
        "during a diagnostic request, so the current dataset is a bounded "
        "sample rather than a complete collection.",
        "",
        "## Data quality",
        "",
    ])

    if quality:
        lines.extend([
            f"- Unified records: {quality.get('total_records', 'not available')}",
            f"- Distinct canonical type/value pairs: "
            f"{quality.get('distinct_canonical_type_value_pairs', 'not available')}",
            f"- Repeated pairs across records: "
            f"{quality.get('pairs_repeated_across_records', 'not available')}",
            f"- Records missing source URLs: "
            f"{quality.get('records_missing_source_url', 'not available')}",
            f"- Records missing values: "
            f"{quality.get('records_missing_value', 'not available')}",
            f"- Records missing types: "
            f"{quality.get('records_missing_type', 'not available')}",
            "",
            "### Canonical type counts",
            "",
            "| Type | Count |",
            "|---|---:|",
        ])
        for kind, count in quality.get("canonical_type_counts", {}).items():
            lines.append(f"| {kind} | {count} |")
    else:
        lines.append(
            "The quality audit file was not found. Run "
            "`python collectors\\audit_collection.py` first."
        )

    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
        "- Extracted records are candidates, not automatically confirmed "
        "malicious indicators.",
        "- CVEs are vulnerability references and must not be counted as "
        "confirmed malicious IoCs.",
        "- URLs and domains can be legitimate references in vendor "
        "advisories or articles.",
        "- Source-reported metadata is retained for traceability; it is "
        "not equivalent to independent validation.",
        "- Repeated type/value pairs are reported for review and are not "
        "automatically removed from the provenance-preserving dataset.",
        "",
        "## Reproducibility",
        "",
        "Run the existing source collectors and parsers to refresh the "
        "datasets. Then run `python collectors\\merge_candidate_datasets.py`, "
        "`python collectors\\audit_collection.py`, and this report generator "
        "in that order.",
        "",
    ])

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print("Collection report generated.")
    print("Report:", REPORT)
    print("Source datasets included:", len(sources))


if __name__ == "__main__":
    main()
