import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADVISORY_FILE = ROOT / "data/processed/certin_advisories_cleaned.json"
CAMPAIGN_FILE = ROOT / "analysis/UAT-11985_Diamond_Model.md"
OUTPUT_FILE = ROOT / "data/processed/cyra_knowledge_base.json"

def split_text(text, chunk_size=900, overlap=150):
    text = " ".join(text.split())
    chunks = []
    start = 0

    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        if end == len(text):
            break

        start = end - overlap

    return chunks

if OUTPUT_FILE.exists():
    raise SystemExit(
        f"Output already exists; refusing to overwrite: {OUTPUT_FILE}"
    )

documents = []

advisories = json.loads(ADVISORY_FILE.read_text(encoding="utf-8"))

for advisory in advisories:
    text = advisory.get("text", "").strip()
    if not text:
        continue

    for index, chunk in enumerate(split_text(text), start=1):
        documents.append({
            "document_id": f"{advisory.get('advisory_id', 'CERTIN')}-chunk-{index}",
            "document_type": "certin_advisory",
            "title": advisory.get("title", "Untitled advisory"),
            "source": advisory.get("source", "CERT-In"),
            "source_url": advisory.get("source_url", ""),
            "advisory_id": advisory.get("advisory_id", ""),
            "severity": advisory.get("severity", ""),
            "chunk_index": index,
            "text": chunk,
        })

campaign_text = CAMPAIGN_FILE.read_text(encoding="utf-8")

for index, chunk in enumerate(split_text(campaign_text), start=1):
    documents.append({
        "document_id": f"UAT-11985-campaign-chunk-{index}",
        "document_type": "campaign_analysis",
        "title": "ThreatLens Campaign Analysis: UAT-11985",
        "source": "ThreatLens campaign analysis based on Cisco Talos reporting",
        "source_url": "https://blog.talosintelligence.com/uat-11985/",
        "chunk_index": index,
        "text": chunk,
        "validation_note": (
            "Source-based analysis; do not infer direct Indian BFSI targeting "
            "or treat listed indicators as independently verified."
        ),
    })

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
OUTPUT_FILE.write_text(
    json.dumps(documents, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print(f"Knowledge-base documents: {len(documents)}")
print(f"CERT-In advisories loaded: {len(advisories)}")
print(f"Output: {OUTPUT_FILE.relative_to(ROOT)}")
print("Source references preserved: yes")
print("Existing output overwritten: no")
