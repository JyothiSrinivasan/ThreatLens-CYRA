
import json
from pathlib import Path
import nbformat as nbf

ROOT = Path(__file__).resolve().parent
NOTEBOOK_DIR = ROOT / "notebooks"
OUTPUT = NOTEBOOK_DIR / "threatlens_nlp_evaluation.ipynb"

NOTEBOOK_DIR.mkdir(exist_ok=True)

nb = nbf.v4.new_notebook()
cells = []

cells.append(nbf.v4.new_markdown_cell("""# ThreatLens — NLP Entity Extraction Evaluation

**Project:** CYRA / ThreatLens — AI-Driven Threat Intelligence, Detection & Risk Analytics  
**Purpose:** Compare the existing regex-based extraction baseline with GLiNER on a small, manually labelled gold set.

## Evaluation scope
- Entity types: CVE identifiers, domains, URLs, IP addresses, hashes, malware families, threat actors, and organizations.
- Baseline: existing ThreatLens candidate extractor, evaluated through equivalent regex patterns on the same text.
- NLP model: `urchade/gliner_small-v2.1`.
- Metrics: exact-span precision, recall, and F1.
- Important: an extracted entity is not automatically malicious. Vendor links, vulnerability references, and contact details must not be treated as confirmed indicators.

The gold set below is a small pilot set, manually labelled from the displayed advisory text. Its scores are exploratory and must not be presented as representative of all ThreatLens data.
"""))

cells.append(nbf.v4.new_code_cell("""from pathlib import Path
import json
import re
from collections import Counter

ROOT = Path.cwd()
if ROOT.name.lower() == "notebooks":
    ROOT = ROOT.parent

ADVISORY_FILE = ROOT / "data" / "processed" / "certin_advisories_cleaned.json"
CANDIDATE_FILE = ROOT / "data" / "processed" / "candidate_iocs.json"

assert ADVISORY_FILE.exists(), f"Missing input: {ADVISORY_FILE}"
assert CANDIDATE_FILE.exists(), f"Missing input: {CANDIDATE_FILE}"

advisories = json.loads(ADVISORY_FILE.read_text(encoding="utf-8"))
existing_candidates = json.loads(CANDIDATE_FILE.read_text(encoding="utf-8"))

print("Project root:", ROOT)
print("Cleaned CERT-In advisories:", len(advisories))
print("Existing regex candidate records:", len(existing_candidates))
print("Existing candidate types:", dict(Counter(x.get("type", "unknown") for x in existing_candidates)))
"""))

cells.append(nbf.v4.new_markdown_cell("""## 1. Select real advisory text

We use five CERT-In advisories already present in the project. Source URLs are retained so the examples can be audited. Text is truncated only for the displayed preview; extraction uses the full text.
"""))

cells.append(nbf.v4.new_code_cell("""selected_indices = [0, 1, 3, 5, 7]
selected = [advisories[i] for i in selected_indices if i < len(advisories)]

for i, record in enumerate(selected, 1):
    print(f"{i}. {record.get('title', 'Untitled')}")
    print("   Source:", record.get("source_url", ""))
    print("   Characters:", len(record.get("text", "")))
"""))

cells.append(nbf.v4.new_markdown_cell("""## 2. Manually labelled gold set

The gold set is embedded here to avoid creating extra project files. Labels represent entity spans in these sample texts, not maliciousness. The labels are manually selected from the advisory text and should be reviewed before final submission.

We deliberately include CVEs, domains/URLs, and organization/vendor names. We do not label every vendor URL as malicious.
"""))

cells.append(nbf.v4.new_code_cell("""# Each item is a source-backed text sample and its manually reviewed entity spans.
# Exact text matching is used to locate gold spans. If a value appears multiple times,
# the first occurrence is used for this compact pilot evaluation.

gold_examples = [
    {
        "title": selected[0].get("title", "Veeam advisory"),
        "source_url": selected[0].get("source_url", ""),
        "text": selected[0]["text"],
        "gold": [
            ("CVE-2024-40711", "cve"),
            ("CVE-2024-39715", "cve"),
            ("Veeam", "organization"),
            ("www.veeam.com", "domain"),
        ],
    },
    {
        "title": selected[1].get("title", "Online scams advisory"),
        "source_url": selected[1].get("source_url", ""),
        "text": selected[1]["text"],
        "gold": [
            ("Phishing Scams", "attack_technique"),
            ("bank", "organization"),
        ],
    },
    {
        "title": selected[2].get("title", "Apple advisory"),
        "source_url": selected[2].get("source_url", ""),
        "text": selected[2]["text"],
        "gold": [
            ("Apple", "organization"),
            ("support.apple.com", "domain"),
        ],
    },
    {
        "title": selected[3].get("title", "D-Link advisory"),
        "source_url": selected[3].get("source_url", ""),
        "text": selected[3]["text"],
        "gold": [
            ("D-Link", "organization"),
            ("CVE-2024-10914", "cve"),
            ("supportannouncement.us.dlink.com", "domain"),
        ],
    },
    {
        "title": selected[4].get("title", "PAN-OS advisory"),
        "source_url": selected[4].get("source_url", ""),
        "text": selected[4]["text"],
        "gold": [
            ("Palo Alto Networks", "organization"),
            ("CVE-2024-0012", "cve"),
            ("CVE-2024-9474", "cve"),
            ("security.paloaltonetworks.com", "domain"),
        ],
    },
]

# Check that every gold value occurs in its corresponding source text.
gold_check = []
for example in gold_examples:
    for value, label in example["gold"]:
        found = value.casefold() in example["text"].casefold()
        gold_check.append((example["title"], value, label, found))

missing_gold = [row for row in gold_check if not row[3]]
print("Gold examples:", len(gold_examples))
print("Gold entity labels:", len(gold_check))
print("Missing gold values:", len(missing_gold))
for row in missing_gold:
    print("REVIEW REQUIRED:", row)
assert not missing_gold, "A gold label was not found in its source text; review it before evaluation."

for example in gold_examples:
    print(f"- {example['title']}: {len(example['gold'])} labelled entities")
"""))

cells.append(nbf.v4.new_markdown_cell("""## 3. Regex baseline

This notebook uses transparent regular expressions to create a reproducible baseline on exactly the same advisory text. The existing `candidate_iocs.json` is also loaded above for provenance and comparison with the project's current pipeline.

For this evaluation, the baseline extracts CVEs, URLs, domains, IPv4 addresses, and common hash lengths. It does not claim to classify extracted values as malicious.
"""))

cells.append(nbf.v4.new_code_cell("""PATTERNS = {
    "cve": re.compile(r"\\bCVE-\\d{4}-\\d{4,}\\b", re.IGNORECASE),
    "url": re.compile(r"https?://[^\\s<>\\\"']+", re.IGNORECASE),
    "ipv4": re.compile(r"(?<![\\w.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\w.])"),
    "md5": re.compile(r"\\b[a-fA-F0-9]{32}\\b"),
    "sha1": re.compile(r"\\b[a-fA-F0-9]{40}\\b"),
    "sha256": re.compile(r"\\b[a-fA-F0-9]{64}\\b"),
}
DOMAIN_RE = re.compile(
    r"\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+"
    r"(?:com|org|net|edu|gov|mil|int|in|uk|io|co|ai|biz|info|dev|app|"
    r"cloud|tech|online|site|xyz|me|us|ca|au|de|fr|jp|ru|cn|br|eu|tv|gg|ly)\\b",
    re.IGNORECASE,
)

def regex_extract(text):
    found = []
    for label, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            found.append({
                "text": match.group(0).rstrip(".,;:)"),
                "label": label,
                "start": match.start(),
                "end": match.start() + len(match.group(0).rstrip(".,;:)")),
            })
    for match in DOMAIN_RE.finditer(text):
        found.append({
            "text": match.group(0),
            "label": "domain",
            "start": match.start(),
            "end": match.end(),
        })
    # Remove duplicate exact spans/labels.
    unique = {}
    for entity in found:
        key = (entity["start"], entity["end"], entity["label"], entity["text"].casefold())
        unique[key] = entity
    return list(unique.values())

baseline_example = regex_extract(gold_examples[0]["text"])
print("Regex entities in first advisory:", len(baseline_example))
print("Sample:", baseline_example[:10])
"""))

cells.append(nbf.v4.new_markdown_cell("""## 4. Load GLiNER and extract custom entities

GLiNER is a zero-shot NLP entity-extraction model, not a generative LLM. It can identify text spans using labels supplied at inference time. We evaluate only the labels represented in the gold set.

The model's confidence score is not the same as measured precision or accuracy.
"""))

cells.append(nbf.v4.new_code_cell("""from gliner import GLiNER
import torch

MODEL_NAME = "urchade/gliner_small-v2.1"
device = "cuda" if torch.cuda.is_available() else "cpu"
print("Device:", device)

model = GLiNER.from_pretrained(MODEL_NAME)
model = model.to(device)

GLINER_LABELS = [
    "CVE identifier",
    "domain",
    "URL",
    "IP address",
    "MD5 hash",
    "SHA-1 hash",
    "SHA-256 hash",
    "organization",
    "malware family",
    "threat actor",
    "attack technique",
]

def gliner_extract(text, threshold=0.3):
    raw = model.predict_entities(text, GLINER_LABELS, threshold=threshold)
    mapped = []
    label_map = {
        "CVE identifier": "cve",
        "domain": "domain",
        "URL": "url",
        "IP address": "ipv4",
        "MD5 hash": "md5",
        "SHA-1 hash": "sha1",
        "SHA-256 hash": "sha256",
        "organization": "organization",
        "malware family": "malware_family",
        "threat actor": "threat_actor",
        "attack technique": "attack_technique",
    }
    for entity in raw:
        mapped.append({
            "text": entity["text"],
            "label": mapped_label if (mapped_label := label_map.get(entity["label"], entity["label"].lower())) else entity["label"].lower(),
            "start": entity["start"],
            "end": entity["end"],
            "score": float(entity["score"]),
        })
    return mapped

test_result = gliner_extract(
    "The advisory reported CVE-2024-12345 and the domain evil-example.com."
)
print("GLiNER test result:", test_result)
"""))

cells.append(nbf.v4.new_markdown_cell("""## 5. Exact-span evaluation

A prediction counts as correct only when its normalized entity text and entity label match a gold annotation. This is strict and reproducible, but it does not measure whether a domain is malicious.

The small gold set contains only selected entities; unlabelled text is not exhaustively annotated. Therefore these results are a pilot and may undercount correct extractions that were not included in the gold set. Expand and review the gold set before treating the scores as robust.
"""))

cells.append(nbf.v4.new_code_cell("""def normalize_label(label):
    aliases = {
        "cve identifier": "cve",
        "url": "url",
        "ip address": "ipv4",
        "md5 hash": "md5",
        "sha-1 hash": "sha1",
        "sha-256 hash": "sha256",
        "malware family": "malware_family",
        "threat actor": "threat_actor",
    }
    return aliases.get(label.casefold(), label.casefold())

def normalize_value(value):
    return value.strip().rstrip(".,;:)").casefold()

def evaluate_predictions(gold_examples, extractor, method_name):
    tp = fp = fn = 0
    rows = []
    for example in gold_examples:
        gold_set = {
            (normalize_value(value), normalize_label(label))
            for value, label in example["gold"]
        }
        predictions = extractor(example["text"])
        pred_set = {
            (normalize_value(p["text"]), normalize_label(p["label"]))
            for p in predictions
        }
        matched = gold_set & pred_set
        missed = gold_set - pred_set
        extra = pred_set - gold_set
        tp += len(matched)
        fn += len(missed)
        fp += len(extra)
        rows.append({
            "method": method_name,
            "title": example["title"],
            "gold": len(gold_set),
            "predicted": len(pred_set),
            "true_positive": len(matched),
            "false_positive": len(extra),
            "false_negative": len(missed),
            "missed_entities": sorted(missed),
            "extra_entities_sample": sorted(extra)[:10],
        })
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    summary = {
        "method": method_name,
        "TP": tp, "FP": fp, "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }
    return summary, rows

regex_summary, regex_rows = evaluate_predictions(
    gold_examples, regex_extract, "Regex baseline"
)
gliner_summary, gliner_rows = evaluate_predictions(
    gold_examples, gliner_extract, "GLiNER"
)

print("Regex baseline:", json.dumps(regex_summary, indent=2))
print("GLiNER:", json.dumps(gliner_summary, indent=2))
"""))

cells.append(nbf.v4.new_markdown_cell("""## 6. Error analysis

Review false positives and false negatives before interpreting scores. A legitimate vendor domain may be correctly extracted as a domain but should not be treated as a malicious IOC. CVEs are vulnerability references, not malicious infrastructure.
"""))

cells.append(nbf.v4.new_code_cell("""for row in regex_rows + gliner_rows:
    print("\\nMETHOD:", row["method"], "| ADVISORY:", row["title"])
    print("TP:", row["true_positive"], "FP:", row["false_positive"], "FN:", row["false_negative"])
    print("Missed:", row["missed_entities"])
    print("Extra predictions (sample):", row["extra_entities_sample"])
"""))

cells.append(nbf.v4.new_markdown_cell("""## 7. Evaluation summary and limitations

Include the actual metric outputs in the capstone report. Do not pre-fill or invent results.

### Limitations
1. The gold set is small and manually labelled; inter-annotator agreement was not measured.
2. The current gold set is not exhaustive. Unlabelled entities can appear as apparent false positives.
3. Exact-span evaluation can penalize reasonable boundary variations.
4. GLiNER confidence scores are not calibrated probabilities of maliciousness.
5. This notebook evaluates entity extraction, not threat attribution, maliciousness validation, or direct coverage of all four BFSI consortium priorities.
6. The regex baseline here is a transparent comparable baseline; it is not a byte-for-byte execution of every rule in the production collector.
7. All outputs must retain source provenance and must not be promoted to confirmed malicious indicators without validation.

### Reproducibility
Record the model name, threshold, package versions, gold-set changes, and date of execution when reporting results.
"""))

nb["cells"] = cells
nb["metadata"] = {
    "kernelspec": {
        "display_name": "Python (.venv)",
        "language": "python",
        "name": "python3",
    },
    "language_info": {
        "name": "python",
        "version": "3.13",
    },
}

nbf.validate(nb)
if OUTPUT.exists():
    raise FileExistsError(
        f"{OUTPUT} already exists. No file was overwritten; inspect it before proceeding."
    )

nbf.write(nb, OUTPUT)
print("Created:", OUTPUT)
print("Cells:", len(nb.cells))
print("Notebook validated:", True)
