import json
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer

ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = ROOT / "data/processed/cyra_vector_index/cyra_faiss.index"
METADATA_PATH = ROOT / "data/processed/cyra_vector_index/cyra_metadata.json"

index = faiss.read_index(str(INDEX_PATH))
documents = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2", device="cuda")

questions = [
    "How does the UAT-11985 campaign steal account credentials?",
    "Which vulnerabilities and CVE identifiers are mentioned in the Veeam advisory?",
]

for question in questions:
    query_vector = model.encode(
        [question],
        convert_to_numpy=True,
        normalize_embeddings=True,
    )
    scores, indices = index.search(query_vector.astype("float32"), 3)

    print(f"\nQUESTION: {question}")
    for rank, (score, idx) in enumerate(zip(scores[0], indices[0]), start=1):
        if idx < 0:
            continue
        doc = documents[int(idx)]
        print(f"\n  RESULT {rank} | similarity={score:.4f}")
        print(f"  Title: {doc.get('title', '')}")
        print(f"  Source: {doc.get('source_url', '')}")
        print(f"  Text: {doc.get('text', '')[:350]}")

