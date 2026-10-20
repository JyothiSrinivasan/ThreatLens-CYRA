import json
from pathlib import Path

import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT / "data/processed/cyra_knowledge_base.json"
OUT_DIR = ROOT / "data/processed/cyra_vector_index"

INDEX_PATH = OUT_DIR / "cyra_faiss.index"
METADATA_PATH = OUT_DIR / "cyra_metadata.json"

if INDEX_PATH.exists() or METADATA_PATH.exists():
    raise SystemExit(
        "Index output already exists. Refusing to overwrite existing files."
    )

documents = json.loads(INPUT.read_text(encoding="utf-8"))
if not documents:
    raise SystemExit("Knowledge base is empty.")

model_name = "sentence-transformers/all-MiniLM-L6-v2"
print(f"Loading embedding model: {model_name}")

model = SentenceTransformer(model_name, device="cuda")
texts = [doc["text"] for doc in documents]

print(f"Generating embeddings for {len(texts)} chunks...")
embeddings = model.encode(
    texts,
    batch_size=16,
    show_progress_bar=True,
    convert_to_numpy=True,
    normalize_embeddings=True,
)

embeddings = np.asarray(embeddings, dtype="float32")
index = faiss.IndexFlatIP(embeddings.shape[1])
index.add(embeddings)

OUT_DIR.mkdir(parents=True, exist_ok=True)
faiss.write_index(index, str(INDEX_PATH))
METADATA_PATH.write_text(
    json.dumps(documents, indent=2, ensure_ascii=False),
    encoding="utf-8",
)

print(f"Indexed vectors: {index.ntotal}")
print(f"Embedding dimensions: {embeddings.shape[1]}")
print(f"FAISS index: {INDEX_PATH.relative_to(ROOT)}")
print(f"Metadata: {METADATA_PATH.relative_to(ROOT)}")
