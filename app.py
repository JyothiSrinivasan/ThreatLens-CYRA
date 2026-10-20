from __future__ import annotations

import json
import sys
from pathlib import Path
from datetime import datetime

import streamlit as st

ROOT = Path(__file__).resolve().parent
ANALYSIS_DIR = ROOT / "analysis"
DATA_DIR = ROOT / "data" / "processed"
REPORTS_DIR = ROOT / "reports"

# Import the existing ASK CYRA pipeline; do not duplicate its retrieval or LLM logic.
sys.path.insert(0, str(ANALYSIS_DIR))
try:
    import ask_cyra_rag as cyra
    CYRA_IMPORT_ERROR = None
except Exception as exc:
    cyra = None
    CYRA_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


st.set_page_config(
    page_title="CYRA | ThreatLens Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background: #f5f7fb; }
    [data-testid="stSidebar"] { background: #10243a; }
    [data-testid="stSidebar"] * { color: #f4f7fb !important; }
    .hero {
        background: linear-gradient(115deg, #10243a 0%, #174a63 100%);
        padding: 1.6rem 1.8rem; border-radius: 16px; color: white;
        margin-bottom: 1rem;
    }
    .hero h1 { color: white; margin: 0; font-size: 2.1rem; }
    .hero p { color: #d8e8f0; margin: .45rem 0 0 0; }
    .small-note { color: #617184; font-size: .88rem; }
    .source-card {
        background: white; padding: 1rem; border: 1px solid #e1e8ef;
        border-radius: 10px; margin: .45rem 0;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def read_json(path: Path):
    try:
        with path.open("r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def count_records(value):
    """Conservative count for common JSON collection shapes."""
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("indicators", "objects", "attributes", "results", "items", "advisories", "pulses", "data"):
            candidate = value.get(key)
            if isinstance(candidate, list):
                return len(candidate)
        return len(value)
    return None


def json_summary(filename):
    path = DATA_DIR / filename
    if not path.exists():
        return None
    data = read_json(path)
    if data is None:
        return {"path": path, "count": None}
    return {"path": path, "count": count_records(data)}


def file_status(path: Path):
    return "Available" if path.exists() else "Not found"


def safe_read_text(path: Path, limit=12000):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""


st.sidebar.markdown("## 🛡️ CYRA")
st.sidebar.caption("ThreatLens intelligence workspace")
page = st.sidebar.radio(
    "Navigate",
    ["Overview", "ASK CYRA", "Campaign analysis", "Data & evidence", "Project reports"],
)
st.sidebar.divider()
st.sidebar.caption("Local prototype · Public OSINT and project evidence")
st.sidebar.caption("LLM answers are evidence-grounded but require human verification.")

st.markdown(
    """
    <div class="hero">
      <h1>CYRA</h1>
      <p>AI-Driven Threat Detection and Risk Analytics</p>
      <p>ThreatLens · GenAI-powered OSINT Threat Intelligence for BFSI</p>
    </div>
    """,
    unsafe_allow_html=True,
)

if page == "Overview":
    st.subheader("Project overview")
    st.write(
        "CYRA is the interactive presentation layer for the existing ThreatLens capstone. "
        "It brings together collected public threat intelligence, campaign analysis, "
        "validation artifacts, and the local ASK CYRA retrieval-augmented generation (RAG) assistant."
    )

    col1, col2, col3, col4 = st.columns(4)
    artifacts = [
        ("Knowledge base", DATA_DIR / "cyra_knowledge_base.json"),
        ("Vector index", DATA_DIR / "cyra_vector_index" / "cyra_faiss.index"),
        ("ASK CYRA engine", ANALYSIS_DIR / "ask_cyra_rag.py"),
        ("MISP evidence", REPORTS_DIR / "MISP_Verification_Evidence.md"),
    ]
    for col, (label, path) in zip((col1, col2, col3, col4), artifacts):
        with col:
            col.metric(label, "Ready" if path.exists() else "Check")

    st.markdown("### Main capabilities")
    a, b, c = st.columns(3)
    with a:
        st.markdown("**Threat collection**")
        st.write("Public OSINT sources, normalized indicator candidates, and source traceability.")
    with b:
        st.markdown("**Threat analysis**")
        st.write("UAT-11985 campaign case study, MITRE ATT&CK references, and STIX 2.1 artifacts.")
    with c:
        st.markdown("**ASK CYRA**")
        st.write("Local retrieval from the project knowledge base with source titles, URLs, and excerpts.")

    st.info(
        "Interpretation note: an indicator appearing in collected data does not by itself establish "
        "that it is malicious or that a campaign targeted an Indian financial institution."
    )

elif page == "ASK CYRA":
    st.subheader("Ask CYRA")
    st.write("Ask a question about the evidence currently indexed in the ThreatLens knowledge base.")
    st.caption("Example: Explain the UAT-11985 phishing campaign and its relevance to a security analyst.")

    if CYRA_IMPORT_ERROR:
        st.error("ASK CYRA could not be imported from analysis/ask_cyra_rag.py.")
        st.code(CYRA_IMPORT_ERROR)
        st.info("Check the project virtual environment and the existing ASK CYRA script before proceeding.")
    else:
        if "cyra_chat" not in st.session_state:
            st.session_state.cyra_chat = []
        if st.button("Clear conversation"):
            st.session_state.cyra_chat = []
            st.rerun()

        for item in st.session_state.cyra_chat:
            with st.chat_message(item["role"]):
                st.markdown(item["content"])
                if item.get("sources"):
                    with st.expander("Retrieved evidence"):
                        for i, source in enumerate(item["sources"], start=1):
                            st.markdown(f"**[Source {i}] {source.get('title', 'Untitled source')}**")
                            if source.get("source_url"):
                                st.markdown(f"[Open source]({source['source_url']})")
                            st.caption(f"Retrieval similarity: {source.get('score', 0):.4f} · not a factual-confidence score")
                            st.write(source.get("text", ""))

        question = st.chat_input("Ask about a campaign, indicator, vulnerability, or advisory…")
        if question:
            st.session_state.cyra_chat.append({"role": "user", "content": question})
            with st.chat_message("user"):
                st.markdown(question)

            with st.chat_message("assistant"):
                try:
                    with st.spinner("Retrieving evidence and asking the local model…"):
                        passages = cyra.retrieve(question)
                        if not passages or not any(p.get("text", "").strip() for p in passages):
                            answer = "I couldn't retrieve usable evidence for that question. Try naming a specific campaign, advisory, CVE, or threat technique."
                        else:
                            answer = cyra.generate_answer(question, passages)
                    st.markdown(answer)
                    st.caption("Verify cited source material. Similarity scores indicate retrieval ranking, not factual confidence.")
                    with st.expander("Retrieved evidence"):
                        for i, source in enumerate(passages, start=1):
                            st.markdown(f"**[Source {i}] {source.get('title', 'Untitled source')}**")
                            if source.get("source_url"):
                                st.markdown(f"[Open source]({source['source_url']})")
                            st.caption(f"Retrieval similarity: {source.get('score', 0):.4f}")
                            st.write(source.get("text", ""))
                    st.session_state.cyra_chat.append(
                        {"role": "assistant", "content": answer, "sources": passages}
                    )
                except Exception as exc:
                    message = (
                        f"ASK CYRA encountered {type(exc).__name__}: {exc}\n\n"
                        "Check that Ollama is running and the configured local model is available."
                    )
                    st.error(message)
                    st.session_state.cyra_chat.append({"role": "assistant", "content": message})

elif page == "Campaign analysis":
    st.subheader("UAT-11985 campaign case study")
    campaign_path = ANALYSIS_DIR / "UAT-11985_Diamond_Model.md"
    if campaign_path.exists():
        content = safe_read_text(campaign_path)
        st.markdown(content if content else "Campaign analysis file is empty.")
    else:
        st.warning(f"Campaign analysis file not found: {campaign_path}")

    st.markdown("### Related artifacts")
    for name, path in [
        ("STIX integration addendum", ANALYSIS_DIR / "UAT11985_STIX_Integration_Addendum.md"),
        ("STIX bundle", ROOT / "stix" / "uat11985_enhanced_bundle.json"),
        ("Original STIX bundle", ROOT / "stix" / "uat11985_bundle.json"),
    ]:
        st.write(f"**{name}:** {file_status(path)}")
        if path.exists() and path.suffix == ".json":
            st.caption(f"`{path.relative_to(ROOT)}`")

    st.warning(
        "The case study is a supporting phishing analysis. Do not present it as proof of direct "
        "targeting of an Indian bank unless independent evidence establishes that connection."
    )

elif page == "Data & evidence":
    st.subheader("Project data inventory")
    st.write("Counts below are read from local project files when available. They are file/record counts, not verified-malicious counts.")

    inventory = [
        ("Cleaned CERT-In advisories", "certin_advisories_cleaned.json"),
        ("Unified IOC candidates", "unified_candidate_iocs.json"),
        ("Candidate IOCs", "candidate_iocs.json"),
        ("VirusTotal + URLScan consolidated enrichment", "misp_enrichment_150_with_vt_urlscan_consolidated.json"),
        ("CYRA knowledge base", "cyra_knowledge_base.json"),
        ("Collection quality audit", "collection_quality_audit.json"),
    ]
    rows = []
    for label, filename in inventory:
        summary = json_summary(filename)
        rows.append({
            "Artifact": label,
            "Status": "Available" if summary else "Not found",
            "Record / top-level count": summary["count"] if summary and summary["count"] is not None else "—",
            "File": f"data/processed/{filename}",
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)

    st.markdown("### Validation reports")
    report_names = [
        "collection_report.md",
        "MISP_Verification_Evidence.md",
        "ThreatLens_NLP_Evaluation.md",
        "Sigma_Splunk_Test_Evidence.md",
        "STIX_Enhanced_Bundle_Validation.md",
        "Wazuh_Live_Ingestion_Test.md",
        "ThreatLens_VirusTotal_Enrichment_Analysis.md",
    ]
    for filename in report_names:
        path = REPORTS_DIR / filename
        with st.expander(f"{filename} — {file_status(path)}"):
            if path.exists():
                st.markdown(safe_read_text(path, limit=8000))
            else:
                st.caption(f"Expected location: {path.relative_to(ROOT)}")

elif page == "Project reports":
    st.subheader("Reports and deliverables")
    st.write("This page displays reports found in the local `reports` folder.")
    if REPORTS_DIR.exists():
        report_files = sorted(
            [p for p in REPORTS_DIR.iterdir() if p.is_file()],
            key=lambda p: p.name.lower(),
        )
        if not report_files:
            st.info("No report files found.")
        for path in report_files:
            with st.expander(path.name):
                st.caption(f"Size: {path.stat().st_size:,} bytes")
                if path.suffix.lower() in {".md", ".txt", ".log"}:
                    st.markdown(safe_read_text(path, limit=10000))
                elif path.suffix.lower() == ".pdf":
                    st.write("PDF report available in the reports folder.")
                    st.code(str(path))
                else:
                    st.write("Artifact available in the reports folder.")
                    st.code(str(path))
    else:
        st.warning(f"Reports folder not found: {REPORTS_DIR}")

st.divider()
st.markdown(
    f"<p class='small-note'>CYRA local prototype · Updated {datetime.now().strftime('%Y-%m-%d %H:%M')} · "
    "Evidence should be independently reviewed before operational use.</p>",
    unsafe_allow_html=True,
)
