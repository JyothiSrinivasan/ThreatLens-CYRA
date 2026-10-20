# ThreatLens — NLP Evaluation Report

## 1. Objective

This evaluation compares rule-based regular-expression (regex) extraction with GLiNER, a zero-shot NLP entity-extraction model, for identifying cybersecurity entities in CERT-In advisories. The goal is to assess how both methods can support ThreatLens OSINT processing.

## 2. Dataset and Methodology

The evaluation uses five manually labelled CERT-In advisories. The notebook reports 131 gold entity annotations. It compares a regex baseline with `urchade/gliner_small-v2.1`, using exact-span evaluation and precision, recall, and F1-score.

The hybrid extraction stage combines predictions from both methods, records their provenance, and deduplicates entity values.

## 3. Evaluation Results

| Metric | Regex baseline | GLiNER |
|---|---:|---:|
| True positives | 123 | 30 |
| False positives | 6 | 29 |
| False negatives | 6 | 99 |
| Precision | 95.35% | 50.85% |
| Recall | 95.35% | 23.26% |
| F1-score | 95.35% | 31.91% |

On this pilot dataset, regex outperformed GLiNER across all three evaluation metrics. GLiNER may complement regex by identifying contextual entities that do not follow fixed patterns.

**Annotation-count clarification:** The notebook constructs 131 raw gold labels. The evaluation normalizes entity text and labels and compares sets within each advisory, resulting in 129 unique normalized gold annotations. The PAN-OS advisory contributes 12 raw labels but 10 unique normalized labels. Both methods therefore have TP + FN = 129. This explains the count difference; the saved metrics have not been independently recomputed in this check.

## 4. Hybrid Extraction in ThreatLens

The hybrid approach combines predictable pattern-based extraction with model-based entity recognition. It records the extraction method for each prediction and deduplicates repeated entity values.

The resulting entities can feed into the broader ThreatLens pipeline for source-preserving enrichment, threat-intelligence correlation, and analyst review. Extracted entities are candidates, not automatically confirmed indicators of compromise (IoCs).

## 5. Limitations

- The evaluation covers only five advisories and is not representative of all cybersecurity reports.
- Results depend on the manually labelled reference set, entity labels, and normalization. Evaluation compares normalized entity values and labels, not exact character offsets. The reference set is not exhaustive, so some extracted entities may be counted as false positives because they are missing from the gold set.- GLiNER confidence scores are not calibrated probabilities of correctness.
- Entity extraction does not establish maliciousness, attribution, or campaign involvement.
- The regex evaluation baseline is not necessarily identical to the production collection pipeline.
- Further testing on a larger, diverse, independently labelled dataset is required.

## 6. Conclusion

The pilot evaluation supports retaining regex as the primary extractor for predictable indicators while evaluating GLiNER as a complementary NLP component. The hybrid approach provides extraction provenance and deduplication, but its overall accuracy must be measured independently before making claims about production performance.

**Scope:** This report documents NLP entity extraction. It does not claim that this notebook implements a generative LLM, retrieval-augmented generation (RAG), or an AI agent.
