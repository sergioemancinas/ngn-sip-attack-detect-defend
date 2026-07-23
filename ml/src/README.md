# Comparison eval harness

The three-arm detector comparison lives here. [`eval/compare.py`](eval/compare.py)
scores Suricata signatures, Wazuh correlation, and the Stage-1 ML classifier on
identical labeled windows and reports the C3 result.

The detectors themselves are implemented elsewhere: [`../stage1/`](../stage1/README.md)
(ML), [`../stage2/`](../stage2/README.md) (LLM), and [`../rag/`](../rag/README.md)
(retrieval corpus). This directory only holds the code that compares them.
