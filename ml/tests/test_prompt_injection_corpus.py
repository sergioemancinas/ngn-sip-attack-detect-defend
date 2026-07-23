"""Measure the prompt-injection guardrail against a red-team corpus (OWASP LLM01:2025).

The syntactic detector is one layer; this quantifies what it does and does not catch so
the limitation is reported, not hidden. Hard requirements:
  - zero false positives on benign SIP control text (a detector that fires on normal
    alerts would route everything to manual review and destroy the FP-reduction goal);
  - full detection of direct English instruction-injection (the forms it is built for).
Paraphrase, multilingual, and encoded bypasses are expected; the overall bypass rate is
printed for the report writeup.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ml" / "stage2"))

from worker import detect_prompt_injection  # noqa: E402

CORPUS = json.loads((ROOT / "ml" / "stage2" / "adversarial_prompts.json").read_text())["cases"]


def _rates() -> dict[str, float]:
    injections = [c for c in CORPUS if c["is_injection"]]
    benign = [c for c in CORPUS if not c["is_injection"]]
    detected = [c for c in injections if detect_prompt_injection(c["text"])]
    false_positives = [c for c in benign if detect_prompt_injection(c["text"])]
    return {
        "detection_rate": len(detected) / len(injections),
        "bypass_rate": 1 - len(detected) / len(injections),
        "false_positive_rate": len(false_positives) / len(benign),
    }


def test_no_false_positives_on_benign_sip_text() -> None:
    benign = [c for c in CORPUS if not c["is_injection"]]
    fired = [c["text"] for c in benign if detect_prompt_injection(c["text"])]
    assert fired == [], f"detector fired on benign control text: {fired}"


def test_direct_english_injections_are_all_detected() -> None:
    direct = [c for c in CORPUS if c["technique"] == "direct_en"]
    missed = [c["text"] for c in direct if not detect_prompt_injection(c["text"])]
    assert missed == [], f"missed direct-English injections: {missed}"


def test_report_bypass_rate() -> None:
    rates = _rates()
    # Reported for the writeup, not a brittle gate: the detector is known to miss
    # paraphrase/multilingual/encoded payloads, which is why the triage gate is paired
    # with output-schema validation and untrusted-content segregation.
    print(
        f"\nprompt_injection_corpus detection_rate={rates['detection_rate']:.2f} "
        f"bypass_rate={rates['bypass_rate']:.2f} "
        f"false_positive_rate={rates['false_positive_rate']:.2f}"
    )
    assert rates["false_positive_rate"] == 0.0
