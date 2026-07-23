#!/usr/bin/env python3
"""Deterministic Docker Scout triage report generator."""

from __future__ import annotations

import csv
import json
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unspecified": 0}
NOT_FIXED = {"", "not fixed", "none", "null", "n/a", "na", "won't fix", "wont fix"}


@dataclass
class ImageFinding:
    image: str
    scout_ref: str
    json_report: str
    markdown_report: str
    status: str
    critical: int
    high: int
    fixable: int
    top_finding: str

    @property
    def total_ch(self) -> int:
        return self.critical + self.high

    @property
    def verdict(self) -> str:
        if self.status == "missing":
            return "missing"
        if self.status != "ok":
            return "scan-failed"
        if self.total_ch == 0:
            return "clean"
        if self.fixable > 0:
            return "bump-available"
        return "accepted-residual"

    @property
    def repo_and_tag(self) -> tuple[str, str]:
        image = self.image
        if image.startswith("MISSING:"):
            image = image.removeprefix("MISSING:")
        if "@" in image:
            repo, digest = image.split("@", 1)
            return repo, "@" + digest[:19]
        if ":" in image and image.rfind(":") > image.rfind("/"):
            repo, tag = image.rsplit(":", 1)
            return repo, tag
        return image, "-"


def int_or_zero(value: Any) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return 0


def text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def get_first(mapping: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        if key not in mapping:
            continue
        value = mapping[key]
        if isinstance(value, dict):
            nested = get_first(value, keys)
            if nested:
                return nested
        value_text = text(value)
        if value_text:
            return value_text
    return ""


def get_cve_id(mapping: dict[str, Any]) -> str:
    value = get_first(mapping, ["cve", "CVE", "cveID", "cve_id", "id", "ID"])
    if value.upper().startswith("CVE-"):
        return value.upper()
    vuln = mapping.get("vulnerability")
    if isinstance(vuln, dict):
        return get_cve_id(vuln)
    if text(vuln).upper().startswith("CVE-"):
        return text(vuln).upper()
    return value


def get_severity(mapping: dict[str, Any]) -> str:
    return get_first(mapping, ["severity", "Severity"]).lower()


def fixed_values(node: Any) -> list[str]:
    values: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            key_l = key.lower()
            if "fixed" in key_l or "fixversion" in key_l or "fix_version" in key_l or key_l == "fix":
                if isinstance(value, list):
                    values.extend(text(item) for item in value)
                else:
                    values.append(text(value))
            elif isinstance(value, (dict, list)):
                values.extend(fixed_values(value))
    elif isinstance(node, list):
        for item in node:
            values.extend(fixed_values(item))
    return values


def has_fix(mapping: dict[str, Any]) -> bool:
    return any(value.lower().strip() not in NOT_FIXED for value in fixed_values(mapping))


def parse_json_counts(path: Path) -> tuple[int, int, int, str]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    findings: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            cve_id = get_cve_id(node)
            severity = get_severity(node)
            if cve_id.upper().startswith("CVE-") and severity in SEVERITY_RANK:
                findings.append({"id": cve_id.upper(), "severity": severity, "fixable": has_fix(node)})
                return
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    critical = sum(1 for item in findings if item["severity"] == "critical")
    high = sum(1 for item in findings if item["severity"] == "high")
    fixable = sum(1 for item in findings if item["severity"] in {"critical", "high"} and item["fixable"])
    top = "-"
    if findings:
        ranked = sorted(
            findings,
            key=lambda item: (
                SEVERITY_RANK.get(str(item["severity"]), -1),
                1 if item["fixable"] else 0,
                str(item["id"]),
            ),
            reverse=True,
        )
        top = f'{ranked[0]["id"]} ({str(ranked[0]["severity"]).upper()})'
    return critical, high, fixable, top


def read_manifest(report_dir: Path) -> list[ImageFinding]:
    manifest = report_dir / "MANIFEST.tsv"
    findings: list[ImageFinding] = []

    if manifest.exists():
        with manifest.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            for row in reader:
                findings.append(
                    ImageFinding(
                        image=row.get("image", ""),
                        scout_ref=row.get("scout_ref", ""),
                        json_report=row.get("json_report", ""),
                        markdown_report=row.get("markdown_report", ""),
                        status=row.get("status", "unknown"),
                        critical=int_or_zero(row.get("critical")),
                        high=int_or_zero(row.get("high")),
                        fixable=int_or_zero(row.get("fixable_critical_high")),
                        top_finding=row.get("top_finding", "-") or "-",
                    )
                )
        return findings

    for json_path in sorted(report_dir.glob("cves_*.json")):
        try:
            critical, high, fixable, top = parse_json_counts(json_path)
            status = "ok"
        except (OSError, json.JSONDecodeError):
            critical, high, fixable, top = 0, 0, 0, "-"
            status = "json-failed"
        image = json_path.stem.removeprefix("cves_").replace("_", "/")
        findings.append(
            ImageFinding(
                image=image,
                scout_ref=image,
                json_report=json_path.name,
                markdown_report="-",
                status=status,
                critical=critical,
                high=high,
                fixable=fixable,
                top_finding=top,
            )
        )
    return findings


def pinned_in(repo: str) -> str:
    if repo in {
        "ngn-sip/pgvector",
        "ngn-sip/asterisk",
        "ngn-sip/kamailio",
        "ngn-sip/rtpengine",
        "ngn-sip/sipp",
    }:
        return "docker-compose.yml"
    if repo == "ngn-sip/attacker":
        return "VM local image"
    if repo.startswith("wazuh/"):
        return "docker-compose.wazuh.yml"
    return "VM image inventory"


def sort_key(item: ImageFinding) -> tuple[int, int, int, int, str]:
    if item.status != "ok":
        bucket = 4
    elif item.fixable > 0:
        bucket = 3
    elif item.total_ch > 0:
        bucket = 2
    else:
        bucket = 1
    return (bucket, item.critical, item.high, item.fixable, item.image)


def write_report(report_dir: Path, output_path: Path, report_date: str, findings: list[ImageFinding]) -> None:
    sorted_findings = sorted(findings, key=sort_key, reverse=True)
    total_critical = sum(item.critical for item in findings)
    total_high = sum(item.high for item in findings)
    total_fixable = sum(item.fixable for item in findings)
    ok_count = sum(1 for item in findings if item.status == "ok")
    non_ok = [item for item in sorted_findings if item.status != "ok"]
    bump_candidates = [item for item in sorted_findings if item.status == "ok" and item.fixable > 0]
    accepted = [item for item in sorted_findings if item.status == "ok" and item.total_ch > 0 and item.fixable == 0]

    lines: list[str] = []
    lines.append(f"# Docker Scout triage - {report_date}")
    lines.append("")
    lines.append(f"Source: `{report_dir}` ({ok_count} scanned images, {len(findings)} total rows).")
    lines.append("Severity filter: critical + high (`docker scout cves --only-severity critical,high`).")
    lines.append("Priority rule: scan gaps first, then fixable critical/high, then accepted residual critical/high.")
    lines.append("")
    lines.append("## Per-image verdict")
    lines.append("")
    lines.append("| Image | Tag | C | H | Fixable | Pinned in | Top finding | Verdict |")
    lines.append("|---|---|---:|---:|---:|---|---|---|")
    for item in sorted_findings:
        repo, tag = item.repo_and_tag
        top = item.top_finding if item.top_finding else "-"
        lines.append(
            f"| `{repo}` | `{tag}` | {item.critical} | {item.high} | {item.fixable} | "
            f"`{pinned_in(repo)}` | {top} | **{item.verdict}** |"
        )
    lines.append(
        f"| **TOTAL** |  | **{total_critical}** | **{total_high}** | **{total_fixable}** |  |  |  |"
    )

    lines.append("")
    lines.append("## Coverage gaps")
    lines.append("")
    if non_ok:
        for item in non_ok:
            lines.append(
                f"- `{item.image}` status is `{item.status}`. Re-run the VM scan after the image exists locally "
                "or after the Scout command error is fixed."
            )
    else:
        lines.append("- No scan gaps in the copied VM report set.")

    lines.append("")
    lines.append("## Bump candidates")
    lines.append("")
    if bump_candidates:
        lines.append("| Current | Target line | Notes |")
        lines.append("|---|---|---|")
        for item in bump_candidates:
            repo, tag = item.repo_and_tag
            target = "same major or vendor-supported patch line"
            if repo.startswith("wazuh/"):
                target = "same Wazuh stack version across manager, indexer, and dashboard"
            lines.append(
                f"| `{repo}:{tag}` | {target} | {item.fixable} fixable critical/high findings. "
                f"Top: {item.top_finding}. |"
            )
    else:
        lines.append("- No fixable critical/high findings were detected in the copied reports.")

    lines.append("")
    lines.append("## Accepted residuals")
    lines.append("")
    if accepted:
        lines.append("These findings have no fixed version in the copied Scout JSON. Keep them visible and re-check on each rebuild.")
        lines.append("")
        lines.append("| Image | C | H | Top finding | Control stance |")
        lines.append("|---|---:|---:|---|---|")
        for item in accepted:
            repo, tag = item.repo_and_tag
            lines.append(
                f"| `{repo}:{tag}` | {item.critical} | {item.high} | {item.top_finding} | "
                "accepted for lab use only with exposure controls and rebuild tracking |"
            )
    else:
        lines.append("- No accepted residual critical/high findings in the copied reports.")

    lines.append("")
    lines.append("## Mitigation-required")
    lines.append("")
    lines.append("- Keep dashboard and SIEM ports bound to loopback or private ingress only.")
    lines.append("- Keep project-built SIP images on the strict zero-fixable critical/high gate.")
    lines.append("- For Wazuh images, keep manager, indexer, and dashboard on the same supported version.")
    lines.append("- Rebuild project images after base-image package fixes land, then rerun the VM scan.")
    lines.append("- Rotate lab defaults before any VM exposure beyond the trusted lab network.")

    lines.append("")
    lines.append("## VM-readiness checklist")
    lines.append("")
    lines.append(f"- [{' ' if non_ok else 'x'}] Every expected `ngn-sip/*` and `wazuh/*` image has a VM Scout row")
    lines.append(f"- [{' ' if total_fixable else 'x'}] Zero fixable critical/high findings")
    lines.append("- [ ] All residual critical/high findings are documented as accepted residuals with controls")
    lines.append("- [ ] Any Wazuh bump keeps manager, indexer, and dashboard on one compatible release")
    lines.append("- [ ] Re-run `make scan-containers-fixable` for project images after rebuilds")

    lines.append("")
    lines.append("## Test plan after each bump")
    lines.append("")
    lines.append("- Project SIP stack: `make build && make smoke`")
    lines.append("- Wazuh stack: `make wazuh-up`, then replay the canonical Wazuh logtest fixture")
    lines.append("- Exposure check: `make check-local-exposure`")
    lines.append("- Scout gate: run `scripts/scout_scan.sh` on the VM and regenerate this report from the Mac")

    lines.append("")
    lines.append("## Generated inputs")
    lines.append("")
    lines.append(f"- Summary: `{report_dir / 'SUMMARY.txt'}`")
    lines.append(f"- Manifest: `{report_dir / 'MANIFEST.tsv'}`")
    lines.append("- Raw JSON: `cves_*.json`")
    lines.append("- Critical/high markdown: `critical_high_*.md`")
    lines.append("")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: scout_triage_summarizer.py <report-dir> <output-md> [yyyy-mm-dd]", file=sys.stderr)
        return 2

    report_dir = Path(sys.argv[1]).expanduser().resolve()
    output_path = Path(sys.argv[2]).expanduser().resolve()
    report_date = sys.argv[3] if len(sys.argv) == 4 else report_dir.name
    if not report_date:
        report_date = date.today().isoformat()

    findings = read_manifest(report_dir)
    if not findings:
        print(f"No Scout report rows found in {report_dir}", file=sys.stderr)
        return 1

    write_report(report_dir, output_path, report_date, findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
