"""Suppression engine v1: YAML rules (shareable) + local label capture (the moat seed).

Posture:
- suppressed findings are MARKED, never deleted — they appear in their own
  report section with the reason; an auditor sees the whole decision;
- every suppression also appends a TP/FP label to a local JSONL file —
  captured on the user's machine, never transmitted (open core never phones
  home; aggregation is an explicit, opt-in, future conversation).

Rule file format (YAML, share it across your team / publish it for your SoC):

    rules:
      - finding_id: CVE-2018-1000517
        component: busybox@1.19.4   # optional; omit to match any component
        reason: "wget applet not compiled into our busybox config"
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from firmgraph.models import Finding


@dataclass(frozen=True)
class SuppressionRule:
    finding_id: str
    reason: str
    component: str | None = None

    def matches(self, finding: Finding) -> bool:
        if finding.finding_id != self.finding_id:
            return False
        return self.component is None or self.component == (finding.component or "")


class SuppressionEngine:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self.labels_path = rules_path.with_name("labels.jsonl")

    # -- rules ---------------------------------------------------------------
    def load(self) -> list[SuppressionRule]:
        if not self.rules_path.is_file():
            return []
        doc = yaml.safe_load(self.rules_path.read_text(encoding="utf-8")) or {}
        rules: list[SuppressionRule] = []
        for raw in doc.get("rules", []) or []:
            finding_id = str(raw.get("finding_id", "")).strip()
            reason = str(raw.get("reason", "")).strip()
            if not finding_id or not reason:  # a suppression without a reason is a lie
                continue
            component = raw.get("component")
            rules.append(
                SuppressionRule(
                    finding_id=finding_id,
                    reason=reason,
                    component=str(component) if component else None,
                )
            )
        return rules

    def add_rule(self, finding_id: str, reason: str, component: str | None = None) -> None:
        rules = self.load()
        new = SuppressionRule(finding_id=finding_id, reason=reason, component=component)
        if any(r == new for r in rules):
            return
        rules.append(new)
        self.rules_path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "rules": [
                {
                    "finding_id": r.finding_id,
                    **({"component": r.component} if r.component else {}),
                    "reason": r.reason,
                }
                for r in rules
            ]
        }
        self.rules_path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        self._capture_label(finding_id, component, "false_positive", reason)

    # -- application ---------------------------------------------------------
    def apply(self, findings: list[Finding]) -> tuple[list[Finding], int]:
        rules = self.load()
        if not rules:
            return list(findings), 0
        updated: list[Finding] = []
        hits = 0
        for finding in findings:
            rule = next((r for r in rules if r.matches(finding)), None)
            if rule is None:
                updated.append(finding)
            else:
                hits += 1
                updated.append(
                    finding.model_copy(
                        update={"suppressed": True, "suppression_reason": rule.reason}
                    )
                )
        return updated, hits

    # -- the moat seed: local-only label capture ------------------------------
    def _capture_label(
        self, finding_id: str, component: str | None, label: str, reason: str
    ) -> None:
        self.labels_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "finding_id": finding_id,
            "component": component,
            "label": label,
            "reason": reason,
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        with self.labels_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


def default_suppressions_path() -> Path:
    return Path.home() / ".firmgraph" / "suppressions.yaml"
