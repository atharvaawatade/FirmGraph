"""Report rendering (Builder): stable section ordering => deterministic reports."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from firmgraph.cra.mapping import MAPPING_DISCLAIMER, aggregate_mapping
from firmgraph.models import Finding, ScanManifest
from firmgraph.pipeline.context import ScanContext
from firmgraph.triage.explainer import ADVISORY_LABEL
from firmgraph.vex import vex_status

LIABILITY_LINE = (
    "FirmGraph drafts, maps, and evidences — the manufacturer signs. This report is "
    "evidence, not a compliance determination. CRA mappings (when present) are "
    "best-effort and not legal advice."
)

_TEMPLATES = Path(__file__).parent / "templates"


@dataclass(frozen=True)
class NotAffectedEntry:
    id: str
    component: str
    reason: str


@dataclass(frozen=True)
class VexSummary:
    total: int
    affected: int
    not_affected_count: int
    under_investigation: int
    not_affected: tuple[NotAffectedEntry, ...]


def _vex_summary(findings: list[Finding]) -> VexSummary:
    """VEX exploitability roll-up for the report — the 'which matter, why the rest
    don't' story surfaced in the HTML, not just the evidence-pack JSON."""
    cves = [f for f in findings if f.kind == "cve"]
    counts = {"affected": 0, "not_affected": 0, "under_investigation": 0}
    entries: list[NotAffectedEntry] = []
    for f in cves:
        status, statement = vex_status(f)
        counts[status] = counts.get(status, 0) + 1
        if status == "not_affected":
            entries.append(
                NotAffectedEntry(id=f.finding_id, component=f.component or "—", reason=statement)
            )
    entries.sort(key=lambda e: e.id)
    return VexSummary(
        total=len(cves),
        affected=counts["affected"],
        not_affected_count=counts["not_affected"],
        under_investigation=counts["under_investigation"],
        not_affected=tuple(entries),
    )


FINDINGS_TABLE_CAP = 100  # long tail lives in evidence-pack/findings.json
FLOOD_THRESHOLD = 50  # a component with more findings gets a noise caveat


@dataclass(frozen=True)
class Summary:
    components: int
    findings: int
    critical: int
    high: int
    medium: int
    low: int
    act_now: int  # P1-P3
    backlog: int  # P4-P5
    kev: int
    no_fix: int


@dataclass(frozen=True)
class ComponentGroup:
    component: str
    total: int
    critical: int
    high: int
    kev: int
    no_fix: int
    top_priority: int
    flood: bool


def _summary(active: list[Finding], component_count: int) -> Summary:
    def sev(s: str) -> int:
        return sum(1 for f in active if f.severity == s)

    return Summary(
        components=component_count,
        findings=len(active),
        critical=sev("critical"),
        high=sev("high"),
        medium=sev("medium"),
        low=sev("low"),
        act_now=sum(1 for f in active if f.priority <= 3),
        backlog=sum(1 for f in active if f.priority >= 4),
        kev=sum(1 for f in active if f.kev),
        no_fix=sum(1 for f in active if f.fix is None),
    )


def _group_by_component(active: list[Finding]) -> list[ComponentGroup]:
    """Collapse thousands of findings into per-component rows — the kernel flood
    becomes one honest line instead of 3000, sorted by what matters most."""
    buckets: dict[str, list[Finding]] = {}
    for f in active:
        buckets.setdefault(f.component or "unknown", []).append(f)
    groups = [
        ComponentGroup(
            component=comp,
            total=len(fs),
            critical=sum(1 for f in fs if f.severity == "critical"),
            high=sum(1 for f in fs if f.severity == "high"),
            kev=sum(1 for f in fs if f.kev),
            no_fix=sum(1 for f in fs if f.fix is None),
            top_priority=min(f.priority for f in fs),
            flood=len(fs) > FLOOD_THRESHOLD,
        )
        for comp, fs in buckets.items()
    ]
    # most-actionable first: best priority, then KEV, then volume, then name
    groups.sort(key=lambda g: (g.top_priority, -g.kev, -g.total, g.component))
    return groups


def render_html(ctx: ScanContext, manifest: ScanManifest) -> str:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")
    active = [f for f in ctx.findings if not f.suppressed and f.source != "cve-bin-tool"]
    binscan = [f for f in ctx.findings if not f.suppressed and f.source == "cve-bin-tool"]
    return template.render(
        manifest=manifest,
        extraction=ctx.extraction,
        components=ctx.components,
        summary=_summary(active, len(ctx.components)),
        groups=_group_by_component(active),
        findings=active[:FINDINGS_TABLE_CAP],
        findings_total=len(active),
        findings_cap=FINDINGS_TABLE_CAP,
        binscan_findings=binscan,
        top_findings=[f for f in active if f.priority <= 3][:25],
        suppressed=[f for f in ctx.findings if f.suppressed],
        vex=_vex_summary(ctx.findings),
        cra_rows=aggregate_mapping(ctx.findings),
        cra_disclaimer=MAPPING_DISCLAIMER,
        explanations=ctx.explanations,
        advisory_label=ADVISORY_LABEL,
        liability=LIABILITY_LINE,
        stub_stages=[s.name for s in manifest.stages if s.status == "stub"],
        failed_stages=[s.name for s in manifest.stages if s.status == "failed"],
    )


def render_markdown(ctx: ScanContext, manifest: ScanManifest) -> str:
    lines: list[str] = [
        f"# FirmGraph Scan Report — `{manifest.scan_id}`",
        "",
        f"- **Image:** `{manifest.image_path}`",
        f"- **SHA-256:** `{manifest.image_sha256}`",
        f"- **Size:** {manifest.image_size} bytes · **Format:** {manifest.image_format}",
        f"- **FirmGraph:** {manifest.firmgraph_version} · **Created:** {manifest.created_at}",
        "",
    ]
    if ctx.extraction:
        lines += [
            "## Extraction (honesty first)",
            f"- Method: {ctx.extraction.method} · **Confidence: {ctx.extraction.confidence:.0%}** "
            f"· Files: {ctx.extraction.files_extracted}",
            "",
        ]
        if ctx.extraction.confidence < 0.5:
            lines += [
                "> ⚠️ **Low extraction confidence — findings below are NOT a security "
                "verdict.** A clean result on unextracted firmware is a false negative, "
                "not a safe device.",
                "",
            ]
    active = [f for f in ctx.findings if not f.suppressed and f.source != "cve-bin-tool"]
    binscan = [f for f in ctx.findings if not f.suppressed and f.source == "cve-bin-tool"]
    suppressed = [f for f in ctx.findings if f.suppressed]

    # -- executive summary: the firehose distilled to what a human reads first --
    s = _summary(active, len(ctx.components))
    lines += [
        "## Summary",
        "",
        f"- **Components:** {s.components}",
        f"- **Findings:** {s.findings}  (Critical {s.critical} · High {s.high} · "
        f"Medium {s.medium} · Low {s.low})",
        f"- **Act now (P1–P3):** {s.act_now}   ·   **Backlog (P4–P5):** {s.backlog}",
        f"- **Known-exploited (KEV):** {s.kev}   ·   **No fix available (EOL):** {s.no_fix}",
        "",
    ]

    top = [f for f in active if f.priority <= 3][:25]
    if top:
        lines += [f"## Top priorities — act on these first ({len(top)})", ""]
        for i, f in enumerate(top, 1):
            lines.append(
                f"{i}. `{f.finding_id}` **P{f.priority}** [{f.severity}] "
                f"{f.component or ''} — {f.priority_reason}"
            )
            explanation = ctx.explanations.get(f.finding_id)
            if explanation:
                quoted = explanation.replace("\n", "\n   > ")
                lines.append(f"   > _{ADVISORY_LABEL}:_ {quoted}")
        lines.append("")

    # -- findings grouped by component: the kernel flood becomes one honest row --
    groups = _group_by_component(active)
    if groups:
        lines += ["## Findings by component", ""]
        for g in groups:
            flag = " ⚠ version-match flood — see Honest Limits" if g.flood else ""
            kev = f" · {g.kev} KEV" if g.kev else ""
            lines.append(
                f"- **{g.component}** — {g.total} findings "
                f"(C:{g.critical} H:{g.high}{kev}, no-fix:{g.no_fix}){flag}"
            )
        lines.append("")

    shown = active[:FINDINGS_TABLE_CAP]
    lines += [f"## All findings (showing {len(shown)} of {len(active)}, by priority)", ""]
    for f in shown:
        fix = f.fix or "**no fix available (EOL evidence)**"
        reach = " · reachable" if f.reachable is True else ""
        lines.append(
            f"- `{f.finding_id}` [P{f.priority}] [{f.severity}]{reach} "
            f"{f.component or ''} — fix: {fix}"
        )
    if len(active) > FINDINGS_TABLE_CAP:
        lines.append(
            f"\n> …and {len(active) - FINDINGS_TABLE_CAP} more — the complete, "
            "unabridged list is in `evidence-pack/findings.json` (the audit record)."
        )
    if binscan:
        lines += [
            "",
            f"## Binary-signature findings — cve-bin-tool ({len(binscan)})",
            "",
            "> A second, independent engine that fingerprints components inside stripped "
            "binaries Syft can't name. Shown **separately and never merged** with the SBOM "
            "path — two engines, no false reconciliation.",
            "",
        ]
        for f in binscan:
            fix = f.fix or "**no fix available (EOL evidence)**"
            lines.append(
                f"- `{f.finding_id}` [P{f.priority}] [{f.severity}] {f.component or ''} — fix: {fix}"
            )
    vex = _vex_summary(ctx.findings)
    if vex.total:
        lines += [
            "",
            "## Exploitability statement (VEX) — drafted, you sign",
            "",
            f"Of {vex.total} CVEs: **{vex.affected} affected** · "
            f"**{vex.not_affected_count} not affected** · "
            f"**{vex.under_investigation} under investigation**. "
            "Full OpenVEX + CycloneDX-VEX in `evidence-pack/`.",
            "",
        ]
        for na in vex.not_affected:
            lines.append(f"- `{na.id}` {na.component} → **not_affected**: {na.reason}")
    cra_rows = aggregate_mapping(ctx.findings)
    if cra_rows:
        lines += ["", "## CRA Annex I mapping (best-effort — not legal advice)", ""]
        lines.append(f"> {MAPPING_DISCLAIMER}")
        lines.append("")
        for row in cra_rows:
            sample = ", ".join(row.finding_ids[:3])
            more = f" (+{row.count - 3} more)" if row.count > 3 else ""
            lines.append(
                f"- **{row.ref.req_id}** {row.ref.title} — {row.count} finding(s): "
                f"{sample}{more}"
            )
    if suppressed:
        lines += ["", f"## Suppressed findings ({len(suppressed)}) — marked, never deleted", ""]
        for f in suppressed:
            lines.append(
                f"- `{f.finding_id}` {f.component or ''} — suppressed: {f.suppression_reason}"
            )
    lines += ["", f"## Components ({len(ctx.components)})", ""]
    for c in ctx.components:
        lines.append(
            f"- {c.name}@{c.version or '?'} ({c.type}, {c.provenance}, conf {c.confidence:.2f})"
        )
    stubs = [s.name for s in manifest.stages if s.status == "stub"]
    if stubs:
        lines += ["", f"> Walking-skeleton build: stub stages emitting placeholders: {', '.join(stubs)}."]
    lines += ["", "---", f"*{LIABILITY_LINE}*", ""]
    return "\n".join(lines)
