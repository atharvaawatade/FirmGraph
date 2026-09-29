"""FirmGraph CLI (Typer): scan · diff · history · version."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

import firmgraph
from firmgraph.graph.repository import GraphRepository
from firmgraph.scanner import Scanner, default_db_path

app = typer.Typer(
    name="firmgraph",
    help="The open evidence layer for firmware. We draft; the manufacturer signs.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    image: Annotated[Path, typer.Argument(help="Path to the firmware image")],
    out: Annotated[Path, typer.Option("--out", "-o", help="Output directory")] = Path(
        "firmgraph_out"
    ),
    db: Annotated[Optional[Path], typer.Option("--db", help="Graph database path")] = None,
    suppressions: Annotated[
        Optional[Path], typer.Option("--suppressions", help="Suppression rules file (YAML)")
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="No progress output")] = False,
) -> None:
    """Scan a firmware image -> graph + reports + exports."""
    if not image.is_file():
        console.print(f"[red]error:[/red] image not found: {image}")
        raise typer.Exit(code=2)
    scanner = Scanner(db_path=db, suppressions_path=suppressions)
    result = scanner.scan(image=image, out_dir=out, quiet=quiet)
    m = result.manifest
    table = Table(title=f"FirmGraph scan {m.scan_id}", show_header=False)
    table.add_row("image", str(m.image_path))
    table.add_row("sha256", m.image_sha256)
    table.add_row("size / format", f"{m.image_size} bytes / {m.image_format}")
    table.add_row("graph nodes", str(result.node_count))
    for p in result.report_paths:
        table.add_row("report", str(p))
    console.print(table)
    stub_stages = [s.name for s in m.stages if s.status == "stub"]
    if stub_stages:
        console.print(
            f"[yellow]walking-skeleton build — stub stages: {', '.join(stub_stages)}[/yellow]"
        )


@app.command()
def diff(
    scan_a: Annotated[str, typer.Argument(help="Older scan id")],
    scan_b: Annotated[str, typer.Argument(help="Newer scan id")],
    db: Annotated[Optional[Path], typer.Option("--db", help="Graph database path")] = None,
) -> None:
    """The release-over-release story: what changed between two scans."""
    from firmgraph.graph import semantic_diff

    repo = GraphRepository(db or default_db_path())
    try:
        for scan_id in (scan_a, scan_b):
            if not repo.exists(scan_id):
                console.print(f"[red]error:[/red] no such scan: {scan_id}")
                console.print("run [bold]firmgraph history[/bold] to list scan ids")
                raise typer.Exit(code=2)
        result = semantic_diff(repo, scan_a, scan_b)
    finally:
        repo.close()

    if result.empty:
        console.print("[green]no differences — identical firmware graphs[/green]")
        return

    for caveat in result.caveats:  # honesty first, before any counts
        console.print(f"[yellow]⚠ {caveat}[/yellow]\n")

    summary = Table(title=f"diff  {scan_a[:16]}…  →  {scan_b[:16]}…", show_header=False)
    summary.add_row("components +/−/changed",
                    f"+{len(result.components_added)} "
                    f"−{len(result.components_removed)} "
                    f"~{len(result.components_changed)}")
    summary.add_row("[green]CVEs resolved[/green]", str(len(result.cves_resolved)))
    intro_style = "red" if result.cves_introduced else "green"
    summary.add_row(f"[{intro_style}]CVEs introduced[/{intro_style}]", str(len(result.cves_introduced)))
    if result.new_critical_high:
        summary.add_row("[red]new critical/high[/red]", str(len(result.new_critical_high)))
    console.print(summary)

    if result.components_changed:
        table = Table(title="component version changes")
        table.add_column("component")
        table.add_column("from")
        table.add_column("to")
        for c in result.components_changed:
            table.add_row(c.name, c.old_version or "—", c.new_version or "—")
        console.print(table)

    if result.new_critical_high:
        console.print("[red]new critical/high CVEs:[/red] " + ", ".join(result.new_critical_high))


@app.command()
def history(
    db: Annotated[Optional[Path], typer.Option("--db", help="Graph database path")] = None,
) -> None:
    """List recorded scans (the product remembers so you don't)."""
    repo = GraphRepository(db or default_db_path())
    try:
        rows = repo.scans()
    finally:
        repo.close()
    if not rows:
        console.print("no scans recorded yet — run: firmgraph scan <image>")
        return
    table = Table(title="scan history")
    table.add_column("scan id")
    table.add_column("image sha256")
    table.add_column("created")
    for scan_id, sha, created in rows:
        table.add_row(scan_id, sha[:16] + "…", created)
    console.print(table)


@app.command()
def suppress(
    finding_id: Annotated[str, typer.Argument(help="Finding id to suppress, e.g. CVE-2016-2148")],
    reason: Annotated[str, typer.Option("--reason", "-r", help="Why this is a false positive")],
    component: Annotated[
        Optional[str],
        typer.Option("--component", "-c", help="Restrict to one component, e.g. busybox@1.19.4"),
    ] = None,
    suppressions: Annotated[
        Optional[Path], typer.Option("--suppressions", help="Suppression rules file (YAML)")
    ] = None,
) -> None:
    """Mark a finding as false positive: rule saved (shareable YAML) + label captured locally."""
    from firmgraph.triage.suppression import SuppressionEngine, default_suppressions_path

    engine = SuppressionEngine(suppressions or default_suppressions_path())
    engine.add_rule(finding_id=finding_id, reason=reason, component=component)
    console.print(
        f"[green]suppressed[/green] {finding_id}"
        + (f" ({component})" if component else "")
        + f" — rule saved to {engine.rules_path}, label captured locally (never transmitted)"
    )
    console.print("re-scan to see it applied; suppressed findings are marked, never deleted")


@app.command("explain-gate")
def explain_gate(
    findings_json: Annotated[
        Path, typer.Argument(help="findings.json from a scan's evidence-pack/")
    ],
    n: Annotated[int, typer.Option("--n", help="How many top findings to explain")] = 50,
    out: Annotated[Path, typer.Option("--out", help="Gate results file")] = Path(
        "gate-results.md"
    ),
) -> None:
    """Phase-8 gate harness: run N real findings through the explainer for human scoring.

    Requires a BYO key (GEMINI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY) and
    `pip install 'firmgraph[ai]'`. If the explanations aren't clearly good, the
    AI layer waits for V0.2 — that's the gate, not a formality.
    """
    import json as _json

    from firmgraph.models import Finding
    from firmgraph.triage.explainer import (
        ADVISORY_LABEL,
        PROMPT_VERSION,
        LiteLLMExplainer,
        default_model,
    )

    model = default_model()
    if model is None:
        console.print("[red]no key found[/red] — set GEMINI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY")
        raise typer.Exit(code=2)
    explainer = LiteLLMExplainer(model=model)
    if not explainer.available():
        console.print("[red]litellm not installed[/red] — run: pip install 'firmgraph[ai]'")
        raise typer.Exit(code=2)

    raw = _json.loads(findings_json.read_text(encoding="utf-8"))
    findings = [Finding.model_validate(item) for item in raw]
    top = [f for f in findings if not f.suppressed][:n]
    console.print(f"explaining {len(top)} findings with {model} (prompt {PROMPT_VERSION})…")

    lines = [
        f"# Explain-gate results — {model} @ {PROMPT_VERSION}",
        "",
        "Score each: **good** (clear, correct, actionable) / **weak** / **wrong**.",
        "Gate passes only if explanations are CLEARLY good. Wrong > 2 => AI layer waits for V0.2.",
        "",
    ]
    ok = 0
    for i, finding in enumerate(top, 1):
        text = explainer.explain(finding)
        lines.append(f"## {i}. {finding.finding_id} [{finding.severity}] {finding.component or ''}")
        if text:
            ok += 1
            lines += ["", f"> {ADVISORY_LABEL}", "", text, "", "Score: [ ] good  [ ] weak  [ ] wrong", ""]
        else:
            lines += ["", "*(no response — API failure or circuit open)*", ""]
        console.print(f"  {i}/{len(top)} {finding.finding_id} {'ok' if text else 'FAILED'}")
    out.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]{ok}/{len(top)} explained[/green] → score them in {out}")


@app.command()
def version() -> None:
    """Print the FirmGraph version."""
    console.print(f"firmgraph {firmgraph.__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
