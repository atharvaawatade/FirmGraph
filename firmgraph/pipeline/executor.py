"""Sequential pipeline executor with an honest Rich progress display.

Deliberately simple (custom DAG executors were cut, seven reviews to zero):
a list of stages, run in order, each recording provenance. Determinism comes
from content-addressing and pinned tools, not from executor cleverness.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from firmgraph.models import ScanManifest
from firmgraph.pipeline.context import ScanContext
from firmgraph.pipeline.manifest import build_manifest

if TYPE_CHECKING:
    from firmgraph.stages.base import Stage


class SequentialPipeline:
    def __init__(self, stages: "list[Stage]") -> None:
        self.stages = stages

    def run(
        self, ctx: ScanContext, console: Console | None = None, quiet: bool = False
    ) -> ScanManifest:
        console = console or Console(stderr=True)
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),  # honest elapsed time, never a fake ETA
            console=console,
            disable=quiet,
        )
        with progress:
            task = progress.add_task("scan", total=len(self.stages))
            for stage in self.stages:
                progress.update(task, description=f"[bold]{stage.name}[/bold]")
                stage.run(ctx)
                progress.advance(task)
        return build_manifest(ctx)
