"""Stage base class (Template Method): every stage gets provenance + an error
envelope for free. Graceful degradation is the default — one failed stage is
recorded honestly, it does not kill the scan (Circuit Breaker posture)."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from firmgraph.models import StageRecord
from firmgraph.pipeline.context import ScanContext


class StageError(Exception):
    """Fatal stage error: only raised when continuing would produce lying output."""


class Stage(ABC):
    name: str = "stage"
    #: stages that emit placeholder data mark themselves honestly
    stub: bool = False

    def run(self, ctx: ScanContext) -> None:
        started = time.monotonic()
        notes: tuple[str, ...] = ()
        status = "stub" if self.stub else "ok"
        try:
            result_notes = self.execute(ctx)
            if result_notes:
                notes = tuple(result_notes)
        except StageError:
            raise
        except Exception as exc:  # graceful degradation, recorded loudly
            status = "failed"
            notes = (f"{type(exc).__name__}: {exc}",)
        duration_ms = int((time.monotonic() - started) * 1000)
        ctx.record_stage(
            StageRecord(name=self.name, status=status, duration_ms=duration_ms, notes=notes)
        )
        for tool, version in self.tool_versions().items():
            ctx.tool_versions[tool] = version

    @abstractmethod
    def execute(self, ctx: ScanContext) -> list[str] | None:
        """Do the work; return optional human-readable notes for the manifest."""

    def tool_versions(self) -> dict[str, str]:
        return {}
