"""[1] INGEST: hash the image, detect format, give the scan a stable identity."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from firmgraph.pipeline.context import ScanContext
from firmgraph.stages.base import Stage, StageError

_CHUNK = 1 << 20

# Minimal magic sniffing for the skeleton; Phase 2 replaces with real detection.
_MAGIC: list[tuple[bytes, str]] = [
    (b"hsqs", "squashfs"),
    (b"sqsh", "squashfs-be"),
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"UBI#", "ubi"),
    (b"\x27\x05\x19\x56", "uimage"),
]


class IngestStage(Stage):
    name = "ingest"

    def execute(self, ctx: ScanContext) -> list[str] | None:
        if not ctx.image_path.is_file():
            raise StageError(f"image not found: {ctx.image_path}")
        digest = hashlib.sha256()
        size = 0
        head = b""
        with ctx.image_path.open("rb") as fh:
            while chunk := fh.read(_CHUNK):
                if not head:
                    head = chunk[:64]
                digest.update(chunk)
                size += len(chunk)
        ctx.image_sha256 = digest.hexdigest()
        ctx.image_size = size
        ctx.image_format = _detect_format(head)
        # microsecond precision: two scans of the same image must never collide
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        ctx.scan_id = f"{ctx.image_sha256[:12]}-{stamp}"
        return [f"sha256={ctx.image_sha256[:16]}… size={size} format={ctx.image_format}"]


def _detect_format(head: bytes) -> str:
    for magic, fmt in _MAGIC:
        if head.startswith(magic):
            return fmt
    return "unknown"
