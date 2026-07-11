# FirmGraph — Docker-first, local-first, nothing phones home.
#
# Based on the official unblob image: native extraction with all extractor
# dependencies included (sasquatch et al.) — the Phase-0 lesson, packaged.
# Hardened per implementation-plan A.4: non-root, single writable /work volume.
#
# Recommended run (air-gapped):
#   docker run --rm --network=none -v "$PWD:/work" firmgraph scan /work/fw.bin -o /work/firmgraph_out

FROM python:3.12-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY firmgraph ./firmgraph
RUN pip install --no-cache-dir build && python -m build --wheel

FROM ghcr.io/onekey-sec/unblob:latest
LABEL org.opencontainers.image.title="FirmGraph" \
      org.opencontainers.image.description="The open evidence layer for firmware" \
      org.opencontainers.image.licenses="Apache-2.0"

# unblob image already ships a non-root user (unblob, uid 1000) — reuse it
USER root
# pinned syft + grype (versions matching the corpus benchmark)
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -sSfL https://get.anchore.io/syft | sh -s -- -b /usr/local/bin v1.46.0 \
    && curl -sSfL https://get.anchore.io/grype | sh -s -- -b /usr/local/bin v0.115.0 \
    && apt-get purge -y curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/dist/*.whl /tmp/
# cve-bin-tool pinned for reproducibility (our determinism ethos).
# NOTE: 3.4 has a known scan-time crash (NoneType.splitlines) — FirmGraph handles
# it as a clean "skipped (unhealthy)" (never a failed row). Enabling real
# binary-signature findings is a tracked enhancement: validate a working version,
# then bump this pin. Syft+Grype are unaffected.
RUN pip install --no-cache-dir /tmp/*.whl "cve-bin-tool==3.4" && rm -f /tmp/*.whl
# cve-bin-tool DB (like grype's) lives in the cache volume:
#   docker run --rm --entrypoint cve-bin-tool -v fg-cache:/home/unblob/.cache firmgraph --update now

USER unblob
WORKDIR /work
ENV HOME=/home/unblob
ENTRYPOINT ["firmgraph"]
CMD ["--help"]
