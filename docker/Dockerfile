# FirmGraph — Docker-first, local-first, nothing phones home.
#
# Based on the official unblob image: native extraction with all extractor
# dependencies included (sasquatch et al.) — the Phase-0 lesson, packaged.
# Hardened per implementation-plan A.4: non-root, single writable /work volume.
#
# Ships a complete offline grype vulnerability DB baked in — CVE matching works
# air-gapped with zero setup. Recommended run (firmware mounted read-only):
#   docker run --rm --network=none -v "$PWD:/work:ro" -v "$PWD/out:/out" \
#     firmgraph scan /work/fw.bin -o /out

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
# Bake the grype vulnerability DB into the image so CVE matching works out of
# the box — fully air-gapped, zero setup. This is the "works offline" promise
# made real: you cannot be air-gapped AND download a ~1.7GB DB, so it must ship
# in the image. Baked at a fixed path a user cache-volume can't shadow; the DB
# build date travels in every scan manifest (determinism/reproducibility).
# Grype's runtime age-check is disabled (see grype adapter) so the pinned DB
# keeps working past grype's 5-day staleness limit — offline for real, not a fuse.
# This layer sits BEFORE the code layer so app changes don't re-download the DB.
# The image is large on purpose — it carries a complete offline vulnerability DB.
ENV GRYPE_DB_CACHE_DIR=/opt/grype/db
RUN mkdir -p /opt/grype/db \
    && grype db update \
    && chmod -R a+rX /opt/grype

# cve-bin-tool pinned for reproducibility (our determinism ethos).
# NOTE: 3.4 has a known scan-time crash (NoneType.splitlines) — FirmGraph handles
# it as a clean "skipped (unhealthy)" (never a failed row). Enabling real
# binary-signature findings is a tracked enhancement: validate a working version,
# then bump this pin. Syft+Grype are unaffected.
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl "cve-bin-tool==3.4" && rm -f /tmp/*.whl

USER unblob
WORKDIR /work
ENV HOME=/home/unblob
ENTRYPOINT ["firmgraph"]
CMD ["--help"]
