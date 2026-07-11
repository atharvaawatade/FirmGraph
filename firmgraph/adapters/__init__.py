"""Adapters: concrete implementations of ports.

Phase 2: real extraction (unblob native/docker -> binwalk fallback, chained).
SBOM/CVE/AI adapters land in Phases 3-8, one file each per the Modularity Contract.
"""

from firmgraph.adapters.binwalk import BinwalkAdapter
from firmgraph.adapters.chain import ExtractorChain
from firmgraph.adapters.cve_bin_tool import CveBinToolAdapter
from firmgraph.adapters.grype import GrypeAdapter
from firmgraph.adapters.stubs import (
    NullBinaryScanner,
    NullExplainer,
    StubExtractor,
    StubSbomEngine,
    StubVulnMatcher,
)
from firmgraph.adapters.syft import SyftAdapter
from firmgraph.adapters.unblob import UnblobDockerAdapter, UnblobNativeAdapter

__all__ = [
    "BinwalkAdapter",
    "CveBinToolAdapter",
    "ExtractorChain",
    "GrypeAdapter",
    "NullBinaryScanner",
    "NullExplainer",
    "StubExtractor",
    "StubSbomEngine",
    "StubVulnMatcher",
    "SyftAdapter",
    "UnblobDockerAdapter",
    "UnblobNativeAdapter",
]
