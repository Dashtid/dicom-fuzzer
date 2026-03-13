"""Corpus management and minimization for DICOM fuzzing."""

from .corpus_minimization import (
    STRIP_TAGS,
    MoonLightMinimizer,
    minimize_corpus_for_campaign,
    optimize_corpus,
    strip_pixel_data,
)
from .coverage_types import (
    GUIStateTransition,
    ProtocolStateTransition,
    SeedCoverageInfo,
    StateCoverage,
    StateFingerprint,
)
from .study_corpus import (
    StudyCorpusEntry,
    StudyCorpusManager,
    create_study_corpus,
)
from .study_minimizer import (
    MinimizationConfig,
    MinimizedStudy,
    StudyMinimizer,
)

__all__ = [
    # Corpus minimization
    "STRIP_TAGS",
    "MoonLightMinimizer",
    "minimize_corpus_for_campaign",
    "optimize_corpus",
    "strip_pixel_data",
    # Coverage tracking
    "GUIStateTransition",
    "ProtocolStateTransition",
    "SeedCoverageInfo",
    "StateCoverage",
    "StateFingerprint",
    # Study corpus
    "StudyCorpusEntry",
    "StudyCorpusManager",
    "create_study_corpus",
    # Study minimizer
    "MinimizationConfig",
    "MinimizedStudy",
    "StudyMinimizer",
]
