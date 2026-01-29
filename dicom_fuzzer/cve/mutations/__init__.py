"""CVE Mutation Functions - Deterministic DICOM mutations for CVE replication.

Each CVE has one or more mutation functions that produce deterministic output.
Functions return a list of (variant_name, mutated_bytes) tuples when there are
multiple attack vectors for a single CVE.
"""

from .memory import (
    mutate_cve_2024_1453,
    mutate_cve_2024_22100,
    mutate_cve_2024_25578,
    mutate_cve_2024_28877,
    mutate_cve_2024_47796,
    mutate_cve_2024_52333,
    mutate_cve_2025_35975,
    mutate_cve_2025_36521,
    mutate_cve_2025_5307,
    mutate_cve_2025_5943,
)
from .protocol import (
    mutate_cve_2019_11687,
    mutate_cve_2020_29625,
    mutate_cve_2021_41946,
    mutate_cve_2022_24193,
    mutate_cve_2024_33606,
    mutate_cve_2025_1001,
    mutate_cve_2025_1002,
    mutate_cve_2025_11266,
    mutate_cve_2025_27578,
    mutate_cve_2025_31946,
    mutate_cve_2025_53618,
    mutate_cve_2025_53619,
)

# Mapping from CVE ID to mutation function
CVE_MUTATIONS = {
    # Memory corruption CVEs
    "CVE-2025-5943": mutate_cve_2025_5943,
    "CVE-2025-35975": mutate_cve_2025_35975,
    "CVE-2025-36521": mutate_cve_2025_36521,
    "CVE-2025-5307": mutate_cve_2025_5307,
    "CVE-2024-22100": mutate_cve_2024_22100,
    "CVE-2024-25578": mutate_cve_2024_25578,
    "CVE-2024-28877": mutate_cve_2024_28877,
    "CVE-2024-1453": mutate_cve_2024_1453,
    "CVE-2024-47796": mutate_cve_2024_47796,
    "CVE-2024-52333": mutate_cve_2024_52333,
    # Protocol/parser CVEs
    "CVE-2025-11266": mutate_cve_2025_11266,
    "CVE-2025-53618": mutate_cve_2025_53618,
    "CVE-2025-53619": mutate_cve_2025_53619,
    "CVE-2025-1001": mutate_cve_2025_1001,
    "CVE-2025-1002": mutate_cve_2025_1002,
    "CVE-2025-27578": mutate_cve_2025_27578,
    "CVE-2025-31946": mutate_cve_2025_31946,
    "CVE-2024-33606": mutate_cve_2024_33606,
    "CVE-2022-24193": mutate_cve_2022_24193,
    "CVE-2021-41946": mutate_cve_2021_41946,
    "CVE-2020-29625": mutate_cve_2020_29625,
    "CVE-2019-11687": mutate_cve_2019_11687,
}

__all__ = [
    "CVE_MUTATIONS",
    # Memory mutations
    "mutate_cve_2025_5943",
    "mutate_cve_2025_35975",
    "mutate_cve_2025_36521",
    "mutate_cve_2025_5307",
    "mutate_cve_2024_22100",
    "mutate_cve_2024_25578",
    "mutate_cve_2024_28877",
    "mutate_cve_2024_1453",
    "mutate_cve_2024_47796",
    "mutate_cve_2024_52333",
    # Protocol mutations
    "mutate_cve_2025_11266",
    "mutate_cve_2025_53618",
    "mutate_cve_2025_53619",
    "mutate_cve_2025_1001",
    "mutate_cve_2025_1002",
    "mutate_cve_2025_27578",
    "mutate_cve_2025_31946",
    "mutate_cve_2024_33606",
    "mutate_cve_2022_24193",
    "mutate_cve_2021_41946",
    "mutate_cve_2020_29625",
    "mutate_cve_2019_11687",
]
