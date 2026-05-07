"""Tests for ResourceExhaustionGenerator.

Validates the FuzzSequence shape and attack_type strings; the strings
are part of StatefulFuzzer's _invalid_attack_types filter, so silent
renames break fuzz(invalid_only=True).
"""

from __future__ import annotations

import pytest

from dicom_fuzzer.attacks.network.stateful.enums import ProtocolEvent
from dicom_fuzzer.attacks.network.stateful.resource_attacks import (
    ResourceExhaustionGenerator,
)
from dicom_fuzzer.attacks.network.stateful.types import FuzzSequence


@pytest.fixture
def gen() -> ResourceExhaustionGenerator:
    return ResourceExhaustionGenerator()


class TestConnectionExhaustion:
    def test_returns_list(self, gen: ResourceExhaustionGenerator) -> None:
        result = gen.generate_connection_exhaustion(num_connections=3)
        assert isinstance(result, list)

    def test_list_length_matches_num_connections(
        self, gen: ResourceExhaustionGenerator
    ) -> None:
        for n in (1, 5, 10):
            assert len(gen.generate_connection_exhaustion(num_connections=n)) == n

    def test_each_entry_is_fuzz_sequence(
        self, gen: ResourceExhaustionGenerator
    ) -> None:
        for seq in gen.generate_connection_exhaustion(num_connections=4):
            assert isinstance(seq, FuzzSequence)

    def test_attack_type_is_connection_exhaustion(
        self, gen: ResourceExhaustionGenerator
    ) -> None:
        for seq in gen.generate_connection_exhaustion(num_connections=2):
            assert seq.attack_type == "connection_exhaustion"

    def test_events_are_protocol_events(self, gen: ResourceExhaustionGenerator) -> None:
        for seq in gen.generate_connection_exhaustion(num_connections=2):
            assert all(isinstance(e, ProtocolEvent) for e in seq.events)

    def test_no_release_in_events(self, gen: ResourceExhaustionGenerator) -> None:
        # The exhaustion premise is to NOT release -- holding connections open.
        for seq in gen.generate_connection_exhaustion(num_connections=2):
            assert ProtocolEvent.A_RELEASE_RQ not in seq.events


class TestPendingReleaseExhaustion:
    def test_returns_fuzz_sequence(self, gen: ResourceExhaustionGenerator) -> None:
        assert isinstance(gen.generate_pending_release_exhaustion(), FuzzSequence)

    def test_attack_type_is_pending_release(
        self, gen: ResourceExhaustionGenerator
    ) -> None:
        assert (
            gen.generate_pending_release_exhaustion().attack_type == "pending_release"
        )

    def test_events_are_protocol_events(self, gen: ResourceExhaustionGenerator) -> None:
        seq = gen.generate_pending_release_exhaustion()
        assert all(isinstance(e, ProtocolEvent) for e in seq.events)

    def test_includes_many_release_requests(
        self, gen: ResourceExhaustionGenerator
    ) -> None:
        seq = gen.generate_pending_release_exhaustion()
        rq_count = sum(1 for e in seq.events if e == ProtocolEvent.A_RELEASE_RQ)
        assert rq_count >= 10
