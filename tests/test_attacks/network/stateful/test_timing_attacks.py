"""Tests for TimingAttackGenerator.

Each generator method returns a FuzzSequence with a stable attack_type
string. These strings are part of the StatefulFuzzer's invalid-attack
filter (_invalid_attack_types), so changing them silently breaks
fuzz(invalid_only=True) routing.
"""

from __future__ import annotations

import pytest

from dicom_fuzzer.attacks.network.stateful.config import StateMachineConfig
from dicom_fuzzer.attacks.network.stateful.enums import ProtocolEvent
from dicom_fuzzer.attacks.network.stateful.timing_attacks import (
    TimingAttackGenerator,
)
from dicom_fuzzer.attacks.network.stateful.types import FuzzSequence


@pytest.fixture
def gen() -> TimingAttackGenerator:
    return TimingAttackGenerator()


class TestTimeoutAttack:
    def test_returns_fuzz_sequence(self, gen: TimingAttackGenerator) -> None:
        seq = gen.generate_timeout_attack()
        assert isinstance(seq, FuzzSequence)

    def test_attack_type_is_timeout(self, gen: TimingAttackGenerator) -> None:
        assert gen.generate_timeout_attack().attack_type == "timeout"

    def test_events_are_protocol_events(self, gen: TimingAttackGenerator) -> None:
        seq = gen.generate_timeout_attack()
        assert len(seq.events) >= 1
        assert all(isinstance(e, ProtocolEvent) for e in seq.events)

    def test_starts_with_associate_rq(self, gen: TimingAttackGenerator) -> None:
        # ARTIM timeout requires sending RQ then waiting -- first event is the trigger
        seq = gen.generate_timeout_attack()
        assert seq.events[0] == ProtocolEvent.A_ASSOCIATE_RQ


class TestSlowDataAttack:
    def test_returns_fuzz_sequence(self, gen: TimingAttackGenerator) -> None:
        assert isinstance(gen.generate_slow_data_attack(), FuzzSequence)

    def test_attack_type_is_slow_data(self, gen: TimingAttackGenerator) -> None:
        assert gen.generate_slow_data_attack().attack_type == "slow_data"

    def test_events_are_protocol_events(self, gen: TimingAttackGenerator) -> None:
        seq = gen.generate_slow_data_attack()
        assert all(isinstance(e, ProtocolEvent) for e in seq.events)

    def test_includes_many_p_data_tf(self, gen: TimingAttackGenerator) -> None:
        # The attack premise is many small P-DATA-TF transfers; we only
        # care that it really sends many, not an exact count.
        seq = gen.generate_slow_data_attack()
        p_data_count = sum(1 for e in seq.events if e == ProtocolEvent.P_DATA_TF)
        assert p_data_count >= 10


class TestRapidReconnectAttack:
    def test_returns_fuzz_sequence(self, gen: TimingAttackGenerator) -> None:
        assert isinstance(gen.generate_rapid_reconnect_attack(), FuzzSequence)

    def test_attack_type_is_rapid_reconnect(self, gen: TimingAttackGenerator) -> None:
        assert gen.generate_rapid_reconnect_attack().attack_type == "rapid_reconnect"

    def test_events_are_protocol_events(self, gen: TimingAttackGenerator) -> None:
        seq = gen.generate_rapid_reconnect_attack()
        assert all(isinstance(e, ProtocolEvent) for e in seq.events)

    def test_alternates_associate_and_abort(self, gen: TimingAttackGenerator) -> None:
        # Each cycle is RQ/connect/abort/close, so both events must be present.
        seq = gen.generate_rapid_reconnect_attack()
        assert ProtocolEvent.A_ASSOCIATE_RQ in seq.events
        assert ProtocolEvent.A_ABORT in seq.events


class TestConfigPropagation:
    def test_uses_supplied_config(self) -> None:
        cfg = StateMachineConfig(min_delay_ms=10, max_delay_ms=20)
        gen = TimingAttackGenerator(cfg)
        assert gen.config is cfg

    def test_default_config_when_none(self) -> None:
        gen = TimingAttackGenerator(config=None)
        assert isinstance(gen.config, StateMachineConfig)
