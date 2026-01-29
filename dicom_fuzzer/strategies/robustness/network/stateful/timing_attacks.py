"""Timing Attack Generator.

Generates timing-based attack sequences for protocol fuzzing.
"""

from .config import StateMachineConfig
from .enums import ProtocolEvent
from .types import FuzzSequence


class TimingAttackGenerator:
    """Generator for timing-based attacks."""

    def __init__(self, config: StateMachineConfig | None = None):
        """Initialize the timing attack generator.

        Args:
            config: Configuration options.

        """
        self.config = config or StateMachineConfig()

    def generate_timeout_attack(self) -> FuzzSequence:
        """Generate timeout attack sequence.

        Sends partial association then waits for timeout.

        Returns:
            Timeout attack sequence.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            # No response - wait for ARTIM timeout
        ]

        return FuzzSequence(
            events=events,
            description="ARTIM timeout attack",
            attack_type="timeout",
        )

    def generate_slow_data_attack(self) -> FuzzSequence:
        """Generate slow data transfer attack.

        Sends data very slowly to test timeout handling.

        Returns:
            Slow data sequence.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        # Many small data transfers
        for _ in range(100):
            events.append(ProtocolEvent.P_DATA_TF)

        return FuzzSequence(
            events=events,
            description="Slow/fragmented data transfer",
            attack_type="slow_data",
        )

    def generate_rapid_reconnect_attack(self) -> FuzzSequence:
        """Generate rapid reconnection attack.

        Rapidly connects and disconnects.

        Returns:
            Rapid reconnect sequence.

        """
        events = []

        for _ in range(50):
            events.extend(
                [
                    ProtocolEvent.A_ASSOCIATE_RQ,
                    ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
                    ProtocolEvent.A_ABORT,
                    ProtocolEvent.TRANSPORT_CLOSE,
                ]
            )

        return FuzzSequence(
            events=events,
            description="Rapid connect/disconnect",
            attack_type="rapid_reconnect",
        )


__all__ = ["TimingAttackGenerator"]
