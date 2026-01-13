"""Resource Exhaustion Attack Generator.

Generates resource exhaustion attack sequences for protocol fuzzing.
"""

from dicom_fuzzer.core.stateful.enums import ProtocolEvent
from dicom_fuzzer.core.stateful.types import FuzzSequence


class ResourceExhaustionGenerator:
    """Generator for resource exhaustion attacks."""

    def generate_connection_exhaustion(
        self,
        num_connections: int = 1000,
    ) -> list[FuzzSequence]:
        """Generate connection exhaustion attack.

        Creates many associations without releasing.

        Args:
            num_connections: Number of connections to create.

        Returns:
            List of sequences (one per connection).

        """
        sequences = []

        for i in range(num_connections):
            events = [
                ProtocolEvent.A_ASSOCIATE_RQ,
                ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
                ProtocolEvent.A_ASSOCIATE_AC,
                # No release - hold connection open
            ]

            sequences.append(
                FuzzSequence(
                    events=events,
                    description=f"Connection exhaustion {i}",
                    attack_type="connection_exhaustion",
                )
            )

        return sequences

    def generate_pending_release_exhaustion(self) -> FuzzSequence:
        """Generate pending release exhaustion.

        Creates many pending releases.

        Returns:
            Pending release exhaustion sequence.

        """
        events = [
            ProtocolEvent.A_ASSOCIATE_RQ,
            ProtocolEvent.TRANSPORT_CONNECT_CONFIRM,
            ProtocolEvent.A_ASSOCIATE_AC,
        ]

        # Many release requests without completions
        for _ in range(100):
            events.append(ProtocolEvent.A_RELEASE_RQ)

        return FuzzSequence(
            events=events,
            description="Pending release exhaustion",
            attack_type="pending_release",
        )


__all__ = ["ResourceExhaustionGenerator"]
