"""DICOM Network Fuzzer Base Types.

Core types, enums, and configuration for DICOM network protocol fuzzing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from dicom_fuzzer.core.types import DICOMCommand, PDUType

# Re-export for backward compatibility
__all__ = [
    "DICOMCommand",
    "PDUType",
    "FuzzingStrategy",
    "NetworkFuzzResult",
    "DICOMNetworkConfig",
]


class FuzzingStrategy(Enum):
    """Network fuzzing strategies."""

    MALFORMED_PDU = "malformed_pdu"
    INVALID_LENGTH = "invalid_length"
    BUFFER_OVERFLOW = "buffer_overflow"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_BYTES = "null_bytes"
    UNICODE_INJECTION = "unicode_injection"
    PROTOCOL_STATE = "protocol_state"
    TIMING_ATTACK = "timing_attack"


@dataclass
class NetworkFuzzResult:
    """Result of a network fuzzing test.

    Attributes:
        strategy: Fuzzing strategy used
        target_host: Target host address
        target_port: Target port number
        test_name: Name of the specific test
        success: Whether the test completed successfully
        response: Response received from server
        error: Error message if failed
        duration: Time taken for test
        timestamp: When the test was performed
        crash_detected: Whether a crash was detected
        anomaly_detected: Whether an anomaly was detected

    """

    strategy: FuzzingStrategy
    target_host: str
    target_port: int
    test_name: str
    success: bool = True
    response: bytes = b""
    error: str = ""
    duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    crash_detected: bool = False
    anomaly_detected: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "strategy": self.strategy.value,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "test_name": self.test_name,
            "success": self.success,
            "response_length": len(self.response),
            "error": self.error,
            "duration": self.duration,
            "timestamp": self.timestamp.isoformat(),
            "crash_detected": self.crash_detected,
            "anomaly_detected": self.anomaly_detected,
        }


@dataclass
class DICOMNetworkConfig:
    """Configuration for DICOM network fuzzing.

    Attributes:
        target_host: Target DICOM server hostname/IP
        target_port: Target DICOM port (default 104 or 11112)
        calling_ae: Calling AE Title
        called_ae: Called AE Title
        timeout: Socket timeout in seconds
        max_pdu_size: Maximum PDU size to use
        use_tls: Whether to use TLS/SSL
        verify_ssl: Whether to verify SSL certificates

    """

    target_host: str = "localhost"
    target_port: int = 11112
    calling_ae: str = "FUZZER_SCU"
    called_ae: str = "ANY_SCP"
    timeout: float = 5.0
    max_pdu_size: int = 16384
    use_tls: bool = False
    verify_ssl: bool = False
