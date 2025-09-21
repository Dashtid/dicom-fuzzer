# DICOM-Fuzzer Project - Claude Code Guidelines

## Project Overview

**DICOM-Fuzzer** is a specialized security testing tool designed to perform comprehensive fuzzing of DICOM (Digital Imaging and Communications in Medicine) implementations. This project focuses on identifying vulnerabilities in medical imaging systems, PACS (Picture Archiving and Communication Systems), and medical device software that handle DICOM data.

### Mission Statement
To enhance the security posture of healthcare IT infrastructure by providing automated vulnerability discovery capabilities for DICOM-based systems, ensuring patient data protection and system reliability.

## Development Environment

**Operating System**: Windows 11
**Shell**: Git Bash / PowerShell / Command Prompt
**Important**: Always use Windows-compatible commands:
- Use `dir` instead of `ls` for Command Prompt
- Use PowerShell commands when appropriate
- File paths use backslashes (`\`) in Windows
- Use `python -m http.server` for local development server
- Git Bash provides Unix-like commands but context should be Windows-aware

## Technical Context & Domain Knowledge

### DICOM Standard Overview
- **DICOM 3.0 Standard**: ISO 12052:2017 compliance requirements
- **Service Classes**: Storage, Query/Retrieve, Print, Workflow Management
- **Network Services**: DICOM Upper Layer Protocol, Association handling
- **Data Elements**: Tags, VRs (Value Representations), Transfer Syntaxes
- **Security**: TLS, user authentication, access control mechanisms

### Healthcare IT Security Landscape
- **Regulatory Compliance**: HIPAA, FDA 510(k), EU MDR, NIS2 Directive
- **Threat Landscape**: Medical device vulnerabilities, ransomware, data breaches
- **Industry Standards**: IEC 62304, ISO 14971, ISO 27001, NIST Cybersecurity Framework
- **Common Vulnerabilities**: Buffer overflows, injection attacks, improper input validation

## Project Architecture & Technology Stack

### Core Technologies
- **Primary Language**: Python 3.11+ for rapid prototyping and extensive library support
- **DICOM Libraries**:
  - `pydicom` for DICOM file manipulation and parsing
  - `pynetdicom` for network communication and protocol handling
- **Fuzzing Framework**: Custom engine built on proven fuzzing methodologies
- **Security Testing**: Integration with existing security tools and frameworks

### Architecture Principles
1. **Modular Design**: Separation of concerns between fuzzing engines, protocol handlers, and analysis modules
2. **Extensibility**: Plugin-based architecture for custom fuzzing strategies
3. **Scalability**: Support for distributed fuzzing campaigns
4. **Observability**: Comprehensive logging, metrics, and crash analysis
5. **Safety**: Isolated testing environments with rollback capabilities

## Development Guidelines for Claude Code

### 🎓 Educational Programming Approach

**IMPORTANT**: This project serves as a learning experience for programming concepts. Claude must provide detailed explanations for:

#### Code Explanation Requirements
1. **Concept Introduction**: Explain what we're building and why
2. **Step-by-Step Breakdown**: Break down complex code into understandable pieces
3. **Programming Concepts**: Explain classes, functions, modules, imports, etc.
4. **Python-Specific Features**: Explain decorators, context managers, type hints, etc.
5. **Security Implications**: Explain why certain security measures are implemented
6. **Testing Logic**: Explain why we test certain things and how tests work

#### Educational Code Comment Style
```python
# LEARNING: This is a class - a blueprint for creating objects
class DicomParser:
    """
    CONCEPT: A class groups related data and functions together.
    This class handles reading and validating DICOM medical files.
    """

    # LEARNING: __init__ is a special method called when creating a new object
    def __init__(self, file_path: str):
        """
        CONCEPT: This is the constructor - it sets up our object when created.

        Args:
            file_path: String containing the path to our DICOM file

        LEARNING: Type hints (like ': str') help us know what type of data expected
        """
        # LEARNING: self.variable stores data that belongs to this specific object
        self.file_path = file_path

    # LEARNING: Methods are functions that belong to a class
    def validate_file(self) -> bool:
        """
        CONCEPT: This method checks if the file is safe to process.

        Returns:
            bool: True if file is valid, False otherwise

        LEARNING: The -> bool tells us this function returns a True/False value
        """
        # LEARNING: We check file exists before trying to open it (defensive programming)
        if not os.path.exists(self.file_path):
            return False
        return True
```

#### When Implementing Features
1. **Start with the "Why"**: Explain the purpose and context
2. **Break Down the "How"**: Explain the implementation approach
3. **Highlight Key Concepts**: Point out important programming patterns
4. **Show Alternatives**: Mention other ways this could be implemented
5. **Connect to Bigger Picture**: How this fits into the overall architecture

### 1. Code Quality Standards

#### Security-First Development
```python
# ALWAYS validate input parameters
def parse_dicom_tag(tag_value: str) -> DicomTag:
    """Parse DICOM tag with comprehensive validation."""
    if not isinstance(tag_value, str):
        raise TypeError(f"Tag must be string, got {type(tag_value)}")

    # Validate format before processing
    if not re.match(r'^[0-9A-Fa-f]{8}$', tag_value):
        raise ValueError(f"Invalid DICOM tag format: {tag_value}")

    return DicomTag.from_hex(tag_value)
```

#### Error Handling Excellence
```python
# Implement comprehensive error handling
class DicomFuzzingError(Exception):
    """Base exception for DICOM fuzzing operations."""
    pass

class NetworkTimeoutError(DicomFuzzingError):
    """Raised when network operations timeout."""
    pass

# Context managers for resource cleanup
@contextmanager
def dicom_association(host: str, port: int) -> DicomAssociation:
    """Manage DICOM association lifecycle."""
    assoc = None
    try:
        assoc = create_association(host, port)
        yield assoc
    except Exception as e:
        logger.error(f"Association failed: {e}")
        raise NetworkTimeoutError(f"Failed to establish association: {e}")
    finally:
        if assoc:
            assoc.release()
```

### 2. Testing & Validation Framework

#### Unit Testing Standards
- **Coverage Requirement**: Minimum 95% code coverage
- **Test Categories**: Unit, integration, security, performance
- **Property-Based Testing**: Use `hypothesis` for comprehensive input validation testing
- **Security Testing**: Automated security scans integrated into CI/CD

#### Test Structure Example
```python
class TestDicomFuzzer:
    """Comprehensive test suite for DICOM fuzzing functionality."""

    @pytest.fixture
    def mock_dicom_server(self):
        """Provide isolated DICOM server for testing."""
        return MockDicomServer(port=11112)

    @hypothesis.given(st.binary(min_size=1, max_size=65536))
    def test_malformed_dicom_handling(self, malformed_data):
        """Test fuzzer behavior with malformed DICOM data."""
        fuzzer = DicomFuzzer()
        result = fuzzer.process_data(malformed_data)
        assert not result.caused_crash
        assert result.error_handling_correct
```

### 3. Performance Optimization

#### Memory Management
```python
# Use generators for large datasets
def generate_fuzz_cases(base_dataset: Dataset) -> Iterator[Dataset]:
    """Generate fuzzing test cases efficiently."""
    for mutation_strategy in get_mutation_strategies():
        for mutation_params in mutation_strategy.get_parameters():
            yield mutation_strategy.apply(base_dataset, mutation_params)

# Implement proper cleanup
class DicomFuzzer:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup_resources()
```

#### Asynchronous Operations
```python
# Use asyncio for concurrent fuzzing operations
async def fuzz_target_concurrent(targets: List[Target]) -> List[FuzzResult]:
    """Execute fuzzing campaigns concurrently."""
    semaphore = asyncio.Semaphore(10)  # Limit concurrent operations

    async def fuzz_single_target(target: Target) -> FuzzResult:
        async with semaphore:
            return await target.execute_fuzzing()

    tasks = [fuzz_single_target(target) for target in targets]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### 4. Documentation Standards

#### Code Documentation
- **Docstring Standard**: Google-style docstrings for all public APIs
- **Type Hints**: Comprehensive type annotations using `typing` module
- **API Documentation**: Auto-generated with Sphinx
- **Security Notes**: Document security implications for all functions

#### Example Documentation
```python
def mutate_dicom_dataset(
    dataset: Dataset,
    mutation_rate: float = 0.1,
    target_elements: Optional[List[DicomTag]] = None,
    preserve_critical: bool = True
) -> Dataset:
    """Mutate DICOM dataset for fuzzing purposes.

    Args:
        dataset: Source DICOM dataset to mutate
        mutation_rate: Probability of mutating each element (0.0-1.0)
        target_elements: Specific elements to target (None for all)
        preserve_critical: Whether to preserve critical elements

    Returns:
        Mutated dataset with tracking metadata

    Raises:
        ValueError: If mutation_rate is not in valid range
        DicomFuzzingError: If dataset mutation fails

    Security:
        This function generates potentially malicious DICOM data.
        Only use in isolated testing environments.

    Example:
        >>> dataset = pydicom.dcmread('test.dcm')
        >>> mutated = mutate_dicom_dataset(dataset, mutation_rate=0.2)
        >>> assert mutated.is_valid()
    """
```

### 5. Security Considerations

#### Secure Development Practices
1. **Input Validation**: Validate all external inputs rigorously
2. **Privilege Separation**: Run with minimal required privileges
3. **Secure Defaults**: Safe configuration defaults
4. **Audit Logging**: Comprehensive security event logging
5. **Dependency Management**: Regular security updates and vulnerability scanning

#### Testing Environment Isolation
```python
# Containerized testing environments
class IsolatedTestEnvironment:
    """Manage isolated testing environments for fuzzing."""

    def __init__(self, container_image: str):
        self.container = create_container(
            image=container_image,
            network_mode='none',  # Isolated network
            read_only=True,       # Read-only filesystem
            tmpfs={'/tmp': 'rw,noexec,nosuid,size=100m'}
        )

    async def execute_test(self, test_case: TestCase) -> TestResult:
        """Execute test case in isolated environment."""
        return await self.container.run(test_case)
```

### 6. Monitoring & Observability

#### Logging Framework
```python
import structlog

# Structured logging configuration
logger = structlog.get_logger()

def configure_logging():
    """Configure structured logging for the application."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

# Usage example
logger.info(
    "Fuzzing campaign started",
    target_host="pacs.hospital.com",
    campaign_id="fc-2024-001",
    test_cases=1500,
    estimated_duration="2h"
)
```

### 7. Configuration Management

#### Environment-Specific Configuration
```python
from pydantic import BaseSettings, validator
from typing import List, Optional

class FuzzerSettings(BaseSettings):
    """Application configuration with validation."""

    # Target configuration
    target_hosts: List[str]
    target_port: int = 11112

    # Fuzzing parameters
    mutation_rate: float = 0.1
    max_test_cases: int = 1000
    timeout_seconds: int = 30

    # Security settings
    enable_network_isolation: bool = True
    log_level: str = "INFO"

    @validator('mutation_rate')
    def validate_mutation_rate(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('mutation_rate must be between 0.0 and 1.0')
        return v

    class Config:
        env_file = ".env"
        env_prefix = "DICOM_FUZZER_"
```

## Implementation Phases

### Phase 1: Foundation (Weeks 1-2)
- Core DICOM protocol handling
- Basic fuzzing engine
- Test infrastructure setup
- Security framework implementation

### Phase 2: Advanced Fuzzing (Weeks 3-4)
- Intelligent mutation strategies
- Protocol-specific fuzzing techniques
- Network service discovery
- Crash analysis and reporting

### Phase 3: Integration & Scalability (Weeks 5-6)
- CI/CD pipeline integration
- Distributed fuzzing capabilities
- Performance optimization
- Comprehensive documentation

### Phase 4: Production Readiness (Weeks 7-8)
- Security hardening
- Compliance validation
- User interface development
- Field testing and validation

## Quality Gates

### Code Quality Metrics
- **Code Coverage**: ≥95%
- **Cyclomatic Complexity**: ≤10 per function
- **Security Scan**: Zero high/critical findings
- **Performance**: Sub-second response for basic operations

### Security Validation
- **SAST/DAST**: Automated security scanning
- **Dependency Scanning**: No known vulnerabilities
- **Penetration Testing**: External security validation
- **Compliance Check**: Healthcare regulation compliance

## Tools & Automation

### Development Tools
- **IDE**: VS Code with Python extensions
- **Linting**: pylint, black, mypy
- **Testing**: pytest, hypothesis, coverage.py
- **Security**: bandit, safety, semgrep
- **Documentation**: Sphinx, mkdocs

### CI/CD Pipeline
- **Version Control**: Git with conventional commits
- **Build System**: GitHub Actions / GitLab CI
- **Container Registry**: Private registry for security
- **Deployment**: Docker containerization

## Best Practices Summary

1. **Security First**: Always consider security implications
2. **Test-Driven Development**: Write tests before implementation
3. **Documentation**: Document as you code
4. **Performance**: Profile before optimizing
5. **Compliance**: Understand healthcare regulations
6. **Isolation**: Test in safe, isolated environments
7. **Monitoring**: Implement comprehensive observability
8. **Automation**: Automate repetitive tasks
9. **Review**: Mandatory code reviews for all changes
10. **Learning**: Stay updated with security research

---

**Remember**: This project deals with critical healthcare infrastructure. Security, reliability, and compliance are paramount. When in doubt, choose the more secure approach.

**Contact**: For questions about these guidelines, consult with the cybersecurity team or refer to the project documentation.