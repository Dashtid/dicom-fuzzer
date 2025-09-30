# DICOM Fuzzer

A specialized security testing tool for comprehensive fuzzing of DICOM (Digital Imaging and Communications in Medicine) implementations, designed to enhance healthcare IT security through automated vulnerability discovery.

## 📋 Project Documentation

- **[📈 PROJECT PLAN](PROJECT_PLAN.md)** - Comprehensive 8-week implementation roadmap
- **[📋 TASK BREAKDOWN](TASK_BREAKDOWN.md)** - Detailed task structure and dependencies
- **[🔧 DEVELOPMENT GUIDELINES](.claude/CLAUDE.md)** - Technical standards and best practices

**Current Status**: Phase 1 (Foundation) - 35% Complete | Next Milestone: Week 2 Core Implementation

## Overview

This fuzzer takes a valid DICOM file as input and generates multiple variations with believable but randomized metadata, corrupted headers, and subtle pixel modifications. It's specifically designed for testing medical imaging applications in a controlled environment.

## Features

- **Metadata Fuzzing**: Generates realistic patient information, study dates, and institutional data
- **Header Manipulation**: Tests edge cases with overlong strings, missing tags, and invalid values
- **Pixel Data Corruption**: Introduces subtle corruptions to image data while maintaining parsability
- **Batch Generation**: Creates multiple test files in a single run
- **Configurable Output**: Customizable mutation strategies and output directories

## Project Structure

```
dicom_fuzzer/
├── core/
│   ├── parser.py       # DICOM file parsing & validation
│   ├── mutator.py      # Mutation strategies
│   ├── generator.py    # File generation logic
│   └── validator.py    # Output validation
├── strategies/
│   ├── metadata_fuzzer.py    # Patient info, study data mutations
│   ├── header_fuzzer.py      # DICOM headers & tags mutations
│   ├── pixel_fuzzer.py       # Image data mutations
│   └── structure_fuzzer.py   # File structure attacks
├── utils/
│   ├── config.py       # Configuration management
│   ├── logger.py       # Logging setup
│   └── helpers.py      # Utility functions
├── tests/
├── main.py            # CLI interface
└── README.md
```

## Installation

### Prerequisites

- Python 3.8+
- pip

### Dependencies

```bash
pip install pydicom numpy
```

### Optional Dependencies

For enhanced functionality:
```bash
pip install pillow  # For additional image processing
```

## Usage

### Basic Usage

Generate 50 fuzzed DICOM files from a source file:

```bash
python main.py sample.dcm -c 50 -o ./test_files
```

### Advanced Usage

```bash
python main.py input.dcm \
    --count 100 \
    --output ./fuzzed_output \
    --strategies metadata,header,pixel \
    --verbose
```

### Parameters

- `input_file`: Path to the original DICOM file
- `-c, --count`: Number of fuzzed files to generate (default: 100)
- `-o, --output`: Output directory (default: ./fuzzed_dicoms)
- `-s, --strategies`: Comma-separated list of mutation strategies
- `-v, --verbose`: Enable verbose logging

## Mutation Strategies

### Metadata Fuzzing
- **Patient Information**: Generates realistic but fake patient names, IDs, and demographics
- **Study Data**: Randomizes study dates, descriptions, and institutional information
- **Equipment Info**: Varies manufacturer, model, and software version data

### Header Fuzzing
- **Overlong Strings**: Tests application handling of extremely long field values
- **Missing Required Tags**: Removes or corrupts mandatory DICOM elements
- **Invalid VR Values**: Introduces invalid Value Representation data
- **Boundary Values**: Tests edge cases in numeric fields

### Pixel Fuzzing
- **Noise Injection**: Adds random noise to small percentages of pixel data
- **Bit Flipping**: Introduces single-bit errors in image data
- **Compression Artifacts**: Simulates various compression-related corruptions

## Configuration

Edit `utils/config.py` to customize mutation behavior:

```python
MUTATION_STRATEGIES = {
    'metadata_probability': 0.8,
    'header_probability': 0.6,
    'pixel_probability': 0.3,
    'max_mutations_per_file': 3
}

FAKE_DATA_POOLS = {
    'institutions': ["General Hospital", "Medical Center", "Clinic"],
    'modalities': ["CT", "MR", "US", "XR"],
    'manufacturers': ["GE", "Siemens", "Philips"]
}
```

## Testing Integration

### Automated Testing Loop

```python
from dicom_fuzzer.core.generator import DICOMGenerator

def test_application_with_fuzzed_files(original_file, app_endpoint):
    generator = DICOMGenerator("./test_output")
    fuzzed_files = generator.generate_batch(original_file, count=50)

    results = []
    for file_path in fuzzed_files:
        try:
            response = upload_to_app(file_path, app_endpoint)
            results.append({'file': file_path.name, 'status': 'success'})
        except Exception as e:
            results.append({'file': file_path.name, 'status': 'error', 'error': str(e)})

    return results
```

## Use Cases

- **Medical Imaging Application Testing**: Validate robustness against malformed DICOM files
- **Security Testing**: Identify potential vulnerabilities in DICOM parsing logic
- **Compliance Testing**: Ensure applications handle edge cases gracefully
- **Performance Testing**: Test application behavior under various data conditions

## Safety and Ethics

⚠️ **Important**: This tool is designed for testing purposes only in controlled environments.

- Only use with synthetic or anonymized test data
- Ensure compliance with HIPAA, GDPR, and other relevant regulations
- Do not use on production systems without proper authorization
- Generated files should be treated as test data and disposed of securely

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-mutation-strategy`)
3. Commit your changes (`git commit -am 'Add new mutation strategy'`)
4. Push to the branch (`git push origin feature/new-mutation-strategy`)
5. Create a Pull Request

## Implementation Roadmap

See **[PROJECT_PLAN.md](PROJECT_PLAN.md)** for detailed implementation phases:

### 🏗️ Phase 1: Foundation (Weeks 1-2) - 35% Complete
- ✅ Core DICOM protocol handling
- ✅ Basic fuzzing engine structure
- 🔨 Core mutation framework (In Progress)
- 🔨 Comprehensive test suite (Target: 95% coverage)

### 🚀 Phase 2: Advanced Fuzzing (Weeks 3-4)
- ⏳ Coverage-guided fuzzing
- ⏳ Grammar-based mutations
- ⏳ Network protocol fuzzing
- ⏳ Automatic crash analysis and reporting

### 🔗 Phase 3: Integration & Scalability (Weeks 5-6)
- ⏳ Web dashboard for results visualization
- ⏳ Support for DICOM-RT (Radiotherapy) structures
- ⏳ Integration with CI/CD pipelines
- ⏳ Performance monitoring during testing

### 🛡️ Phase 4: Production Readiness (Weeks 7-8)
- ⏳ Security hardening and compliance validation
- ⏳ Field testing and user interface
- ⏳ Complete documentation and training materials

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Built using the excellent [pydicom](https://pydicom.github.io/) library
- Inspired by the need for robust testing in medical imaging applications
- Developed for enhancing security and reliability in healthcare technology

## Disclaimer

This software is provided for educational and testing purposes. Users are responsible for ensuring compliance with all applicable laws and regulations when using this tool. The authors assume no liability for any misuse or damage caused by this software.
