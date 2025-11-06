# Documentation Structure

This directory contains comprehensive documentation for the DICOM Fuzzer project.

## Quick Navigation

### User Documentation

Start here if you're new to DICOM Fuzzer:

- **[Main README](../README.md)** - Project overview, installation, and quick start
- **[QUICKSTART.md](QUICKSTART.md)** - 5-minute quick start guide for new users
- **[EXAMPLES.md](EXAMPLES.md)** - Practical examples and use cases
- **[FUZZING_GUIDE.md](FUZZING_GUIDE.md)** - Comprehensive fuzzing methodology and best practices
- **[CRASH_INTELLIGENCE.md](CRASH_INTELLIGENCE.md)** - Crash triaging, minimization, and stability tracking
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions
- **[REPORTING.md](REPORTING.md)** - Report generation and analysis

### Feature Documentation

#### Core Features

- **[STABILITY.md](STABILITY.md)** - Production stability features (resource management, error recovery)
- **[TESTING.md](TESTING.md)** - Testing guide and test coverage information
- **[COVERAGE.md](COVERAGE.md)** - Detailed test coverage analysis

#### 3D DICOM Fuzzing

- **[3D_FUZZING_ROADMAP.md](3D_FUZZING_ROADMAP.md)** - 3D fuzzing roadmap and features (Phases 1-4)
- **[VIEWER_TESTING_3D.md](VIEWER_TESTING_3D.md)** - 3D viewer testing guide
- **[PERFORMANCE_3D.md](PERFORMANCE_3D.md)** - Performance optimization for large series

### Development Documentation

For contributors and developers:

- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contribution guidelines and development setup
- **[SECURITY.md](../SECURITY.md)** - Security policy and responsible disclosure
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design and technical architecture
- **[STRUCTURE.md](STRUCTURE.md)** - Repository organization and architecture
- **[TEST_COVERAGE.md](TEST_COVERAGE.md)** - Test coverage details and goals
- **[PROJECT_STATUS.md](PROJECT_STATUS.md)** - Current project status (historical tracking)
- **[PERFORMANCE.md](PERFORMANCE.md)** - Performance benchmarking and optimization

## Documentation Categories

### [+] By Purpose

- **Getting Started**: QUICKSTART.md, Main README, EXAMPLES.md
- **Using Features**: FUZZING_GUIDE.md, CRASH_INTELLIGENCE.md, STABILITY.md, REPORTING.md
- **Troubleshooting**: TROUBLESHOOTING.md
- **Contributing**: CONTRIBUTING.md, ARCHITECTURE.md, STRUCTURE.md, TESTING.md
- **Security**: SECURITY.md

### [+] By Component

- **Core Fuzzing**: FUZZING_GUIDE.md
- **3D Features**: 3D_FUZZING_ROADMAP.md, VIEWER_TESTING_3D.md, PERFORMANCE_3D.md
- **Crash Analysis**: CRASH_INTELLIGENCE.md
- **Stability**: STABILITY.md
- **Testing**: TESTING.md, TEST_COVERAGE.md

## Archive

Historical documentation and session notes are stored in:

- **[archive/sessions/](archive/sessions/)** - Development session notes and logs
- **[archive/PROJECT_PLAN.md](archive/PROJECT_PLAN.md)** - Original 8-week development plan (archived)
- **[archive/TASK_BREAKDOWN.md](archive/TASK_BREAKDOWN.md)** - Original task breakdown (archived)

These files are kept for historical reference but are not part of the active documentation.

## Docker Documentation

Docker setup is documented in:

- **[../docker-compose.yml](../docker-compose.yml)** - Docker Compose orchestration (comprehensive comments)
- **[../docker/](../docker/)** - Dockerfiles for DCMTK and Orthanc services

## Contributing to Documentation

When adding or updating documentation:

1. **User-facing docs**: Keep in this directory (docs/)
2. **Code documentation**: Use inline comments and docstrings
3. **Session notes**: Add to archive/sessions/ with date prefix
4. **Temporary analysis**: Don't commit (use .gitignore patterns)

## Documentation Standards

- Use Markdown format (.md)
- Include table of contents for documents >100 lines
- Add practical, runnable examples
- Keep README.md up-to-date with project state
- Link between related documents
