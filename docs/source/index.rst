DICOM-Fuzzer Documentation
==========================

Welcome to DICOM-Fuzzer's documentation! This is a professional-grade DICOM fuzzing tool designed for healthcare security testing.

.. warning::
   DICOM-Fuzzer generates potentially malicious DICOM data for security testing.
   Only use in isolated testing environments with proper authorization.

Overview
--------

DICOM-Fuzzer is a specialized security testing tool for comprehensive fuzzing of DICOM
(Digital Imaging and Communications in Medicine) implementations. It helps identify
vulnerabilities in medical imaging systems, PACS, and medical device software.

**Key Features:**

* 🎯 **Grammar-Based Fuzzing** - DICOM-aware mutations with structure preservation
* 🔍 **Crash Analysis** - Automatic crash detection and deduplication
* 📊 **Performance Profiling** - Real-time metrics and throughput tracking
* 📝 **Comprehensive Reporting** - HTML and JSON reports for automation
* ⚙️ **Configuration Management** - Environment-specific settings with validation
* 🧪 **Extensive Test Suite** - 493 tests with 100% coverage
* 🔐 **Security-First Design** - Input validation and safety checks

Quick Start
-----------

Installation
~~~~~~~~~~~~

.. code-block:: bash

   git clone https://github.com/Dashtid/DICOM-Fuzzer.git
   cd DICOM-Fuzzer
   uv venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   uv pip install -e .

Basic Usage
~~~~~~~~~~~

.. code-block:: bash

   # Run the demo
   python demo_fuzzing.py

   # Or use the CLI
   python main.py --input samples/CT_small.dcm --output output/ --count 100

Configuration
~~~~~~~~~~~~~

Copy and customize the environment file:

.. code-block:: bash

   cp .env.example .env
   # Edit .env with your settings

See :doc:`user_guide/configuration` for detailed configuration options.

Contents
--------

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   user_guide/installation
   user_guide/quickstart
   user_guide/configuration
   user_guide/fuzzing_strategies
   user_guide/crash_analysis
   user_guide/reporting

.. toctree::
   :maxdepth: 2
   :caption: API Reference

   api/core
   api/strategies
   api/utils

.. toctree::
   :maxdepth: 1
   :caption: Development

   development/architecture
   development/testing
   development/roadmap

.. toctree::
   :maxdepth: 1
   :caption: Project Info

   project/changelog
   project/license

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
