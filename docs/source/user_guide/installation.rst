Installation
============

This guide covers the installation and setup of DICOM-Fuzzer.

Requirements
------------

**System Requirements:**

* Python 3.11, 3.12, or 3.13
* 4GB RAM minimum (8GB recommended)
* 500MB disk space

**Operating Systems:**

* Linux (Ubuntu 20.04+, Debian 11+)
* Windows 10/11
* macOS 12+ (Intel and Apple Silicon)

Dependencies
------------

DICOM-Fuzzer uses modern Python tooling:

* **uv** - Fast Python package manager (recommended)
* **pydicom** - DICOM file parsing and manipulation
* **pydantic** - Settings management and validation
* **pytest** - Testing framework
* **sphinx** - Documentation generation

Installation Methods
--------------------

Method 1: Using UV (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

UV is the fastest way to install Python packages and manage environments.

1. **Install UV:**

   .. code-block:: bash

      # Linux/macOS
      curl -LsSf https://astral.sh/uv/install.sh | sh

      # Windows (PowerShell)
      irm https://astral.sh/uv/install.ps1 | iex

2. **Clone the repository:**

   .. code-block:: bash

      git clone https://github.com/Dashtid/DICOM-Fuzzer.git
      cd DICOM-Fuzzer

3. **Create virtual environment and install:**

   .. code-block:: bash

      uv venv

      # Linux/macOS
      source .venv/bin/activate

      # Windows
      .venv\Scripts\activate

      # Install dependencies
      uv pip install -e .

4. **Install development dependencies (optional):**

   .. code-block:: bash

      uv pip install -e ".[dev]"

Method 2: Using Pip
~~~~~~~~~~~~~~~~~~~

If you prefer traditional pip:

.. code-block:: bash

   git clone https://github.com/Dashtid/DICOM-Fuzzer.git
   cd DICOM-Fuzzer
   python -m venv .venv
   source .venv/bin/activate  # Windows: .venv\Scripts\activate
   pip install -e .

Verification
------------

Verify the installation by running the test suite:

.. code-block:: bash

   pytest tests/ -v

You should see all 493 tests passing.

Quick Test
~~~~~~~~~~

Run the demo to ensure everything is working:

.. code-block:: bash

   python demo_fuzzing.py

This will:

1. Load configuration
2. Parse a sample DICOM file
3. Generate 10 fuzzed variants
4. Validate outputs
5. Generate performance report

Next Steps
----------

* :doc:`quickstart` - Learn basic usage
* :doc:`configuration` - Configure for your environment
* :doc:`fuzzing_strategies` - Understanding mutation strategies
