Quick Start Guide
=================

Get up and running with DICOM-Fuzzer in minutes.

Your First Fuzzing Campaign
----------------------------

1. **Prepare Sample DICOM Files**

   Place your sample DICOM files in the ``samples/`` directory:

   .. code-block:: bash

      cp /path/to/your/dicom/files/*.dcm samples/

   .. warning::
      Never use real patient data! Always use synthetic or anonymized samples.

2. **Run the Demo**

   The easiest way to start is with the included demo:

   .. code-block:: bash

      python demo_fuzzing.py

   This will:

   * Load configuration from ``.env`` or defaults
   * Generate 10 fuzzed variants
   * Validate each output
   * Create performance reports
   * Display statistics

3. **Check the Results**

   Generated files and reports are in:

   * ``output/`` - Fuzzed DICOM files
   * ``reports/`` - HTML performance reports
   * ``crashes/`` - Crash analysis reports (if any)

Basic CLI Usage
---------------

Generate Fuzzed Files
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   python main.py --input samples/CT_small.dcm --output output/ --count 100

This generates 100 fuzzed variants of the input file.

Custom Strategies
~~~~~~~~~~~~~~~~~

Specify which fuzzing strategies to use:

.. code-block:: bash

   python main.py --input samples/CT_small.dcm \\
                  --output output/ \\
                  --strategies metadata header pixel \\
                  --count 50

Available strategies:

* ``metadata`` - Mutate patient information, study details
* ``header`` - Mutate DICOM tags and structure
* ``pixel`` - Mutate pixel data (if present)
* ``structure`` - Mutate file structure, sequences

Configuration
-------------

Basic Configuration
~~~~~~~~~~~~~~~~~~~

Create a ``.env`` file in the project root:

.. code-block:: bash

   cp .env.example .env

Edit ``.env`` to customize settings:

.. code-block:: ini

   # Fuzzing Configuration
   FUZZING__METADATA_PROBABILITY=0.8
   FUZZING__MAX_MUTATIONS_PER_FILE=3
   FUZZING__MAX_FILES_PER_CAMPAIGN=1000

   # Security Limits
   SECURITY__MAX_FILE_SIZE_MB=100
   SECURITY__STRICT_VALIDATION=false

   # Output Paths
   PATHS__OUTPUT_DIR=./output
   PATHS__CRASH_DIR=./crashes

Environment Profiles
~~~~~~~~~~~~~~~~~~~~

Use predefined environment profiles:

.. code-block:: bash

   # Development (aggressive fuzzing, verbose logs)
   cp .env.development .env

   # Testing (predictable, for CI/CD)
   cp .env.testing .env

   # Production (optimized, strict security)
   cp .env.production .env

Understanding Output
--------------------

Generated Files
~~~~~~~~~~~~~~~

Fuzzed DICOM files are named systematically:

.. code-block:: text

   output/
   ├── fuzzed_001.dcm
   ├── fuzzed_002.dcm
   └── ...

Performance Reports
~~~~~~~~~~~~~~~~~~~

HTML reports show:

* Throughput (files/second)
* Memory usage
* Strategy effectiveness
* Campaign duration

Open ``reports/performance_report_*.html`` in a browser.

Crash Reports
~~~~~~~~~~~~~

If fuzzing discovers crashes:

.. code-block:: text

   crashes/
   ├── crash_20241001_123456_abc123.txt
   └── ...

Each report contains:

* Stack trace
* Exception details
* Test case that triggered crash
* Severity classification

Common Tasks
------------

Batch Processing
~~~~~~~~~~~~~~~~

Process multiple files:

.. code-block:: bash

   for file in samples/*.dcm; do
       python main.py --input "$file" --output output/ --count 10
   done

Integration with Testing
~~~~~~~~~~~~~~~~~~~~~~~~~

Use fuzzed files to test your DICOM parser:

.. code-block:: python

   from pathlib import Path
   import your_dicom_parser

   # Test with fuzzed files
   for fuzzed_file in Path("output").glob("*.dcm"):
       try:
           your_dicom_parser.parse(fuzzed_file)
       except Exception as e:
           print(f"Found issue: {e}")

Next Steps
----------

* :doc:`configuration` - Detailed configuration options
* :doc:`fuzzing_strategies` - Understanding mutation strategies
* :doc:`crash_analysis` - Analyzing discovered vulnerabilities
* :doc:`reporting` - Working with reports
