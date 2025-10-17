Testing
=======

DICOM-Fuzzer maintains 100% test coverage with 493 comprehensive tests.

Running Tests
-------------

.. code-block:: bash

   # All tests
   pytest tests/ -v

   # Specific module
   pytest tests/test_parser.py -v

   # With coverage
   pytest tests/ --cov=. --cov-report=html

Test Structure
--------------

* Unit tests - Individual component testing
* Integration tests - End-to-end workflows
* Property-based tests - Using Hypothesis
* Security tests - Validation and safety checks

CI/CD
-----

Tests run automatically on:

* Every push to main/develop
* All pull requests
* Python 3.11, 3.12, 3.13, 3.14
* Windows, Linux, and macOS
