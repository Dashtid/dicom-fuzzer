#!/usr/bin/env python3
"""
DICOM Fuzzer - Complete Workflow Demonstration

This script demonstrates a complete fuzzing workflow:
1. Parse seed DICOM files
2. Generate multiple fuzzed variations
3. Visualize the fuzzing results
4. Generate a comprehensive report
"""

import sys
from pathlib import Path
from typing import List
import logging

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from core.parser import DICOMParser
from core.generator import DICOMGenerator
from core.mutator import DICAMMutator
from core.fuzzing_session import FuzzingSession
from core.reporter import Reporter
from core.crash_analyzer import CrashAnalyzer
from core.corpus import Corpus
from core.coverage_tracker import CoverageTracker
from core.statistics import Statistics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_directories():
    """Create necessary directories for the demo."""
    dirs = [
        'demo_output',
        'demo_output/fuzzed',
        'demo_output/crashes',
        'demo_output/images',
        'demo_output/reports'
    ]
    for dir_path in dirs:
        Path(dir_path).mkdir(parents=True, exist_ok=True)
    logger.info("Created output directories")


def find_seed_files() -> List[Path]:
    """Find example DICOM files to use as seeds."""
    # Look for example DICOM files in common locations
    example_dir = Path("//c/Data/Kiwi - Example Data - 20210423")

    if example_dir.exists():
        # Find DICOM files (they often have no extension or .dcm)
        dicom_files = list(example_dir.rglob("*.dcm"))[:3]  # Limit to 3 files
        if not dicom_files:
            # Try files without extension
            dicom_files = [f for f in example_dir.rglob("*") if f.is_file()][:3]
        return dicom_files

    logger.warning(f"Example directory not found: {example_dir}")
    return []


def visualize_dicom(file_path: Path, output_path: Path) -> bool:
    """
    Visualize a DICOM file and save as PNG.

    Args:
        file_path: Path to DICOM file
        output_path: Path to save PNG image

    Returns:
        True if successful, False otherwise
    """
    try:
        import pydicom
        import matplotlib.pyplot as plt
        import numpy as np

        # Read DICOM file
        ds = pydicom.dcmread(str(file_path))

        # Get pixel data if available
        if hasattr(ds, 'pixel_array'):
            pixel_data = ds.pixel_array

            # Create visualization
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

            # Display image
            ax1.imshow(pixel_data, cmap='gray')
            ax1.set_title(f'DICOM Image\n{file_path.name}')
            ax1.axis('off')

            # Display histogram
            ax2.hist(pixel_data.flatten(), bins=50, color='blue', alpha=0.7)
            ax2.set_title('Pixel Intensity Distribution')
            ax2.set_xlabel('Pixel Value')
            ax2.set_ylabel('Frequency')
            ax2.grid(True, alpha=0.3)

            plt.tight_layout()
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()

            logger.info(f"Saved visualization: {output_path}")
            return True
        else:
            logger.warning(f"No pixel data in {file_path}")
            return False

    except Exception as e:
        logger.error(f"Failed to visualize {file_path}: {e}")
        return False


def simulate_target_application(dicom_file: Path) -> tuple[bool, str]:
    """
    Simulate a target application that processes DICOM files.
    This simulates various crash conditions for demonstration.

    Args:
        dicom_file: Path to DICOM file to process

    Returns:
        Tuple of (success, error_message)
    """
    try:
        import pydicom

        ds = pydicom.dcmread(str(dicom_file))

        # Simulate various crash conditions

        # Check for extremely large dimensions (simulated crash)
        if hasattr(ds, 'Rows') and hasattr(ds, 'Columns'):
            if ds.Rows > 10000 or ds.Columns > 10000:
                raise ValueError(f"Image dimensions too large: {ds.Rows}x{ds.Columns}")

        # Check for invalid pixel data (simulated crash)
        if hasattr(ds, 'pixel_array'):
            pixel_data = ds.pixel_array
            if pixel_data.size == 0:
                raise ValueError("Empty pixel data array")

            # Simulate crash on unusual pixel values
            if pixel_data.max() > 65535:
                raise OverflowError(f"Pixel value overflow: {pixel_data.max()}")

        # Check for missing required tags (simulated crash)
        required_tags = ['SOPClassUID', 'SOPInstanceUID', 'StudyInstanceUID']
        for tag in required_tags:
            if not hasattr(ds, tag):
                raise AttributeError(f"Missing required tag: {tag}")

        # Successfully processed
        return True, ""

    except Exception as e:
        return False, str(e)


def run_fuzzing_workflow():
    """Run the complete fuzzing workflow."""
    logger.info("=" * 80)
    logger.info("DICOM Fuzzer - Complete Workflow Demonstration")
    logger.info("=" * 80)

    # Setup
    setup_directories()

    # Find seed files
    logger.info("\n[1/5] Finding seed DICOM files...")
    seed_files = find_seed_files()

    if not seed_files:
        logger.error("No seed files found. Please ensure example DICOM files are available.")
        return

    logger.info(f"Found {len(seed_files)} seed files:")
    for seed in seed_files:
        logger.info(f"  - {seed}")

    # Visualize original seed files
    logger.info("\n[2/5] Visualizing original DICOM files...")
    for i, seed in enumerate(seed_files):
        output_path = Path(f"demo_output/images/original_{i+1}.png")
        visualize_dicom(seed, output_path)

    # Generate fuzzed variants
    logger.info("\n[3/5] Generating fuzzed variants...")
    parser = DICOMParser()
    generator = DICOMGenerator()
    mutator = DICAMMutator()

    fuzzed_files = []
    mutations_per_seed = 10

    for seed_idx, seed in enumerate(seed_files):
        try:
            # Parse seed file
            dicom_dict = parser.parse_file(str(seed))

            # Generate fuzzed variants
            for variant_idx in range(mutations_per_seed):
                # Mutate the DICOM structure
                mutated = mutator.mutate(dicom_dict)

                # Generate output file
                output_file = Path(f"demo_output/fuzzed/seed{seed_idx+1}_variant{variant_idx+1}.dcm")
                generator.generate(mutated, str(output_file))
                fuzzed_files.append(output_file)

                # Visualize first few variants
                if variant_idx < 3:
                    img_output = Path(f"demo_output/images/seed{seed_idx+1}_variant{variant_idx+1}.png")
                    visualize_dicom(output_file, img_output)

            logger.info(f"Generated {mutations_per_seed} variants from {seed.name}")

        except Exception as e:
            logger.error(f"Failed to process {seed}: {e}")

    logger.info(f"Total fuzzed files generated: {len(fuzzed_files)}")

    # Run fuzzing session
    logger.info("\n[4/5] Running fuzzing session...")

    corpus = Corpus()
    coverage = CoverageTracker()
    analyzer = CrashAnalyzer()
    stats = Statistics()

    session = FuzzingSession(
        corpus=corpus,
        mutator=mutator,
        generator=generator,
        coverage_tracker=coverage,
        crash_analyzer=analyzer,
        statistics=stats,
        max_iterations=len(fuzzed_files)
    )

    # Test each fuzzed file
    crashes_found = []
    for fuzz_file in fuzzed_files:
        success, error_msg = simulate_target_application(fuzz_file)

        if not success:
            # Record crash
            crashes_found.append({
                'file': fuzz_file,
                'error': error_msg
            })

            # Analyze crash
            try:
                parser = DICOMParser()
                crash_dict = parser.parse_file(str(fuzz_file))
                analyzer.analyze_crash(crash_dict, error_msg)

                # Save crash file
                crash_output = Path(f"demo_output/crashes/{fuzz_file.name}")
                fuzz_file.rename(crash_output)
            except Exception as e:
                logger.error(f"Failed to analyze crash: {e}")

        # Update statistics
        stats.increment_iterations()
        if not success:
            stats.increment_crashes()

    logger.info(f"Fuzzing complete: {len(crashes_found)} crashes found")

    # Generate report
    logger.info("\n[5/5] Generating comprehensive report...")

    reporter = Reporter(
        statistics=stats,
        crash_analyzer=analyzer,
        coverage_tracker=coverage
    )

    report_path = Path("demo_output/reports/fuzzing_report.md")
    reporter.generate_report(str(report_path))

    # Also generate HTML report
    html_report_path = Path("demo_output/reports/fuzzing_report.html")
    reporter.export_html(str(html_report_path))

    logger.info(f"Report saved to: {report_path}")
    logger.info(f"HTML report saved to: {html_report_path}")

    # Summary
    logger.info("\n" + "=" * 80)
    logger.info("WORKFLOW COMPLETE - Summary")
    logger.info("=" * 80)
    logger.info(f"Seed files processed: {len(seed_files)}")
    logger.info(f"Fuzzed variants generated: {len(fuzzed_files)}")
    logger.info(f"Crashes discovered: {len(crashes_found)}")
    logger.info(f"Unique crash signatures: {len(analyzer.crash_signatures)}")
    logger.info(f"\nOutput directories:")
    logger.info(f"  - Images: demo_output/images/")
    logger.info(f"  - Fuzzed files: demo_output/fuzzed/")
    logger.info(f"  - Crashes: demo_output/crashes/")
    logger.info(f"  - Reports: demo_output/reports/")
    logger.info("=" * 80)

    if crashes_found:
        logger.info("\nCrash Details:")
        for i, crash in enumerate(crashes_found[:5], 1):  # Show first 5
            logger.info(f"  {i}. {crash['file'].name}")
            logger.info(f"     Error: {crash['error']}")
        if len(crashes_found) > 5:
            logger.info(f"  ... and {len(crashes_found) - 5} more (see report)")


if __name__ == '__main__':
    try:
        run_fuzzing_workflow()
    except KeyboardInterrupt:
        logger.info("\nWorkflow interrupted by user")
    except Exception as e:
        logger.error(f"Workflow failed: {e}", exc_info=True)
        sys.exit(1)
