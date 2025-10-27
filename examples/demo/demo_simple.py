#!/usr/bin/env python3
"""
Simple DICOM Fuzzer Demonstration

This script runs a simplified fuzzing demo that:
1. Finds example DICOM files
2. Generates fuzzed variants
3. Visualizes the results
4. Creates a report
"""

import sys

import matplotlib
import matplotlib.pyplot as plt
import pydicom

matplotlib.use("Agg")  # Use non-interactive backend
import logging
import random
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def setup_output_dirs():
    """Create output directories."""
    dirs = [
        "demo_output",
        "demo_output/fuzzed",
        "demo_output/crashes",
        "demo_output/images",
        "demo_output/reports",
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)
    return Path("demo_output")


def find_seed_files() -> list[Path]:
    """Find example DICOM files."""
    example_dir = Path("./test_data/dicom_samples")

    if not example_dir.exists():
        logger.error(f"Example directory not found: {example_dir}")
        logger.info("Please place DICOM test files in ./test_data/dicom_samples/")
        return []

    # Find DICOM files
    dicom_files = []
    for ext in ["*.dcm", "*.DCM", "*"]:
        files = list(example_dir.rglob(ext))
        dicom_files.extend(files)
        if len(dicom_files) >= 3:
            break

    # Filter to valid DICOM files
    valid_files = []
    for f in dicom_files[:10]:  # Check first 10
        try:
            ds = pydicom.dcmread(str(f), force=True)
            if hasattr(ds, "pixel_array"):
                valid_files.append(f)
                if len(valid_files) >= 3:
                    break
        except Exception:
            continue

    return valid_files


def visualize_dicom(file_path: Path, output_path: Path, title: str = None) -> bool:
    """Visualize a DICOM file."""
    try:
        ds = pydicom.dcmread(str(file_path))

        if not hasattr(ds, "pixel_array"):
            return False

        pixel_data = ds.pixel_array

        # Create figure
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

        # Display image
        im = ax1.imshow(pixel_data, cmap="gray")
        ax1.set_title(title or file_path.name, fontsize=10)
        ax1.axis("off")
        plt.colorbar(im, ax=ax1, fraction=0.046)

        # Display histogram
        ax2.hist(
            pixel_data.flatten(),
            bins=50,
            color="steelblue",
            alpha=0.7,
            edgecolor="black",
        )
        ax2.set_title("Pixel Value Distribution")
        ax2.set_xlabel("Pixel Value")
        ax2.set_ylabel("Frequency")
        ax2.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        plt.close()

        logger.info(f"Saved visualization: {output_path.name}")
        return True

    except Exception as e:
        logger.error(f"Failed to visualize {file_path.name}: {e}")
        return False


def simple_mutate_dicom(ds: pydicom.Dataset) -> pydicom.Dataset:
    """Apply simple mutations to a DICOM dataset."""
    # Make a copy
    mutated = ds.copy()

    # Choose random mutation
    mutation_type = random.choice(
        ["modify_pixel", "modify_tag", "flip_bits", "scale_values", "add_noise"]
    )

    if mutation_type == "modify_pixel" and hasattr(mutated, "pixel_array"):
        # Modify random pixels
        pixels = mutated.pixel_array.copy()
        num_modifications = random.randint(10, 100)
        for _ in range(num_modifications):
            y = random.randint(0, pixels.shape[0] - 1)
            x = random.randint(0, pixels.shape[1] - 1)
            pixels[y, x] = random.randint(0, pixels.max())
        mutated.PixelData = pixels.tobytes()

    elif mutation_type == "modify_tag":
        # Modify a random tag value
        modifiable_tags = ["PatientName", "StudyDescription", "SeriesDescription"]
        for tag in modifiable_tags:
            if hasattr(mutated, tag):
                setattr(mutated, tag, f"FUZZED_{random.randint(1000, 9999)}")
                break

    elif mutation_type == "flip_bits" and hasattr(mutated, "pixel_array"):
        # Flip random bits in pixel data
        pixels = mutated.pixel_array.copy()
        num_flips = random.randint(5, 50)
        for _ in range(num_flips):
            y = random.randint(0, pixels.shape[0] - 1)
            x = random.randint(0, pixels.shape[1] - 1)
            pixels[y, x] ^= 1 << random.randint(0, 7)
        mutated.PixelData = pixels.tobytes()

    elif mutation_type == "scale_values" and hasattr(mutated, "pixel_array"):
        # Scale pixel values
        pixels = mutated.pixel_array.copy()
        scale_factor = random.uniform(0.5, 2.0)
        pixels = (pixels * scale_factor).astype(pixels.dtype)
        mutated.PixelData = pixels.tobytes()

    elif mutation_type == "add_noise" and hasattr(mutated, "pixel_array"):
        # Add random noise
        import numpy as np

        pixels = mutated.pixel_array.copy()
        noise = np.random.normal(0, pixels.std() * 0.1, pixels.shape)
        pixels = np.clip(pixels + noise, 0, pixels.max()).astype(pixels.dtype)
        mutated.PixelData = pixels.tobytes()

    return mutated


def simulate_target(dicom_file: Path) -> tuple[bool, str]:
    """Simulate a target application processing DICOM files."""
    try:
        ds = pydicom.dcmread(str(dicom_file))

        # Simulate various crash conditions

        # Check dimensions
        if hasattr(ds, "Rows") and hasattr(ds, "Columns"):
            if ds.Rows > 10000 or ds.Columns > 10000:
                return (
                    False,
                    f"DimensionError: Image too large ({ds.Rows}x{ds.Columns})",
                )
            if ds.Rows == 0 or ds.Columns == 0:
                return False, "DimensionError: Zero dimension"

        # Check pixel data
        if hasattr(ds, "pixel_array"):
            pixels = ds.pixel_array

            if pixels.size == 0:
                return False, "PixelDataError: Empty pixel array"

            # Simulate crash on extreme values
            if pixels.max() > 65535:
                return (
                    False,
                    f"OverflowError: Pixel value {pixels.max()} exceeds maximum",
                )

            # Simulate crash on NaN or inf
            import numpy as np

            if np.any(np.isnan(pixels)) or np.any(np.isinf(pixels)):
                return False, "ValueError: Invalid pixel values (NaN/Inf)"

        # Check required tags
        required = ["SOPClassUID", "SOPInstanceUID"]
        for tag in required:
            if not hasattr(ds, tag):
                return False, f"MissingTagError: Required tag {tag} missing"

        return True, ""

    except Exception as e:
        return False, f"{type(e).__name__}: {e!s}"


def run_demo():
    """Run the fuzzing demonstration."""
    print("=" * 80)
    print("DICOM FUZZER - DEMONSTRATION")
    print("=" * 80)
    print()

    # Setup
    logger.info("Setting up output directories...")
    output_dir = setup_output_dirs()

    # Find seeds
    logger.info("Finding seed DICOM files...")
    seeds = find_seed_files()

    if not seeds:
        logger.error("No valid DICOM seed files found!")
        return

    print(f"\nFound {len(seeds)} seed files:")
    for seed in seeds:
        print(f"  - {seed.name}")

    # Visualize originals
    print("\n[1/4] Visualizing original DICOM files...")
    for i, seed in enumerate(seeds):
        output = output_dir / "images" / f"original_{i + 1}.png"
        visualize_dicom(seed, output, f"Original Seed #{i + 1}: {seed.name}")

    # Generate fuzzed variants
    print("\n[2/4] Generating fuzzed variants...")
    fuzzed_files = []
    variants_per_seed = 10

    for seed_idx, seed in enumerate(seeds):
        try:
            ds = pydicom.dcmread(str(seed))

            for var_idx in range(variants_per_seed):
                # Mutate
                mutated = simple_mutate_dicom(ds)

                # Save
                output_file = (
                    output_dir / "fuzzed" / f"seed{seed_idx + 1}_var{var_idx + 1}.dcm"
                )
                mutated.save_as(str(output_file))
                fuzzed_files.append(output_file)

                # Visualize first few
                if var_idx < 3:
                    img_output = (
                        output_dir
                        / "images"
                        / f"fuzzed_seed{seed_idx + 1}_var{var_idx + 1}.png"
                    )
                    visualize_dicom(
                        output_file,
                        img_output,
                        f"Fuzzed Variant: Seed #{seed_idx + 1}, Variant #{var_idx + 1}",
                    )

            logger.info(f"Generated {variants_per_seed} variants from {seed.name}")

        except Exception as e:
            logger.error(f"Failed to process {seed.name}: {e}")

    print(f"\nTotal fuzzed files generated: {len(fuzzed_files)}")

    # Test variants
    print("\n[3/4] Testing fuzzed files against simulated target...")
    crashes = []

    for fuzz_file in fuzzed_files:
        success, error = simulate_target(fuzz_file)

        if not success:
            crashes.append({"file": fuzz_file.name, "error": error})

            # Move to crashes dir
            crash_dest = output_dir / "crashes" / fuzz_file.name
            fuzz_file.rename(crash_dest)

    print("\nTesting complete:")
    print(f"  - Files tested: {len(fuzzed_files)}")
    print(f"  - Crashes found: {len(crashes)}")
    print(f"  - Crash rate: {len(crashes) / len(fuzzed_files) * 100:.1f}%")

    # Generate report
    print("\n[4/4] Generating report...")

    report = f"""# DICOM Fuzzer - Demonstration Report

## Executive Summary

**Date:** {Path("demo_output").stat().st_mtime}
**Duration:** Demo session
**Status:** Complete

## Configuration

- **Seed Files:** {len(seeds)}
- **Variants Per Seed:** {variants_per_seed}
- **Total Fuzzed Files:** {len(fuzzed_files)}

## Results

### Overall Statistics

| Metric | Value |
|--------|-------|
| Total Test Cases | {len(fuzzed_files)} |
| Crashes Detected | {len(crashes)} |
| Crash Rate | {len(crashes) / len(fuzzed_files) * 100:.1f}% |
| Successful Tests | {len(fuzzed_files) - len(crashes)} |

### Seed Files

"""

    for i, seed in enumerate(seeds, 1):
        report += f"{i}. `{seed.name}`\n"

    report += "\n### Crashes Detected\n\n"

    if crashes:
        # Group by error type
        error_types = {}
        for crash in crashes:
            error_type = crash["error"].split(":")[0]
            if error_type not in error_types:
                error_types[error_type] = []
            error_types[error_type].append(crash)

        for error_type, crash_list in error_types.items():
            report += f"\n#### {error_type} ({len(crash_list)} occurrences)\n\n"
            for crash in crash_list[:5]:  # Show first 5
                report += f"- `{crash['file']}`: {crash['error']}\n"
            if len(crash_list) > 5:
                report += f"- ... and {len(crash_list) - 5} more\n"
    else:
        report += "\nNo crashes detected.\n"

    report += "\n## Visualizations\n\n"
    report += "### Original Seed Files\n\n"

    for i in range(len(seeds)):
        report += f"![Original Seed {i + 1}](../images/original_{i + 1}.png)\n\n"

    report += "### Example Fuzzed Variants\n\n"

    for seed_idx in range(len(seeds)):
        for var_idx in range(min(3, variants_per_seed)):
            img_file = f"fuzzed_seed{seed_idx + 1}_var{var_idx + 1}.png"
            if (output_dir / "images" / img_file).exists():
                report += f"![Fuzzed Variant](../images/{img_file})\n\n"

    report += "\n## Output Files\n\n"
    report += f"- **Visualizations:** `demo_output/images/` ({len(list((output_dir / 'images').glob('*.png')))} images)\n"
    report += f"- **Fuzzed Files:** `demo_output/fuzzed/` ({len(list((output_dir / 'fuzzed').glob('*.dcm')))} files)\n"
    report += f"- **Crashes:** `demo_output/crashes/` ({len(list((output_dir / 'crashes').glob('*.dcm')))} files)\n"
    report += "- **Reports:** `demo_output/reports/`\n"

    report += "\n---\n\n"
    report += "*Generated by DICOM Fuzzer - Demonstration Mode*\n"

    # Save report
    report_path = output_dir / "reports" / "FUZZING_REPORT.md"
    report_path.write_text(report)

    logger.info(f"Report saved to: {report_path}")

    # Summary
    print("\n" + "=" * 80)
    print("DEMONSTRATION COMPLETE")
    print("=" * 80)
    print("\nResults:")
    print(f"  Seed files: {len(seeds)}")
    print(f"  Fuzzed variants: {len(fuzzed_files)}")
    print(f"  Crashes found: {len(crashes)}")
    print("\nOutput locations:")
    print(f"  Images: {output_dir / 'images'}")
    print(f"  Crashes: {output_dir / 'crashes'}")
    print(f"  Report: {report_path}")
    print("\n" + "=" * 80)

    return report_path


if __name__ == "__main__":
    try:
        run_demo()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        logger.error(f"Demo failed: {e}", exc_info=True)
        sys.exit(1)
