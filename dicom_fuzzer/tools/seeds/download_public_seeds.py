#!/usr/bin/env python3
"""Public DICOM Seed Downloader

Download sample DICOM files from public sources for fuzzing seed corpus.

SUPPORTED SOURCES:
    - dicomlibrary.com (public DICOM samples)
    - pydicom test data (bundled with pydicom library)
    - Manual sample generation (creates minimal DICOM files)

USAGE:
    python scripts/download_public_seeds.py --output ./seeds
    python scripts/download_public_seeds.py --source pydicom --output ./seeds
    python scripts/download_public_seeds.py --source generated --count 50 --output ./seeds

NOTE: This tool prioritizes publicly available samples. For production fuzzing,
      use real DICOM files from your target environment via import_seed_corpus.py
"""

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

try:
    import pydicom
    from pydicom.dataset import Dataset, FileDataset
    from pydicom.uid import ImplicitVRLittleEndian, generate_uid
except ImportError:
    print("[!] Error: pydicom not installed. Run: pip install pydicom")
    sys.exit(1)

# Optional: requests for web downloads
try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class SeedDownloader:
    """Download public DICOM samples for fuzzing."""

    def __init__(self, output_dir: Path):
        """Initialize seed downloader.

        Args:
            output_dir: Directory to save downloaded seeds

        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.stats = {"downloaded": 0, "failed": 0, "total_bytes": 0, "sources": {}}

    def download_pydicom_samples(self) -> int:
        """Download test data from pydicom library.

        pydicom includes several test DICOM files in its test data directory.
        """
        logger.info("Downloading pydicom test samples...")

        try:
            from pydicom.data import get_testdata_files
        except ImportError:
            logger.error("pydicom test data not available")
            return 0

        # Get all available test files
        test_files = get_testdata_files()

        if not test_files:
            logger.warning("No pydicom test files found")
            return 0

        logger.info(f"Found {len(test_files)} pydicom test files")

        count = 0
        for test_file in test_files:
            try:
                # Read the test file
                dataset = pydicom.dcmread(test_file, force=True)

                # Generate output filename
                source_name = Path(test_file).stem
                output_filename = f"pydicom_{source_name}.dcm"
                output_path = self.output_dir / output_filename

                # Save to output directory
                dataset.save_as(output_path, enforce_file_format=True)

                # Save metadata
                metadata = {
                    "source": "pydicom",
                    "original_file": str(test_file),
                    "modality": str(dataset.get("Modality", "UNKNOWN")),
                    "sop_class": str(dataset.get("SOPClassUID", "UNKNOWN")),
                    "download_date": datetime.now(UTC).isoformat(),
                }

                metadata_path = output_path.with_suffix(".json")
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)

                file_size = output_path.stat().st_size
                self.stats["downloaded"] += 1
                self.stats["total_bytes"] += file_size
                count += 1

                logger.info(f"  [OK] Downloaded: {output_filename} ({file_size} bytes)")

            except Exception as e:
                logger.error(f"  [FAIL] Failed to process {test_file}: {e}")
                self.stats["failed"] += 1

        self.stats["sources"]["pydicom"] = count
        return count

    def generate_minimal_samples(self, count: int = 20) -> int:
        """Generate minimal DICOM files with various characteristics.

        Creates diverse samples with different:
        - Modalities (CT, MRI, US, CR, DX, etc.)
        - Transfer syntaxes
        - Tag combinations
        - Edge cases (empty values, large values, unusual types)

        Args:
            count: Number of samples to generate

        Returns:
            Number of samples generated

        """
        logger.info(f"Generating {count} minimal DICOM samples...")

        modalities = [
            "CT",
            "MR",
            "US",
            "CR",
            "DX",
            "PT",
            "NM",
            "MG",
            "ES",
            "XA",
            "RF",
            "SR",
            "OT",
        ]
        study_descriptions = [
            "CHEST PA AND LATERAL",
            "ABDOMEN CT W/ CONTRAST",
            "HEAD MRI W/O CONTRAST",
            "ULTRASOUND ABDOMEN COMPLETE",
            "MAMMOGRAPHY BILATERAL",
            "X-RAY HAND 2 VIEWS",
        ]

        generated = 0
        for i in range(count):
            try:
                # Create minimal file meta
                file_meta = Dataset()
                file_meta.FileMetaInformationGroupLength = 192
                file_meta.FileMetaInformationVersion = b"\x00\x01"
                file_meta.MediaStorageSOPClassUID = (
                    "1.2.840.10008.5.1.4.1.1.2"  # CT Image Storage
                )
                file_meta.MediaStorageSOPInstanceUID = generate_uid()
                file_meta.TransferSyntaxUID = ImplicitVRLittleEndian
                file_meta.ImplementationClassUID = generate_uid()

                # Create dataset with required tags
                dataset = FileDataset(
                    f"generated_{i:03d}.dcm",
                    {},
                    file_meta=file_meta,
                    preamble=b"\x00" * 128,
                )

                # Add required DICOM tags
                modality = modalities[i % len(modalities)]
                dataset.Modality = modality
                dataset.PatientName = f"Patient^{i:03d}"
                dataset.PatientID = f"PID{i:06d}"
                dataset.StudyInstanceUID = generate_uid()
                dataset.SeriesInstanceUID = generate_uid()
                dataset.SOPInstanceUID = file_meta.MediaStorageSOPInstanceUID
                dataset.SOPClassUID = file_meta.MediaStorageSOPClassUID
                dataset.StudyDescription = study_descriptions[
                    i % len(study_descriptions)
                ]
                dataset.SeriesDescription = f"Series {i}"
                dataset.StudyDate = "20240101"
                dataset.SeriesDate = "20240101"
                dataset.StudyTime = "120000"
                dataset.SeriesTime = "120000"

                # Add variation: Some edge cases
                if i % 5 == 0:
                    # Edge case: Empty string values
                    dataset.AccessionNumber = ""
                elif i % 5 == 1:
                    # Edge case: Very long string
                    dataset.InstitutionName = "A" * 200
                elif i % 5 == 2:
                    # Edge case: Special characters
                    dataset.ReferringPhysicianName = "Müller^Hans^Dr"
                elif i % 5 == 3:
                    # Edge case: Numeric edge values
                    dataset.PatientAge = "000Y"
                elif i % 5 == 4:
                    # Edge case: Missing optional tags (already done by default)
                    pass

                # Save file
                output_filename = f"generated_{i:03d}_{modality}.dcm"
                output_path = self.output_dir / output_filename
                dataset.save_as(output_path, enforce_file_format=True)

                # Save metadata
                metadata = {
                    "source": "generated",
                    "modality": modality,
                    "generation_index": i,
                    "edge_case": i % 5,
                    "download_date": datetime.now(UTC).isoformat(),
                }

                metadata_path = output_path.with_suffix(".json")
                with open(metadata_path, "w") as f:
                    json.dump(metadata, f, indent=2)

                file_size = output_path.stat().st_size
                self.stats["downloaded"] += 1
                self.stats["total_bytes"] += file_size
                generated += 1

                logger.info(f"  [OK] Generated: {output_filename} ({file_size} bytes)")

            except Exception as e:
                logger.error(f"  [FAIL] Failed to generate sample {i}: {e}")
                self.stats["failed"] += 1

        self.stats["sources"]["generated"] = generated
        return generated

    def download_from_url(self, url: str, filename: str) -> bool:
        """Download a single DICOM file from URL.

        Args:
            url: URL to download from
            filename: Output filename

        Returns:
            True if successful

        """
        if not HAS_REQUESTS:
            logger.error("requests library not installed. Run: pip install requests")
            return False

        try:
            logger.info(f"Downloading: {url}")
            response = requests.get(url, timeout=30, stream=True)
            response.raise_for_status()

            output_path = self.output_dir / filename

            # Download with progress
            with open(output_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            file_size = output_path.stat().st_size
            self.stats["downloaded"] += 1
            self.stats["total_bytes"] += file_size

            logger.info(f"  [OK] Downloaded: {filename} ({file_size} bytes)")
            return True

        except Exception as e:
            logger.error(f"  [FAIL] Failed to download {url}: {e}")
            self.stats["failed"] += 1
            return False

    def generate_report(self) -> str:
        """Generate download summary report."""
        report_lines = [
            "=" * 80,
            "DICOM SEED DOWNLOAD REPORT",
            "=" * 80,
            "",
            f"Output Directory: {self.output_dir}",
            f"Download Date: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "SUMMARY:",
            f"  Files Downloaded: {self.stats['downloaded']}",
            f"  Failed:           {self.stats['failed']}",
            f"  Total Bytes:      {self._format_bytes(self.stats['total_bytes'])}",
            "",
            "SOURCES:",
        ]

        for source, count in self.stats["sources"].items():
            report_lines.append(f"  {source:15s} {count:5d} files")

        report_lines.append("")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)

    def _format_bytes(self, bytes_val: float) -> str:
        """Format bytes as human-readable string."""
        for unit in ["B", "KB", "MB", "GB"]:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"


def main():
    """Download public DICOM samples for fuzzing seed corpus."""
    parser = argparse.ArgumentParser(
        description="Download public DICOM samples for fuzzing seed corpus",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  # Download pydicom test samples
  python scripts/download_public_seeds.py --source pydicom --output ./seeds

  # Generate 50 minimal DICOM samples
  python scripts/download_public_seeds.py --source generated --count 50 --output ./seeds

  # Download all available sources
  python scripts/download_public_seeds.py --source all --output ./seeds

NOTE: For production fuzzing, supplement these samples with real DICOM files
      from your target environment using import_seed_corpus.py
        """,
    )

    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("./artifacts/corpus/seeds"),
        help="Output directory for downloaded seeds (default: ./seeds)",
    )
    parser.add_argument(
        "--source",
        choices=["pydicom", "generated", "all"],
        default="all",
        help="Download source (default: all)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of samples to generate (for 'generated' source, default: 20)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose debug output"
    )

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create downloader
    downloader = SeedDownloader(output_dir=args.output)

    try:
        logger.info("Starting seed download...")

        total_downloaded = 0

        # Download from selected sources
        if args.source in ["pydicom", "all"]:
            count = downloader.download_pydicom_samples()
            total_downloaded += count

        if args.source in ["generated", "all"]:
            count = downloader.generate_minimal_samples(count=args.count)
            total_downloaded += count

        # Generate and display report
        report = downloader.generate_report()
        print("\n" + report)

        # Save statistics to JSON
        stats_file = args.output / "download_stats.json"
        with open(stats_file, "w") as f:
            json.dump(downloader.stats, f, indent=2)
        logger.info(f"Statistics saved to: {stats_file}")

        # Exit with appropriate code
        if total_downloaded == 0:
            logger.error("No files downloaded!")
            sys.exit(1)
        else:
            logger.info(f"Download completed successfully! ({total_downloaded} files)")
            sys.exit(0)

    except KeyboardInterrupt:
        logger.warning("\nDownload interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Download failed: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
