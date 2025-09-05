# Primary libraries
import pydicom          # DICOM file manipulation
import numpy as np      # Pixel data manipulation
import random           # Basic randomization
import uuid             # Unique identifiers
import os, json, logging
from pathlib import Path
from datetime import datetime, timedelta

import argparse
from core.generator import DICOMGenerator

def main():
    parser = argparse.ArgumentParser(description="DICOM Fuzzer")
    parser.add_argument("input_file", help="Original DICOM file")
    parser.add_argument("-c", "--count", type=int, default=100, 
                       help="Number of fuzzed files to generate")
    parser.add_argument("-o", "--output", default="./fuzzed_dicoms",
                       help="Output directory")
    
    args = parser.parse_args()
    
    generator = DICOMGenerator(args.output)
    files = generator.generate_batch(args.input_file, args.count)
    
    print(f"Generated {len(files)} fuzzed DICOM files in {args.output}")

if __name__ == "__main__":
    main()