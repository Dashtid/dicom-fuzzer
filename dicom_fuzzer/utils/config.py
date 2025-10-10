# config.py
MUTATION_STRATEGIES = {
    "metadata_probability": 0.8,
    "header_probability": 0.6,
    "pixel_probability": 0.3,
    "max_mutations_per_file": 3,
}

FAKE_DATA_POOLS = {
    "institutions": ["General Hospital", "Medical Center", "Clinic"],
    "modalities": ["CT", "MR", "US", "XR"],
    "manufacturers": ["GE", "Siemens", "Philips"],
}
