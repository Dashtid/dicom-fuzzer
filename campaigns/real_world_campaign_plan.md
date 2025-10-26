# Real-World DICOM Fuzzing Campaign

**Campaign Start Date**: 2025-10-26
**Campaign Goal**: Find real bugs in popular DICOM viewers using 3D series fuzzing
**Expected Duration**: 1-2 weeks

---

## Campaign Objectives

1. **Primary**: Discover crashes, memory corruption, or DoS vulnerabilities in DICOM viewers
2. **Secondary**: Validate fuzzer effectiveness with real-world data
3. **Tertiary**: Generate compelling case studies for project documentation

---

## Target Selection

### DICOM Viewers to Test

**Priority 1 (Free/Open Source)**:

- ✅ **MicroDicom** - Popular free Windows viewer
  - Download: https://www.microdicom.com/downloads.html
  - Version: Latest stable
  - Reason: Widely used, closed-source, good fuzzing target

- ✅ **Horos** (Mac only) - Open-source fork of OsiriX
  - Download: https://horosproject.org/
  - Reason: Open-source, can verify bugs in code

**Priority 2 (Commercial - Trial Versions)**:

- ⚠️ **RadiAnt Viewer** - Professional viewer (30-day trial)
  - Download: https://www.radiantviewer.com/
  - Reason: Enterprise-grade, worth testing

- ⚠️ **Sante DICOM Viewer** - Medical imaging viewer (trial)
  - Download: https://www.santesoft.com/
  - Reason: Used in medical facilities

**Priority 3 (Command-Line Tools)**:

- ✅ **DCMTK dcmdump** - Industry standard
  - Install: `choco install dcmtk` (Windows)
  - Reason: Reference implementation, less likely to crash but worth testing

---

## Test Dataset Strategy

### Approach: Start Small, Scale Up

**Phase 1: Curated Test Sets** (Week 1)

- Use existing `test_data/dicom_samples/` directory
- Create synthetic 3D series (10-50 slices)
- Modalities: CT, MR (most common)

**Phase 2: Real Medical Data** (Week 1-2)

- Download from public repositories (see below)
- Focus on multi-slice CT/MR series
- 100-500 slices per series

### Public DICOM Datasets (Legal & Free)

1. **NEMA DICOM Sample Files** ⭐ RECOMMENDED
   - URL: https://www.dicomstandard.org/
   - Content: Official test files from DICOM standards committee
   - License: Public domain
   - Pros: Clean, well-formed, legal

2. **Medical Segmentation Decathlon**
   - URL: http://medicaldecathlon.com/
   - Content: 10 tasks, CT/MR datasets
   - License: CC BY-SA 4.0
   - Pros: Real clinical data, diverse modalities

3. **TCIA (The Cancer Imaging Archive)**
   - URL: https://www.cancerimagingarchive.net/
   - Content: Thousands of CT/MR/PET series
   - License: Varies (check each collection)
   - Pros: Large-scale real data
   - Cons: Requires registration, large downloads

4. **Visible Human Project**
   - URL: https://www.nlm.nih.gov/research/visible/getting_data.html
   - Content: Full body CT/MR scans
   - License: NLM license
   - Pros: Complete anatomical coverage

**Recommendation**: Start with NEMA samples + create synthetic series

---

## Fuzzing Strategy

### Campaign Structure

```
campaigns/
├── campaign_001_microdicom/
│   ├── config.yaml              # Campaign configuration
│   ├── input/                   # Original DICOM series
│   ├── fuzzed/                  # Mutated series
│   ├── crashes/                 # Crash artifacts
│   ├── reports/                 # Phase 5 reports
│   └── logs/                    # Fuzzing logs
├── campaign_002_radiant/
└── campaign_003_dcmtk/
```

### Mutation Strategy Priority

**Week 1 Focus**:

1. **metadata_corruption** (40% of mutations)
   - Most likely to find bugs
   - Targets parser vulnerabilities

2. **slice_position_attack** (30% of mutations)
   - 3D-specific vulnerabilities
   - Reconstruction bugs

3. **boundary_slice_targeting** (20% of mutations)
   - Edge case vulnerabilities

4. **inconsistency_injection** (10% of mutations)
   - Type confusion bugs

**Week 2 (If bugs found)**:

- Focus on strategies that produced crashes
- Increase severity to "aggressive"
- Test edge cases more thoroughly

### Fuzzing Parameters

**Conservative Start** (Day 1-2):

```bash
python examples/fuzz_3d_series.py \
    --input ./test_data/dicom_samples \
    --output ./campaigns/campaign_001/fuzzed \
    --severity minimal \
    --count 50 \
    --strategy metadata_corruption
```

**Aggressive Testing** (Day 3+):

```bash
python examples/fuzz_3d_series.py \
    --input ./real_datasets/ct_chest \
    --output ./campaigns/campaign_001/fuzzed \
    --severity aggressive \
    --count 200 \
    --all-strategies
```

---

## Testing Methodology

### Step-by-Step Process

1. **Generate Fuzzed Series**

   ```bash
   python examples/fuzz_3d_series.py --input SOURCE --output TARGET --count 100
   ```

2. **Test with Viewer** (Manual for now)

   ```bash
   # MicroDicom
   "C:/Program Files/MicroDicom/MicroDicom.exe" "path/to/fuzzed/series"

   # Monitor for:
   # - Crash dialogs
   # - Hangs (>30 seconds)
   # - Error messages
   # - Memory spikes (Task Manager)
   ```

3. **Document Findings**
   - Screenshot crashes
   - Copy error messages
   - Save crash dumps (if available)
   - Record reproduction steps

4. **Generate Reports**
   ```bash
   python scripts/generate_3d_report.py \
       --campaign-name "MicroDicom Campaign 001" \
       --output-dir ./campaigns/campaign_001/reports
   ```

### Success Criteria

**Minimal Success** (Worth documenting):

- ✅ 1+ reproducible crash
- ✅ Clear crash log/screenshot
- ✅ Identified triggering mutation
- ✅ Phase 5 report generated

**Good Success**:

- ✅ 3+ unique crashes
- ✅ Multiple viewers affected
- ✅ Memory corruption indicators
- ✅ Detailed case study

**Exceptional Success**:

- ✅ 10+ unique vulnerabilities
- ✅ Critical bugs (RCE, memory corruption)
- ✅ CVE-worthy findings
- ✅ Vendor notification process

---

## Safety & Ethics

### Legal Considerations ✅

- ✅ Testing on **your own machine**
- ✅ Using **publicly available software**
- ✅ Using **public domain DICOM data**
- ✅ **No patient data** involved
- ✅ **Responsible disclosure** if bugs found

### Ethical Guidelines

1. **Do NOT**:
   - ❌ Test on production medical systems
   - ❌ Use real patient data
   - ❌ Test software you don't own/license
   - ❌ Publicly disclose 0-days without vendor notification

2. **DO**:
   - ✅ Test on isolated VM/machine
   - ✅ Use synthetic or public datasets
   - ✅ Follow responsible disclosure (90-day window)
   - ✅ Document findings professionally
   - ✅ Offer to help vendors fix bugs

### Responsible Disclosure Process

If critical bug found:

1. **Day 0**: Document bug thoroughly
2. **Day 1-7**: Attempt vendor contact (security@vendor.com)
3. **Day 7-90**: Work with vendor on fix
4. **Day 90+**: Public disclosure (with or without vendor cooperation)

---

## Expected Outcomes

### Realistic Expectations

**High Probability** (80%+):

- Parser errors (non-crash)
- Warning dialogs
- Incorrect rendering
- Performance degradation

**Medium Probability** (30-50%):

- Application crashes
- Memory leaks
- Hangs/infinite loops
- Unhandled exceptions

**Low Probability** (5-10%):

- Memory corruption bugs
- Code execution vulnerabilities
- Critical security issues

### Value Regardless of Findings

Even if **zero crashes** found:

- ✅ Proves fuzzer works correctly
- ✅ Demonstrates systematic testing
- ✅ Shows Phase 5 reporting
- ✅ Validates project methodology
- ✅ Portfolio-worthy case study

---

## Timeline

### Week 1: Setup & Initial Fuzzing

**Day 1-2: Environment Setup**

- Install DICOM viewers
- Download test datasets
- Verify fuzzer functionality
- Create campaign directory structure

**Day 3-4: First Campaign**

- Run initial fuzzing (100-200 test cases)
- Manual testing with viewers
- Document any findings
- Generate Phase 5 reports

**Day 5-7: Analysis & Iteration**

- Analyze results
- Adjust strategies if needed
- Focus on promising mutation types
- Create preliminary documentation

### Week 2: Scale & Document

**Day 8-10: Extended Fuzzing**

- Increase test case count
- Test additional viewers
- Explore edge cases
- Capture screenshots/videos

**Day 11-12: Reporting**

- Generate final Phase 5 reports
- Create case study document
- Prepare demonstration materials
- Update README with findings

**Day 13-14: Publication**

- Polish documentation
- Create demo video/GIF
- Write blog post
- Share results (if appropriate)

---

## Deliverables

### At Campaign Completion

1. **Campaign Report** (`campaigns/campaign_001/REPORT.md`)
   - Executive summary
   - Methodology
   - Findings (crashes, bugs, interesting behaviors)
   - Statistics (mutations applied, test cases, coverage)
   - Phase 5 charts and graphs

2. **Case Study** (`docs/CASE_STUDY_MICRODICOM.md`)
   - Detailed vulnerability analysis
   - Reproduction steps
   - Screenshots/proof
   - Remediation suggestions

3. **Updated README**
   - "Real-World Results" section
   - Bug statistics
   - Viewer compatibility matrix
   - Success stories

4. **Demo Materials**
   - Screenshots of Phase 5 reports
   - Video of fuzzing in action
   - Before/after comparisons

---

## Next Immediate Steps

Run this to get started right now:

```bash
# 1. Create campaign directory
mkdir -p campaigns/campaign_001_microdicom/{input,fuzzed,crashes,reports,logs}

# 2. Check if we have test data
ls test_data/dicom_samples/

# 3. Run first fuzzing batch (conservative)
python examples/fuzz_3d_series.py \
    --input ./test_data/dicom_samples \
    --output ./campaigns/campaign_001_microdicom/fuzzed \
    --severity minimal \
    --count 20

# 4. Generate initial report
python scripts/generate_3d_report.py \
    --campaign-name "MicroDicom Campaign 001 - Initial Run" \
    --series-count 5 \
    --mutation-count 100 \
    --output-dir ./campaigns/campaign_001_microdicom/reports
```

---

**Ready to start? Let's fuzz! 🚀**
