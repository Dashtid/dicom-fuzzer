# dicom-seeds (local)

This directory is a **local, untracked** seed corpus for your own dicom-fuzzer campaigns. The directory scaffolding (modality subfolders and this README) is version-controlled; the `.dcm` files you place inside are **not** — they are excluded by the root `.gitignore` to prevent accidental PHI commits.

Build up a high-quality corpus here over time. The fuzzer will pick up anything you drop in.

## Directory Structure

```
dicom-seeds/
  ct/               CT Image Storage
  dx/               Digital X-Ray (DX) Image Storage
  encapsulated-pdf/ Encapsulated PDF Storage
  mr/               MR Image Storage
  nm/               Nuclear Medicine Image Storage
  pet/              PET Image Storage
  rt-dose/          RT Dose Storage
  rt-struct/        RT Structure Set Storage
  seg/              Segmentation Storage
```

## Filename Convention

```
<modality>_<dimensions>_<bit-depth>_<transfer-syntax>.dcm
```

| Component       | Format                           | Examples                                                         |
| --------------- | -------------------------------- | ---------------------------------------------------------------- |
| modality        | Lowercase DICOM modality         | `ct`, `mr`, `dx`, `pt`, `nm`, `rtdose`, `rtstruct`, `seg`, `doc` |
| dimensions      | `WxH` or `WxHxNf` for multiframe | `512x512`, `128x128x78f`                                         |
| bit-depth       | `Nbit` (BitsStored value)        | `8bit`, `12bit`, `16bit`                                         |
| transfer-syntax | Short code                       | `ivle`, `evle`, `evbe`                                           |

Omit dimensions and bit-depth for modalities without pixel data (e.g. RTSTRUCT, Encapsulated PDF).

### Transfer Syntax Codes

| Code   | Transfer Syntax UID    | Name                      |
| ------ | ---------------------- | ------------------------- |
| `ivle` | 1.2.840.10008.1.2      | Implicit VR Little Endian |
| `evle` | 1.2.840.10008.1.2.1    | Explicit VR Little Endian |
| `evbe` | 1.2.840.10008.1.2.2    | Explicit VR Big Endian    |
| `jpls` | 1.2.840.10008.1.2.4.70 | JPEG Lossless SV1         |

### Example filenames

```
ct/ct_512x512_12bit_ivle.dcm
dx/dx_1024x1024_8bit_ivle.dcm
mr/mr_260x320_12bit_ivle.dcm
nm/nm_128x128x118f_16bit_ivle.dcm
pet/pt_144x144_16bit_ivle.dcm
rt-dose/rtdose_128x128x78f_16bit_evle.dcm
rt-struct/rtstruct_ivle.dcm
seg/seg_64x64x2f_1bit_evle.dcm
encapsulated-pdf/doc_evle.dcm
```

Prefer realistic clinical dimensions (CT 512x512, DX 1024+, multiframe NM/RT with real frame counts) and the transfer syntaxes your target viewer actually consumes. Small, downscaled seeds exercise less parser code and find fewer bugs.

## Usage

Point the fuzzer at this directory to exercise all modality-specific strategies:

```bash
dicom-fuzzer ./dicom-seeds/ -r -c 50 -o ./artifacts/campaigns/demo
```

Note: `-c N` is **per seed file**, not total. With 9 seeds, `-c 10` produces 90 fuzzed files.

## Sourcing Seeds (all must be PHI-free before placing here)

- **Public datasets** -- [NIH Chest X-ray](https://cloud.google.com/healthcare-api/docs/resources/public-datasets/nih-chest) (CC BY 4.0), [TCIA](https://www.cancerimagingarchive.net/), [pydicom/pydicom-data](https://github.com/pydicom/pydicom-data)
- **Synthetic** -- `dicom-fuzzer generate-seeds --synthetic {seg,rtss,pdf}` generates valid skeletons from scratch
- **In-house clinical data** -- run `dicom-fuzzer sanitize <source-dir> -o <target-in-dicom-seeds>` to strip PHI before placing files here. Never drop unsanitized clinical files into this directory; the `.gitignore` is a last line of defense, not a substitute for sanitization.
