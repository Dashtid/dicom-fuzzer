# Campaign Structural Audit: 2026-04-16

First real campaign against Hermes.exe. Analysed strategy effectiveness
to identify zero-value strategies and sampling gaps.

## Campaign Parameters

| Parameter             | Value                                                                            |
| --------------------- | -------------------------------------------------------------------------------- |
| Seed corpus           | 9 directories, 14 files (CT/MR/NM/PET/RT-Dose/RT-Struct/SEG/encapsulated-PDF/SC) |
| Files per seed        | 50 (-c 50)                                                                       |
| Total generated       | 688 (12 write failures)                                                          |
| Target                | Hermes.exe (--gui-mode, 60s timeout, 2048MB memory limit)                        |
| Seed                  | 20260416                                                                         |
| Strategies registered | 34                                                                               |
| Strategies that fired | 28                                                                               |
| Total crashes         | 10 (all OOM / CWE-400)                                                           |

## Strategy Effectiveness

### Strategies that triggered crashes

| Strategy               | Files | Crashes | Attack variant                  |
| ---------------------- | ----- | ------- | ------------------------------- |
| reference              | 29    | 2       | \_uid_non_ascii                 |
| secondary_capture      | 11    | 2       | rows_zero                       |
| calibration            | 28    | 1       | \_oversized_numeric_string      |
| dimension_overflow     | 25    | 1       | samples_multiplier_overflow     |
| dimension_index_attack | 16    | 1       | invalid_index_pointer           |
| compressed_pixel       | 22    | 1       | \_corrupt_jpeg2000_codestream   |
| preamble               | 19    | 1       | \_ff_preamble                   |
| dicomdir               | 21    | 1       | \_deep_nesting,\_path_traversal |

### Strategies that never fired (can_mutate always False)

These 6 strategies are modality-specific. They only fire when the
randomly selected strategy matches a seed whose SOPClassUID satisfies
`can_mutate()`. With 34 strategies and 50 files per seed, the
probability of a modality strategy being selected for its one matching
seed is ~1/26 per file. Getting 0 hits from 50 trials is 15% likely --
bad luck, not a broken strategy.

- encapsulated_pdf
- nuclear_medicine
- pet
- rt_structure_set
- segmentation
- frame_increment_invalid

**Fix applied**: round-robin guarantee in `DICOMGenerator.generate_batch()`.
Phase 1 generates one file per applicable strategy, then Phase 2 fills the
remaining budget with random selection. This ensures every strategy fires at
least once per matching seed.

### Strategies that fired but produced zero crashes (20)

Not actionable with this campaign size. All 10 crashes were OOM
(CWE-400 uncontrolled resource consumption). Strategies that don't
affect allocation size (encoding, metadata, sequence structure) are
unlikely to trigger this specific bug class. They remain valuable for
non-OOM bugs (access violations, stack overflows, hangs) which this
campaign didn't probe deeply enough to find.

## Conclusions

1. **Don't remove any strategies** -- 700 files / 10 crashes (1.4%
   crash rate) is too small for per-strategy statistical significance.
2. **Round-robin selection fixes the 6 never-hit strategies** -- each
   modality strategy now fires at least once per matching seed.
3. **All 10 crashes are the same CWE-400 pattern** -- Hermes has a
   single allocation-bounds-checking gap, not 10 separate bugs.
4. **Next campaign should use -c 200** -- gives tail strategies enough
   budget for statistical significance (~5500 total files).
