# Backlog

Prioritized work items for a complete DICOM fuzzing product.
Each item is sized for 1 atomic Claude Code session. Items include
exact tags, values, and CVE/issue references for implementation.

---

---

## Format fuzzing -- P2: CVE gap coverage (larger scope)

---

## Series/Study fuzzing -- P2

### ~~Temporal (4D) series attacks~~ DONE

### ~~Registration geometry attacks~~ DONE

Multiple series with same FrameOfReferenceUID but conflicting
ImagePositionPatient. FoR UID orphaning.

---

## Network protocol fuzzing -- Prototype to Production

### ~~P0: PDU binary format (PS3.8 Section 7)~~ DONE

### ~~P0: State machine wiring~~ DONE

### ~~P0: DIMSE command generation~~ DONE

### P1: Real TLS testing

Replace hardcoded vulnerability enumeration with actual TLS probes.

**Effort:** 1-2 sessions.

### P1: Query/Retrieve fuzzing

C-FIND/C-MOVE with query tag corruption, wildcard injection.

**Effort:** 1-2 sessions.

---

## Campaign & validation

### Build local high-quality DICOM seed corpus

Assemble a diverse, realistic seed corpus in the local-only
`dicom-seeds/` directory (fully gitignored). See project wiki
for quality bar per modality and sourcing process.

**Effort:** Ongoing.

### Full campaign run

Overnight run with 9 seeds + 30s timeout. Analyze crash-by-strategy.

### Second-pass structural audit

After campaign data: remove/redesign zero-crash strategies.

---

## Low priority / deferred

- Structural/content code comments
- CrashAnalyzer rename
- Test flakiness investigation
- Strategy effectiveness charts
- End-of-campaign auto-triage
- Authentication negotiation fuzzing

---

## Long-term vision

### Full DICOM SOP Class coverage

186 Storage SOP Classes. Current 30 strategies. Target ~40-44.

### Coverage-guided fuzzing

DynamoRIO/Frida instrumentation, coverage feedback, seed selection.

---

## Completed (reference only)

| Item                                                                               | PR(s)                          |
| ---------------------------------------------------------------------------------- | ------------------------------ |
| Audit mutations for crash potential (structural/content split)                     | #188, #198                     |
| Formalize variant terminology + replay --decompose                                 | #195, #184, #197               |
| Re-encode pixel data (PixelReencodingFuzzer)                                       | #204                           |
| Attack mode / scope filtering (--target-type)                                      | #205                           |
| Move mutate_patient_info to utils/anonymizer.py                                    | #201                           |
| Centralize attack payloads in dicom_dictionaries                                   | #194                           |
| Seed corpus diversification (SEG, RTSS, PDF)                                       | #206                           |
| Unify reporting CSS/HTML systems                                                   | #200                           |
| Make reports minimalistic and professional                                         | #200 (CSS cleaned up)          |
| Consolidate crash data types (CrashRecord)                                         | #203                           |
| Add can_mutate() guards to multiframe strategies                                   | #202                           |
| Register multiframe strategies in DicomMutator dispatch                            | (all 10 registered)            |
| Track binary mutations in MutationRecord                                           | #197                           |
| Seed fuzzer engine + log RNG seed                                                  | #184, #185                     |
| crash_by_strategy telemetry                                                        | #191                           |
| Structural mutation reweighting                                                    | #188                           |
| Merge/disambiguate corpus_minimization vs corpus_minimizer                         | (corpus_minimizer.py deleted)  |
| CrashRecord.reproduction_command always None                                       | (conditionally populated)      |
| Pre-mutation safety checks (--safety-mode)                                         | #209                           |
| Seed file sanitization (dicom-fuzzer sanitize)                                     | #210                           |
| Seed corpus diversification (MR, DX, NM, PT, RTDOSE, RTSTRUCT)                     | (seed corpus populated)        |
| Surface multiframe attack type via last_variant                                    | #217                           |
| Mutation taxonomy (boundary/malformed/injection)                                   | Dropped (not effective)        |
| Crash discovery saturation curve                                                   | Dropped (insufficient data)    |
| EmptyValueFuzzer (9 present-but-empty .NET crash attacks)                          | #229                           |
| StructureFuzzer binary VR corruption (4 attacks)                                   | #230                           |
| CompressedPixelFuzzer binary encapsulation (6 attacks)                             | #231                           |
| Overlay attacks + private SQ at EOF + odd-length pixel data                        | #232                           |
| Bump cryptography >= 46.0.7 (Dependabot #43)                                       | #233                           |
| CVE-to-strategy coverage audit (~140 CVEs, 13 gaps, 2 rounds)                      | #234, #235                     |
| Fully untrack dicom-seeds directory                                                | #236                           |
| P1 CVE quick wins: G1, G4, G6, G8, G9, G12, G13 (7 gaps)                           | (7 attacks across 3 fuzzers)   |
| P1 CVE medium: G2 JPEG-LS, G7 VOI LUT, G10 duplicate meta                          | (3 attacks across 3 fuzzers)   |
| MR modality expansion (6 attack types in CalibrationFuzzer)                        | (fuzz_mr_parameters)           |
| DX/CR modality expansion (5 attack types in CalibrationFuzzer)                     | (fuzz_dx_parameters)           |
| Multiframe functional group crash attacks (2 new attacks)                          | (empty frame content + NaN)    |
| Concurrent field mismatches (PixelFuzzer)                                          | (\_concurrent_field_mismatch)  |
| Registration geometry attacks (4 sub-attacks in StudyMutator)                      | (REGISTRATION_GEOMETRY)        |
| G11: Preamble polyglot (PE/ELF/JSON/ff/random, PreambleFuzzer)                     | (preamble strategy)            |
| G5: DICOMDIR path traversal + deep nesting (DicomdirFuzzer)                        | (dicomdir strategy)            |
| G3: Decompression bomb 128MB/512MB/1GB/corrupted (DeflateBombFuzzer)               | (deflate_bomb strategy)        |
| Temporal (4D) attacks: InstanceCreationTime, delta violations, cardiac TriggerTime | (3 sub-attacks in strategy 12) |
| P0: State machine wiring: StatefulFuzzer.fuzz(), execute_event() PDU building      | (build_pdu_for_event + types)  |
| P0: DIMSE PDU packing: DIMSEMessage.to_p_data_tf_pdu() + C-STORE from pydicom      | (26 new tests)                 |
