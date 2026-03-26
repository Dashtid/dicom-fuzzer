# Implementation Plan: Add seed to FuzzingSession and surface it at campaign end

## Summary

Most of the seed infrastructure is already built: `DICOMGenerator` auto-generates a seed
and passes it to `DicomMutator` which calls `random.seed()`, the `--seed INT` CLI flag
exists, and the seed appears in `mutation_map.json` and the campaign stats `session.json`.
The gap is that `FuzzingSession` (the forensic `session_{id}.json` with full MutationRecords)
has no `seed` field, `TargetTestingController` reads the mutation map but discards the seed
when constructing `FuzzingSession`, and the seed is never printed to the console so users
have no easy way to copy it for reproduction.

## Prerequisites

- [x] Branch `feat/replay-decompose` merged or a new branch created
- [x] All relevant files read and understood

## Phase 1: Add seed field to FuzzingSession

### Files to Modify

| File                                           | Changes                              | Est. lines |
| ---------------------------------------------- | ------------------------------------ | ---------- |
| `dicom_fuzzer/core/session/fuzzing_session.py` | Add `seed` param + include in report | ~6         |

### Exact Changes

1. In `FuzzingSession.__init__()` (line 117), add `seed: int | None = None` as last param
2. Store as `self.seed: int | None = seed` after the `self.config = config or {}` block (~line 149)
3. In `generate_session_report()` `"session_info"` dict (~line 432), add `"seed": self.seed`

### Verification

- [ ] `python -m pytest tests/test_core/session/ -v` — all pass
- [ ] Manually confirm `session_{id}.json` contains `"seed"` key in `session_info`

---

## Phase 2: Thread seed from mutation_map into FuzzingSession

### Files to Modify

| File                                                | Changes                                                               | Est. lines |
| --------------------------------------------------- | --------------------------------------------------------------------- | ---------- |
| `dicom_fuzzer/cli/controllers/target_controller.py` | Change `_load_mutation_map` return type + pass seed to FuzzingSession | ~10        |

### Exact Changes

1. Change `_load_mutation_map` return type from `dict[str, dict[str, str | None]]` to
   `tuple[dict[str, dict[str, str | None]], int | None]`
2. In `_load_mutation_map`, extract `seed = raw.get("seed")` after the `_mutations` unwrap
   (~line 204), cast to `int | None`, and return `(normalized, seed)` instead of `normalized`
3. At the call site (~line 88): unpack `mutation_map, campaign_seed = TargetTestingController._load_mutation_map(files)`
4. Pass `seed=campaign_seed` to the `FuzzingSession(...)` constructor (~line 75)

### Verification

- [ ] `python -m pytest tests/test_cli/controllers/ -v` — all pass
- [ ] Confirm `session_{id}.json["session_info"]["seed"]` matches `mutation_map.json["seed"]`

---

## Phase 3: Print seed to console at campaign end

### Files to Modify

| File                                              | Changes                                | Est. lines |
| ------------------------------------------------- | -------------------------------------- | ---------- |
| `dicom_fuzzer/cli/controllers/campaign_runner.py` | Add Seed to display_results stats dict | ~3         |

### Exact Changes

1. In `display_results()` (~line 384), add `"Seed": str(results_data.get("seed", "n/a"))`
   to the `stats` dict after the `"Output"` entry
   — this prints it for both normal and quiet-with-result modes

### Verification

- [ ] Run `python -m dicom_fuzzer input.dcm -c 5` and confirm "Seed: XXXXXXXX" appears in output
- [ ] Run with `--json` and confirm seed already appears in JSON output (it does — no change needed)

---

## Phase 4: Tests

### Files to Modify

| File                                                   | Changes                                | Est. lines |
| ------------------------------------------------------ | -------------------------------------- | ---------- |
| `tests/test_core/session/test_fuzzing_session.py`      | Add 2 tests for seed in session report | ~25        |
| `tests/test_cli/controllers/test_target_controller.py` | Add test for seed extraction           | ~30        |

### Test cases

**`test_fuzzing_session.py`:**

- `test_seed_stored_in_session_info`: Pass `seed=12345` to `FuzzingSession`, call
  `generate_session_report()`, assert `report["session_info"]["seed"] == 12345`
- `test_seed_none_when_not_provided`: No seed passed → `report["session_info"]["seed"] is None`

**`test_target_controller.py`:**

- `test_load_mutation_map_returns_seed`: Write a temp `mutation_map.json` with
  `{"seed": 99999, "mutations": {...}}`, call `_load_mutation_map([temp_file])`,
  assert returned tuple's second element equals `99999`
- `test_load_mutation_map_seed_none_when_absent`: Old-format map (no seed key) →
  second element is `None`

### Verification

- [ ] `python -m pytest tests/test_core/session/ tests/test_cli/controllers/ -v` — all pass

---

## Testing Strategy

Run after each phase:

```
python -m pytest tests/test_core/session/ tests/test_cli/controllers/ -v
```

Full suite after Phase 4:

```
python -m pytest tests/ -x
```

## Rollback Plan

All changes are additive (new param with default `None`, new dict key). If anything breaks:

1. `git revert HEAD` or `git restore` the 3 changed files
2. No schema migrations — the JSON field is simply absent on old sessions

## Estimated Scope

- Files changed: 4 (fuzzing_session.py, target_controller.py, campaign_runner.py, 2 test files)
- Lines added: ~65
- Lines modified: ~10
- Risk: Low — all changes are additive with `None` defaults
