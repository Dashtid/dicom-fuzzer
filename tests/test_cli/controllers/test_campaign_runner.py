"""Tests for CampaignRunner._save_session_json and _log_strategy_table."""

from __future__ import annotations

import json
import logging
from argparse import Namespace
from pathlib import Path

from dicom_fuzzer.cli.controllers.campaign_runner import CampaignRunner


def _runner(output_dir: Path) -> CampaignRunner:
    """Build a minimal CampaignRunner pointed at output_dir/fuzzed/."""
    fuzzed_dir = output_dir / "fuzzed"
    fuzzed_dir.mkdir(parents=True, exist_ok=True)
    args = Namespace(
        output=str(fuzzed_dir),
        input_file="dummy.dcm",
        verbose=False,
        count=10,
    )
    return CampaignRunner(args, input_files=[Path("dummy.dcm")])


def _hit_rate_data(zero_strategy: str | None = None) -> dict:
    """Craft a results_data dict with strategy_hit_rates."""
    return {
        "status": "success",
        "generated_count": 10,
        "skipped_count": 0,
        "duration_seconds": 1.0,
        "files_per_second": 10.0,
        "output_directory": "/tmp/fuzzed",
        "files": [],
        "strategy_hit_rates": {
            "metadata": {"hits": 5, "hit_rate_pct": 50.0},
            "header": {"hits": 5, "hit_rate_pct": 50.0},
            **(
                {zero_strategy: {"hits": 0, "hit_rate_pct": 0.0}}
                if zero_strategy
                else {}
            ),
        },
    }


class TestSaveSessionJson:
    def test_session_json_written_to_reports_dir(self, tmp_path):
        """_save_session_json writes to <run_dir>/reports/json/session.json."""
        runner = _runner(tmp_path)
        data = _hit_rate_data()

        runner._save_session_json(data)

        expected = tmp_path / "reports" / "json" / "session.json"
        assert expected.exists()

    def test_session_json_contains_strategy_hit_rates(self, tmp_path):
        """session.json round-trips strategy_hit_rates correctly."""
        runner = _runner(tmp_path)
        data = _hit_rate_data()

        runner._save_session_json(data)

        session_path = tmp_path / "reports" / "json" / "session.json"
        loaded = json.loads(session_path.read_text())
        assert "strategy_hit_rates" in loaded
        assert loaded["strategy_hit_rates"]["metadata"]["hits"] == 5
        assert loaded["strategy_hit_rates"]["header"]["hit_rate_pct"] == 50.0


class TestLogStrategyTable:
    def test_zero_hit_warning_logged(self, tmp_path, caplog):
        """_log_strategy_table emits WARNING for every zero-hit strategy."""
        runner = _runner(tmp_path)
        data = _hit_rate_data(zero_strategy="segmentation")

        with caplog.at_level(
            logging.WARNING, logger="dicom_fuzzer.cli.controllers.campaign_runner"
        ):
            runner._log_strategy_table(data)

        warnings = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("segmentation" in w for w in warnings)

    def test_no_warning_when_all_strategies_hit(self, tmp_path, caplog):
        """_log_strategy_table emits no WARNING when all strategies have hits."""
        runner = _runner(tmp_path)
        data = _hit_rate_data()  # no zero-hit strategies

        with caplog.at_level(
            logging.WARNING, logger="dicom_fuzzer.cli.controllers.campaign_runner"
        ):
            runner._log_strategy_table(data)

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 0

    def test_noop_when_no_hit_rates(self, tmp_path, caplog):
        """_log_strategy_table does nothing when strategy_hit_rates is absent."""
        runner = _runner(tmp_path)
        data = {"status": "success"}

        with caplog.at_level(
            logging.INFO, logger="dicom_fuzzer.cli.controllers.campaign_runner"
        ):
            runner._log_strategy_table(data)

        assert len(caplog.records) == 0


class TestSaveMutationMap:
    """Tests for _save_mutation_map writing the strategy+variant format."""

    def test_writes_strategy_and_variant(self, tmp_path):
        """mutation_map.json must contain {seed, mutations} wrapper with strategy+variant dicts."""
        from unittest.mock import MagicMock

        runner = _runner(tmp_path)
        runner.seed = 42
        generator = MagicMock()
        generator.file_strategy_map = {"fuzz_001.dcm": "pixel"}
        generator.file_variant_map = {
            "fuzz_001.dcm": "_dimension_mismatch,_rescale_attack"
        }
        generator.file_binary_mutations_map = {}

        runner._save_mutation_map(generator)

        map_path = tmp_path / "fuzzed" / "mutation_map.json"
        assert map_path.exists()
        data = json.loads(map_path.read_text())
        assert data["seed"] == 42
        assert data["mutations"]["fuzz_001.dcm"]["strategy"] == "pixel"
        assert (
            data["mutations"]["fuzz_001.dcm"]["variant"]
            == "_dimension_mismatch,_rescale_attack"
        )

    def test_variant_null_when_not_in_variant_map(self, tmp_path):
        """variant must be null for files absent from file_variant_map."""
        from unittest.mock import MagicMock

        runner = _runner(tmp_path)
        runner.seed = 99
        generator = MagicMock()
        generator.file_strategy_map = {"fuzz_001.dcm": "header"}
        generator.file_variant_map = {}
        generator.file_binary_mutations_map = {}

        runner._save_mutation_map(generator)

        map_path = tmp_path / "fuzzed" / "mutation_map.json"
        data = json.loads(map_path.read_text())
        assert data["mutations"]["fuzz_001.dcm"]["strategy"] == "header"
        assert data["mutations"]["fuzz_001.dcm"]["variant"] is None

    def test_noop_when_strategy_map_empty(self, tmp_path):
        """_save_mutation_map writes nothing when file_strategy_map is empty."""
        from unittest.mock import MagicMock

        runner = _runner(tmp_path)
        generator = MagicMock()
        generator.file_strategy_map = {}
        generator.file_variant_map = {}

        runner._save_mutation_map(generator)

        map_path = tmp_path / "fuzzed" / "mutation_map.json"
        assert not map_path.exists()


class TestSeedInOutputs:
    """Tests that the seed appears in session.json and mutation_map.json."""

    def test_session_json_contains_seed(self, tmp_path):
        """_save_session_json must include the seed field."""
        runner = _runner(tmp_path)
        runner.seed = 42
        data = {"status": "success", "seed": runner.seed, "generated_count": 5}

        runner._save_session_json(data)

        session_path = tmp_path / "reports" / "json" / "session.json"
        loaded = json.loads(session_path.read_text())
        assert loaded["seed"] == 42

    def test_mutation_map_seed_matches_runner_seed(self, tmp_path):
        """mutation_map.json seed key must match runner.seed."""
        from unittest.mock import MagicMock

        runner = _runner(tmp_path)
        runner.seed = 1234
        generator = MagicMock()
        generator.file_strategy_map = {"fuzz_001.dcm": "metadata"}
        generator.file_variant_map = {}
        generator.file_binary_mutations_map = {}

        runner._save_mutation_map(generator)

        map_path = tmp_path / "fuzzed" / "mutation_map.json"
        data = json.loads(map_path.read_text())
        assert data["seed"] == 1234
        assert "fuzz_001.dcm" in data["mutations"]
