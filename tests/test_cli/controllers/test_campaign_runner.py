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
