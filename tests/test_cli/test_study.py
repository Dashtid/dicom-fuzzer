"""Tests for study.py - Study-Level Mutation CLI.

Tests cover argument parsing, strategy listing, mutation execution, and main entry point.
"""

import argparse
from unittest.mock import MagicMock, patch

import pytest

from dicom_fuzzer.cli.study import (
    create_parser,
    main,
    run_list_strategies,
    run_study_mutation,
)


class TestCreateParser:
    """Test argument parser creation."""

    def test_parser_requires_action(self):
        """Test that parser requires mutually exclusive action."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_parser_study_action(self):
        """Test --study action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--study", "./test_study"])

        assert args.study == "./test_study"
        assert args.list_strategies is False

    def test_parser_list_strategies_action(self):
        """Test --list-strategies action parsing."""
        parser = create_parser()
        args = parser.parse_args(["--list-strategies"])

        assert args.list_strategies is True
        assert args.study is None

    def test_parser_mutually_exclusive_actions(self):
        """Test that actions are mutually exclusive."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--study", "./test", "--list-strategies"])

    def test_parser_mutation_defaults(self):
        """Test default values for mutation options."""
        parser = create_parser()
        args = parser.parse_args(["--study", "./test"])

        assert args.strategy == "all"
        assert args.severity == "moderate"
        assert args.count == 5

    def test_parser_mutation_options(self):
        """Test custom mutation options."""
        parser = create_parser()
        args = parser.parse_args(
            [
                "--study",
                "./test",
                "--strategy",
                "cross-series",
                "--severity",
                "aggressive",
                "-c",
                "10",
            ]
        )

        assert args.strategy == "cross-series"
        assert args.severity == "aggressive"
        assert args.count == 10

    def test_parser_all_strategies(self):
        """Test all valid strategy choices."""
        parser = create_parser()
        valid_strategies = [
            "cross-series",
            "frame-of-reference",
            "patient-consistency",
            "study-metadata",
            "mixed-modality",
            "all",
        ]

        for strategy in valid_strategies:
            args = parser.parse_args(["--study", "./test", "--strategy", strategy])
            assert args.strategy == strategy

    def test_parser_invalid_strategy(self):
        """Test invalid strategy raises error."""
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--study", "./test", "--strategy", "invalid"])

    def test_parser_all_severity_levels(self):
        """Test all valid severity levels."""
        parser = create_parser()
        valid_severities = ["minimal", "moderate", "aggressive", "extreme"]

        for severity in valid_severities:
            args = parser.parse_args(["--study", "./test", "--severity", severity])
            assert args.severity == severity

    def test_parser_output_options(self):
        """Test output options."""
        parser = create_parser()
        args = parser.parse_args(["--study", "./test", "-o", "/custom/output", "-v"])

        assert args.output == "/custom/output"
        assert args.verbose is True


class TestRunListStrategies:
    """Test run_list_strategies function."""

    def test_list_strategies_returns_zero(self, capsys):
        """Test that list_strategies returns 0."""
        result = run_list_strategies()
        assert result == 0

    def test_list_strategies_output(self, capsys):
        """Test that list_strategies prints strategy information."""
        run_list_strategies()
        captured = capsys.readouterr()

        assert "Study Mutation Strategies" in captured.out
        assert "cross-series" in captured.out
        assert "frame-of-reference" in captured.out
        assert "patient-consistency" in captured.out
        assert "study-metadata" in captured.out
        assert "mixed-modality" in captured.out


class TestRunStudyMutation:
    """Test run_study_mutation function."""

    def test_mutation_study_not_found(self, tmp_path, capsys):
        """Test handling of non-existent study directory."""
        args = argparse.Namespace(
            study=str(tmp_path / "nonexistent"),
            strategy="all",
            severity="moderate",
            count=5,
            output=str(tmp_path / "output"),
            verbose=False,
        )

        mock_module = MagicMock()
        mock_module.StudyMutator = MagicMock()
        mock_module.StudyMutationStrategy = MagicMock()

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.strategies.study_mutator": mock_module}
        ):
            result = run_study_mutation(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_mutation_success(self, tmp_path, capsys):
        """Test successful study mutation."""
        study_path = tmp_path / "study"
        study_path.mkdir()
        (study_path / "series_001").mkdir()

        mock_study = MagicMock()
        mock_study.series_list = [MagicMock()]

        mock_record = MagicMock()
        mock_record.strategy = "cross-series"
        mock_record.tag = "0008,0060"
        mock_record.mutated_value = "XX"

        mock_ds = MagicMock()
        mock_ds.save_as = MagicMock()

        mock_mutator = MagicMock()
        mock_mutator.load_study.return_value = mock_study
        mock_mutator.mutate_study.return_value = ([[mock_ds]], [mock_record])

        mock_strategy_enum = MagicMock()
        mock_strategy_enum.CROSS_SERIES_REFERENCE = MagicMock()
        mock_strategy_enum.CROSS_SERIES_REFERENCE.value = "cross-series"
        mock_strategy_enum.FRAME_OF_REFERENCE = MagicMock()
        mock_strategy_enum.PATIENT_CONSISTENCY = MagicMock()
        mock_strategy_enum.STUDY_METADATA = MagicMock()
        mock_strategy_enum.MIXED_MODALITY_STUDY = MagicMock()

        args = argparse.Namespace(
            study=str(study_path),
            strategy="cross-series",
            severity="moderate",
            count=5,
            output=str(tmp_path / "output"),
            verbose=True,
        )

        mock_module = MagicMock()
        mock_module.StudyMutator = MagicMock(return_value=mock_mutator)
        mock_module.StudyMutationStrategy = mock_strategy_enum

        with patch.dict(
            "sys.modules", {"dicom_fuzzer.strategies.study_mutator": mock_module}
        ):
            result = run_study_mutation(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "Study-Level Mutation" in captured.out
        assert "Applied" in captured.out

    def test_mutation_import_error(self, tmp_path, capsys):
        """Test handling of import error."""
        study_path = tmp_path / "study"
        study_path.mkdir()

        args = argparse.Namespace(
            study=str(study_path),
            strategy="all",
            severity="moderate",
            count=5,
            output=str(tmp_path / "output"),
            verbose=False,
        )

        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if "study_mutator" in name:
                raise ImportError("Module not available")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", mock_import):
            result = run_study_mutation(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Module not available" in captured.out


class TestMain:
    """Test main entry point."""

    def test_main_list_strategies(self, capsys):
        """Test main with --list-strategies."""
        result = main(["--list-strategies"])
        assert result == 0
        captured = capsys.readouterr()
        assert "Study Mutation Strategies" in captured.out

    def test_main_study_mutation(self, tmp_path):
        """Test main with --study dispatches correctly."""
        study_path = tmp_path / "study"
        study_path.mkdir()

        with patch(
            "dicom_fuzzer.cli.study.run_study_mutation", return_value=0
        ) as mock_run:
            result = main(["--study", str(study_path)])
            assert result == 0
            mock_run.assert_called_once()

    def test_main_no_args_fails(self, capsys):
        """Test main with no args fails."""
        with pytest.raises(SystemExit):
            main([])
