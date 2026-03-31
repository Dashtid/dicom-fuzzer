"""Tests for --safety-mode CLI argument."""

from __future__ import annotations

import pytest

from dicom_fuzzer.cli.utils.argument_parser import create_parser


class TestSafetyModeArgument:
    """Verify the --safety-mode CLI flag."""

    def test_default_is_off(self):
        parser = create_parser()
        args = parser.parse_args(["dummy.dcm"])
        assert args.safety_mode == "off"

    @pytest.mark.parametrize("mode", ["off", "lenient", "strict"])
    def test_valid_choices_accepted(self, mode):
        parser = create_parser()
        args = parser.parse_args(["dummy.dcm", "--safety-mode", mode])
        assert args.safety_mode == mode

    def test_invalid_choice_rejected(self):
        parser = create_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["dummy.dcm", "--safety-mode", "invalid"])
