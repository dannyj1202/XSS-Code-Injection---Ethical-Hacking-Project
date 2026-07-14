"""Tests for SafetyConfig authorization gating."""

from pathlib import Path

import pytest

from src.config.safety import SafetyConfig, SafetyValidationError


class TestSafetyConfig:
    def test_rejects_missing_authorization_flag(self, tmp_path: Path) -> None:
        targets = tmp_path / "TARGETS.txt"
        targets.write_text("192.168.1.101\n")
        safety = SafetyConfig(targets)
        with pytest.raises(SafetyValidationError, match="--i-have-authorization"):
            safety.validate(i_have_authorization=False)

    def test_rejects_missing_targets_file(self, tmp_path: Path) -> None:
        safety = SafetyConfig(tmp_path / "missing.txt")
        with pytest.raises(SafetyValidationError, match="not found"):
            safety.validate(i_have_authorization=True)

    def test_rejects_public_ip(self, tmp_path: Path) -> None:
        targets = tmp_path / "TARGETS.txt"
        targets.write_text("8.8.8.8\n")
        safety = SafetyConfig(targets)
        with pytest.raises(SafetyValidationError, match="non-RFC1918"):
            safety.validate(i_have_authorization=True)

    def test_accepts_private_targets(self, tmp_path: Path) -> None:
        targets = tmp_path / "TARGETS.txt"
        targets.write_text("# lab victim\n192.168.1.101\n")
        safety = SafetyConfig(targets)
        safety.validate(i_have_authorization=True)
        assert safety.targets == {"192.168.1.101"}
