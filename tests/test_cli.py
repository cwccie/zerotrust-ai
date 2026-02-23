"""Tests for CLI."""

import pytest
from click.testing import CliRunner

from zerotrust_ai.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLI:
    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ZeroTrust-AI" in result.output

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_baseline(self, runner):
        result = runner.invoke(cli, ["baseline", "--events", "50", "--entities", "5"])
        assert result.exit_code == 0
        assert "Baselines learned" in result.output

    def test_analyze(self, runner):
        result = runner.invoke(cli, ["analyze", "--entity", "user-001", "--hour", "3"])
        assert result.exit_code == 0
        assert "Anomaly" in result.output

    def test_detect(self, runner):
        result = runner.invoke(cli, ["detect", "--nodes", "8", "--edges", "20"])
        assert result.exit_code == 0
        assert "Lateral Movement" in result.output

    def test_policy(self, runner):
        result = runner.invoke(cli, ["policy"])
        assert result.exit_code == 0
        assert "Policy" in result.output

    def test_demo(self, runner):
        result = runner.invoke(cli, ["demo"])
        assert result.exit_code == 0
        assert "Demo complete" in result.output
