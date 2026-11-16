"""Keep composite-action Bash extraction aligned with action.yml."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml


def _load_linter() -> Any:
    path = Path(__file__).resolve().parents[2] / "scripts/lint-composite-action.py"
    spec = importlib.util.spec_from_file_location("composite_action_linter", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_composite_action_run_scripts_are_all_bash():
    root = Path(__file__).resolve().parents[2]
    action = yaml.safe_load((root / "action.yml").read_text(encoding="utf-8"))
    scripts = _load_linter().bash_steps(action)
    assert len(scripts) >= 7
    assert all(script.strip() for _, script in scripts)


def test_composite_action_linter_rejects_non_bash_run_blocks():
    action = {"runs": {"using": "composite", "steps": [{"shell": "sh", "run": "echo hi"}]}}
    with pytest.raises(ValueError, match="unsupported shell"):
        _load_linter().bash_steps(action)


def test_linter_checks_each_run_block_and_fails_on_shellcheck_errors(tmp_path, monkeypatch):
    path = tmp_path / "action.yml"
    path.write_text(
        "runs:\n  using: composite\n  steps:\n"
        "    - shell: bash\n      run: echo one\n"
        "    - shell: bash\n      run: echo two\n",
        encoding="utf-8",
    )
    inspected: list[str] = []

    def fake_shellcheck(args: list[str], *, input: str, text: bool, check: bool) -> SimpleNamespace:
        assert args == ["shellcheck", "--shell=bash", "-"]
        assert text is True
        assert check is False
        inspected.append(input)
        return SimpleNamespace(returncode=1 if "two" in input else 0)

    module = _load_linter()
    monkeypatch.setattr(module.subprocess, "run", fake_shellcheck)
    assert module.main(path) == 1
    assert inspected == ["echo one", "echo two"]
