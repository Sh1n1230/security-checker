"""Context Builder とマスキングの回帰テスト (設計書 §8, §19.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from security_checker.config.schema import ContextConfig
from security_checker.context.builder import ContextBuilder
from security_checker.context.facts import collect_repo_facts
from security_checker.context.slicer import line_window, shrink
from security_checker.models.candidate import Candidate, Location, PackageRef
from security_checker.models.enums import Category, Severity
from security_checker.models.task import CodeSlice, RepoFacts

SECRET = "xoxb-TESTONLY-DUMMY-NOT-A-REAL-SECRET"  # noqa: S105  gitleaks:allow


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "\n".join(f"line{index}" for index in range(1, 101)) + "\n", encoding="utf-8"
    )
    (tmp_path / "settings.py").write_text(f'TOKEN = "{SECRET}"\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\nrequests\n", encoding="utf-8")
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("print('entry')\n", encoding="utf-8")
    return tmp_path


def sast_candidate(line: int = 50) -> Candidate:
    return Candidate(
        id="c1",
        scanner="semgrep",
        category=Category.SAST,
        rule_id="rules.x",
        title="x",
        message="m",
        location=Location(path="src/app.py", start_line=line, end_line=line),
        severity_reported=Severity.HIGH,
    )


def secret_candidate() -> Candidate:
    return Candidate(
        id="c2",
        scanner="gitleaks",
        category=Category.SECRET,
        rule_id="slack-bot-token",
        title="secret",
        message="m",
        location=Location(path="settings.py", start_line=1, end_line=1, snippet="xoxb****"),
        severity_reported=Severity.CRITICAL,
        redacted=True,
    )


def builder(repo: Path, **overrides: Any) -> ContextBuilder:
    config = ContextConfig(**{"window_lines": 5, **overrides})
    return ContextBuilder(repo, config, RepoFacts(languages=["Python"]))


def test_line_window_centers_on_finding(repo):
    slice_ = line_window(
        repo, Location(path="src/app.py", start_line=50, end_line=50), window_lines=5
    )
    assert slice_ is not None
    assert slice_.start_line == 45
    assert slice_.end_line == 55
    assert "line50" in slice_.text


def test_line_window_clamps_at_file_edges(repo):
    slice_ = line_window(
        repo, Location(path="src/app.py", start_line=2, end_line=2), window_lines=10
    )
    assert slice_ is not None
    assert slice_.start_line == 1


def test_line_window_missing_file(repo):
    assert (
        line_window(repo, Location(path="nope.py", start_line=1, end_line=1), window_lines=5)
        is None
    )


def test_line_window_skips_binary(repo):
    (repo / "blob.bin").write_bytes(b"\x00\x01\x02" * 100)
    assert (
        line_window(repo, Location(path="blob.bin", start_line=1, end_line=1), window_lines=5)
        is None
    )


def test_numbered_output_has_line_numbers(repo):
    slice_ = line_window(
        repo, Location(path="src/app.py", start_line=50, end_line=50), window_lines=2
    )
    assert slice_ is not None
    assert slice_.numbered().splitlines()[0].startswith("48|")


def test_build_task_for_sast(repo):
    task = builder(repo).build(sast_candidate())
    assert task.code_context.primary is not None
    assert task.code_context.truncated is False
    assert task.budget.estimated_input_tokens > 0
    assert task.notes == []


def test_secret_values_are_masked_before_sending(repo):
    """検出値を外部 LLM に送らない. これが崩れると二次漏洩になる (§19.2)."""
    task = builder(repo).build(secret_candidate())
    primary = task.code_context.primary
    assert primary is not None
    assert SECRET not in primary.text
    assert "xoxb" in primary.text
    assert any("マスク" in note for note in task.notes)


def test_budget_truncates_and_notes_it(repo):
    task = builder(repo, window_lines=50, max_tokens_per_task=20).build(sast_candidate())
    primary = task.code_context.primary
    assert primary is not None
    assert task.code_context.truncated is True
    assert "line50" in primary.text  # 該当行は必ず残す
    assert any("切り詰め" in note for note in task.notes)


def test_missing_file_is_noted(repo):
    candidate = sast_candidate().model_copy(
        update={"location": Location(path="gone.py", start_line=1, end_line=1)}
    )
    task = builder(repo).build(candidate)
    assert task.code_context.primary is None
    assert any("読み込め" in note for note in task.notes)


def test_dependency_candidate_has_no_code(repo):
    candidate = Candidate(
        id="c3",
        scanner="osv",
        category=Category.DEPENDENCY,
        rule_id="CVE-2024-0001",
        title="dep",
        message="m",
        package=PackageRef(ecosystem="PyPI", name="requests", version="2.0.0"),
    )
    task = builder(repo).build(candidate)
    assert task.code_context.primary is None
    assert any("依存パッケージ" in note for note in task.notes)


def test_shrink_keeps_focus_line():
    slice_ = CodeSlice(
        path="a.py", start_line=1, end_line=100, text="\n".join(f"l{i}" for i in range(1, 101))
    )
    shrunk = shrink(slice_, keep_lines=10, focus_line=80)
    assert "l80" in shrunk.text
    assert len(shrunk.text.splitlines()) == 10


def test_repo_facts(repo):
    facts = collect_repo_facts(repo)
    assert "Python" in facts.languages
    assert "flask" in facts.frameworks
    assert "app.py" in facts.entrypoints
    assert "Dockerfile" in facts.deployment_hints
    assert facts.is_public_repo is None  # 分からないものは埋めない


def test_repo_facts_can_be_disabled(repo):
    task = builder(repo, include_repo_facts=False).build(sast_candidate())
    assert task.repo_facts.languages == []
