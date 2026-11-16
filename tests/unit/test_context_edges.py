"""文脈の組み立ての境界: 読めないファイル・空のファイル・予算に入らない本文 (設計書 §8)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from security_checker.context import budget, facts, slicer
from security_checker.context.budget import CHARS_PER_TOKEN, estimate_tokens
from security_checker.context.builder import _mask_detected_lines, _mask_long_tokens_on_line
from security_checker.context.facts import collect_repo_facts
from security_checker.context.slicer import clip_lines, line_window, read_text_file, resolve_inside
from security_checker.models.candidate import Location, PackageRef
from security_checker.models.task import CodeSlice
from security_checker.policy.ignore import AnnotationReader
from tests.factories import make_candidate

# --- トークンの見積り -------------------------------------------------------------


@pytest.fixture
def no_encoder_cache():
    budget._encode_fn.cache_clear()
    yield
    budget._encode_fn.cache_clear()


def test_empty_text_costs_nothing():
    assert estimate_tokens("") == 0


def test_without_tiktoken_the_estimate_is_by_characters(monkeypatch, no_encoder_cache):
    monkeypatch.setitem(sys.modules, "tiktoken", None)  # import を失敗させる
    assert estimate_tokens("x" * (CHARS_PER_TOKEN * 3 + 1)) == 4


def test_with_tiktoken_the_encoder_is_used(monkeypatch, no_encoder_cache):
    class Encoder:
        def encode(self, text: str) -> list[int]:
            return [0] * 7

    class Tiktoken:
        @staticmethod
        def get_encoding(name: str) -> Encoder:
            assert name == "cl100k_base"
            return Encoder()

    monkeypatch.setitem(sys.modules, "tiktoken", Tiktoken)
    assert estimate_tokens("anything") == 7


def test_tiktoken_that_cannot_load_its_dictionary_falls_back(monkeypatch, no_encoder_cache):
    class Tiktoken:
        @staticmethod
        def get_encoding(name: str) -> object:
            raise OSError("offline")

    monkeypatch.setitem(sys.modules, "tiktoken", Tiktoken)
    assert estimate_tokens("abcd") == 1


# --- ファイルの読み取り -----------------------------------------------------------


def test_a_path_that_cannot_be_resolved_is_outside(tmp_path, monkeypatch):
    def loop(self: Path, strict: bool = False) -> Path:
        raise RuntimeError("Symlink loop")

    monkeypatch.setattr(Path, "resolve", loop)
    assert resolve_inside(tmp_path, "a.py") is None


def test_unreadable_file_has_no_text(tmp_path, monkeypatch):
    path = tmp_path / "a.py"
    path.write_text("x = 1\n", encoding="utf-8")

    def deny(self: Path) -> bytes:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_bytes", deny)
    assert read_text_file(path) is None


def test_empty_file_and_a_line_past_the_end_have_no_window(tmp_path):
    (tmp_path / "empty.py").write_text("", encoding="utf-8")
    (tmp_path / "short.py").write_text("a\nb\n", encoding="utf-8")
    empty = Location(path="empty.py", start_line=1, end_line=1)
    beyond = Location(path="short.py", start_line=50, end_line=50)
    assert line_window(tmp_path, empty, window_lines=5) is None
    assert line_window(tmp_path, beyond, window_lines=5) is None


def test_nothing_is_sent_when_even_the_truncation_mark_does_not_fit():
    slice_ = CodeSlice(path="a.py", start_line=1, end_line=1, text="x" * 100)
    assert clip_lines(slice_, focus_line=1, max_chars=len(slicer.TRUNCATED_LINE_MARK)) is None


def test_masking_leaves_text_alone_for_candidates_without_a_location():
    candidate = make_candidate(location=None, package=PackageRef(ecosystem="PyPI", name="p"))
    # 長い引用符付きの値. リポジトリ自身の秘密検査に掛からないよう、実行時に組み立てる
    text = f'VALUE = "{"0123456789abcdef" * 2}"'
    assert _mask_long_tokens_on_line(text, candidate) == text
    assert _mask_detected_lines(text, 1, candidate) == text


# --- リポジトリの事実 -------------------------------------------------------------


def test_excluded_files_and_non_files_are_not_counted(tmp_path):
    (tmp_path / "app.py").write_text("print()\n", encoding="utf-8")
    (tmp_path / "generated.py").write_text("print()\n", encoding="utf-8")
    try:
        (tmp_path / "dangling.py").symlink_to(tmp_path / "missing.py")
    except OSError:
        pytest.skip("シンボリックリンクを作れない環境")
    collected = collect_repo_facts(tmp_path, exclude=["generated.py"])
    assert collected.languages == ["Python"]
    assert collected.truncated is False


def test_unreadable_manifest_is_skipped(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    original = Path.read_text

    def deny(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "requirements.txt":
            raise PermissionError(13, "Permission denied")
        return original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", deny)
    assert collect_repo_facts(tmp_path).frameworks == []
    assert facts.FRAMEWORK_MARKERS["requirements.txt"]


# --- 注釈 -------------------------------------------------------------------------


def test_annotations_are_not_looked_up_for_unreadable_files_or_line_zero(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1  # security-checker: ignore[r]\n", encoding="utf-8")
    reader = AnnotationReader(tmp_path)
    file_level = make_candidate(path="a.py", line=0)
    assert reader.find(file_level) is None

    def deny(self: Path, *args: object, **kwargs: object) -> str:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "read_text", deny)
    assert reader.find(make_candidate(path="a.py", line=1)) is None
