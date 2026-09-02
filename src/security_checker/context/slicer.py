"""コードスライシング (設計書 §8.2).

v2.0 は (1) 行ウィンドウから始める。全言語で常に機能するフォールバックであり、
関数境界抽出 (2) や tree-sitter (3) は後続フェーズで重ねる。
"""

from __future__ import annotations

from pathlib import Path

from security_checker.models.candidate import Location
from security_checker.models.task import CodeSlice

MAX_FILE_BYTES = 2_000_000
BINARY_SNIFF_BYTES = 4096


def read_text_file(path: Path) -> list[str] | None:
    """テキストとして読めなければ None. バイナリを文脈に混ぜない."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:BINARY_SNIFF_BYTES]:
        return None
    return raw.decode("utf-8", "replace").splitlines()


def line_window(
    root: Path,
    location: Location,
    *,
    window_lines: int,
    label: str = "primary",
) -> CodeSlice | None:
    """該当行の前後 window_lines 行を切り出す."""
    lines = read_text_file(root / location.path)
    if lines is None:
        return None
    total = len(lines)
    if total == 0:
        return None

    start_line = max(1, location.start_line)
    end_line = max(start_line, location.end_line)
    start = max(1, start_line - window_lines)
    end = min(total, end_line + window_lines)
    if start > total:
        return None

    return CodeSlice(
        path=location.path,
        start_line=start,
        end_line=end,
        text="\n".join(lines[start - 1 : end]),
        label=label,
    )


def shrink(slice_: CodeSlice, *, keep_lines: int, focus_line: int) -> CodeSlice:
    """予算超過時にウィンドウを縮める. 該当行を必ず含めたまま前後を削る."""
    lines = slice_.text.splitlines()
    if len(lines) <= keep_lines:
        return slice_
    focus_index = max(0, min(len(lines) - 1, focus_line - slice_.start_line))
    half = max(1, keep_lines // 2)
    start_index = max(0, focus_index - half)
    end_index = min(len(lines), start_index + keep_lines)
    start_index = max(0, end_index - keep_lines)
    return CodeSlice(
        path=slice_.path,
        start_line=slice_.start_line + start_index,
        end_line=slice_.start_line + end_index - 1,
        text="\n".join(lines[start_index:end_index]),
        label=slice_.label,
    )
