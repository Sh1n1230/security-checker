"""PR の差分取得と変更行マッピング (設計書 §7.4).

PR レビューでは、変更行に関係しない候補を落とす。

  - コード起因 (`sast`, `secret`): 行範囲が diff の追加行と重なるものだけ残す。
  - 依存起因 (`dependency`): マニフェスト / ロックファイルが変更された場合のみ。
  - 設定起因 (`config`): 対象ファイルが変更された場合のみ。

差分は `git merge-base <base> HEAD` と作業ツリーの比較で取る。PR の merge コミットでも
手元の未コミットの変更でも、同じ規則で「この変更で増えた行」になる。
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from security_checker.errors import ConfigError, SecurityCheckerError
from security_checker.models.candidate import Candidate
from security_checker.models.enums import Category

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_BINARY_RE = re.compile(r"^Binary files .* differ$")
#: `git` の C 形式のエスケープ (core.quotePath). 8 進はバイト列として UTF-8 で戻す
_C_ESCAPES = {"a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v", "f": "\f", "r": "\r"}
GIT_TIMEOUT_S = 60


class DiffError(SecurityCheckerError):
    """差分を取得できなかった (git が無い・base が見つからない・shallow clone など)."""


@dataclass(frozen=True)
class DiffScope:
    """変更されたファイルと、新しい側で追加された行範囲 (両端を含む)."""

    base: str
    added: Mapping[str, tuple[tuple[int, int], ...]] = field(default_factory=dict)
    changed_files: frozenset[str] = frozenset()

    def overlaps(self, path: str, start: int, end: int) -> bool:
        return any(lo <= end and start <= hi for lo, hi in self.added.get(path, ()))

    def is_commentable(self, path: str, line: int) -> bool:
        """inline コメントを付けられる行か. GitHub は diff に含まれる行にしか付けられない."""
        return self.overlaps(path, line, line)

    def touches(self, candidate: Candidate) -> bool:
        """この候補が PR の変更に関係するか (§7.4)."""
        location = candidate.location
        if candidate.category in (Category.SAST, Category.SECRET):
            if location is None:
                return False
            return self.overlaps(
                location.path, location.start_line, max(location.end_line, location.start_line)
            )
        if candidate.category is Category.DEPENDENCY:
            manifest = candidate.package.manifest if candidate.package else None
            paths = {p for p in (manifest, location.path if location else None) if p}
            return bool(paths & self.changed_files)
        if candidate.category is Category.CONFIG:
            return location is not None and location.path in self.changed_files
        # web などファイルに紐づかないものは差分で絞れない. 落とさない
        return True

    def split(self, candidates: list[Candidate]) -> tuple[list[Candidate], list[Candidate]]:
        """(変更に関係する候補, 関係しない候補) に分ける. 順序は保つ."""
        inside: list[Candidate] = []
        outside: list[Candidate] = []
        for candidate in candidates:
            (inside if self.touches(candidate) else outside).append(candidate)
        return inside, outside


def parse_unified_diff(text: str) -> tuple[dict[str, tuple[tuple[int, int], ...]], set[str]]:
    """`git diff --unified=0` の出力から、追加行の範囲と変更ファイルを取り出す.

    `--- ` / `+++ ` はファイルヘッダ (`diff --git` から最初のハンクまで) の中でだけ解釈する。
    ハンクの本文でも、`-- ` で始まる行の削除や `++ ` で始まる行の追加は同じ形になるため。
    """
    added: dict[str, list[tuple[int, int]]] = {}
    changed: set[str] = set()
    current: str | None = None
    old_path: str | None = None
    # `diff --git` 行の無い素の unified diff も受け付けるよう、先頭はヘッダとして扱う
    in_header = True
    # `diff --git` 行から取ったパス. `---`/`+++` の無いバイナリの差分で使う
    header_path: str | None = None
    for line in text.splitlines():
        if line.startswith("diff --git "):
            in_header = True
            current = old_path = None
            header_path = _header_path(line[len("diff --git ") :])
            continue
        if in_header and _BINARY_RE.match(line):
            # バイナリ (jar・wheel など) は行を持たないが、変更されたことは数える
            if header_path is not None:
                changed.add(header_path)
            continue
        if in_header and line.startswith("--- "):
            old_path = _strip_prefix(line[4:])
            continue
        if in_header and line.startswith("+++ "):
            current = _strip_prefix(line[4:])
            if current is not None:
                changed.add(current)
            elif old_path is not None:
                # 削除されたファイルも「変更された」に数える (依存の削除など)
                changed.add(old_path)
            continue
        match = _HUNK_RE.match(line)
        if match:
            in_header = False
        if match and current is not None:
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            if count > 0:
                added.setdefault(current, []).append((start, start + count - 1))
    return {path: tuple(ranges) for path, ranges in added.items()}, changed


def _strip_prefix(raw: str) -> str | None:
    if raw.startswith('"'):
        # タブ・改行・引用符・バックスラッシュを含むパスは core.quotePath=false でも引用される
        unquoted = _unquote_c(raw)
        if unquoted is None:
            return None
        path = unquoted[0]
    else:
        path = raw.split("\t", 1)[0]
    if path == "/dev/null":
        return None
    return path[2:] if path[:2] in ("a/", "b/") else path


def _header_path(rest: str) -> str | None:
    """`diff --git a/<path> b/<path>` の新しい側のパス."""
    if rest.startswith('"'):
        first = _unquote_c(rest)
        if first is None:
            return None
        rest = rest[first[1] :].lstrip(" ")
        return _strip_prefix(rest)
    # 引用されていない場合、名前の変更が無ければ両側は同じなので半分に割れる
    if rest.startswith("a/"):
        half = (len(rest) - 1) // 2
        old, new = rest[:half], rest[half + 1 :]
        if new.startswith("b/") and old[2:] == new[2:]:
            return new[2:]
    marker = rest.rfind(" b/")
    if marker == -1:
        return None
    return _strip_prefix(rest[marker + 1 :])


def _unquote_c(raw: str) -> tuple[str, int] | None:
    """`"..."` を C 形式のエスケープを戻して読む. (パス, 閉じ引用符の次の位置) を返す."""
    out = bytearray()
    index = 1
    while index < len(raw):
        char = raw[index]
        if char == '"':
            return out.decode("utf-8", errors="replace"), index + 1
        if char != "\\":
            out += char.encode("utf-8")
            index += 1
            continue
        escape = raw[index + 1 : index + 2]
        if escape in _C_ESCAPES:
            out += _C_ESCAPES[escape].encode()
            index += 2
        elif escape[:1].isdigit():
            digits = raw[index + 1 : index + 4]
            out.append(int(digits, 8) & 0xFF)
            index += 4
        else:  # \" と \\ とそれ以外は文字そのもの
            out += escape.encode("utf-8")
            index += 2
    return None


def _git(root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GIT_TIMEOUT_S,
            check=False,
        )
    except FileNotFoundError as exc:
        if not root.is_dir():
            raise DiffError(f"git を実行するディレクトリがありません: {root}") from exc
        raise DiffError("git が見つかりません。diff モードには git が必要です") from exc
    except OSError as exc:
        # Windows は、存在しない cwd を NotADirectoryError で知らせる
        raise DiffError(f"git を起動できません ({type(exc).__name__}): {root}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiffError(f"git {args[0]} が {GIT_TIMEOUT_S} 秒以内に終わりませんでした") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        raise DiffError(f"git {' '.join(args)} が失敗しました: {detail[-1] if detail else ''}")
    return completed.stdout


def compute_diff(root: Path, base: str) -> DiffScope:
    """base との差分を取る. パスは root からの相対 (Candidate と同じ基準) にそろえる."""
    try:
        merge_base = _git(root, "merge-base", base, "HEAD").strip()
    except DiffError as exc:
        raise DiffError(
            f"base '{base}' との共通祖先が見つかりません。CI では checkout に "
            f"fetch-depth: 0 を指定してください ({exc})"
        ) from exc
    text = _git(
        root,
        "diff",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--relative",
        merge_base,
        "--",
    )
    added, changed = parse_unified_diff(text)
    # 作業ツリーと比べるので、まだ git add していない新規ファイルも「この変更で増えた行」に含める
    for path in _git(root, "ls-files", "--others", "--exclude-standard", "-z").split("\0"):
        if not path:
            continue
        changed.add(path)
        lines = _count_lines(root / path)
        if lines:
            added[path] = ((1, lines),)
    return DiffScope(base=base, added=added, changed_files=frozenset(changed))


def _count_lines(path: Path) -> int:
    """テキストの行数. 読めないもの・バイナリは 0 (変更ファイルとしてだけ数える)."""
    try:
        data = path.read_bytes()
    except OSError:
        return 0
    if b"\0" in data[:8192]:
        return 0
    return data.count(b"\n") + (0 if not data or data.endswith(b"\n") else 1)


def repo_prefix(root: Path) -> str | None:
    """検査対象のリポジトリ内の接頭辞 (例: `services/api/`). git 管理外なら None.

    候補のパスは検査対象からの相対だが、SARIF と PR の files API はルートからの相対で読む。
    """
    try:
        return _git(root, "rev-parse", "--show-prefix").strip()
    except DiffError:
        return None


def head_commit(root: Path) -> str | None:
    """検査した作業ツリーの HEAD. git 管理外・コミットがまだ無いなら None."""
    try:
        return _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip() or None
    except DiffError:
        return None


#: 検査した行番号 → PR の head の行番号. 対応が取れなければ None
LineMapper = Callable[[str, int], int | None]

_DIFF_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def map_line_to_head(diff_text: str, line: int) -> int | None:
    """`git diff -U0 <head> <検査したコミット>` の結果で、検査した行番号を head の行番号に直す.

    base 側の変更で増えた行は head に存在しないので None を返す (推測しない)。
    """
    offset = 0
    for match in _DIFF_HUNK_RE.finditer(diff_text):
        old_count = int(match.group(2)) if match.group(2) is not None else 1
        new_start = int(match.group(3))
        new_count = int(match.group(4)) if match.group(4) is not None else 1
        if line < new_start:
            break
        if line < new_start + new_count:
            return None
        offset += new_count - old_count
    return line - offset


def head_line_mapper(
    repo_dir: Path, scanned: str | None, head_sha: str | None
) -> LineMapper | None:
    """検査したコミットが PR の head と違うとき (pull_request の merge コミット) の対応表を作る.

    `scanned` はレポートに記録した検査時の HEAD。同じコミットを検査したなら None を返す
    (git を呼ばない)。記録が無い (git 管理外を検査した・古いレポート) ときも、比べようが
    ないので None を返す。違うのに `repo_dir` で 2 つのコミットを比較できないときは
    `DiffError` を投げる (推測した行に付けない)。パスはリポジトリルートからの相対で受け取る。
    """
    if head_sha is None or scanned is None or scanned == head_sha:
        return None
    toplevel = Path(_git(repo_dir, "rev-parse", "--show-toplevel").strip())
    for commit in (scanned, head_sha):
        _git(toplevel, "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")
    cache: dict[str, str] = {}

    def to_head(path: str, line: int) -> int | None:
        if path not in cache:
            cache[path] = _git(
                toplevel,
                "diff",
                "--unified=0",
                "--no-color",
                "--no-ext-diff",
                head_sha,
                scanned,
                "--",
                f":(top,literal){path}",
            )
        return map_line_to_head(cache[path], line)

    return to_head


Mode = Literal["auto", "full", "diff"]


def resolve_base(
    mode: Mode, base: str | None, environ: Mapping[str, str] | None = None
) -> str | None:
    """diff の基準を決める. None は「全件を検査する」.

    auto は PR の文脈 (GitHub Actions の GITHUB_BASE_REF) があるときだけ diff にする。
    """
    if mode == "full":
        return None
    env = os.environ if environ is None else environ
    resolved = base or (f"origin/{env['GITHUB_BASE_REF']}" if env.get("GITHUB_BASE_REF") else None)
    if mode == "diff" and resolved is None:
        raise ConfigError(
            "target.mode: diff には比較の基準が必要です。--base <ref> を指定するか、"
            "PR の文脈 (GITHUB_BASE_REF) で実行してください"
        )
    return resolved


def prepare_scope(
    mode: Mode,
    root: Path,
    base: str | None,
    environ: Mapping[str, str] | None = None,
) -> tuple[DiffScope | None, list[str]]:
    """モードと基準から DiffScope を作る. 返す警告は必ずレポートに残すこと.

    明示的な diff で差分が取れないのは実行エラーにする (黙って全件にすると、
    コストが想定の何倍にもなる)。auto は全件に戻して、そのことを警告する。
    """
    resolved = resolve_base(mode, base, environ)
    if resolved is None:
        return None, []
    try:
        return compute_diff(root, resolved), []
    except DiffError as exc:
        if mode == "diff":
            raise
        return None, [f"差分を取得できなかったため、全件を検査します: {exc}"]
