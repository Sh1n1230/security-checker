"""Candidate — Scanner 出力の正規化形 (設計書 §6.1)."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from security_checker.models.enums import Category, Severity

# `.` は re.DOTALL で改行にも当たる. そのまま `.*$` にすると、行コメント 1 つで
# スニペットの残り全部が消える (ID はスニペット全体から作るので、後ろの行が
# 別物でも同じ ID になっていた). 行コメントは行内で止め、ブロックコメントだけ
# 改行をまたがせる.
_COMMENT_RE = re.compile(r"(#|//|--)[^\n]*$|/\*[\s\S]*?\*/", re.MULTILINE)
_WS_RE = re.compile(r"\s+")
# 文字列リテラルの中の `//` `#` `--` はコメントではない. 除去の前に退避する
# (URL の `https://` が消えると、URL だけが違う 2 件が同じ ID になっていた).
_STRING_RE = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')

_MASK = "\x00"


def normalize_snippet(text: str) -> str:
    """安定 ID 用の正規化: 文字列退避 → コメント除去 → 空白圧縮.

    大文字小文字は保持する。識別子の大文字小文字だけが異なる別の指摘を
    baseline で同一視しないため。
    """
    literals: list[str] = []

    def stash(m: re.Match[str]) -> str:
        literals.append(m.group(0))
        return f"{_MASK}{len(literals) - 1}{_MASK}"

    protected = _STRING_RE.sub(stash, text)
    without_comments = _COMMENT_RE.sub(" ", protected)
    if literals:
        without_comments = re.sub(
            f"{_MASK}(\\d+){_MASK}",
            lambda m: literals[int(m.group(1))],
            without_comments,
        )
    return _WS_RE.sub(" ", without_comments).strip()


class Location(BaseModel):
    """コード上の位置. path は検査対象からの相対パス (設計書 §6.1)."""

    model_config = ConfigDict(frozen=True)

    path: str
    start_line: int = Field(ge=0)
    end_line: int = Field(ge=0)
    snippet: str | None = None

    @property
    def is_file_level(self) -> bool:
        """行を持たない、ファイル全体への指摘か (`start_line` が 0).

        スキャナが行を返さなかった場合と、ファイルの存在そのものが指摘の場合 (repo-hygiene) がある。
        """
        return self.start_line < 1

    @field_validator("path")
    @classmethod
    def _reject_absolute(cls, value: str) -> str:
        # v1 はレポートに絶対パスを書き出していた. 型の不変条件として禁止する.
        if value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value):
            raise ValueError(f"location.path は相対パスでなければなりません: {value}")
        return value.replace("\\", "/")


class PackageRef(BaseModel):
    """依存パッケージ参照."""

    model_config = ConfigDict(frozen=True)

    ecosystem: str
    name: str
    version: str | None = None
    manifest: str | None = None

    def as_key(self) -> str:
        """パッケージを ecosystem:name@version 形式で表す (版が未指定なら *)."""
        return f"{self.ecosystem}:{self.name}@{self.version or '*'}"


class Candidate(BaseModel):
    """スキャナが報告した「機械的な事実」. LLM の判断は一切含まない."""

    model_config = ConfigDict(frozen=True)

    id: str
    scanner: str
    category: Category
    rule_id: str
    title: str
    message: str

    location: Location | None = None
    package: PackageRef | None = None

    severity_reported: Severity | None = None
    confidence_reported: float | None = None
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    fix_available: str | None = None

    raw: dict[str, Any] = Field(default_factory=dict)
    redacted: bool = False
    #: 同じ指摘を報告した他のスキャナ (dedupe で 1 件にまとめた分)
    also_reported_by: list[str] = Field(default_factory=list)
    #: 秘密の値の sha256. baseline の照合だけに使い、実行中のメモリから外へ出さない。
    #: 低エントロピーの値は総当たりで戻せるので、レポートにもログにも載せない (§19.2, ADR 0008)
    secret_digest: str | None = Field(default=None, exclude=True, repr=False)

    @property
    def where(self) -> str:
        """人間向けの位置表記."""
        if self.location is not None:
            if self.location.is_file_level:
                return self.location.path
            return f"{self.location.path}:{self.location.start_line}"
        if self.package is not None:
            return self.package.as_key()
        return "-"


def candidate_id(
    scanner: str,
    rule_id: str,
    path: str,
    fingerprint_source: str,
    occurrence: int = 0,
) -> str:
    """安定 ID (設計書 §6.1).

    行番号を含めない. 無関係な編集で ID が変わると baseline と PR コメントが壊れるため.
    同一ファイル内で同じスニペットが複数ある場合のみ出現順の連番で区別する.
    """
    payload = "\x00".join([scanner, rule_id, path, normalize_snippet(fingerprint_source)])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    return digest if occurrence == 0 else f"{digest}-{occurrence}"


class IdFactory:
    """同一 (scanner, rule_id, path, snippet) の重複に出現順の連番を振る (設計書 §6.1)."""

    def __init__(self) -> None:
        """出現順を追跡するための空のカウンターを初期化する."""
        self._seen: dict[tuple[str, str, str, str], int] = {}

    def make(self, scanner: str, rule_id: str, path: str, fingerprint_source: str) -> str:
        """正規化した候補に安定 ID を割り当て、重複には出現順の連番を付ける."""
        key = (scanner, rule_id, path, normalize_snippet(fingerprint_source))
        occurrence = self._seen.get(key, 0)
        self._seen[key] = occurrence + 1
        return candidate_id(scanner, rule_id, path, fingerprint_source, occurrence)
