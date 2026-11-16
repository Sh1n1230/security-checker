"""リポジトリの衛生の検査 (git だけで動く内蔵チェック).

中身のパターンを見る秘密検出では拾えないものを、git の追跡状態とファイル名で見つける。

  1. `.gitignore` に載っているのに追跡されているファイル
  2. 資格情報を含みうる名前のファイルのコミット
  3. `.mcp.json` の env / headers に直書きされた値

**値はどこにも載せない。** 報告するのはパス、ルール、`.mcp.json` ならキー名だけである (§19.2)。
候補はファイル単位 (`start_line=0`) にするので、Reviewer に渡す文脈にもファイルの本文は入らない。
"""

from __future__ import annotations

import fnmatch
import json
import time
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

from security_checker.config.schema import RepoHygieneConfig
from security_checker.models.candidate import Candidate, IdFactory, Location
from security_checker.models.enums import Category, Severity
from security_checker.scanners.base import (
    BaseScanner,
    ScanContext,
    ScanResult,
    Target,
    elapsed_ms,
    run_command,
)
from security_checker.scanners.filters import is_excluded

SCANNER_NAME = "repo-hygiene"
RULE_TRACKED_IGNORED = "tracked-ignored-file"
RULE_CREDENTIAL_FILE = "credential-file-committed"
RULE_MCP_LITERAL = "mcp-config-literal-value"

CREDENTIAL_NAMES = (
    ".env",
    ".env.*",
    ".mcp.json",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "credentials.json",
    "client_secret*.json",
    "*service-account*.json",
    "id_rsa",
    "id_ecdsa",
    "id_ed25519",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
)
#: 値を持たない雛形として広く使われる名前
TEMPLATE_NAMES = (".env.example", ".env.sample", ".env.template")
CREDENTIAL_PATHS = (".claude/settings.local.json",)
#: 鍵か証明書かを見分けるのに読む量. PEM の見出しは先頭にある
_SNIFF_BYTES = 64 * 1024
#: `.mcp.json` として読む上限. これを超えるものは JSON として読めず、警告になる
_MCP_MAX_BYTES = 1024 * 1024
_KEY_SUFFIXES = (".pem", ".key")


def is_credential_path(path: str) -> bool:
    """資格情報を含みうる名前か. 雛形 (`.env.example` など) は除く."""
    if path in CREDENTIAL_PATHS:
        return True
    name = PurePosixPath(path).name
    if name in TEMPLATE_NAMES:
        return False
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in CREDENTIAL_NAMES)


def key_file_severity(data: bytes) -> Severity:
    """`*.pem` / `*.key` の重大度. 秘密鍵なら high、公開鍵証明書だけなら info."""
    if b"PRIVATE KEY-----" in data:
        return Severity.HIGH
    if b"-----BEGIN CERTIFICATE-----" in data:
        return Severity.INFO
    return Severity.MEDIUM


def literal_mcp_keys(payload: Any) -> list[str]:
    """`mcpServers.*.env` / `headers` のうち、値が直書きのキーを返す. 値は返さない.

    `${VAR}` を含む値と空文字は直書きとして扱わない。
    """
    if not isinstance(payload, dict):
        raise ValueError("トップレベルがオブジェクトではありません")
    servers = payload.get("mcpServers")
    if not isinstance(servers, dict):
        return []
    keys: list[str] = []
    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        for section in ("env", "headers"):
            values = server.get(section)
            if not isinstance(values, dict):
                continue
            keys.extend(
                f"mcpServers.{server_name}.{section}.{key}"
                for key, value in values.items()
                if isinstance(value, str) and value and "${" not in value
            )
    return keys


class RepoHygieneScanner(BaseScanner):
    """`git ls-files` の結果とファイル名から候補を作る."""

    name = SCANNER_NAME
    category = Category.SECRET
    requires: ClassVar[list[str]] = ["git"]
    install_hint = "git を導入するか、scanners.repo_hygiene.enabled: false で無効化してください"

    settings: RepoHygieneConfig

    def __init__(self, settings: RepoHygieneConfig) -> None:
        super().__init__(settings)

    async def scan(self, target: Target, ctx: ScanContext) -> ScanResult:
        status = self.probe()
        if not status.available:
            return self.skipped(status.reason or "git が利用できません", unavailable=True)

        started = time.monotonic()
        inside = await run_command(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=target.root,
            timeout_s=self.settings.timeout_s,
        )
        if inside.exit_code != 0:
            return self.skipped(
                "検査対象が git 管理外のため、追跡状態を確かめられません", version=status.version
            )

        tracked = await self._ls_files(target, ["--cached"])
        ignored = await self._ls_files(target, ["--cached", "--ignored", "--exclude-standard"])
        if tracked is None or ignored is None:
            return self.failed(
                "git ls-files に失敗しました (追跡状態の検査は行われていません)",
                duration_ms=elapsed_ms(started),
                version=status.version,
            )

        candidates, warnings = build_candidates(tracked, set(ignored), target.root, ctx.exclude)
        return self.ok(
            candidates,
            duration_ms=elapsed_ms(started),
            exit_code=0,
            version=status.version,
            parse_warnings=warnings,
        )

    async def _ls_files(self, target: Target, options: list[str]) -> list[str] | None:
        result = await run_command(
            ["git", "ls-files", "-z", *options],
            cwd=target.root,
            timeout_s=self.settings.timeout_s,
        )
        if result.timed_out or result.exit_code != 0:
            return None
        text = result.stdout.decode("utf-8", "replace")
        return [path for path in text.split("\0") if path]


def build_candidates(
    tracked: list[str], ignored: set[str], root: Path, exclude: list[str]
) -> tuple[list[Candidate], list[str]]:
    """追跡中のファイル一覧から候補を作る. 読めないファイルは警告にして続行する."""
    ids = IdFactory()
    candidates: list[Candidate] = []
    warnings: list[str] = []
    for path in sorted(tracked):
        if is_excluded(path, exclude):
            continue
        credential = is_credential_path(path)
        if path in ignored:
            severity = Severity.HIGH if credential else Severity.LOW
            candidates.append(
                _candidate(
                    ids,
                    RULE_TRACKED_IGNORED,
                    path,
                    severity,
                    f"{path} は .gitignore に載っていますが追跡されています。"
                    "無視しているつもりでも、内容はリポジトリに残ります",
                )
            )
        elif credential:
            candidates.append(
                _candidate(
                    ids,
                    RULE_CREDENTIAL_FILE,
                    path,
                    _credential_severity(root, path),
                    f"{path} は資格情報を含みうる名前のファイルで、コミットされています",
                )
            )
        if PurePosixPath(path).name == ".mcp.json":
            candidates.extend(_mcp_candidates(ids, root, path, warnings))
    return candidates, warnings


def _credential_severity(root: Path, path: str) -> Severity:
    if not path.endswith(_KEY_SUFFIXES):
        return Severity.MEDIUM
    data = _read_head(root, path, _SNIFF_BYTES)
    return Severity.MEDIUM if data is None else key_file_severity(data)


def _read_head(root: Path, path: str, limit: int) -> bytes | None:
    resolved = (root / path).resolve()
    # シンボリックリンクで検査対象の外を読まない
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        return None
    try:
        with resolved.open("rb") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _mcp_candidates(ids: IdFactory, root: Path, path: str, warnings: list[str]) -> list[Candidate]:
    data = _read_head(root, path, _MCP_MAX_BYTES)
    if data is None:
        return []
    try:
        keys = literal_mcp_keys(json.loads(data.decode("utf-8", "replace")))
    except ValueError as exc:
        warnings.append(f"{SCANNER_NAME}: {path} を JSON として読めません: {type(exc).__name__}")
        return []
    return [
        _candidate(
            ids,
            RULE_MCP_LITERAL,
            path,
            Severity.HIGH,
            f"{path} の {key} に値が直書きされています。${{VAR}} 形式で環境変数から渡してください",
            fingerprint=key,
        )
        for key in keys
    ]


def _candidate(
    ids: IdFactory,
    rule_id: str,
    path: str,
    severity: Severity,
    message: str,
    *,
    fingerprint: str | None = None,
) -> Candidate:
    return Candidate(
        id=ids.make(SCANNER_NAME, rule_id, path, fingerprint or rule_id),
        scanner=SCANNER_NAME,
        category=Category.SECRET,
        rule_id=rule_id,
        title=f"リポジトリの衛生: {rule_id}",
        message=message,
        # 行を持たない (ファイル単位). 行を指すと、その前後の本文が Reviewer に送られる
        location=Location(path=path, start_line=0, end_line=0),
        severity_reported=severity,
        cwe=["CWE-538"],
        redacted=True,
    )
