"""repo-hygiene: 追跡状態とファイル名で見つける資格情報ファイル (#103)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from security_checker.config.schema import Config, ContextConfig, RepoHygieneConfig
from security_checker.context.builder import ContextBuilder
from security_checker.github.pr import DiffScope
from security_checker.models.candidate import Candidate
from security_checker.models.enums import ScanStatus, Severity
from security_checker.models.task import RepoFacts
from security_checker.report.json_writer import write_json
from security_checker.run import run_scan
from security_checker.scanners.base import ScanContext, ScanResult, Target
from security_checker.scanners.repo_hygiene import (
    RULE_CREDENTIAL_FILE,
    RULE_MCP_LITERAL,
    RULE_TRACKED_IGNORED,
    RepoHygieneScanner,
    is_credential_path,
    key_file_severity,
    literal_mcp_keys,
)

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git 未導入")

# 完結した形の値をリポジトリに残さない (push protection と自リポジトリの検査に掛かる)
LITERAL_VALUE = "hygiene-" + "fixture-" + "value-0123456789"
DOTENV = ".env"
MCP = ".mcp.json"


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def repo(tmp_path: Path, files: dict[str, str], *, gitignore: str = "") -> Path:
    """`files` を追跡した git リポジトリを作る. `.gitignore` に載っていても `add -f` で追跡する."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    if gitignore:
        (root / ".gitignore").write_text(gitignore, encoding="utf-8")
        git(root, "add", ".gitignore")
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        git(root, "add", "-f", name)
    return root


async def scan(root: Path, tmp_path: Path, exclude: list[str] | None = None) -> ScanResult:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir(exist_ok=True)
    scanner = RepoHygieneScanner(RepoHygieneConfig())
    ctx = ScanContext(raw_dir=raw_dir, exclude=exclude or [])
    return await scanner.scan(Target(root=root), ctx)


def by_rule(result: ScanResult, rule_id: str) -> list[Candidate]:
    return [c for c in result.candidates if c.rule_id == rule_id]


def mcp_json(env: dict[str, object], headers: dict[str, object] | None = None) -> str:
    server: dict[str, object] = {"command": "server", "env": env}
    if headers is not None:
        server["headers"] = headers
    return json.dumps({"mcpServers": {"github": server}})


# --- 名前の判定 ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        DOTENV,
        "app/.env.production",
        MCP,
        "sub/.npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "config/credentials.json",
        "client_secret_1234.json",
        "my-service-account-prod.json",
        "keys/id_rsa",
        "id_ecdsa",
        "id_ed25519",
        "certs/server.pem",
        "server.key",
        "store.p12",
        "store.pfx",
        ".claude/settings.local.json",
    ],
)
def test_credential_names_are_matched(path):
    assert is_credential_path(path)


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        "app/.env.sample",
        ".env.template",
        "environment.py",
        "id_rsa.pub",
        "README.md",
        # ルートの .claude/ だけを見る。同名の別の場所は資格情報の置き場ではない
        "docs/.claude/settings.local.json",
        ".claude/settings.json",
    ],
)
def test_templates_and_ordinary_files_are_not_matched(path):
    assert not is_credential_path(path)


def test_key_file_severity_tells_private_keys_from_certificates():
    private = b"-----BEGIN " + b"PRIVATE KEY-----\nabc\n"
    assert key_file_severity(private) is Severity.HIGH
    assert key_file_severity(b"-----BEGIN CERTIFICATE-----\nabc\n") is Severity.INFO
    # 証明書と秘密鍵が同じファイルにあれば秘密鍵として扱う
    assert key_file_severity(b"-----BEGIN CERTIFICATE-----\n" + private) is Severity.HIGH
    assert key_file_severity(b"\x00\x01binary") is Severity.MEDIUM


# --- .mcp.json の解析 ------------------------------------------------------------------


def test_literal_mcp_keys_reports_only_literal_strings():
    payload = {
        "mcpServers": {
            "github": {
                "env": {"TOKEN": LITERAL_VALUE, "FROM_ENV": "${GITHUB_TOKEN}", "EMPTY": ""},
                "headers": {"Authorization": "Bearer " + LITERAL_VALUE, "X-Env": "Bearer ${T}"},
            },
            "broken": "not-an-object",
            "no-env": {"command": "x", "env": ["not", "a", "mapping"]},
        }
    }
    assert literal_mcp_keys(payload) == [
        "mcpServers.github.env.TOKEN",
        "mcpServers.github.headers.Authorization",
    ]


def test_literal_mcp_keys_without_servers_is_empty():
    assert literal_mcp_keys({}) == []
    assert literal_mcp_keys({"mcpServers": []}) == []


def test_literal_mcp_keys_rejects_a_non_object():
    with pytest.raises(ValueError, match="オブジェクト"):
        literal_mcp_keys([])


# --- スキャナ --------------------------------------------------------------------------


@needs_git
async def test_tracked_but_ignored_credential_file_is_high(tmp_path):
    root = repo(tmp_path, {MCP: mcp_json({"TOKEN": LITERAL_VALUE})}, gitignore=f"{MCP}\n")
    result = await scan(root, tmp_path)

    assert result.status is ScanStatus.OK
    [tracked] = by_rule(result, RULE_TRACKED_IGNORED)
    assert tracked.severity_reported is Severity.HIGH
    assert tracked.location is not None
    assert tracked.location.path == MCP
    assert tracked.location.is_file_level
    # .gitignore に載っているものは tracked-ignored に寄せ、同じファイルを 2 回数えない
    assert by_rule(result, RULE_CREDENTIAL_FILE) == []
    [literal] = by_rule(result, RULE_MCP_LITERAL)
    assert literal.severity_reported is Severity.HIGH
    assert "mcpServers.github.env.TOKEN" in literal.message


@needs_git
async def test_tracked_but_ignored_ordinary_file_is_low(tmp_path):
    root = repo(tmp_path, {"build/out.txt": "x\n"}, gitignore="build/\n")
    result = await scan(root, tmp_path)
    [tracked] = by_rule(result, RULE_TRACKED_IGNORED)
    assert tracked.severity_reported is Severity.LOW
    assert tracked.location is not None
    assert tracked.location.path == "build/out.txt"


@needs_git
async def test_committed_credential_file_is_medium_and_templates_are_skipped(tmp_path):
    root = repo(tmp_path, {DOTENV: "A=1\n", ".env.example": "A=\n", "app.py": "x = 1\n"})
    result = await scan(root, tmp_path)
    [candidate] = result.candidates
    assert candidate.rule_id == RULE_CREDENTIAL_FILE
    assert candidate.severity_reported is Severity.MEDIUM
    assert candidate.location is not None
    assert candidate.location.path == DOTENV


@needs_git
async def test_untracked_credential_file_is_not_reported(tmp_path):
    root = repo(tmp_path, {"app.py": "x = 1\n"}, gitignore=f"{DOTENV}\n")
    (root / DOTENV).write_text("A=1\n", encoding="utf-8")
    result = await scan(root, tmp_path)
    assert result.status is ScanStatus.OK
    assert result.candidates == []


@needs_git
async def test_key_files_are_graded_by_content(tmp_path):
    root = repo(
        tmp_path,
        {
            "private.pem": "-----BEGIN " + "PRIVATE KEY-----\nabc\n",
            "public.pem": "-----BEGIN CERTIFICATE-----\nabc\n",
        },
    )
    result = await scan(root, tmp_path)
    severities = {
        c.location.path: c.severity_reported for c in result.candidates if c.location is not None
    }
    assert severities == {"private.pem": Severity.HIGH, "public.pem": Severity.INFO}


@needs_git
async def test_mcp_env_expansion_is_not_reported(tmp_path):
    root = repo(tmp_path, {MCP: mcp_json({"TOKEN": "${GITHUB_TOKEN}", "EMPTY": ""})})
    result = await scan(root, tmp_path)
    assert by_rule(result, RULE_MCP_LITERAL) == []
    # ファイル名の候補は残る (中身に値が無くても、置き場として注意が要る)
    assert len(by_rule(result, RULE_CREDENTIAL_FILE)) == 1


@needs_git
async def test_each_literal_key_gets_its_own_stable_id(tmp_path):
    root = repo(tmp_path, {MCP: mcp_json({"A": LITERAL_VALUE, "B": LITERAL_VALUE})})
    first = by_rule(await scan(root, tmp_path), RULE_MCP_LITERAL)
    second = by_rule(await scan(root, tmp_path), RULE_MCP_LITERAL)
    assert len({c.id for c in first}) == 2
    assert [c.id for c in first] == [c.id for c in second]


@needs_git
async def test_invalid_mcp_json_is_a_warning_not_a_failure(tmp_path):
    root = repo(tmp_path, {MCP: "{ not json " + LITERAL_VALUE})
    result = await scan(root, tmp_path)
    assert result.status is ScanStatus.OK
    assert by_rule(result, RULE_MCP_LITERAL) == []
    [warning] = result.parse_warnings
    assert MCP in warning
    assert LITERAL_VALUE not in warning


@needs_git
async def test_excluded_paths_are_not_reported(tmp_path):
    root = repo(tmp_path, {"tests/fixtures/" + DOTENV: "A=1\n", DOTENV: "A=1\n"})
    result = await scan(root, tmp_path, exclude=["tests/fixtures/**"])
    assert [c.location.path for c in result.candidates if c.location is not None] == [DOTENV]


@needs_git
async def test_symlink_pointing_outside_the_target_is_not_read(tmp_path):
    outside = tmp_path / "outside.pem"
    outside.write_text("-----BEGIN " + "PRIVATE KEY-----\n", encoding="utf-8")
    root = repo(tmp_path, {"app.py": "x = 1\n"})
    try:
        (root / "link.pem").symlink_to(outside)
    except OSError:
        pytest.skip("シンボリックリンクを作れない環境")
    git(root, "add", "link.pem")
    result = await scan(root, tmp_path)
    [candidate] = result.candidates
    # 外のファイルの中身 (秘密鍵) を見て high にしない
    assert candidate.severity_reported is Severity.MEDIUM


@needs_git
async def test_outside_a_git_repository_is_skipped_with_a_reason(tmp_path, monkeypatch):
    root = tmp_path / "plain"
    root.mkdir()
    (root / DOTENV).write_text("A=1\n", encoding="utf-8")
    # 親ディレクトリがたまたま git 管理下でも、このテストの結果を変えない
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    result = await scan(root, tmp_path)
    assert result.status is ScanStatus.SKIPPED
    assert result.reason is not None
    assert "git 管理外" in result.reason
    # 入れていないわけではない。baseline の更新や SARIF を止める「未導入」とは区別する
    assert result.unavailable is False


async def test_missing_git_is_skipped_as_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    result = await scan(tmp_path, tmp_path)
    assert result.status is ScanStatus.SKIPPED
    assert result.unavailable is True


def test_extra_args_are_rejected():
    with pytest.raises(ValidationError, match="extra_args"):
        Config.model_validate({"scanners": {"repo_hygiene": {"extra_args": ["--x"]}}})


# --- 値がどこにも出ないこと (§19.2) ----------------------------------------------------


@needs_git
async def test_values_never_reach_the_report_or_the_review_task(tmp_path):
    root = repo(
        tmp_path,
        {
            MCP: mcp_json({"TOKEN": LITERAL_VALUE}, {"Authorization": "Bearer " + LITERAL_VALUE}),
            DOTENV: f"API_KEY={LITERAL_VALUE}\n",
        },
        gitignore=f"{MCP}\n",
    )
    config = Config.model_validate(
        {
            "scanners": {
                "semgrep": {"enabled": False},
                "gitleaks": {"enabled": False},
                "osv": {"enabled": False},
            },
            "output": {"dir": str(tmp_path / "out")},
        }
    )
    outcome = await run_scan(config, root, base_dir=tmp_path)
    assert len(outcome.report.candidates) == 4

    write_json(outcome.report, outcome.output_dir)
    for path in outcome.output_dir.rglob("*"):
        if path.is_file():
            assert LITERAL_VALUE not in path.read_text(encoding="utf-8", errors="replace")

    # Reviewer に渡す文脈にも本文を入れない (行を指すと前後の行が送られる)
    builder = ContextBuilder(root, ContextConfig(), RepoFacts())
    for candidate in outcome.report.candidates:
        task = builder.build(candidate)
        assert task.code_context.primary is None
        assert LITERAL_VALUE not in task.model_dump_json()
        assert any("ファイル全体" in note for note in task.notes)


# --- 差分モード ------------------------------------------------------------------------


@needs_git
async def test_file_level_candidates_follow_the_changed_files_in_diff_mode(tmp_path):
    root = repo(tmp_path, {DOTENV: "A=1\n", "sub/" + DOTENV: "A=1\n"})
    result = await scan(root, tmp_path)
    scope = DiffScope(base="main", added={DOTENV: ((1, 1),)}, changed_files=frozenset({DOTENV}))
    touched = [c.location.path for c in result.candidates if c.location and scope.touches(c)]
    assert touched == [DOTENV]
