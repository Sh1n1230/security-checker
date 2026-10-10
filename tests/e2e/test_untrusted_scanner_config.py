"""E2E: 信用できない検査対象に置かれたスキャナ設定で、検出を消せないこと (#43).

実スキャナを使う。導入されていない環境では skip する。
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from security_checker.config.schema import Config
from security_checker.policy.suppress import SuppressionRules
from security_checker.run import run_scan

pytestmark = pytest.mark.e2e

# GitHub push protection に弾かれないよう、実行時に組み立てる
SECRET_VALUE = "xoxb-" + "1234567890" + "-" + "0987654321" + "-" + "abcdefghijklmnopqrstuvwx"


def config(output_dir: Path, scanner: str) -> Config:
    scanners = {
        name: {"enabled": name == scanner} for name in ("semgrep", "gitleaks", "osv", "trivy")
    }
    return Config.model_validate(
        {"scanners": scanners, "output": {"dir": str(output_dir)}, "policy": {"strict": False}}
    )


async def count(tmp_path: Path, root: Path, scanner: str, *, untrusted: bool) -> int:
    outcome = await run_scan(
        config(tmp_path / "out", scanner),
        root,
        base_dir=tmp_path,
        suppression=SuppressionRules(untrusted_target=untrusted),
    )
    run = next(r for r in outcome.report.scanners if r.scanner == scanner)
    assert run.status.value == "ok", run.reason
    return len(outcome.report.candidates)


@pytest.mark.skipif(shutil.which("gitleaks") is None, reason="gitleaks 未導入")
async def test_gitleaks_config_in_the_tree_cannot_hide_a_secret(tmp_path):
    root = tmp_path / "pr"
    root.mkdir()
    (root / "settings.py").write_text(f'SLACK_TOKEN = "{SECRET_VALUE}"\n', encoding="utf-8")
    (root / ".gitleaks.toml").write_text(
        '[extend]\nuseDefault = true\n[allowlist]\npaths = ["settings.py"]\n', encoding="utf-8"
    )
    # 信用する場合は、対象の設定が効いて消える (= この攻撃が成立する前提の確認)
    assert await count(tmp_path, root, "gitleaks", untrusted=False) == 0
    assert await count(tmp_path, root, "gitleaks", untrusted=True) == 1


@pytest.mark.skipif(shutil.which("trivy") is None, reason="trivy 未導入")
@pytest.mark.parametrize(
    ("name", "content"),
    [
        (".trivyignore", "DS-0002\nDS-0026\n"),
        ("trivy.yaml", "scan:\n  skip-files:\n    - Dockerfile\n"),
    ],
)
async def test_trivy_config_in_the_tree_cannot_hide_a_misconfiguration(tmp_path, name, content):
    root = tmp_path / "pr"
    root.mkdir()
    # USER も HEALTHCHECK も無い Dockerfile (trivy の既定のチェックで検出される)
    (root / "Dockerfile").write_text("FROM alpine:3.20\nRUN echo hi\n", encoding="utf-8")
    trusted = await count(tmp_path, root, "trivy", untrusted=True)
    (root / name).write_text(content, encoding="utf-8")
    assert await count(tmp_path, root, "trivy", untrusted=False) == 0
    assert await count(tmp_path, root, "trivy", untrusted=True) == trusted > 0


@pytest.mark.skipif(shutil.which("osv-scanner") is None, reason="osv-scanner 未導入")
async def test_osv_config_in_the_tree_cannot_hide_a_vulnerability(tmp_path):
    root = tmp_path / "pr"
    (root / "sub").mkdir(parents=True)
    # 既知の脆弱性がある版 (osv.dev への問い合わせが必要)
    (root / "sub" / "requirements.txt").write_text("jinja2==2.10\n", encoding="utf-8")
    before = await count(tmp_path, root, "osv", untrusted=True)
    ids = ["GHSA-462w-v97r-4m45", "PYSEC-2019-217"]
    (root / "sub" / "osv-scanner.toml").write_text(
        "".join(f'[[IgnoredVulns]]\nid = "{i}"\n' for i in ids), encoding="utf-8"
    )
    assert await count(tmp_path, root, "osv", untrusted=True) == before > 0
