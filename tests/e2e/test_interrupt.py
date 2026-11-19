"""Ctrl-C で止めても、ここまでの結果を書き出す (設計書 §20.2, #218).

実際に CLI を子プロセスで起動し、SIGINT を送って確かめる。
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

INTERRUPTED = 130

# 1 回目の呼び出しには判定を返し、2 回目以降は返さない Reviewer.
# 状態は、プロンプトと一緒に渡されないので、引数のディレクトリに置く
REVIEWER = r"""
import json, pathlib, sys, time
sys.stdin.read()
marker = pathlib.Path(sys.argv[1])
if marker.exists():
    time.sleep(120)
marker.write_text("called", encoding="utf-8")
print(json.dumps({
    "vulnerable": True, "vulnerability_type": "x", "cwe": ["CWE-78"], "severity": "high",
    "confidence": 0.9, "false_positive_probability": 0.05, "exploitability": "likely",
    "impact": "x", "attack_vector": "x", "attack_path": [], "evidence": [],
    "reasoning": "first call", "remediation": None, "needs_more_context": [],
}))
"""


@pytest.mark.skipif(os.name != "posix", reason="SIGINT を子プロセスに送る")
def test_sigint_writes_the_partial_report_and_exits_130(tmp_path: Path) -> None:
    root = tmp_path / "app"
    root.mkdir()
    # 外部スキャナに頼らず候補を作る: git だけで動く repo_hygiene が
    # 「.gitignore に載っているのに追跡されているファイル」を 1 件ずつ候補にする
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")
    names = ("a.log", "b.log", "c.log")
    for name in names:
        (root / name).write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-f", *names], cwd=root, check=True)
    reviewer = tmp_path / "reviewer.py"
    reviewer.write_text(REVIEWER, encoding="utf-8")
    marker = tmp_path / "marker"
    (root / "security-checker.yml").write_text(
        json.dumps(
            {
                "version": 1,
                "scanners": {
                    "semgrep": {"enabled": False},
                    "gitleaks": {"enabled": False},
                    "osv": {"enabled": False},
                },
                "reviewers": [
                    {
                        "name": "slow",
                        "transport": "process",
                        "command": [sys.executable, str(reviewer), str(marker)],
                        "timeout_s": 120,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    process = subprocess.Popen(
        [sys.executable, "-m", "security_checker", "review", str(root), "--full", "-o", str(out)],
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 60
        while not marker.exists() and time.monotonic() < deadline and process.poll() is None:
            time.sleep(0.1)
        if not marker.exists():
            process.kill()
            stdout, stderr = process.communicate()
            pytest.fail(f"Reviewer が呼ばれませんでした:\n{stdout}\n{stderr}")
        time.sleep(1.0)  # 1 件目の判定が記録されるのを待つ
        process.send_signal(signal.SIGINT)
        stdout, stderr = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()

    assert process.returncode == INTERRUPTED, stdout + stderr
    assert "中断されました" in stderr
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert "中断" in report["stopped_reason"]
    statuses = sorted(finding["status"] for finding in report["findings"])
    assert statuses.count("not_reviewed") == len(statuses) - 1
    assert len(statuses) > 1
    # 送った呼び出しの記録も残る
    assert list((out / "trace").rglob("calls/*.json"))
