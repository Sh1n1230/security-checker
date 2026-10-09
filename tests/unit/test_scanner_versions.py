"""action.yml と Dockerfile でスキャナの版をそろえる (#45).

composite action と Docker イメージで版が違うと、同じ PR でも結果が食い違う。
版を上げるときは両方を同じ PR で変える。ここが落ちたら片方だけ変えている。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]

#: action.yml の input 名 → Dockerfile の ARG 名
PAIRS = {
    "gitleaks-version": "GITLEAKS_VERSION",
    "trivy-version": "TRIVY_VERSION",
    "osv-scanner-version": "OSV_SCANNER_VERSION",
    "semgrep-version": "SEMGREP_VERSION",
}


def dockerfile_args() -> dict[str, str]:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    return dict(re.findall(r"^ARG\s+([A-Z_]+)=(\S+)\s*$", text, flags=re.MULTILINE))


def action_inputs() -> dict[str, str]:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    return {name: str(spec.get("default", "")) for name, spec in action["inputs"].items()}


@pytest.mark.parametrize(("input_name", "arg_name"), sorted(PAIRS.items()))
def test_action_defaults_match_dockerfile(input_name, arg_name):
    assert action_inputs()[input_name] == dockerfile_args()[arg_name]


@pytest.mark.parametrize("input_name", sorted(PAIRS))
def test_action_defaults_are_pinned(input_name):
    """既定値に latest を使わない (実行のたびに版が変わるため)."""
    assert re.fullmatch(r"\d+\.\d+\.\d+", action_inputs()[input_name])
