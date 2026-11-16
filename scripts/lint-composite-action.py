"""Run ShellCheck on Bash run blocks in a GitHub composite action.

actionlint checks workflow run blocks but intentionally does not check action.yml.
This small companion validates the remaining shell scripts in the action itself.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml

EXPECTED_ARGV_LENGTH = 2


def bash_steps(action: dict[str, Any]) -> list[tuple[str, str]]:
    """Return named Bash snippets while rejecting unsupported inline shells."""
    if action.get("runs", {}).get("using") != "composite":
        raise ValueError("expected a composite action")
    scripts: list[tuple[str, str]] = []
    for index, step in enumerate(action["runs"].get("steps", []), start=1):
        if "run" not in step:
            continue
        shell = step.get("shell")
        if shell != "bash":
            raise ValueError(f"run step {index} has unsupported shell: {shell!r}")
        scripts.append((step.get("name", f"step {index}"), step["run"]))
    return scripts


def main(path: Path) -> int:
    """Report each composite Bash step that ShellCheck finds unsafe."""
    action = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(action, dict):
        raise ValueError("expected an action mapping")
    failed = False
    for name, script in bash_steps(action):
        sys.stderr.write(f"ShellCheck: {name}\n")
        result = subprocess.run(
            ["shellcheck", "--shell=bash", "-"],
            input=script,
            text=True,
            check=False,
        )
        failed |= result.returncode != 0
    return int(failed)


if __name__ == "__main__":
    if len(sys.argv) != EXPECTED_ARGV_LENGTH:
        raise SystemExit("usage: lint-composite-action.py ACTION_YML")
    raise SystemExit(main(Path(sys.argv[1])))
