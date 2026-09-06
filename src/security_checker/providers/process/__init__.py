"""transport: process — 任意の非対話コマンドを Reviewer にする (設計書 §9.7)."""

from security_checker.providers.process.runner import (
    TEXT_IO_DIALECT,
    ProcessProvider,
    process_capabilities,
)
from security_checker.providers.process.sandbox import (
    PROMPT_FILE_PLACEHOLDER,
    SandboxResult,
    run_sandboxed,
)

__all__ = [
    "PROMPT_FILE_PLACEHOLDER",
    "TEXT_IO_DIALECT",
    "ProcessProvider",
    "SandboxResult",
    "process_capabilities",
    "run_sandboxed",
]
