"""security-checker: 拡張可能な AI Security Review プラットフォーム."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

__all__ = ["__version__"]

# バージョンの正は pyproject.toml の 1 か所だけ (release-please が更新する)。
# ここに文字列で書くと、リリースのたびに片方だけ上がって食い違う。
# 配布名を変えたら (NEXT-STEPS D1) ここの引数も変えること。
try:
    __version__ = version("security-checker")
except PackageNotFoundError:  # pragma: no cover - インストールせずにソースから読み込んだとき
    __version__ = "0+unknown"
