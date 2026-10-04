"""Scanner 契約テスト (設計書 §25, §29).

外部プラグイン作者は次だけ書けば自作 Scanner の適合性を検証できる:

    from security_checker.testing import ScannerContractTests

    class TestMyScanner(ScannerContractTests):
        def make_scanner(self):
            return MyScanner(MyConfig())

        def populate(self, root):          # 任意: 検出させたいファイルを置く
            (root / "app.py").write_text("eval(input())\\n")

検証する契約 (v1 で踏んだ罠を型とテストで塞ぐ §7.2):

  1. name / category を持ち、probe() は例外を投げない
  2. ツールが無ければ skipped を返す (ok + 0 件にしない。「壊れているのに緑」の原因)
  3. failed には必ず reason がある
  4. 候補の scanner は自分の name、ID は run 内で一意、2 回走らせても同じ (安定 ID §6.1)
  5. 候補のパスは検査対象からの相対パス (Location が型で強制する) で、対象の外を指さない
  6. 生出力は raw_dir の中に書く
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_checker.models.enums import Category, ScanStatus
from security_checker.scanners.base import ScanContext, Scanner, ScanResult, Target, ToolStatus


class ScannerContractTests:
    """すべての Scanner が満たすべき契約."""

    def make_scanner(self) -> Scanner:  # pragma: no cover - サブクラスが実装する
        raise NotImplementedError

    def populate(self, root: Path) -> None:
        """検査対象に置くファイル. 既定は空のディレクトリ."""

    async def _scan(self, tmp_path: Path, name: str = "target") -> tuple[ScanResult, Path, Path]:
        root = tmp_path / name
        root.mkdir()
        self.populate(root)
        raw = tmp_path / f"raw-{name}"
        raw.mkdir()
        scanner = self.make_scanner()
        result = await scanner.scan(Target(root=root), ScanContext(raw_dir=raw, exclude=[]))
        return result, root, raw

    def test_identity(self) -> None:
        scanner = self.make_scanner()
        assert isinstance(scanner.name, str) and scanner.name
        assert isinstance(scanner.category, Category)

    def test_probe_does_not_raise(self) -> None:
        assert isinstance(self.make_scanner().probe(), ToolStatus)

    @pytest.mark.asyncio
    async def test_status_is_explicit(self, tmp_path: Path) -> None:
        scanner = self.make_scanner()
        result, _, _ = await self._scan(tmp_path)
        assert isinstance(result, ScanResult)
        assert result.scanner == scanner.name
        assert isinstance(result.status, ScanStatus)
        if not scanner.probe().available:
            assert result.status is ScanStatus.SKIPPED, (
                "ツールが無いのに skipped 以外を返しました。"
                "ok + 0 件は「検査できた」と区別できません"
            )
        if result.status is ScanStatus.FAILED:
            assert result.reason, "failed には理由が必要です"
        if result.status is not ScanStatus.OK:
            assert result.candidates == [], "ok 以外で候補を返してはいけません"

    @pytest.mark.asyncio
    async def test_candidates_are_well_formed(self, tmp_path: Path) -> None:
        scanner = self.make_scanner()
        result, root, raw = await self._scan(tmp_path)
        ids = [candidate.id for candidate in result.candidates]
        assert len(ids) == len(set(ids)), "候補 ID が run 内で重複しています"
        for candidate in result.candidates:
            assert candidate.scanner == scanner.name
            if candidate.location is not None:
                resolved = (root / candidate.location.path).resolve()
                assert resolved.is_relative_to(root.resolve()), (
                    f"検査対象の外を指しています: {candidate.location.path}"
                )
        if result.raw_path is not None:
            assert Path(result.raw_path).resolve().is_relative_to(raw.resolve()), (
                "生出力は raw_dir の中に書いてください"
            )

    @pytest.mark.asyncio
    async def test_ids_are_stable_across_runs(self, tmp_path: Path) -> None:
        first, _, _ = await self._scan(tmp_path, "first")
        second, _, _ = await self._scan(tmp_path, "second")
        assert [c.id for c in first.candidates] == [c.id for c in second.candidates], (
            "同じ入力で候補 ID が変わりました。baseline と PR コメントの重複防止が壊れます"
        )
