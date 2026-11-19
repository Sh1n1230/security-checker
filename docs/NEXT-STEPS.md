# 残っている作業と、決める必要があること

この文書は「いま何が残っているか」だけを書きます。済んだ作業の経緯は CHANGELOG.md と git の履歴、
設計上の判断は [adr/](adr/README.md) にあります。機能の要望とバグは
[Issues](https://github.com/Sh1n1230/security-checker/issues) で管理しています。

設計書 ([DESIGN.md](DESIGN.md) §32) のフェーズでいうと、P1〜P5 (本体・複数 LLM・GitHub 統合・品質) は完了、
**P6 (評価と公開) と P7 (ゲートを締める) の一部が残っています。**

## 現状

| 項目 | 状態 |
|---|---|
| リリース | GitHub Release で公開している (CHANGELOG.md)。インストールは `uv tool install git+https://github.com/Sh1n1230/security-checker@<タグ>` |
| PyPI / GHCR | **未公開。** `release.yml` に手順はあり、リポジトリ変数 (`PUBLISH_PYPI` / `PUBLISH_GHCR`) で止めている |
| GitHub Action | composite action (`action.yml`) として使える。Docker イメージ版は GHCR の公開後 ([ADR 0005](adr/0005-composite-action-until-ghcr.md)) |
| 精度の評価 | `eval` コマンドと同梱データセット (100 件) はある。**実 LLM での結果はまだ公開していない** |
| 品質 | lint (ruff)・型検査 (mypy --strict)・テスト (Linux / macOS / Windows、カバレッジ 80% 以上が必須) を CI で回している |

## 決める必要があること

メンテナの判断が要るものです。番号は当初の検討メモのものを引き継いでいます。

| # | 決めること | いまの考え | 関連 |
|---|---|---|---|
| D1 | **PyPI の配布名。** `security-checker` は別のプロジェクトが登録済み | `security-checker-ai` などを確保する。CLI の名前は `security-checker` のまま | #53 |
| D12 | **既定の Reviewer の数と集約戦略** | 決めていない。実 LLM での eval の結果を見て決める。効果が無ければ「1 モデルで十分」と正直に書く | #52 |
| — | **ドキュメントの英語化** | README は英語が正、`docs/` は日本語のまま ([ADR 0002](adr/0002-docs-language.md))。英語化は手伝いを歓迎します | #54 |

## 公開までの手順 (P6)

1. **実 LLM で eval を回す。** 課金が発生します。`eval` には `--estimate` が無いので、まずデータセットを数件に絞った
   コピーで試してください。

   ```sh
   security-checker eval -d benchmarks/datasets/handmade-v1 -c security-checker.local.yml \
     -o benchmarks/results/<date>.json -m benchmarks/results/<date>.md
   ```

   single / consensus / judge を比べて D12 を決め、結果を README の Accuracy 節に書きます。
2. **PyPI。** 閉じた環境で一度通してから公開します。
   1. TestPyPI に Trusted Publisher を登録し、配布物とインストール手順を確かめる
   2. PyPI で配布名を確保し、Trusted Publisher に `release.yml` と environment `pypi` を登録する
   3. `pyproject.toml` の `name` と `src/security_checker/__init__.py` の `version("...")` を配布名に変える
   4. リポジトリ変数 `PUBLISH_PYPI=true` を設定する
3. **GHCR。** リポジトリ変数 `PUBLISH_GHCR=true` を設定する。

リリースは release-please が作るリリース PR をマージすると始まります。配布物は、同じコミットの CI が
成功するまで作られません (`release.yml` の `ci-passed`)。

**リリース PR の CI について。** release-please は `GITHUB_TOKEN` で PR を作るため、その PR では workflow が起動せず、
必須チェックが付きません。リリース PR は**一度 close → reopen** して CI を起動してください。
手間になったら GitHub App のトークンを release-please に渡します (PAT は置きません)。

## ゲートを締める (P7)

#56 で追跡しています。

1. 各スキャナの生の SARIF (category `semgrep`・`gitleaks`・`trivy`・`osv-scanner`。`security.yml` の `raw-sarif` ジョブ) を
   空の SARIF で閉じ、ジョブを消す。LLM を通した結果 (category `security-checker`) だけを残す
2. `workflow_run` パターンで fork PR の SARIF アップロードが通ることを確かめてから、Ruleset に
   "Require code scanning results" (ツール名 `security-checker`) を足す

完了の条件は、high 以上の confirmed を含む PR がマージできないことを実際に確かめることです。

## メンテナ向けのメモ

- **必須チェック。** Ruleset `protect main` の必須チェックは `security` (自己検査) だけです。`CI` (lint・型検査・テスト) は
  必須になっていないので、テストの落ちる変更でもマージできてしまいます。`quality`・`tests-os`・`dogfooding`・`docker`・
  `lint-ci`・`package` を必須に足すことを勧めます。
- **dogfooding に使う Reviewer。** 開発に使っている AI と同じ系統を、自分のリポジトリのレビューに使わない
  (「開発に使う AI とレビューする AI を分ける」という設計書 §9 の原則)。
- **無料の HTTP エンドポイント。** 振り分け先がプロンプトを学習・記録しうるものは、公開リポジトリのコードに限って使う
  ([security-model.md](security-model.md))。
- **`process` Reviewer のツールの禁止。** 拒否リスト (`--disallowed-tools` など) は、CLI にツールが増えると漏れます。
  許可リストか「ツールをすべて無効にする」指定があれば、そちらを使ってください ([process-transport.md](process-transport.md))。
