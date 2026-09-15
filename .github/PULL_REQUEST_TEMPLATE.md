<!--
PR タイトルは Conventional Commits 形式にしてください (squash 後のコミットメッセージになります)。
  例: feat(providers): add ollama_chat dialect / fix(scanners): handle null package name
-->

## 何を変えるか

<!-- 1〜3 文。設計書の該当節があれば書いてください (例: 設計書 §9.4)。 -->

## なぜ

<!-- 解決する問題。Issue があれば `Closes #123`。 -->

## 確認したこと

- [ ] `uv run ruff check . && uv run ruff format --check src tests`
- [ ] `uv run mypy`
- [ ] `uv run pytest --cov --cov-fail-under=80`
- [ ] 異常系のテストを足した（パーサ・Provider を触った場合）
- [ ] ドキュメントを更新した（挙動や設定が変わる場合）

## 設計上の不変条件（CONTRIBUTING.md）

- [ ] Reviewer に write / exec 系の能力を足していない（P3）
- [ ] コードにベンダー名・製品名を書いていない（P1。ベンダー知識は `providers/presets/**.yml` のデータのみ）
- [ ] 検出したシークレットの値が LLM・レポート・トレースに流れる経路を作っていない（§19.2）
- [ ] 失敗を成功に見せていない。受け付けた設定を黙って無視していない（P9）

## プリセットを追加する PR の場合

- [ ] 非対話モードがあり、スクリプトから起動できる
- [ ] ツール実行・ファイル書き込みを無効化する手段があり、その指定を含めた
- [ ] 出力を標準出力から取得できる
- [ ] 自動化利用が提供元の利用規約で明示的に禁止されていない
- [ ] 一覧はアルファベット順のまま（順位づけ・推奨表記なし）

## プロンプトを変更する PR の場合

- [ ] `security-checker eval` を回し、結果を貼った
