# 0005. GHCR 公開までは composite action で配る

- 状態: 採用 (2026-10-04)
- 関連: DESIGN.md §21.1 (この ADR に合わせて注記済み)

## 背景

設計書は、スキャナを同梱した Docker イメージ (GHCR) を使う Docker コンテナアクションを最終形としている。
利用者側でのツール導入とバージョン差異をなくせるため。ただしイメージの公開は P6 で、まだ無い。

Docker コンテナアクションは他の action を呼べないため、SARIF のアップロードに公式の
`github/codeql-action/upload-sarif` を使えず、API を自前で叩く必要もある。

## 決定

- P6 で GHCR にイメージを公開するまでは composite action とする。スキャナは実行時に取得し、
  公式のチェックサムで検証する (`curl | sh` のインストールスクリプトは使わない)。
- `Dockerfile` は先に用意し、手元と CI で使えるようにしておく。
- v1 の action の入力名 (`min-score` / `upload-sarif` / `token` / `url`) は受け付け続ける。
  `min-score` の既定は 0 (判定しない) に変わり、`url` は警告を出して無視する。

## 結果

- 起動ごとにスキャナを取得するため遅い (数十秒)。GHCR 公開後に Docker 化するか、
  composite のままイメージを `docker run` で使うかを改めて決める。
