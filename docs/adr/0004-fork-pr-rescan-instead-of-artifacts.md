# 0004. fork PR の publish 側は成果物を使わず、読むだけで検査し直す

- 状態: 採用 (2026-10-04)
- 関連: DESIGN.md §18.4.3, §21.2 (この ADR に合わせて改訂済み)

## 背景

fork からの PR は `pull_request` イベントでシークレットも書き込み権限も持たないため、SARIF の
アップロードも PR コメントもできない。設計書は当初、`pull_request` 側で SARIF を artifact として出し、
`workflow_run` 側 (権限あり) がそれを取得してアップロードする形を推奨していた。

しかし `pull_request` で動く workflow は **PR の内容 (= fork 側が書き換えた workflow ファイル)** で動く。
fork 側は artifact を自由に偽造でき、偽の「指摘ゼロ」SARIF を上げれば Code Scanning のゲートを
素通りできる。

## 決定

- `workflow_run` 側 (既定ブランチの定義で動く) は artifact を使わない。
- 既定ブランチの action と設定で、PR のコードを**読むだけ**で検査し直す。スキャナはファイルを
  読むだけで、PR のコードを実行しない。ビルド・テスト・依存のインストールは足さない。
- 検査対象のツリーにある設定 (`security-checker.yml` / `.local.yml`)・ignore ファイル・コード内注釈は
  読まない (`SECURITY_CHECKER_UNTRUSTED_TARGET=1`)。読むと、PR が置いた Reviewer の `command` が
  シークレット付きで実行される。PR が自分の指摘を自分で抑制することもできてしまう。
- `transport: process` の Reviewer は fork のコードに向けない (ツールを持ちうるため)。

## 結果

- 検査は 2 回走る (pull_request 側と publish 側)。publish 側だけが結果を公開する。
- スキャナ自身が検査対象から読む設定 (`.gitleaks.toml`・`.semgrepignore`) は依然として PR 側が
  変えられる。コード実行にはならないが検出を減らせるため、fork PR の「指摘ゼロ」はこれらの変更が
  無いことを確かめてから信用する (docs/github-actions.md に明記)。
