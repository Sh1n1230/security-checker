# 0010. 信用できない検査対象では、スキャナ自身の設定と注釈も読ませない

- 状態: 採用 (2026-10-10。記録は 2026-11-17)
- 関連: [0004](0004-fork-pr-rescan-instead-of-artifacts.md) の「結果」の 2 点目を置き換える。
  docs/security-model.md §5.1、docs/github-actions.md §5

## 背景

0004 は、fork PR を権限のある文脈で検査し直すとき、security-checker の設定・ignore ファイル・コード内注釈を
読まないと決めた。一方で「スキャナ自身が検査対象から読む設定 (`.gitleaks.toml`・`.semgrepignore`) は PR 側が
変えられる」ことを、受け入れたリスクとして残していた。

これは小さな穴ではなかった。PR に `.gitleaks.toml` を 1 つ足すだけで、秘密の検出をすべて止められる。
コードは実行されないが、Code Scanning のゲートを「指摘ゼロ」で通れる。

## 決定

`SECURITY_CHECKER_UNTRUSTED_TARGET=1` (action の `untrusted-target: true`) のとき、各スキャナに設定を明示的に渡し、
検査対象のツリーにある設定を読ませない (`scanners/untrusted.py`)。

| 対象 | 扱い |
|---|---|
| `.gitleaks.toml`・`gitleaks:allow` 注釈 | 読まない (`--config` に既定ルールだけの設定、`--ignore-gitleaks-allow`) |
| `nosemgrep` 注釈 | 効かせない (`--disable-nosem`) |
| `trivy.yaml`・`.trivyignore` | 読まない |
| `osv-scanner.toml` | 読まない |

設定は検査対象の外の一時ディレクトリに作る。

## 結果

- 残る穴は、検査対象の直下に置く `.gitleaksignore` と `.semgrepignore` の 2 つ。どちらもスキャナに
  読ませない手段が無い。存在すればレポートに警告を出す。**fork PR の「指摘ゼロ」は、この警告が無いことを
  確かめてから信用する。**
- trivy のコード内注釈 (`trivy:ignore`) も止められないので、同じく警告にする。
- 信用する検査対象 (自分のリポジトリの push など) では、従来どおりスキャナの設定を読む。
