---
name: security-check
description: プロジェクトや環境のセキュリティ検査を実行し結果を解釈する。「セキュリティチェックして」「安全か確認して」「脆弱性を調べて」「公開前チェック」等の依頼で使用。~/security-checker のツール群を実行し、スコアと修正方針を日本語で報告する。
---

# セキュリティ検査の実行と解釈

`~/security-checker` にあるOSSベースの検査ツール群を使う。AIによる判定ではなく既存の静的解析ツール(gitleaks/semgrep/osv-scanner/trivy)の実行結果を扱うため、どのモデルでも同じ品質で動く。

## 手順

1. **対象の確認**: ユーザーが何を検査したいか特定する
   - プロジェクト(コード) → `~/security-checker/check.sh <dir>`
   - 稼働中のWebサービス → `--url https://...` を追加
   - 自分のMac環境 → `~/security-checker/tools/run_all.sh`
   - 特定の観点のみ → 下の対応表から単体ツールを選ぶ

2. **実行**: 該当コマンドを実行する。ツール未インストールの警告が出たら、
   スキップされたカテゴリを報告に明記し `brew install <tool>` を案内する。

3. **結果の解釈と報告**:
   - スコア(100点満点)とランク(A/B/C/D)を最初に伝える
   - 詳細は `~/security-checker/reports/summary.json` を jq で読む
   - Critical/High から順に、**何が・どこで・なぜ危険か・どう直すか** を具体的に説明する
   - 検出された問題の修正はユーザーに提案し、承認を得てから行う

## 観点別ツール対応表

| 知りたいこと | コマンド |
|---|---|
| コード・依存・設定の総合スコア | `~/security-checker/check.sh <dir> [--min-score N]` |
| Webのヘッダー/HTTPS | `~/security-checker/check.sh <dir> --url <URL>` |
| TLS証明書の期限 | `~/security-checker/tools/check_tls_cert.sh <domain>` |
| git履歴に秘密が残っていないか | `~/security-checker/tools/check_git_history.sh <repo>` |
| Mac本体の設定 | `~/security-checker/tools/audit_macos.sh` |
| 開いているポート | `~/security-checker/tools/check_ports.sh` |
| ファイル権限 | `~/security-checker/tools/check_permissions.sh [dir]` |
| シェル履歴/環境変数の秘密 | `~/security-checker/tools/check_shell_env.sh` |
| OS/パッケージ更新・バックアップ | `~/security-checker/tools/check_updates.sh` |
| 環境チェック全部 | `~/security-checker/tools/run_all.sh [dir] [--domain <domain>]` |
| コミット時の秘密混入を予防 | `~/security-checker/tools/install_hooks.sh <repo>` |

## 注意

- すべて exit 0 = 問題なし / exit 1 = 要対応 / exit 2 = 実行エラー
- 検査は自分の成果物・自分の環境に対してのみ行う。他者のサービスへのスキャンはしない
- シークレットが検出されたら「キーの無効化・再発行が最優先」と必ず伝える(履歴やファイルから消すだけでは不十分)
- ツールで検出できない設計面(認証・権限)は `~/security-checker/checklist/CHECKLIST.md` を案内する
