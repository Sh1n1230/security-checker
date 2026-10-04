---
name: security-check
description: プロジェクトのセキュリティ検査を実行し結果を解釈する。「セキュリティチェックして」「安全か確認して」「脆弱性を調べて」「公開前チェック」等の依頼で使用。security-checker CLI (v2) を実行し、検出結果と修正方針を報告する。
---

# セキュリティ検査の実行と解釈

`security-checker` CLI を使う。検出は既存の静的解析ツール (semgrep / gitleaks / osv-scanner / trivy) が行い、
設定されていれば独立した LLM Reviewer が各候補を判定する。

## 手順

0. **導入の確認**: `security-checker version` が動かなければ
   `uv tool install git+https://github.com/Sh1n1230/security-checker` を案内する。

1. **検査**: 対象ディレクトリで実行する。
   - スキャナのみ (外部送信なし): `security-checker scan <dir>`
   - LLM レビュー付き: `security-checker review <dir>`
     - Reviewer 未設定なら `security-checker init` を案内する
     - 送信内容を確認したいときは `--dry-run`、費用の見積りは `--estimate`
   - 変更分だけ: `security-checker review <dir> --base origin/main`

2. **未導入スキャナ**: 出力に `skipped` があれば、該当カテゴリが検査されていないことを報告に明記する。
   `failed` はツールの異常終了であり「問題なし」ではない。

3. **結果の解釈と報告**:
   - 詳細は `<dir>/.security-checker/report.md` (人間向け) を読む
   - `confirmed` / `likely` → `review_required` の順に、**何が・どこで・なぜ危険か・どう直すか**を説明する
   - `review_required` は Reviewer の判断が割れたもの。人間の判断が必要だと伝える
   - 判定の根拠は `security-checker explain <id>` で確認できる
   - 修正はユーザーに提案し、承認を得てから行う

## 終了コード

0 = ポリシー違反なし / 1 = `fail_on` 以上の検出 / 2 = 設定エラー / 3 = 実行エラー (`--strict` 時のスキャナ失敗)

## 注意

- 検査は自分の成果物に対してのみ行う。他者のサービスへのスキャンはしない
- シークレットが検出されたら「キーの無効化・再発行が最優先」と必ず伝える (履歴やファイルから消すだけでは不十分)
- ツールで検出できない設計面 (認証・権限) は `checklist/CHECKLIST.md` を案内する
- 自分の端末の設定監査 (ポート・権限・シェル履歴など) は `contrib/host-audit/` の単体スクリプトを使う
