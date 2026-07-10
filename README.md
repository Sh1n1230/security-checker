# security-checker

自作の成果物(コード・アプリ・設定など)がどれだけ安全かを測るための仕組み。
AIを使わず、OSSの静的解析ツールのみで構成(再現性が高く無料)。

## 3つの使い方

1. **CLI**: `./check.sh <対象ディレクトリ>` (Windowsは `pwsh ./check.ps1 <対象ディレクトリ>`) でスコア(100点満点)とランクを出す
2. **CI**: [ci/security.yml](ci/security.yml) を GitHub Actions にコピーして push 毎に自動検査
3. **手動チェックリスト**: [checklist/CHECKLIST.md](checklist/CHECKLIST.md) でツールで測れない項目を確認

## セットアップ

```sh
git clone https://github.com/Sh1n1230/security-checker.git ~/security-checker
cd ~/security-checker

# 検査ツール (macOS)
brew install jq gitleaks semgrep trivy osv-scanner
```

Linuxでは各ツールを公式手順でインストールしてください(スクリプト自体はbashのみで動作)。
`tools/audit_macos.sh` 以外はLinuxでも概ね動作します。主対象はmacOS/Windowsです。

jq のみ必須(Windowsで `check.ps1` を使う場合は不要)。他は未インストールなら該当カテゴリをスキップして動きます。

### Windows

`check.ps1` / `tools/windows/*.ps1` を PowerShell 7 (`pwsh`) で実行します。jq は使用しません(`ConvertFrom-Json` / `ConvertTo-Json` で代替)。Git Bash で `check.sh` を使う場合のみ jq が必要です。

```powershell
git clone https://github.com/Sh1n1230/security-checker.git ~/security-checker
cd ~/security-checker

# 検査ツール (winget)
winget install jqlang.jq Gitleaks.Gitleaks AquaSecurity.Trivy Google.OSVScanner
# jq は check.sh (Git Bash) を使う場合のみ必要。check.ps1 なら不要
pip install semgrep   # winget非対応。pipx install semgrep も可
```

scoop でも代替可能です: `scoop install jq gitleaks trivy osv-scanner`

Microsoft Store 版 Python の場合、`pip install` 後のスクリプトディレクトリ
(`%LOCALAPPDATA%\Packages\PythonSoftwareFoundation...\LocalCache\local-packages\Python312\Scripts`)
が PATH に含まれず `semgrep` コマンドが見つからないことがあります。その場合は PATH に追加してください。

`tools/install_hooks.sh` は Git for Windows 同梱の Git Bash が sh フックを実行できるため、Windows でもそのまま使えます。

## 使い方

```sh
./check.sh ~/my-project                     # ディレクトリを検査
./check.sh ~/my-project --url https://example.com  # 稼働中サービスも検査
./check.sh ~/my-project --min-score 70      # スコアが70未満なら exit 1 (CI用)
./check.sh ~/my-project --check-updates     # 使用ツールの最新版チェックも実行
```

Windows (PowerShell 7):

```powershell
pwsh ./check.ps1 . -Url https://example.com -MinScore 80
pwsh ./check.ps1 . -CheckUpdates             # 使用ツールの最新版チェックも実行
pwsh ./tools/windows/run_all.ps1 [-Project <dir>] [-Domain example.com]
```

## 検査カテゴリ

| カテゴリ | ツール | 内容 |
|---|---|---|
| シークレット | gitleaks | APIキー・パスワードの混入 |
| コード解析 | semgrep | インジェクション等の脆弱なコードパターン |
| 依存CVE | osv-scanner | 依存パッケージの既知脆弱性(言語横断) |
| 設定ファイル | trivy | Dockerfile・IaC・CI設定の危険な設定 |
| Web検査 | curl | HTTPS強制・セキュリティヘッダー(--url 指定時) |

## スコアの意味

100点から重大度別に減点: Critical −20 / High −10 / Medium −3 / Low −1(カテゴリ毎の減点上限 40)。

| ランク | スコア | 目安 |
|---|---|---|
| A | 90+ | 公開してよい水準 |
| B | 70–89 | 軽微な改善余地あり |
| C | 50–69 | 重要な問題あり。修正推奨 |
| D | <50 | 重大な問題あり。公開前に必ず修正 |

詳細な検出内容は `reports/summary.json` と各 `reports/*_raw.json` に保存されます。

## 補助ツール (tools/)

成果物ではなく「自分の環境・運用」を検査する単体ツール群。すべて読み取り専用(install_hooks.sh を除く)。

| ツール | 内容 |
|---|---|
| `tools/audit_macos.sh` | Mac本体の設定監査(FileVault・ファイアウォール・SIP・共有設定等) |
| `tools/check_ports.sh` | 待ち受け中ポートの棚卸しと外部公開の警告 |
| `tools/check_permissions.sh [dir]` | ~/.ssh や認証情報ファイルの権限、誰でも書けるファイルの検出 |
| `tools/install_hooks.sh <repo>` | コミット前にシークレット検査する pre-commit フックを導入 |
| `tools/check_shell_env.sh` | シェル履歴・dotfiles・環境変数へのシークレット漏れを検出 |
| `tools/check_git_history.sh <repo>` | git全履歴からシークレット漏洩を検出(現在消していても過去分を発見) |
| `tools/check_tls_cert.sh <domain>` | TLS証明書の期限・古いTLS(1.0/1.1)受け入れを検査 |
| `tools/check_updates.sh` | OS/brewの未適用アップデートとバックアップ状態を確認 |
| `tools/run_all.sh [dir] [--domain d]` | 上記の環境系チェックを一括実行(定期実行向け) |

いずれも問題検出時は exit 1 を返すので、cron や CI に組み込めます。

### Windows版 (tools/windows/)

同等の環境系チェックの PowerShell 7 版です。

| ツール | 内容 |
|---|---|
| `tools/windows/audit_windows.ps1` | Windows本体の設定監査(BitLocker・Defender・ファイアウォール・共有設定等) |
| `tools/windows/check_ports.ps1` | 待ち受け中ポートの棚卸しと外部公開の警告 |
| `tools/windows/check_permissions.ps1 [-Target dir]` | ACLの緩いファイル・認証情報ファイルの検出 |
| `tools/windows/check_shell_env.ps1` | PowerShell履歴・環境変数へのシークレット漏れを検出 |
| `tools/windows/check_tls_cert.ps1 -Domain <domain>` | TLS証明書の期限・古いTLS(1.0/1.1)受け入れを検査 |
| `tools/windows/check_updates.ps1` | Windows Update/wingetの未適用アップデートを確認 |
| `tools/windows/run_all.ps1 [-Project dir] [-Domain d]` | 上記の環境系チェックを一括実行(タスクスケジューラ等での定期実行向け) |

`tools/check_git_history.sh` は bash 実装のため、Windows では Git Bash 経由(`tools/windows/run_all.ps1` から自動検出して呼び出し)で利用します。専用の `.ps1` 版はありません。

## Claude Code スキル (skills/)

Claude Code から自然言語で検査・修正を頼めるスキル(モデル非依存)。導入:

```sh
cp -r skills/security-check skills/security-fix ~/.claude/skills/
```

- **security-check**: 「セキュリティチェックして」→ 適切なツールを選んで実行し、結果を日本語で解説
- **security-fix**: 「検出された問題を直して」→ 優先順位付けと安全な修正手順で対応

スコアはあくまで自動検出できる範囲の指標です。認証設計・権限管理などは
[checklist/CHECKLIST.md](checklist/CHECKLIST.md) で手動確認してください。
