# security-checker

自作の成果物(コード・アプリ・設定など)がどれだけ安全かを測るための仕組み。

現在、**v2「複数の独立した LLM を Security Auditor として使える AI Security Review プラットフォーム」**へ
移行中です([docs/DESIGN.md](docs/DESIGN.md))。v1(bash/PowerShell 実装)はそのまま使えます。

## v2 (開発中)

Python 実装。移行計画(設計書 §32)のうち **P2.5「`process` transport」まで完了**しています。

| フェーズ | 内容 | 状態 |
|---|---|---|
| P1 | models / config / CLI の骨格、`scan` サブコマンド、semgrep + gitleaks アダプタ | ✅ 完了 |
| P2 | 単一 LLM レビュー(`http` transport / Context Builder / Structured Output) | ✅ 完了 |
| P2.5 | `process` transport(API キーなしで動く) | ✅ 完了 |
| P3〜P7 | Multi-LLM / GitHub 統合 / Judge / 評価と公開 | 未着手 |

```sh
uv sync --group dev                      # 開発環境
uv run security-checker scan .           # スキャナのみで検査 (LLM は使わない)
uv run security-checker scan . --strict --fail-on high
uv run security-checker review .         # スキャン結果を LLM Reviewer でレビュー
uv run security-checker review . --dry-run       # 送信予定の内容を送信前に全部見る
uv run security-checker config show --explain    # 解決された設定と、その決定元
uv run security-checker init                     # 環境を検出して設定を生成する
```

### Reviewer の設定 (review 用)

Reviewer は**ベンダーではなく transport × dialect** で指定します。`openai_chat` 方言を話す
エンドポイントであれば、提供元がどこであっても同じ設定で動きます。

```yaml
reviewers:
  - name: r1
    transport: http           # 必須。推測で補完しない
    dialect: openai_chat      # リクエスト/レスポンスの「形」
    base_url: https://<endpoint>/v1
    model: <model-id>
    api_key_env: MY_API_KEY   # 環境変数名のみ。平文キーの項目は存在しない
    rate_limit: { rpm: 10 }   # 無料枠などの制限を宣言するとスケジューラが尊重する
```

既定の Reviewer は**ありません**(特定のベンダーを事実上の標準にしないため)。
ベンダー知識は `providers/presets/*.yml` の**データ**にのみ置き、コードには現れません。

同梱プリセットを使うと `base_url` などを省略できます(`http`: `openai` / `process`: `claude`。
アルファベット順で、推奨の意味はありません)。**一覧に無いものも同じように動きます** —
`dialect` + `base_url` や `command` を直接書くだけです。
`~/.config/security-checker/presets/<transport>/<name>.yml` に置けば、自分用のプリセットを
追加・上書きできます(PR 不要)。詳しくは [docs/providers.md](docs/providers.md)。

### API キーを持っていない場合 — `process` transport

**手元の非対話コマンドをそのまま Reviewer にできます。**認証はそのコマンド側の既存ログインに
委ねるため、API キーの設定は要りません。特定の CLI 向けの機能ではなく、
「stdin を受け取り stdout にテキストを返す」契約を満たすものはすべて同じ経路で扱われます。

```yaml
reviewers:
  - name: local-command
    transport: process
    command: ["<your-command>", "--non-interactive", "--no-tools"]
    prompt_via: stdin         # stdin | file
    timeout_s: 300
```

```sh
uv run security-checker init --command '<your-command> --non-interactive --no-tools'
```

起動対象は任意のコマンドなので、**P3(レビュー対象を書き換えない)を transport の性質に
よらず守ります**。毎回作り直す空の一時ディレクトリで `shell=False` 起動し、プロンプトは
stdin(または一時ファイル)でのみ渡し、実行後に書き込みを検知して警告し、タイムアウト時は
プロセスグループごと回収します。ただし**コマンド自体の書き込み能力を無効化できているかは
本体からは検証できない**ため、非対話・ツール無効のフラグは利用者が指定してください
(起動時に警告が出ます)。

`process` は「安価だが荒い」transport です。構造化出力は `prompt_only` のみ、
コストは `unknown`、トークンは推定値になります。詳細と注意点(**対象コマンドの利用規約は
利用者が確認してください**)は [docs/process-transport.md](docs/process-transport.md) に
まとめてあります。性質の異なる transport を混ぜると agreement が情報量を持ちやすくなります。

構造化出力は `json_schema → json_mode → prompt_only` の順に自動で降格し、
スキーマ違反の応答は 1 回だけ修復を試みます。それでも駄目なら `schema_error` として
**レポートに残します**(黙って消しません)。

### レビュー結果の読み方

判定は `confirmed` / `likely` / `review_required` / `false_positive` / `inconclusive` /
`error` / `not_reviewed` に分かれます。**`review_required`(判断が割れた・信頼度が低い)は
`confirmed` の直後に表示します。** 割れた判断こそ人間が見るべきものだからです。
Reviewer が 1 個のときは `agreement: not_applicable` とし、「1 モデルの合意」を
高い一致度として偽装しません。

コードを外部に送ることについては [docs/security-model.md](docs/security-model.md) を参照してください。

出力は `.security-checker/` 配下に、**人間向けの `report.md`** と機械可読の
`report.json`(`schema_version` 付き)、各スキャナの生出力 `raw/`。`report.json` は 19 個の
トップレベルキーを持つ機械可読レポートなので、**読むのは `report.md` かターミナル出力**です。

レポート本文(判断理由・攻撃経路・対応方針)は LLM が書いた文章そのものです。言語は
`output.language` で決まり、既定の `auto` はロケール(`LANG` など)から推定します。
日本語環境ならそのまま日本語で出力されます。明示するなら:

```yaml
output:
  language: ja      # auto | ja | en | ko | ... (未知のタグはそのまま LLM に渡す)
```

推定結果はトレースに記録されるので、後から「どの言語で書かせたか」を確認できます。
設定は `security-checker.yml`(サンプルはリポジトリ直下)を自動探索し、
**組み込み既定値 → `--preset` → 設定ファイル → ローカル設定 → 環境変数
(`SECURITY_CHECKER__POLICY__FAIL_ON` 形式)→ CLI フラグ** の順に、後勝ちで合成します。

手元でだけ使う Reviewer は `security-checker.local.yml`(git 管理外・`.gitignore` 済み)に
書きます。共有設定の後に重なるので、`security-checker.yml` を汚さずに個人の Reviewer を
足せます。`security-checker init --local` で生成でき、`config show --explain` に
どの層で決まったかが出ます。

終了コードは目的別に分かれています(設計書 §17.1)。

| code | 意味 |
|---|---|
| 0 | ポリシー違反なし |
| 1 | `fail_on` 以上の検出、または `min_score` 未満 |
| 2 | 設定エラー |
| 3 | 実行エラー(`--strict` 時にスキャナが失敗した) |

**1 と 3 を分けているのが v1 との最大の違いです。** v1 には「スキャナが失敗しても 0 件成功として扱われ、
スコアが満点に見える」欠陥がありました。v2 は `skipped`(未導入)と `failed`(異常終了)を区別し、
どちらの場合もスコアに `partial` フラグを立てます。

検出されたシークレットの値は Candidate にもレポートにも書き出しません(マスク済みの形式のみ)。
漏洩した値を成果物や外部 LLM に再送しないためです(設計書 §19.2)。

## v1 の3つの使い方

1. **CLI**: `./check.sh <対象ディレクトリ>` (Windowsは `pwsh ./check.ps1 <対象ディレクトリ>`) でスコア(100点満点)とランクを出す
2. **CI**: [ci/security.yml](ci/security.yml) を GitHub Actions にコピーして push 毎に自動検査(GitHub Code Scanning への SARIF 登録つき)
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

## GitHub Code Scanning 連携

`ci/security.yml` は、スコア判定に加えて 4 つのスキャナの SARIF を GitHub Code Scanning に
アップロードします。Security タブに履歴が残り、指摘が PR の Files changed に直接表示されます。

必要な設定:

- ワークフローの job に `permissions: security-events: write`(`ci/security.yml` に記載済み)
- パブリックリポジトリなら追加費用なし。**プライベートリポジトリでは GitHub Advanced Security が必要**です

注意点:

- **fork からの PR ではアップロードできません。** `GITHUB_TOKEN` が read-only に降格されるためで、
  ワークフローはこの場合スキップして、その旨をジョブサマリに残します。
- 空の SARIF を上げると Code Scanning 上の既存アラートが「解決済み」として閉じられ、
  スキャナの故障が「指摘ゼロ」に見えてしまいます。ワークフローは生成に失敗したスキャナの
  結果をアップロードせず、ジョブを失敗させます。
- Ruleset の **"Require code scanning results"** でマージ条件にもできますが、
  上記の fork PR の制約があるため、外部からの PR を受け付けるリポジトリでは慎重に判断してください。

Code Scanning とスコア判定は役割が違います。スコア判定(status check)は「ツールが壊れていないか」、
Code Scanning は「脆弱性があるか」を見ます。両方を残すことを推奨します。

## 補助ツール (tools/)

成果物ではなく「自分の環境・運用」を検査する単体ツール群。すべて読み取り専用(install_hooks.sh を除く)。

| ツール | 内容 |
|---|---|
| `tools/audit_macos.sh` | Mac本体の設定監査(FileVault・ファイアウォール・SIP・共有設定等) |
| `tools/check_ports.sh` | 待ち受け中ポートの棚卸しと外部公開の警告 |
| `tools/check_permissions.sh [dir]` | ~/.ssh や認証情報ファイルの権限、誰でも書けるファイルの検出 |
| `tools/install_hooks.sh [repo]` | git フックを導入(pre-commit: シークレット検査 / pre-push: 保護ブランチへの直接 push と force push を禁止)。省略時は現在のリポジトリ |
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

## 開発時のガードレール

AI エージェントにも人間にも危険な git 操作をさせないための仕掛けを、**強制力の順に3層**に分けています。

| 層 | 効く範囲 | 迂回手段 | 置き場所 |
|---|---|---|---|
| 1. GitHub Ruleset | 全員・全ツール(サーバ側) | **なし** | GitHub 設定 |
| 2. git フック | ローカルの全操作。人間にも任意のエージェントにも効く | `--no-verify` | `tools/hooks/` |
| 3. エージェントの権限設定 | そのツールのエージェントのみ | シェルの書き方で容易に迂回可 | `.claude/settings.json` |

```sh
./tools/install_hooks.sh          # 2 を導入する
```

**保護ブランチへの直接 push と force push の禁止は 1 と 2 に置いています。** 3 には置いていません。
コマンド文字列のパターンマッチは `git -C <path> push --force origin main` のような書き方で
容易にすり抜けるため、そこに防御を委ねてはいけないからです。3 の役割は
「実行前に人間へ確認を返す」という体験だけに限っています。

`.claude/settings.json` は**宣言のみで実行スクリプトを含みません**。エージェント用のフックスクリプトは
「clone して開いた人のマシンで実行されるコード」になるため、このリポジトリでは置かない方針です。
他のツールを使う場合も、実体は `tools/hooks/` がそのまま使えます。

## Claude Code スキル (skills/)

Claude Code から自然言語で検査・修正を頼めるスキル(モデル非依存)。導入:

```sh
cp -r skills/security-check skills/security-fix ~/.claude/skills/
```

- **security-check**: 「セキュリティチェックして」→ 適切なツールを選んで実行し、結果を日本語で解説
- **security-fix**: 「検出された問題を直して」→ 優先順位付けと安全な修正手順で対応

スコアはあくまで自動検出できる範囲の指標です。認証設計・権限管理などは
[checklist/CHECKLIST.md](checklist/CHECKLIST.md) で手動確認してください。

## 参加する

- [CONTRIBUTING.md](CONTRIBUTING.md) — 開発環境、PR の出し方、**設計上の不変条件**、
  プリセットの足し方（コードを書かずに新しい LLM を足す方法）
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — 行動規範（Contributor Covenant v2.1）
- [SECURITY.md](SECURITY.md) — **脆弱性は公開 Issue ではなく非公開で報告してください**
- [docs/DESIGN.md](docs/DESIGN.md) — 「なぜそうなっているか」はここに書いてあります
- [docs/NEXT-STEPS.md](docs/NEXT-STEPS.md) — 残作業と、決める必要があること

Issue と PR は日本語でも英語でも構いません。

## ライセンス

[MIT](LICENSE)
