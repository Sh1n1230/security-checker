# security-checker

[English](README.md) | **日本語**

[![CI](https://github.com/Sh1n1230/security-checker/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Sh1n1230/security-checker/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Sh1n1230/security-checker/badge)](https://scorecard.dev/viewer/?uri=github.com/Sh1n1230/security-checker)
[![Release](https://img.shields.io/github/v/release/Sh1n1230/security-checker)](https://github.com/Sh1n1230/security-checker/releases)
[![License: MIT](https://img.shields.io/github/license/Sh1n1230/security-checker)](LICENSE)

AI によるセキュリティレビューの基盤です。いつものスキャナを実行し、その検出を **独立した LLM が
第三者の監査役として 1 件ずつレビュー**します。本物の問題を隠さずに、誤検出を減らします。

> **状況:** alpha。リリースはいまのところ GitHub でだけ公開しています (git からインストールします)。
> PyPI への公開はこれからです。残っている作業は [docs/NEXT-STEPS.md](docs/NEXT-STEPS.md) にあります。
> この README は [英語版](README.md) の訳で、食い違いがあれば英語版が正です。`docs/` は日本語です。

## 何であって、何でないか

- **レビューをする道具です。** スキャナ (semgrep・gitleaks・osv-scanner・trivy) が候補を挙げ、1 つ以上の
  LLM Reviewer が、それぞれの候補が実際に到達できる本物の脆弱性かを判断し、理由を説明します。
- **コードを書き換えません。** Reviewer は対応方針を提案するだけで、適用するかはいつも利用者が決めます。
- **LLM にバグを探させません。** 検出は決定的なスキャナが行うので、結果を再現でき、監査できます。
- **特定のベンダーに依りません。** 既定のモデルも「対応 LLM の一覧」もありません。手元にあるもの —
  4 つの API の形のどれかを話す HTTP エンドポイントか、非対話で動く任意のコマンド — を選びます。

## コードを書いた AI と、レビューする AI を分ける

コードを書くのを手伝ったモデルに、そのコードが安全かどうかも判断させると、自分の書いたものに同意しがちです。
security-checker では、開発に使っているアシスタントとは**別の** Reviewer を (複数でも) 選べ、
その一致と不一致が見えるようになります。

```text
  開発者の AI ──書く──► コード ──スキャナ──► 候補 ──► Reviewer の AI ──► 指摘
                                                      (独立している)
```

Reviewer の判断が割れた指摘は、白黒を無理に付けず **`review_required`** として報告します。
割れた判断こそ、人が見るべきものです。

## 60 秒で試す

```sh
uv tool install git+https://github.com/Sh1n1230/security-checker
security-checker scan .        # スキャナだけ。何も外に送りません
security-checker init          # Reviewer に使えるものを検出し、security-checker.yml を書く
security-checker review . --dry-run    # 送る内容を、送らずにすべて表示する
security-checker review .
```

`init` は、**あなたの環境で**実際に使えるもの (非対話の CLI、API キーの環境変数) を一覧します。
この README はあえてモデルの名前を挙げません。ここに書いたものが事実上の推奨になってしまうからです。
はじめての方は [docs/getting-started.md](docs/getting-started.md) をどうぞ。

## 結果の読み方

| status | 意味 | CI を落とすか |
|---|---|---|
| `confirmed` / `likely` | Reviewer が本物の問題と判断した | 重大度が `policy.fail_on` 以上なら落とす |
| **`review_required`** | Reviewer の判断が割れた、または確信が無い | 落とさない。ただし `confirmed` の直後に表示する |
| `false_positive` | Reviewer が、ここでは悪用できないと判断した | 落とさない (`report.json` に残し、PR には出さない) |
| `inconclusive` / `error` / `not_reviewed` | 判定なし | 落とさない。「問題なし」としては決して見せない |

終了コードは *「何かを見つけた」* (1) と *「ツールが壊れている」* (3) を分けています。
スキャナの失敗が、問題の無い実行に見えることはありません。

`security-checker explain <id>` は、判定の裏にある各 Reviewer の理由と LLM の呼び出しをすべてたどります。

## GitHub Actions

```yaml
permissions:
  contents: read
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write   # sticky なサマリと inline コメント
      security-events: write # Code Scanning への SARIF のアップロード
    steps:
      - uses: actions/checkout@<SHA>
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: Sh1n1230/security-checker@<SHA>
        env:
          YOUR_PROVIDER_API_KEY: ${{ secrets.YOUR_PROVIDER_API_KEY }}
```

PR では、変更された行に関係する候補だけをレビューし、サマリのコメントを **1 件だけ**更新し続け、
同じ inline コメントを二度投稿せず、固定のツール名 `security-checker` で SARIF をアップロードします。
fork からの PR も安全に扱います (スキャンのみ・シークレットなし。任意で、`workflow_run` の workflow が
信頼できる設定で PR のコードを読むだけで検査し直します)。`pull_request_target` は使いません。
詳しくは [docs/github-actions.md](docs/github-actions.md)。

## 設定

Reviewer 以外にはすべて既定値があります。Reviewer 1 つから始めて、増やし、Judge を足していけます。

```yaml
reviewers:
  - name: r1
    transport: http
    dialect: openai_chat          # openai_chat | anthropic_messages | gemini_generate | ollama_chat
    base_url: https://<endpoint>/v1
    model: <model-id>
    api_key_env: MY_API_KEY       # 環境変数の名前を書く。キーの直書きは受け付けません
  - name: r2
    transport: process            # 非対話で動く任意のコマンド。API キーは要りません
    command: ["<your-command>", "--non-interactive", "--no-tools"]
aggregation:
  strategy: consensus             # consensus | weighted | judge
```

リファレンス: [docs/configuration.md](docs/configuration.md) ·
集約の戦略: [docs/aggregation.md](docs/aggregation.md)。

## LLM を足す 2 つの経路

1. **既知の API の形を話す HTTP エンドポイント** → 設定 1 ブロック。大事なのはベンダーではなく、
   形 (方言) です。
2. **非対話で動き、JSON を出力するコマンド** → `transport: process` の設定 1 ブロック。

`security-checker providers check` が、新しい Reviewer を端から端まで (設定・疎通・構造化出力) 確かめます。
詳しくは [docs/providers.md](docs/providers.md)。`process` transport の制約 (ツールの実行やファイルの
書き込みを無効にできることを**利用者が確かめる**必要があります) は
[docs/process-transport.md](docs/process-transport.md) にあります。

## 仕組み

```text
スキャナ ─► 正規化 ─► 抑制 (baseline / ignore / 注釈) ─► 差分の範囲
        ─► 文脈の組み立て (コードの窓・リポジトリの事実) ─► Reviewer (レートと予算の制限つき)
        ─► 集約 (consensus / weighted / judge) ─► ポリシー ─► terminal / JSON / Markdown / SARIF / PR
```

## 精度

LLM のレビューが本当に役に立つかを、正解を付けたデータセット (手書きの 100 件。過半が誤検出) で測ります。
**主指標は Recall です。** 本物の問題を切り捨てるなら、誤検出を減らしても意味がありません。真陽性を 1 件でも
見逃すと `eval` は失敗します。複数の Reviewer が 1 つに勝てないなら、そう書きます。
詳しくは [docs/evaluation.md](docs/evaluation.md)。

## セキュリティとプライバシー

`review` は、指摘されたコードとその前後の文脈 (リポジトリ全体ではありません) を、設定した Reviewer に送ります。
検出した秘密の値は、保存・送信の前に伏せます。`scan` はコードを送りません
(依存の照会でパッケージ名とバージョンが外に出ます。止め方を含めて
[docs/security-model.md](docs/security-model.md) にあります)。

## 終了コード

| code | 意味 |
|---|---|
| 0 | ポリシー違反なし |
| 1 | ポリシー違反 (`fail_on` 以上の指摘、または `min_score` 未満) |
| 2 | 設定エラー。何かを送る前に止まります |
| 3 | 実行エラー。`strict` (既定) では、スキャナの失敗・Reviewer の無効化・レビューの途中停止・未レビューの候補 |

「脆弱性が見つかった」(1) と「ツールが壊れた」(3) は決して混ざりません。コマンドごとの詳細は
[docs/exit-codes.md](docs/exit-codes.md)。

## ホスト監査スクリプト (contrib/host-audit/)

コードベースではなく**手元のマシンと作業の流れ**を監査する、単体で動く読み取り専用のスクリプトです
(v1 から引き継いだもので、Python のパッケージとは独立しています)。問題を見つけると 1、検査できなかった
(必要なコマンドが無い) ときは 2 で終了するので、cron や CI に組み込めます。pre-push フックは既定で
`main` / `master` を保護します。変えるには `git config security-checker.protectedBranches '<正規表現>'`。

| スクリプト | 検査するもの |
|---|---|
| `audit_macos.sh` / `windows/audit_windows.ps1` | OS の設定 (FileVault / BitLocker、ファイアウォール、SIP / Defender、共有) |
| `check_ports.sh` / `windows/check_ports.ps1` | 待ち受けているポートと、localhost の外に公開されているもの |
| `check_permissions.sh [dir]` / `windows/check_permissions.ps1` | `~/.ssh` と資格情報ファイルの権限、誰でも書けるファイル |
| `check_shell_env.sh` / `windows/check_shell_env.ps1` | シェルの履歴・ドットファイル・環境変数に漏れた秘密 |
| `check_git_history.sh <repo>` | git の履歴のどこかにある秘密 (削除済みのものを含む) |
| `check_tls_cert.sh <domain>` / `windows/check_tls_cert.ps1` | 証明書の期限と、TLS 1.0 / 1.1 を受け付けるか |
| `check_updates.sh` / `windows/check_updates.ps1` | 未適用の OS / パッケージマネージャの更新と、バックアップの状態 |
| `install_hooks.sh [repo]` | git フックを入れる: pre-commit で秘密を検査、pre-push で保護ブランチへの直接 push と force push を止める |
| `run_all.sh` / `windows/run_all.ps1` | 上の環境の検査をまとめて実行する |

## 開発時のガードレール

危険な git の操作を 3 層で止めます。迂回しにくい順です。

| 層 | 対象 | 迂回 | 場所 |
|---|---|---|---|
| 1. GitHub の Ruleset | 全員・すべてのツール (サーバ側) | **できない** | GitHub の設定 |
| 2. git フック | 手元のすべての操作 (人でもエージェントでも) | `--no-verify` | `contrib/host-audit/hooks/` |
| 3. エージェントの権限設定 | そのエージェントだけ | コマンドを言い換えれば簡単にできる | `.claude/settings.json` |

保護ブランチへの直接 push と force push を止めるのは、1 と 2 の層だけです。コマンドの文字列を
パターンで見る方法 (3 の層) は、`git -C <path> push --force origin main` のような書き方で簡単にすり抜けられます。
`.claude/settings.json` は宣言だけで、実行できるフックのスクリプトは同梱していません。同梱すると、
リポジトリを clone して開いた人のマシンで動いてしまうからです。

## Claude Code のスキル (skills/)

モデルに依らないスキルが 2 つあり、検査や修正を普通の言葉で頼めます。

```sh
cp -r skills/security-check skills/security-fix ~/.claude/skills/
```

- **security-check** — `security-checker scan` / `review` を実行し、結果を説明する
- **security-fix** — 指摘に優先順位を付け、安全な直し方を順に案内する

自動の検査が見られるのは全体の一部です。認証と認可の設計は、
[checklist/CHECKLIST.md](checklist/CHECKLIST.md) を使って人の目で確かめてください。

## 参加する / ライセンス

[CONTRIBUTING.md](CONTRIBUTING.md)・[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)・[SECURITY.md](SECURITY.md)
を見てください (**脆弱性は公開の Issue ではなく、非公開で報告してください**)。文書の一覧は
[docs/README.md](docs/README.md) にあります。Issue と PR は日本語でも英語でも歓迎します。ライセンスは MIT です。

最初の v1 (bash / PowerShell) は v1.1.0 の後に削除しました。必要なら `v1.1.0` タグを参照してください。
