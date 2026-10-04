# 設定

すべての項目に既定値があり、設定ファイルが無くても動きます (Reviewer を除く)。

## 探索と合成

設定ファイルは検査対象のディレクトリから次の順に探します:
`security-checker.yml` → `security-checker.yaml` → `.security-checker.yml` →
`.security-checker.yaml` → `.github/security-checker.yml`。

値は次の順に**後勝ち**で合成します。

```text
組み込み既定値 ← --preset ← 設定ファイル ← security-checker.local.yml ← 環境変数 ← CLI フラグ
```

- `security-checker.local.yml` は git 管理しない個人用の層です (手元でだけ使う Reviewer など)。
- 環境変数は `SECURITY_CHECKER__POLICY__FAIL_ON=critical` の形 (`__` で階層を区切る)。
- どの層で値が決まったかは `security-checker config show --explain` で見られます。
- 未知のキーはエラーになります。打ち間違いを黙って無視しません。
- **受け付けるが効かない設定は無い**ようにしています。方言に合わない項目
  (例: `ollama_chat` 以外での `num_ctx`) は警告します。

`SECURITY_CHECKER_UNTRUSTED_TARGET=1` のときは、検査対象のツリーから設定を一切読まず、
`--config` で対象外のファイルを渡す必要があります (fork PR を権限付きで検査するとき。
[github-actions.md](github-actions.md#5-fork-からの-pr))。

## プリセット

`--preset` は**構成の形**で、ベンダーは含みません。

| 名前 | 用途 |
|---|---|
| `minimal` | 速度優先。semgrep + gitleaks、critical で失敗 |
| `frugal` | コスト優先。候補 30 件・予算 $0.10・文脈を狭く |
| `thorough` | 網羅優先。全スキャナ・文脈を広く・medium で失敗 |
| `ci` | CI 用。全スキャナ・strict・SARIF 出力・JSON ログ |

## 項目

### target

| キー | 既定 | 説明 |
|---|---|---|
| `mode` | `auto` | `auto` (PR の文脈なら差分のみ) / `full` / `diff`。CLI の `--base` / `--full` で上書き |
| `exclude` | vendor・node_modules など | 除外する glob。CLI の `--exclude` は**置き換え** (追加ではない) |

### scanners

| キー | 既定 | 説明 |
|---|---|---|
| `semgrep.enabled` / `config` | `true` / `p/default` | SAST。`config` はルールセットかファイル |
| `gitleaks.enabled` | `true` | シークレット。検出値はマスクしてから保存・送信する |
| `osv.enabled` | `false` | 依存の既知脆弱性 (別名をまとめて 1 件にする) |
| `trivy.enabled` / `scanners` | `false` / `[config]` | `config` (誤設定) / `vuln` (依存)。`secret` は受け付けない |
| `*.timeout_s` / `extra_args` | | タイムアウトと追加引数 |

詳細は [scanners.md](scanners.md)。

### reviewers

既定値はありません。`security-checker init` で生成します。書き方は [providers.md](providers.md)。

| キー | 説明 |
|---|---|
| `name` / `transport` | 必須。`transport` は `http` / `process` |
| `dialect` / `base_url` / `model` / `api_key_env` | http 用。キーは**環境変数名**だけを書く |
| `command` / `preset` / `prompt_via` | process 用 |
| `weight` | `weighted` 集約での重み |
| `timeout_s` / `concurrency` / `max_output_tokens` / `seed` | 呼び出しの制御 |
| `rate_limit.rpm` / `tpm` / `rpd` | 毎分のリクエスト数・トークン数、1 日のリクエスト数 |
| `capabilities.*` | 構造化出力の方式などの明示指定 (自動判定より優先) |

`rpd` はプロセスをまたいで `~/.cache/security-checker/quota.json` (UTC の日付) に数えます。
開始時に残りが候補数に足りなければ警告し、上限に達した Reviewer はその時点で止めます。
`tpm` は送るプロンプトの見積り + 出力上限で数えます。

### aggregation

| キー | 既定 | 説明 |
|---|---|---|
| `strategy` | `consensus` | `consensus` / `weighted` / `judge` |
| `consensus.min_votes` / `min_ratio` / `severity` | `2` / `0.5` / `median` | |
| `weighted.threshold` | `0.6` | |
| `judge.reviewer` | | Judge 役の Reviewer 名 (一次レビューには参加しない) |
| `judge.fallback` | `consensus` | Judge が失敗したとき / Judge に回さない候補の戦略 |
| `judge.only_on_disagreement` | `true` | 判断が割れた候補だけを Judge に回す |

選び方は [aggregation.md](aggregation.md)。

### policy

| キー | 既定 | 説明 |
|---|---|---|
| `fail_on` | `high` | この重大度以上で exit 1。`none` で判定しない |
| `fail_on_status` | `[confirmed, likely]` | 失敗させる status |
| `min_confidence` | `0.5` | これ未満の confirmed / likely は `review_required` に落とす |
| `strict` | `true` | スキャナの失敗・判定不能を exit 3 にする |
| `baseline` | | baseline ファイル (設定ファイルの場所からの相対パス) |
| `min_score` | | スコアの下限 (補助指標) |

### budget / concurrency / context

| キー | 既定 | 説明 |
|---|---|---|
| `budget.max_candidates` | `200` | レビューに回す候補の上限 (超えた分は `not_reviewed`) |
| `budget.max_usd` / `max_total_tokens` | `1.0` / `2,000,000` | 超えたら新規呼び出しを止め、部分結果を出す |
| `budget.on_exceed` | `stop_and_report` | `warn_and_continue` にすると止めない |
| `concurrency.scanners` / `reviews_per_provider` | `4` / `4` | |
| `context.window_lines` / `max_callers` / `max_tokens_per_task` | `40` / `3` / `8000` | LLM に渡す文脈 |

### output / github / logging

| キー | 既定 | 説明 |
|---|---|---|
| `output.dir` | `.security-checker/` | |
| `output.formats` | `[terminal, json, markdown]` | `sarif` を足すと `report.sarif`。CLI の `-f` で置き換え |
| `output.language` | `auto` | LLM に書かせる本文の言語 |
| `output.save_prompts` | `false` | プロンプト全文をトレースに保存する (警告が出る) |
| `github.comment` / `comment_mode` | `true` / `sticky` | `security-checker comment` の挙動 |
| `github.inline_comments` / `inline_min_status` / `max_inline_comments` | `true` / `likely` / `20` | |
| `github.comment_on_clean` | `false` | 指摘ゼロで既存コメントが無いときも投稿するか |
| `logging.level` / `format` | `info` / `text` | **この節を書いたときだけ**標準エラーにログを出す。`--log-format json` でも可 |

## 抑制

既存の指摘を段階的に扱うための 3 つの方法です。抑制した候補は消えずにレポートの
`suppressed` に理由付きで残り、レビュー (LLM の費用) とゲートの対象から外れます。

**baseline** — いまの検出をまとめて記録する。

```sh
security-checker baseline update     # .security-checker-baseline.json を書き、設定例を表示する
```

キーは候補の安定 ID (行番号を含まない) なので、無関係な編集では壊れません。
スキャナが失敗した run では更新を拒否します (復旧後に既存の検出が「新規」として噴き出すため)。

**`.security-checker-ignore`** — パスとルールで外す。

```text
# パス (gitignore と同じ glob)
docs/**
/build/
# ルール。scanner/rule_id でも rule_id だけでもよい
rule:semgrep/python.lang.security.audit.eval-detected
# ルールをパスで限定する
rule:generic-api-key tests/**
```

**コード内の注釈** — 候補の行かその直前の行に書く。**理由の記述を必須**とし、理由が無いと警告します。

```python
subprocess.run(cmd, shell=True)  # security-checker: ignore[python.lang.security.audit.subprocess-shell-true] reason=cmd は固定文字列のみ
```

信用できない検査対象 (`SECURITY_CHECKER_UNTRUSTED_TARGET=1`) では、検査対象の中の ignore ファイルと
注釈を読みません。PR 側が自分の指摘を自分で消せてしまうためです。
