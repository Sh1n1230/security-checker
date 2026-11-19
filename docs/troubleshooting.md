# うまくいかないとき

表示されたメッセージから引けるように、よくある失敗と対処を並べています。メッセージは実際の文言の一部です
(`<...>` は実行ごとに変わる部分)。終了コードの意味は [exit-codes.md](exit-codes.md) を見てください。

まず状況を知るためのコマンド:

```sh
security-checker config show --explain   # いま効いている設定と、どの層で決まったか
security-checker providers check         # Reviewer ごとに 設定 → 疎通 → 構造化出力 を確かめる
security-checker review . --dry-run      # 何も送らずに、送る内容と警告を見る
security-checker explain <id>            # 1 件の指摘について、判定と LLM の呼び出しをたどる
security-checker scan . --log-level debug --log-format text   # 詳しいログ (内部エラーのトレースバックを含む)
```

## スキャナ

### `<スキャナ> が利用できません` — status が `skipped`

ツールが入っていません。**その観点は検査されていません** (「問題なし」ではありません)。メッセージの後ろに
導入方法が出ます。使わないスキャナなら `scanners.<名前>.enabled: false` で明示的に無効にしてください。
`baseline update` は、有効なのに未導入のスキャナがあると止まります (欠けた結果で上書きしないため)。

### `<スキャナ> の実行に失敗しました` — status が `failed`、終了コード 3

ツールが異常終了しました。レポートの `stderr_excerpt` (ターミナルの警告にも出ます) に原因が出ています。
よくあるのは、ルールセットの取得に失敗した (ネットワーク)、`extra_args` に渡したフラグの誤りです。
strict (既定) では終了コード 3 になります。壊れた検査を緑にしないためです。

### `<スキャナ> が <N>s でタイムアウトしました`

`scanners.<名前>.timeout_s` を延ばすか、`target.exclude` で大きなディレクトリ (依存・生成物) を外してください。
`target.exclude` を書くと既定の除外を**置き換える**ので、既定の項目も書き写してください
([configuration.md](configuration.md))。

### `内部エラー (<例外の型>): ...`

スキャナのアダプタ (またはプラグイン) の不具合です。`--log-level debug` でトレースバックが出ます。
それを添えて Issue を立ててください。

### 何も検出されないはずなのに、キャッシュや依存の中のファイルが出る

`--exclude` や `target.exclude` で既定の除外を置き換えていないか確かめてください。
`config show` の `target.exclude` に `**/node_modules/**` などが残っているのが正しい状態です。

## Reviewer (LLM)

### `reviewers が設定されていません`

`review` には Reviewer が要ります。`security-checker init` で、手元で使えるものを検出して設定を作れます。
LLM を使わない検査は `security-checker scan` です。

### `環境変数 <名前> が設定されていません` — 終了コード 2

`api_key_env` / `headers_env` に書いた環境変数がありません。何も送る前に止まります。
GitHub Actions では、その変数を action の `env:` に渡しているか確かめてください。

### `平文の api_key は設定できません` / `値が直書きされています`

設定ファイルにキーを書くことはできません。`api_key_env` に**環境変数の名前**を書いてください。
設定ファイルは Issue に貼られたり、コミットされたりするためです。

### `認証に失敗しました (401 / 403)`

キーの値と、そのキーで `model` を使えるかを確かめてください。認証の失敗は再試行せず、その Reviewer を
この実行の間は無効にします。strict では終了コード 3 です。

### `レート制限に達しました` / `1 日の上限 (rpd <N>) に達しました`

提供元の上限です。`reviewers[].rate_limit` (`rpm` / `tpm` / `rpd`) に提供元の値を書くと、送る前に待ちます。
並列度は `reviewers[].concurrency` で下げられます。`Retry-After` が長すぎるときは待たずに打ち切り、
その候補は `error` として残ります。

### `構造化出力を <json_mode | prompt_only> に降格しました`

エンドポイントがスキーマの指定を受け付けなかったので、1 段弱い方式で送り直しました。動作はしています。
毎回出るなら、`capabilities.structured_output` にその方式を書いておくと、無駄な 1 往復が無くなります
([providers.md](providers.md#構造化出力の降格))。

### `スキーマ検証に失敗しました` — status が `schema_error`

モデルが決められた形の JSON を返せませんでした (1 回だけ修復を試みます)。`explain <id>` で実際の応答を
確かめられます (`output.save_prompts: true` のとき全文)。出力が途中で切れているなら
`max_output_tokens` を増やしてください。小さなモデルでは `prompt_only` だと安定しないことがあります。

### `モデルが見つかりません。先にモデルを取得してください`

`ollama_chat` 方言で、指定したモデルが手元にありません。`ollama pull <model>` で取得してください。

### `<N> 回連続で失敗したため無効化しました`

同じ Reviewer が続けて失敗したので、残りの候補には使いません (壊れた Reviewer に予算を使い続けないため)。
`providers check <name>` で原因を切り分けてください。

### `コマンドが見つかりません: <コマンド>` (process transport)

`command` の先頭が PATH にありません。絶対パスで書くか、PATH を確かめてください。
コマンドは検査対象とは別の空の一時ディレクトリで起動するので、相対パスは使えません。

### `Reviewer が隔離ディレクトリに書き込みを行いました`

`process` の Reviewer がファイルを作りました。ツールの実行やファイルの書き込みを無効にするフラグが
`command` に足りていません ([process-transport.md](process-transport.md))。隔離ディレクトリの外への
書き込みは検知できないので、必ず直してください。

## 予算と見積り

### `予算 $<N> を超える見込みのため止めました` / `予算・上限・中断のためレビューされていません`

`budget.max_usd`・`max_total_tokens`・`max_candidates`・`deadline_s` のどれかに達しました。それまでの結果は
レポートに出ており、残りは `not_reviewed` です (strict では終了コード 3)。先に
`review --estimate` で見積もれます。

### 金額が `unknown` になる

価格表 `pricing.yml` が無いか、`model` の名前が価格表と完全には一致していません
([configuration.md](configuration.md#コストと-pricingyml))。`process` transport はトークンを測れないので、
常に `unknown` です。

## 差分と GitHub

### `base '<ref>' との共通祖先が見つかりません`

差分の基準になるコミットがありません。GitHub Actions では `actions/checkout` に `fetch-depth: 0` を
指定してください。手元では `git fetch origin <ブランチ>` をしてから `--base origin/<ブランチ>` を渡します。

### `git が見つかりません。diff モードには git が必要です`

差分だけを見るモードには git が要ります。全体を検査するなら `--full` を付けてください。

### `コメント先の PR を特定できません`

`comment` は pull_request イベントの中で動かすか、`--repo <owner/name> --pr <番号>` を渡してください。

### `GITHUB_TOKEN (または GH_TOKEN) が設定されていません`

`comment` にはトークンが要ります。Actions では `env: GITHUB_TOKEN: ${{ github.token }}` を渡し、
ジョブに `pull-requests: write` を付けます。

### `PR にコメントできませんでした (権限不足の可能性 ...)`

fork からの PR では、`GITHUB_TOKEN` が読み取り専用になります。コメントと SARIF を出すには
`workflow_run` の workflow を足してください ([github-actions.md](github-actions.md#5-fork-からの-pr))。

### inline コメントが付かない (`diff 外` / `patch なし` / `拒否`)

`comment` の最後に内訳が出ます。`diff 外` は変更された行に乗っていない指摘、`patch なし` は差分が大きく
GitHub が patch を返さなかったファイル、`拒否` は GitHub が行を受け付けなかったものです。
どれもサマリのコメントには載っています。

## 設定

### `設定が不正です:` — 終了コード 2

続く行に、項目のパスと理由が出ます。未知のキーは受け付けません (打ち間違いを黙って無視しないため)。

### `preset '<名前>' は存在しません` / `は見つかりません`

前者は `--preset` (構成のプリセット)、後者は `reviewers[].preset` (Provider のプリセット) です。
使える名前はメッセージと `providers list` に出ます。

### `<項目> は transport: <http | process> では使われません` などの警告

書いた設定が、その組み合わせでは効きません。エラーにはしませんが、効いていると思い込まないよう
必ず警告します。不要なら消してください。

### baseline を書いたのに、指摘が減らない

`baseline update` で書き出しただけでは効きません。設定に `policy.baseline: <ファイル>` を書いてください
([getting-started.md](getting-started.md))。版を上げた後に効かなくなった場合は
[adoption.md](adoption.md) の「安定 ID の互換性が変わったとき」を見てください。

## それでも分からないとき

`security-checker version` の出力、実行したコマンド、`report.json` の `warnings` と `scanners` の部分を添えて
[Issue](https://github.com/Sh1n1230/security-checker/issues) を立ててください。
**検査対象のコードや秘密の値は貼らないでください。** 脆弱性の報告は Issue ではなく
[SECURITY.md](../SECURITY.md) の手順でお願いします。
