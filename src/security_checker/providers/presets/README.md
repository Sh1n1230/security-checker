# プリセット (データ)

ここにあるのは **データだけ** です。コードにベンダー名もコマンド名も現れません(設計書 §9)。

同梱プリセットは意図的に空です。プリセットは省略記法にすぎず、設定に
`dialect` / `base_url` / `model`(`http`)や `command`(`process`)を直接書けば、
プリセットが 1 つもなくても動きます。

## 自分のプリセットを追加する

`~/.config/security-checker/presets/<transport>/<name>.yml`(`XDG_CONFIG_HOME` を尊重)に置きます。
同名のファイルを置けば同梱分を上書きできます。PR は不要で、コードも書きません。

### `http/<name>.yml`

```yaml
name: my-endpoint
dialect: openai_chat
base_url: https://example.internal/v1
api_key_env: MY_ENDPOINT_KEY
match:                       # 省略時は名前指定でのみ使われる
  host: example.internal
  model: "^my-model"
capabilities:
  structured_output: json_schema
  max_context_tokens: 128000
```

一致するエントリがない未知のエンドポイントでも、最も互換性の高い `json_mode` に
フォールバックして「まず動く」ようにしてあります(設計書 §9.3)。

### `process/<name>.yml`

```yaml
name: my-command
command: ["<binary>", "<non-interactive-flag>", "<disable-tools-flag>"]
prompt_via: stdin            # stdin | file
parse: json_in_stdout
capabilities:
  max_context_tokens: 200000
requires_readonly_flags: true   # 安全要件を満たしていることの申告 (§9.7)
```

`requires_readonly_flags: true` は「この `command` はツール実行・ファイル書き込みを
無効化してある」という宣言です。申告のないプリセット、および設定に `command` を
直接書いた場合は、起動時に「書き込み能力の無効化は利用者の責任である」旨を警告します。

`process` transport の構造化出力は `prompt_only` に固定されるため、
`capabilities.structured_output` を指定しても実態は変わりません(設計書 §9.7)。

詳細は [`docs/process-transport.md`](../../../../docs/process-transport.md) を参照してください。
