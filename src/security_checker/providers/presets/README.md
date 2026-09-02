# プリセット (データ)

ここにあるのは **データだけ** です。コードにベンダー名は現れません(設計書 §9)。

同梱プリセットは意図的に空です。プリセットは省略記法にすぎず、設定に
`dialect` / `base_url` / `model`(`http`)や `command`(`process`)を直接書けば、
プリセットが 1 つもなくても動きます。

## 自分のプリセットを追加する

`~/.config/security-checker/presets/http/<name>.yml`(`XDG_CONFIG_HOME` を尊重)に置きます。
同名のファイルを置けば同梱分を上書きできます。PR は不要で、コードも書きません。

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
