# `process` transport — API キーなしで Reviewer を用意する

> 設計書: §9.7 / §9.8 / §25.2
> 対象読者: API キーを持っていない、または手元のコマンドの既存ログインをそのまま使いたい人

## これは何か

**外部コマンドを subprocess で起動し、その標準出力を LLM 応答として扱う仕組み**です。
特定の CLI を対象にした機能ではありません。次の契約を満たすものは**すべて** Reviewer にできます。

```text
起動   : argv で指定されたコマンドを、非対話モードで実行する
入力   : プロンプトを stdin (または一時ファイル) で渡す
出力   : stdout にテキストを返す。そこから JSON を抽出する
終了   : exit code 0 を成功とみなす
```

自作のシェルスクリプト、社内の推論ゲートウェイ、ローカルモデルのランナー、
コーディングエージェントの CLI — すべて同じ経路で扱われます。
本体は、対象が何であるかを知りません。

## 最小の設定

```yaml
reviewers:
  - name: my-reviewer
    transport: process
    command: ["<your-command>", "--non-interactive", "--no-tools"]
    prompt_via: stdin            # stdin | file
    parse: json_in_stdout        # stdout から最初の JSON オブジェクトを抽出する
    timeout_s: 300
    concurrency: 1
```

`api_key_env` は**書きません**。認証は起動されるコマンド側の既存ログインに委ねます。

環境を検出して雛形を作ることもできます。

```bash
security-checker init --command '<your-command> --non-interactive --no-tools'
security-checker review --dry-run     # 何が送信されるかを、送信前に全部見る
security-checker review
```

共有リポジトリの `security-checker.yml` を汚したくない場合は `--local` を付けます。
`security-checker.local.yml`(git 管理外)に書き出され、共有設定に後勝ちで重なります。

```bash
security-checker init --local --command '<your-command> --non-interactive --no-tools'
```

## ★ 安全性 — ここが本題です

起動対象は**任意のコマンド**であり、その中にはファイルを書き換える能力を持つものが含まれます。
何も考えずに起動すると、Security Reviewer がレビュー対象リポジトリを勝手に編集しかねません。
**P3 (No Automatic Modification) はこのツールの根幹**なので、対象が何であるかによらず
次を一律に強制します。

| # | 強制していること | 実装 |
|---|---|---|
| 1 | **リポジトリの外で起動する** | cwd は毎回作り直す空の一時ディレクトリ。コマンドにリポジトリのパスを渡さない |
| 2 | **シェルを経由しない** | `argv` のリストで起動し `shell=False` 固定 |
| 3 | **プロンプトを引数に埋め込まない** | 必ず stdin か一時ファイル。長さ制限・`ps` からの可視性・フラグ誤解釈を避ける |
| 4 | **実行後に書き込みを検査する** | 一時 cwd に何か作られていたら warning を出し trace に記録する |
| 5 | **プロセスグループごと kill する** | `start_new_session` + `killpg`。タイムアウトで子プロセスを残さない |

### ただし、あなたの責任として残るもの

本体は `command:` に書かれたコマンドの**中身を検証できません**。
そのため、`command` を直接書いた場合は起動時に必ず次の警告が出ます。

```text
process transport は隔離した一時ディレクトリで起動し、書き込みがあれば検知しますが、
コマンド自体の書き込み能力を無効化できているかは本体からは検証できません。
非対話・ツール無効 (または読み取り専用) の指定が command に含まれていることを
確認してください
```

**非対話モードのフラグと、ツール実行・ファイル書き込みを無効化するフラグを
必ず `command` に含めてください。** 一時ディレクトリの隔離は最後の防波堤であって、
最初の防波堤ではありません。

### 利用規約について

**起動するコマンドの自動化利用が、その提供元の利用規約で許されているかは、
利用者が確認してください。** 本体は既定で何も有効化しませんし、
同梱プリセットも 1 つもありません。判断はあなたのものです。

## `http` との違い (正直に書きます)

| 項目 | `http` | `process` |
|---|---|---|
| Structured Output | `json_schema` / `json_mode` | **`prompt_only` のみ**。抽出 + 修復パスに依存する |
| トークン / コスト計測 | 正確 | **不可**。`cost_known: false`、tokens は推定値の参考表示 |
| レイテンシ | 数秒 | 数十秒〜数分 (既定 timeout 300s) |
| 並列度 | 数〜十数 | **既定 1**。プロセス起動が重く、対象側にも制限があることが多い |
| 決定性 | temperature 0 / seed | 対象依存。制御できない前提で扱う |
| 安定性 | API バージョンで担保 | **対象コマンドのバージョン差異で壊れうる**。バージョンを trace に残す |
| 利用規約 | エンドポイントの利用規約 | **対象コマンドの利用規約。判断は利用者の責任** |

`process` は一般に「安価だが荒い」ものです。ただしこれは transport の性質であって、
特定の対象の優劣ではありません。組み合わせ方の一般則としては、
**性質の異なる transport を混ぜると agreement が情報量を持ちやすい**です。

```yaml
reviewers:
  - name: http-reviewer
    transport: http
    dialect: openai_chat
    base_url: https://<endpoint>/v1
    model: <model-id>
    api_key_env: <ENV_VAR_NAME>
  - name: local-command
    transport: process
    command: ["<your-command>", "--non-interactive", "--no-tools"]
```

## `prompt_via: file` を使う

stdin を受け付けないコマンド向けです。プロンプトは**一時 cwd の外**のファイルに書かれ、
そのパスが argv に渡ります。`{prompt_file}` と書けばその位置に、書かなければ末尾に付きます。

```yaml
command: ["<your-command>", "--input", "{prompt_file}", "--non-interactive"]
prompt_via: file
```

## プリセット — コードではなくデータ

同じ `command` を何度も書きたくない場合、名前を付けて呼べます。

```yaml
# ~/.config/security-checker/presets/process/<name>.yml  (XDG_CONFIG_HOME を尊重)
name: <name>
command: ["<binary>", "<non-interactive-flag>", "<disable-tools-flag>"]
prompt_via: stdin
parse: json_in_stdout
capabilities:
  max_context_tokens: 200000
requires_readonly_flags: true      # 上記の安全要件を満たしていることの申告
```

```yaml
reviewers:
  - name: r1
    transport: process
    preset: <name>
```

- **PR は不要、コードも不要**です。ファイルを置くだけで追加・上書きできます。
- `requires_readonly_flags: true` を申告したプリセット経由の場合のみ、前述の警告が出ません。
  申告は「このプリセットの `command` は書き込み能力を無効化してある」という宣言です。
- 同梱プリセットは**意図的に 0 個**です。既定の Reviewer を持たないのは、特定のベンダーを
  事実上の標準として押し付けないためです (§9.8)。プリセットが 1 つも無くても、
  `command` 直書きで同じように動きます。

### 同梱プリセットの採否基準

同梱を提案する場合、判断材料は**人気や提供元ではなく、次の客観的条件のみ**です。

1. 非対話モードがあり、スクリプトから起動できる
2. **ツール実行・ファイル書き込みを無効化する手段がある** (必須)
3. 出力を標準出力から取得できる
4. 自動化利用が、その提供元の利用規約で明示的に禁止されていない

条件を満たす提案は**先着順で受け入れ、一覧はアルファベット順で表示します。**
順位づけ・推奨マーク・「おすすめ」表記は付けません。特定の 1 つを既定値にもしません。

## 監査証跡

`process` 呼び出しも `http` と同じ形式で trace に残ります (`.security-checker/trace/<run_id>/calls/*.json`)。

```json
{
  "params": {
    "transport": "process",
    "dialect": "text_io",
    "argv": ["<your-command>", "--non-interactive"],
    "version": "<取得できたバージョン>",
    "prompt_via": "stdin",
    "cwd": "isolated-temp-dir"
  },
  "response": {
    "raw": "<stdout 全文>",
    "stderr": "<stderr の抜粋>",
    "exit_code": 0,
    "created_paths": []
  }
}
```

`created_paths` が空であることが、**P3 が守られたことの実測値**です。

## うまくいかないとき

| 症状 | 見るところ |
|---|---|
| `stdout が空でした` | 非対話モードのフラグが足りない。対話モードで待機している可能性 |
| `コマンドが exit N で終了しました` | trace の `stderr` を見る。フラグ名の変更やログイン切れが多い |
| `N s 以内に終了しませんでした` | `timeout_s` を上げる。既定 300s |
| `スキーマ検証に失敗しました` | `prompt_only` では避けられない場合がある。1 回だけ自動修復を試みた結果 |
| `書き込みを行いました` の警告 | `command` に書き込み無効化のフラグを足す |

## 自作 Provider を作る場合

`process` transport は追加の契約テストを公開しています。

```python
from security_checker.testing import ProcessProviderContractTests

class TestMyProcessProvider(ProcessProviderContractTests):
    def make_process_provider(self, command):
        return MyProcessProvider(command=command)
```

検証されるのは、共通契約に加えて次の 4 点です。

7. シェルを経由せず、プロンプトが argv に現れない
8. cwd がレビュー対象リポジトリの外である
9. 実行後、cwd にファイルが作られていない (書き込みを試みるコマンドは検知できる)
10. タイムアウト時に子プロセスが残らない
