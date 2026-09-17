# コントリビューションガイド

ありがとうございます。このプロジェクトは **拡張可能な AI Security Review プラットフォーム**で、
設計の詳細は [docs/DESIGN.md](docs/DESIGN.md) にあります。

このドキュメントの言語は日本語ですが、**Issue と PR は日本語でも英語でも構いません。**

---

## 開発環境

```sh
git clone https://github.com/Sh1n1230/security-checker.git
cd security-checker
uv sync --group dev
```

外部スキャナ（`semgrep` / `gitleaks`）は入っていなくても大半のテストは動きます。
入っていない場合は `skipped` として扱われます（`failed` とは区別します）。

```sh
uv run security-checker scan .          # スキャナのみ。LLM は使わない
uv run security-checker review .        # Reviewer を設定してあれば LLM レビュー
uv run security-checker config show --explain
```

## 出す前に通すもの

CI と同じものをローカルで回せます。

```sh
uv run ruff check .
uv run ruff format --check src tests
uv run mypy
uv run pytest --cov --cov-fail-under=80
```

- **CI は実 LLM を一切叩きません**（設計書 §25）。テストは `FakeProvider` / `ScriptedProvider`
  （`security_checker.testing.fakes`）か `respx` による HTTP モックで書いてください。
- 新しい Provider を足したら `ProviderContractTests` を通してください（§25.2）。
  `process` transport はさらに `ProcessProviderContractTests` も必要です。
- スキャナのパーサを触ったら、**異常系**（空・null・壊れた JSON・ツール失敗）のケースを必ず足してください。
  v1 で実害のあったバグ 2 件は、いずれもここで防げたものです。

## PR の出し方

- `main` は保護ブランチです。直接 push はできません。
- ブランチ名: `feat/<slug>` / `fix/<slug>` / `docs/<slug>` / `chore/<slug>`
- **マージは squash のみ**です。squash 後のコミットメッセージは PR タイトルになるため、
  **PR タイトルを [Conventional Commits](https://www.conventionalcommits.org/) 形式**にしてください
  （作業ブランチ内の個々のコミットメッセージは自由です）。CI がタイトルを検査します。

```text
feat(providers): add ollama_chat dialect
fix(scanners): handle null package name
docs: describe process transport limitations
```

  型は `feat` / `fix` / `perf` / `docs` / `refactor` / `test` / `chore`、
  破壊的変更は `feat!:` または本文に `BREAKING CHANGE:`。
  スコープは領域名（`providers` / `scanners` / `aggregate` / `report` / `config` …）。

- **1 PR = 1 論点。** レビューできる粒度に保ってください。
- プロンプト（`src/security_checker/review/prompts/*.jinja`）を変更する PR は、
  評価（`security-checker eval`）の結果を本文に貼ってください。プロンプトは精度に直結します。

---

## 設計上の不変条件

次の 4 つは **PR で覆せません。** 破る変更は、内容がどれだけ便利でも却下されます。

### 1. Reviewer はレビュー対象を書き換えない（P3）

- Reviewer に write / exec 系のツールを与えない。ツール定義に追加する PR は設計違反です。
- パッチファイルの出力機能も付けません。修正方針と参考コード例の提示までが範囲です。
- `process` transport は必ず「リポジトリ外の空の一時 cwd」「`shell=False`」「stdin か一時ファイル経由」
  「実行後の書き込み検知」「`killpg` による回収」の 5 点を守ります（§9.7）。

### 2. コードにベンダー名を書かない（P1）

分類軸は **transport（`http` / `process`）× dialect（リクエストとレスポンスの形）**です。
ベンダー知識は `src/security_checker/providers/presets/**.yml` という**データ**にのみ置きます。
特定のサービスを想定した分岐をコードに入れないでください。

### 3. 検出したシークレットの値を LLM に送らない（§19.2）

`context/redact.py` は Context Builder の必須通過点です。ここを迂回する経路を作らないでください。
「値をマスクしたこと」はレポートにも残します。

### 4. 部分的な失敗を成功に見せない（P9）

- `skipped`（ツール未導入）と `failed`（異常終了）を同じ扱いにしない。
- 失敗があればレポート冒頭に警告を出し、スコアに `partial` を立てる。
- **受け付けた設定を黙って無視しない。** 未実装の項目は警告かエラーにしてください。

---

## プリセットを足す（コードを書かずにできること）

「新しい LLM に対応する」は、9 割の場合コードを書かずに終わります。

1. **設定 1 ブロック** — `http` なら `dialect` + `base_url` + `model`、`process` なら `command`。
   これだけで動きます。プリセットは省略記法にすぎません。
2. **自分用のプリセット** — `~/.config/security-checker/presets/<transport>/<name>.yml` に置くだけ。
   PR は不要です。同名のファイルを置けば同梱分を上書きできます。
3. **同梱プリセットへの PR** — 他の人にも役立つなら、同じ YAML をそのまま PR できます。

### 同梱プリセットの採否基準

人気や提供元では判断しません。**次の客観条件だけ**で決めます（設計書 §9.7）。

1. 非対話モードがあり、スクリプトから起動できる
2. **ツール実行・ファイル書き込みを無効化する手段がある**（必須）
3. 出力を標準出力から取得できる
4. 自動化利用が、その提供元の利用規約で明示的に禁止されていない

条件を満たす提案は**先着順**で受け入れます。一覧は**アルファベット順**で、
順位づけ・推奨マーク・「おすすめ」表記は付けません。特定の 1 つを既定値にもしません。
`requires_readonly_flags: true` を申告するプリセットは、その申告どおりのフラグを含めてください。

---

## Provider / Scanner / Aggregator / Reporter を足す

上記で表現できない形（新しい API 方言など）だけ、コードが要ります。
内蔵も外部プラグインも同じ entry point 経由で登録されるため、プラグインが二級市民になることはありません。

| entry point group | Protocol |
|---|---|
| `security_checker.providers` | `LLMProvider` |
| `security_checker.scanners` | `Scanner` |
| `security_checker.aggregators` | `Aggregator` |
| `security_checker.reporters` | `Reporter` |

---

## 行動規範

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) に従ってください。

## 脆弱性の報告

Issue ではなく [SECURITY.md](SECURITY.md) の手順でお願いします。
