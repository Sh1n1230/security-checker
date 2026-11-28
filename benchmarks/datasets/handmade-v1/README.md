# handmade-v1

`security-checker eval` 用のラベル付きデータセットです。1 ケース = `cases/<id>.yaml` の 1 ファイルで、
**スキャナが出したことにする候補 + 文脈込みのコード + 人手の正解ラベル (と理由)** を持ちます。
書式と指標の読み方は [docs/evaluation.md](../../../docs/evaluation.md) を参照してください。

## 内訳 (108 件)

| 正解 | 件数 |
|---|---|
| 真陽性 (`vulnerable: true`) | 52 |
| 誤検知 (`vulnerable: false`) | 56 |

| カテゴリ | スキャナ | 件数 |
|---|---|---|
| sast | semgrep | 75 |
| secret | gitleaks | 15 |
| config | trivy | 10 |
| dependency | osv | 8 |

| 言語 | 件数 |
|---|---|
| Python | 51 |
| JavaScript | 18 |
| Go | 6 |
| YAML | 6 |
| Java | 5 |
| HCL (Terraform) | 5 |
| テキスト | 3 |
| TypeScript | 2 |
| Dockerfile | 2 |
| dotenv | 1 |
| Markdown | 1 |
| Kotlin | 4 |
| Swift | 4 |

PHP・Ruby・C#・Rust・C / C++ のケースはまだありません (issue で募集しています)。

## 出典

**すべて手書き (`source: handmade`) です。** 業務コードや非公開のコード、他のデータセットからの転載は含みません。
誤検知のケースは「スキャナのルールは正しく反応したが、文脈 (到達可能性・用途・対策済み) を見れば問題ではない」
ものを中心にしています。LLM レビューの価値はそこにあるためです。

シークレットの値はすべてダミーです。リポジトリ自身の gitleaks 検査からは `.gitleaks.toml` で除外しています。

## ケースを足すとき

- `rationale` を必ず書く (ラベルの妥当性を後から検証できるように)
- `id` (省略時はファイル名) は英数字と `.` `_` `-` だけ。`path` は相対パスで、`..` は使えません
- 件数や内訳が変わったら、この README の表も直す

## Added paired cases

Kotlin, Swift: each language adds two vulnerable cases and two negative controls.
The candidate locations identify the security-sensitive operation; the rationale
explains the relevant source, sink, and mitigation or benign use. These are seeded
Reviewer-evaluation inputs, not scanner-detection or live-LLM accuracy results.
