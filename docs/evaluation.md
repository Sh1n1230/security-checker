# 評価 (eval)

**「LLM レビューを足したら本当に良くなったのか」を測れなければ、このプロジェクトは主張を持てません。**
そのための仕組みが `security-checker eval` です。

```sh
security-checker eval \
  --dataset benchmarks/datasets/handmade-v1 \
  --config security-checker.local.yml \
  --output benchmarks/results/2026-09-18.json \
  --markdown benchmarks/results/2026-09-18.md
```

実行時とまったく同じ経路（Context Builder → Reviewer → Aggregator → Finding）を通します。
**評価専用の近道は作りません。** 近道を作ると、測っているものが実際の挙動とずれます。

## 指標の読み方

| 指標 | 定義 | 位置づけ |
|---|---|---|
| **Recall（検出率）** | TP / (TP + FN + 保留した陽性) | **主指標。** 陽性全体のうち、自動で検出した割合 |
| 判定した中での Recall | TP / (TP + FN) | 参考値。保留が増えると上がるので比較に使わない |
| Precision | TP / (TP + FP) | 副指標。ノイズの少なさ |
| F1 | 調和平均 | 総合 |
| **FP 削減率** | TN / (TN + FP + 保留した陰性) | このツールの価値そのもの。保留した陰性は削減に数えない |
| **見逃した真陽性** | 本物を `false_positive` と判定した件数 | **0 に近いことが必須条件** |
| review_required 率 | 判断が割れた割合 | 高すぎると実用性が下がる |
| Severity MAE | 正解との平均絶対誤差 | 重大度判定の質 |
| CWE 一致率 | 正解 CWE と重なった割合 | 分類の質 |

### なぜ Recall が主指標なのか

**FP を減らすのは簡単です。全部「誤検知」と答えればよい。** その場合 FP 削減率は 100% になりますが、
Recall は 0% に落ちます。意味のある問いは **「見逃しを増やさずに FP をどれだけ削れたか」**だけです。

同じことは**全部保留**でも起こせます。`eval` が失敗で終わるのは次のときです。

| 条件 | exit | 緩める方法 |
|---|---|---|
| 採点できなかったケースがある (`error` / `not_reviewed`) | 3 | `--allow-incomplete` |
| 真陽性を 1 件でも見逃した | 1 | なし |
| `review_required` の割合が上限を超えた | 1 | `--max-deferred-rate` (既定 0.5) |

### `review_required` の扱い

**自動では検出していない結果**として扱います。保留した陽性は Recall の分母に残し、保留した陰性は
FP 削減に数えません。人間に渡した件数は内訳の表と `review_required` 率で別に見ます。
どちらかを緩めると、判断を保留しただけで数字が良く見えてしまいます。

### 採点しないケース

Provider のエラー (`errors`) と、予算や上限でレビューされなかったケース (`not_reviewed`) は採点から外し、
別に数えます。**故障や打ち切りを「精度の問題」に化けさせない**ためです。

`eval` にも `budget.max_usd` (既定 $1.00) と `max_total_tokens` がそのまま効きます。
有料モデルで同梱の 100 件を回すときは、設定の `budget` を上げてください。

## 同梱のデータセット

`benchmarks/datasets/handmade-v1/` に 100 件 (真陽性 48 / 誤検知 52) あります。

| カテゴリ | 件数 | 主な題材 |
|---|---|---|
| sast | 67 | コマンド / SQL インジェクション、デシリアライズ、パストラバーサル、XSS、SSRF、XXE、CSRF、IDOR、乱数、TLS 検証 |
| secret | 15 | 本番設定・CI・フロントエンドへの直書き、`.env.example`・ドキュメント例・テスト用の値 |
| config | 10 | Kubernetes・Dockerfile・Terraform (S3・セキュリティグループ) |
| dependency | 8 | 到達する脆弱性 / 使っていない機能・開発依存・インストールされない extra |

言語は Python・JavaScript / TypeScript・Go・Java と設定ファイル。
誤検知のケースは「スキャナのルールは正しく反応したが、文脈 (到達可能性・用途・対策済み) を見れば
問題ではない」ものを中心にしています。LLM レビューの価値はそこにあるためです。

シークレットの値はすべてダミーです。リポジトリ自身の gitleaks 検査からは `.gitleaks.toml` で除外しています。

## ケースを足す

`benchmarks/datasets/<name>/cases/<id>.yaml` に 1 件 1 ファイルで置きます。

```yaml
candidate:                 # スキャナが出したことにする候補
  scanner: semgrep
  rule_id: python.lang.security.dangerous-subprocess-use
  category: sast           # secret | sast | dependency | config | web
  message: subprocess の呼び出しに shell=True が指定されています
  path: app/upload.py
  start_line: 12
  severity_reported: high
  cwe: ["CWE-78"]
code: |                    # 文脈込みの実コード (呼び出し元も含める)
  ...
ground_truth:
  vulnerable: true
  cwe: ["CWE-78"]
  severity: high
  rationale: |             # **必須**。なぜその正解なのか
    filename は POST のフォーム値をそのまま受け取り、検証もエスケープもされずに…
```

守ること:

- **`rationale` を必ず書く。** ラベルの妥当性を後から検証できないと、評価自体が信用できません
- **誤検知のケースを多めに含める。** 実運用の分布は FP が支配的です
- **業務コードや非公開コードを置かない。** 公開リポジトリに入ります
- 壊れたケース・未知のキー・id の重複はすべてエラーになります（黙って飛ばすと評価が静かに壊れるため）

## 何を比べるか

同じデータセットで **Reviewer の構成を変えて**走らせ、結果を比べます。

- 1 モデル vs 複数モデル（`consensus` / `weighted`）— 複数に本当に意味があるのか
- `http` のみ vs `http` + `process` — 性質の異なる transport を混ぜる効果
- プロンプトを変更したとき（変更前後で必ず回す）

**効果がなければ「1 モデルで十分」と正直に書きます。** そのほうが OSS としての信頼は高いからです。
