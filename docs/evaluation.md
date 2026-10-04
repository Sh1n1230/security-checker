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
| **Recall（検出率）** | TP / (TP + FN) | **主指標。** 見逃しを増やしていないか |
| Precision | TP / (TP + FP) | 副指標。ノイズの少なさ |
| F1 | 調和平均 | 総合 |
| **FP 削減率** | (スキャナ単体の FP − レビュー後の FP) / スキャナ単体の FP | このツールの価値そのもの |
| **見逃した真陽性** | 本物を `false_positive` と判定した件数 | **0 に近いことが必須条件** |
| review_required 率 | 判断が割れた割合 | 高すぎると実用性が下がる |
| Severity MAE | 正解との平均絶対誤差 | 重大度判定の質 |
| CWE 一致率 | 正解 CWE と重なった割合 | 分類の質 |

### なぜ Recall が主指標なのか

**FP を減らすのは簡単です。全部「誤検知」と答えればよい。** その場合 FP 削減率は 100% になりますが、
Recall は 0% に落ちます。意味のある問いは **「見逃しを増やさずに FP をどれだけ削れたか」**だけです。

そのため `eval` は、真陽性を 1 件でも見逃したら **exit 1 で終わります**。数字を眺めて見過ごせないようにするためです。

### `review_required` の扱い

TP にも FN にも数えず、**「人間に渡した」という第 3 の結果**として別に数えます。
混ぜると、判断を保留しただけで数字が良く見えてしまいます。

### エラーの扱い

Provider のエラーは採点対象から外し、`errors` として別に数えます。
**故障を「精度の問題」に化けさせない**ためです。

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
