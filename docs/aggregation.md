# 集約 — 複数の Reviewer の判定をどうまとめるか

Reviewer が 1 つなら、その判定がそのまま結果になります。
複数あるときの戦略は 3 つです。**どれが良いかは eval で確かめてください** ([evaluation.md](evaluation.md))。
効果が無ければ 1 モデルで十分です。

## 原則: 割れたら答えを出さない

意見が割れた候補を多数決で無理に片付けず、`review_required` として人間に渡します。
これは失敗ではなく正しい出力です。`review_required` は CI を落とさず、PR と Security タブには残ります。

## consensus (既定)

「脆弱」と判定した Reviewer の数と比率で決めます。

| 条件 | 結果 |
|---|---|
| 脆弱の票が `min_votes` 以上かつ比率が `min_ratio` 以上 | 一致度が高く確信度の平均が 0.8 以上なら `confirmed`、それ以外は `likely` |
| 全員が「脆弱ではない」 | `false_positive` |
| それ以外 | `review_required` |

重大度は脆弱と判定した Reviewer の中央値 (`consensus.severity` で `max` / `weighted_mean` も選べる)。

## weighted

Reviewer ごとの重み (`reviewers[].weight`) で加重したスコアが `weighted.threshold` を超えたら脆弱とします。
**重みを勘で決めないでください。** eval で各 Reviewer の精度を測り、その結果を根拠にします。

## judge

一次レビューの結果を `judge.fallback` (既定 consensus) で集約し、**判断が割れた候補だけ**を
Judge 役の Reviewer に回します (`only_on_disagreement: true`)。

```yaml
reviewers:
  - { name: r1, ... }
  - { name: r2, ... }
  - { name: r3, ... }        # Judge。一次レビューには参加しない
aggregation:
  strategy: judge
  judge:
    reviewer: r3
    fallback: consensus
    only_on_disagreement: true
```

- **匿名化**: Judge に渡す意見からモデル名・Reviewer 名を除き `Reviewer A/B/C` にし、順序を並べ替えます
  (並べ替えは候補ごとに固定で、再現できます)。ブランドや順序によるバイアスを減らすためです。
- **元のコードも渡します。** 意見だけでは多数決の言い換えしかできません。
- **新しい脆弱性は探させません。** 渡された論点を評価するだけです。採否の理由は `reasoning` に書かせ、
  `explain` で見られます。
- **見逃しを増やさない方向に倒します。** Judge が「脆弱ではない」と言っても、確信度が 0.8 未満か、
  文脈が足りないと言っている場合は `review_required` のまま残します。
- **Judge が失敗したら** (エラー・予算切れ・一次レビューの停止) fallback の結果をそのまま使い、
  そのことを `aggregation.detail.fallback_used` に残します。Judge を単一障害点にしません。
- 費用は「割れた候補の数 × 1 回」です。`review --estimate` は全候補が割れた場合の上限で見積もります。

## 一致度 (agreement)

| 値 | 意味 |
|---|---|
| `high` / `medium` / `low` | Reviewer 間の判定と重大度がどれだけ揃ったか |
| `not_applicable` | Reviewer が 1 つ。「1 モデルの合意」を高い一致度として偽装しない |

## 閾値の後処理

どの戦略でも、`confirmed` / `likely` で確信度が `policy.min_confidence` 未満のものは
`review_required` に落とします。
