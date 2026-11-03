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
| 脆弱の票が `min_votes` 以上、比率が `min_ratio` 以上、かつ過半数 (半々は含まない) | 一致度が高く確信度の平均が 0.8 以上なら `confirmed`、それ以外は `likely` |
| 全員が「脆弱ではない」、確信度の平均が 0.8 以上で、文脈不足を訴える Reviewer がいない | `false_positive` |
| 全員が「脆弱ではない」だが確信度が低い | `review_required` |
| それ以外 | `review_required` |
| 複数の Reviewer に割り当てたが、有効な判定が 1 つしか残らなかった (他はエラー・無効化・停止) | 残った判定が「脆弱」かつ確信度 0.5 以上なら `likely`、それ以外は `review_required`。`false_positive` と `confirmed` にはしない |

最後の行は weighted でも同じです。Reviewer の 1 つがレート制限やタイムアウトで落ちただけで、
残った 1 つの「脆弱ではない」で候補が消えないようにするためです。`aggregation.detail` に
`mode: partial_reviewers` と失敗した数 (`failed_verdicts`) が残ります。

重大度は脆弱と判定した Reviewer の中央値です (`consensus.severity` で `max` / `weighted_mean` も選べます。
`weighted_mean` は `reviewers[].weight` で加重します)。割り切れないときは x.5 を上へ丸めるので、
medium と high に割れたら high、high と critical に割れたら critical になります。

Reviewer が 1 つのときは、戦略によらず次の規則です。

| 判定 | 確信度 | 結果 |
|---|---|---|
| 脆弱 | 0.8 以上 | `confirmed` |
| 脆弱 | 0.5 以上 | `likely` |
| 脆弱 | 0.5 未満 | `review_required` |
| 脆弱ではない | 0.8 以上 (文脈不足を訴えていない) | `false_positive` |
| 脆弱ではない | それ以外 | `review_required` |

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
