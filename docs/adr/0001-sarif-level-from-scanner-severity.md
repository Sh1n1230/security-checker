# 0001. SARIF の level はスキャナ由来の重大度で決める

- 状態: 採用 (2026-09-15。NEXT-STEPS の D3)
- 関連: DESIGN.md §18.3, §18.4, R14

## 背景

SARIF の `level` (error / warning / note) と `security-severity` は、Code Scanning のマージゲート
(Ruleset の "Require code scanning results") が直接見る値です。

LLM の判定は温度 0 でも決定的ではなく、同じコードでも run ごとに重大度が揺れます。
LLM の判定で level を決めると、コードが変わっていないのに alert が開いたり閉じたりし、
ゲートが PR ごとに違う判断をします。

## 決定

- `level` と `security-severity` は**スキャナが報告した重大度**で決める。
- LLM の判定 (status・重大度・確信度・各 Reviewer の判断) は `message` と `properties` に載せる。
- status による調整だけは行う: `likely` は 1 段下げる、`review_required` と判定の無いものは `note` / 0.0、
  `false_positive` と抑制済みは出さない。

## 結果

- alert の開閉はスキャナの検出と LLM の status (割れたか・誤検知か) でしか変わらない。
- LLM が「スキャナより重い」と判断しても SARIF の level は上がらない。その判断は PR コメントと
  `report.md` で人間に見せる。
