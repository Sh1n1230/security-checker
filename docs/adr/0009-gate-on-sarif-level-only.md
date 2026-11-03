# 0009. Code Scanning のゲートは SARIF の level だけで掛け、security-severity を付けない

- 状態: 採用 (2026-11-04)
- 関連: #90, #56, DESIGN.md §18.3, §18.4.1。ADR 0001 と 0006 の `security-severity` の部分を置き換える

## 背景

これまで `security-severity` を result の `properties` に書いていたが、GitHub が読むのは
rule (`reportingDescriptor`) の `properties.security-severity` だけで、result 側は無視される。
rule に置くと、その rule の結果は security alert として扱われ、merge protection の
Security alerts の閾値で判定される。security severity は rule 単位なので result ごとに下げられない。
`review_required`・`not_reviewed`・diff 外の結果まで rule の値のまま security alert になり、
「`review_required` は CI を落とさない」(§18.4.1) を Ruleset 側で破ることになる。

指紋も同じで、GitHub が使うのは `primaryLocationLineHash` だけで `partialFingerprints.primary` は読まない。

## 決定

- `security-severity` を付けない。ゲートは result の `level` と Alerts の閾値 (`Errors`) で掛ける。
- Ruleset の Security alerts の閾値は `None` にする。
- `partialFingerprints.primary` のキーは変えない。既存の alert の同一性に影響しないこと、
  他の SARIF の読み手には安定 ID が役立つことが理由。GitHub がこれを読まないことは §18.3 に書く。

## 検討した案

- rule ID を status で分ける (`semgrep/xxx#review`): status が変わると alert が閉じて別の alert が開く (R14 の再発)。
- rule に置いて閾値を `None` にする: Security タブの表示は得られるが、security result になった後も
  Alerts の閾値が level で効くかどうかが文書に無く、実測が要る。

## 結果

- Security タブに Critical / High の表示は出ない。重大度は `message` と `properties` と PR コメントで見る。
- alert の追跡は行の内容のハッシュによるので、行の中身が変わると別の alert になりうる。
