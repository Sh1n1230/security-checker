# 0007. メンテナが 1 人の間は、マージに承認を必須にしない

- 状態: 採用 (2026-10-19)
- 関連: Code Scanning の Scorecard アラート #30 (Branch-Protection)・#40 (Code-Review)

## 背景

OpenSSF Scorecard が次の 2 つを high で報告している。

- **Branch-Protection**: `main` の Ruleset (`protect main`) で、承認数・CODEOWNERS レビュー・
  stale review の取り消し・最後の push への承認が必須になっていない。
- **Code-Review**: 直近の変更に、作成者以外が承認したものが無い。

どちらも「作成者以外の人間がレビューして承認する」ことを求めている。しかし現在コラボレーターは
リポジトリオーナー 1 人で、GitHub は PR の作成者自身による承認を認めない。承認を必須にすると、
オーナーは自分の PR をマージできなくなる。

## 検討した選択肢

- **承認を必須にし、管理者を bypass actor に置く**: 実際には毎回 bypass でマージすることになり、
  「承認がある」ことを保証しない。Ruleset の見た目だけが厳しくなり、運用と食い違う。
  Code-Review は他者の承認が無い限り改善しない。
- **bot に承認させる**: 人間のレビューの代わりにならず、Scorecard の意図を偽ることになる。

## 決定

- メンテナが 1 人の間は、Ruleset で承認を必須にしない。
- 代わりに、マージの前に次を必須とする (Ruleset で強制済み)。
  - 必須ステータスチェック `security` (この action による自己検査) と、ブランチを最新にすること
  - `main` への force push と削除の禁止
- Scorecard の 2 アラートは、この ADR を理由に "won't fix" で閉じる。

## 結果

- Scorecard の Branch-Protection / Code-Review の点数は低いままになる。
- **2 人目のメンテナが加わったら見直す**。そのときは承認 1・CODEOWNERS レビュー・
  stale review の取り消し・最後の push への承認を Ruleset で必須にし、この ADR を置き換える。
