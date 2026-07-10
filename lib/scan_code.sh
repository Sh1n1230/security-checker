#!/usr/bin/env bash
# semgrep によるコード静的解析 → reports/code.json (正規化形式)
set -uo pipefail

OUT="$REPORT_DIR/code.json"

if ! command -v semgrep >/dev/null 2>&1; then
  echo '{"category":"code","skipped":true,"findings":[]}' > "$OUT"
  echo "スキップ (semgrep 未インストール)"
  exit 0
fi

RAW="$REPORT_DIR/code_raw.json"
# --config auto は --metrics=off と併用不可のため、明示的にルールセットを指定する
if ! semgrep scan --config p/default --json --quiet --metrics=off "$TARGET" > "$RAW" 2> "$REPORT_DIR/code_err.log"; then
  echo "エラー: semgrep の実行に失敗 ($REPORT_DIR/code_err.log を確認)"
  echo '{"category":"code","skipped":true,"findings":[]}' > "$OUT"
  exit 1
fi

jq '{
  category: "code",
  skipped: false,
  findings: [ .results[] | {
    severity: (if .extra.severity == "ERROR" then "HIGH"
               elif .extra.severity == "WARNING" then "MEDIUM"
               else "LOW" end),
    message: (.check_id | split(".") | last),
    location: (.path + ":" + (.start.line|tostring))
  } ]
}' "$RAW" > "$OUT"

count=$(jq '.findings | length' "$OUT")
echo "検出: ${count} 件"
