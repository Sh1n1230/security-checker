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
semgrep scan --config auto --json --quiet --metrics=off "$TARGET" > "$RAW" 2>/dev/null || true

if [[ ! -s "$RAW" ]]; then echo '{"results":[]}' > "$RAW"; fi

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
