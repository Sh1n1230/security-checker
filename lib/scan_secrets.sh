#!/usr/bin/env bash
# gitleaks によるシークレット検出 → reports/secrets.json (正規化形式)
set -uo pipefail

OUT="$REPORT_DIR/secrets.json"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo '{"category":"secrets","skipped":true,"findings":[]}' > "$OUT"
  echo "スキップ (gitleaks 未インストール)"
  exit 0
fi

RAW="$REPORT_DIR/secrets_raw.json"
gitleaks detect --no-git --source "$TARGET" --report-format json --report-path "$RAW" --exit-code 0 >/dev/null 2>&1

# gitleaks は検出0件だと空 or [] を出す
if [[ ! -s "$RAW" ]]; then echo '[]' > "$RAW"; fi

jq '{
  category: "secrets",
  skipped: false,
  findings: [ .[] | {
    severity: "CRITICAL",
    message: ("シークレット検出: " + .RuleID),
    location: (.File + ":" + (.StartLine|tostring))
  } ]
}' "$RAW" > "$OUT"

count=$(jq '.findings | length' "$OUT")
echo "検出: ${count} 件"
