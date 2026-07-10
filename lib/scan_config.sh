#!/usr/bin/env bash
# trivy による設定ファイル(Dockerfile, CI, IaC等)検査 → reports/config.json (正規化形式)
set -uo pipefail

OUT="$REPORT_DIR/config.json"

if ! command -v trivy >/dev/null 2>&1; then
  echo '{"category":"config","skipped":true,"findings":[]}' > "$OUT"
  echo "スキップ (trivy 未インストール)"
  exit 0
fi

RAW="$REPORT_DIR/config_raw.json"
trivy fs --scanners misconfig --format json --quiet "$TARGET" > "$RAW" 2>/dev/null || true

if ! jq -e '.Results' "$RAW" >/dev/null 2>&1; then echo '{"Results":[]}' > "$RAW"; fi

jq '{
  category: "config",
  skipped: false,
  findings: [ (.Results // [])[] | .Target as $t | .Misconfigurations[]? | {
    severity: (.Severity // "LOW"),
    message: (.ID + ": " + .Title),
    location: $t
  } ]
}' "$RAW" > "$OUT"

count=$(jq '.findings | length' "$OUT")
echo "検出: ${count} 件"
