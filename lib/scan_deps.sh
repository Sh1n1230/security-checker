#!/usr/bin/env bash
# osv-scanner による依存パッケージCVE検査 → reports/deps.json (正規化形式)
set -uo pipefail

OUT="$REPORT_DIR/deps.json"

if ! command -v osv-scanner >/dev/null 2>&1; then
  echo '{"category":"deps","skipped":true,"findings":[]}' > "$OUT"
  echo "スキップ (osv-scanner 未インストール)"
  exit 0
fi

RAW="$REPORT_DIR/deps_raw.json"
osv-scanner scan --recursive --format json "$TARGET" > "$RAW" 2>/dev/null || true

if ! jq -e '.results' "$RAW" >/dev/null 2>&1; then echo '{"results":[]}' > "$RAW"; fi

jq '{
  category: "deps",
  skipped: false,
  findings: [ (.results // [])[] | .packages[]? as $p | $p.vulnerabilities[]? | {
    severity: (
      ((.database_specific.severity // "MODERATE") | ascii_upcase) as $s |
      if $s == "CRITICAL" then "CRITICAL"
      elif $s == "HIGH" then "HIGH"
      elif $s == "MODERATE" or $s == "MEDIUM" then "MEDIUM"
      else "LOW" end),
    message: (($p.package.name // "?") + ": " + .id),
    location: (($p.package.name // "?") + "@" + ($p.package.version // "?"))
  } ]
}' "$RAW" > "$OUT"

count=$(jq '.findings | length' "$OUT")
echo "検出: ${count} 件"
