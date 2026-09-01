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

# gitleaks 8.19+ は `dir`。`detect --no-git --source` は非推奨で --help からも消えている
if gitleaks dir --help >/dev/null 2>&1; then
  scan=(gitleaks dir "$TARGET")
else
  scan=(gitleaks detect --no-git --source "$TARGET")
fi

# --exit-code 0 により「検出あり」でも 0 が返る。したがって非 0 は実行失敗を意味する。
# ここを握りつぶすと「検査できていない」が「0 件」に化けるため、必ず区別する。
if ! "${scan[@]}" --report-format json --report-path "$RAW" --exit-code 0 >/dev/null 2>&1; then
  echo '{"category":"secrets","skipped":true,"findings":[]}' > "$OUT"
  echo "エラー: gitleaks の実行に失敗しました (シークレット検査は行われていません)"
  exit 1
fi

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
