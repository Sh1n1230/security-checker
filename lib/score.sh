#!/usr/bin/env bash
# 各スキャン結果を集計し100点満点のスコアを算出 → reports/summary.json
# 減点: CRITICAL -20 / HIGH -10 / MEDIUM -3 / LOW -1 (カテゴリ毎の減点上限 40)
set -uo pipefail

SUMMARY="$REPORT_DIR/summary.json"

jq -s '
  def penalty: {CRITICAL: 20, HIGH: 10, MEDIUM: 3, LOW: 1};
  def cap: 40;
  map(select(.category != null)) |
  map(. as $c | {
    category: $c.category,
    skipped: $c.skipped,
    counts: ($c.findings | group_by(.severity) | map({(.[0].severity): length}) | add // {}),
    findings: $c.findings,
    deduction: (if $c.skipped then 0 else
      ([$c.findings[] | penalty[.severity] // 1] | add // 0 | if . > cap then cap else . end)
    end)
  }) as $cats |
  (100 - ($cats | map(.deduction) | add // 0)) as $raw |
  (if $raw < 0 then 0 else $raw end) as $score |
  {
    total_score: $score,
    rank: (if $score >= 90 then "A" elif $score >= 70 then "B" elif $score >= 50 then "C" else "D" end),
    categories: $cats
  }
' "$REPORT_DIR"/secrets.json "$REPORT_DIR"/code.json "$REPORT_DIR"/deps.json "$REPORT_DIR"/config.json \
  $( [[ -f "$REPORT_DIR/web.json" ]] && echo "$REPORT_DIR/web.json" ) > "$SUMMARY"

# --- ターミナル表示 ---
name_ja() {
  case "$1" in
    secrets) echo "シークレット" ;;
    code)    echo "コード解析  " ;;
    deps)    echo "依存CVE     " ;;
    config)  echo "設定ファイル" ;;
    web)     echo "Web検査     " ;;
  esac
}

echo "==================== 結果 ===================="
printf "%-14s %5s %5s %5s %5s   %s\n" "カテゴリ" "Crit" "High" "Med" "Low" "減点"
echo "----------------------------------------------"
for cat in $(jq -r '.categories[].category' "$SUMMARY"); do
  row=$(jq -r --arg c "$cat" '.categories[] | select(.category==$c)' "$SUMMARY")
  if [[ $(jq -r '.skipped' <<< "$row") == "true" ]]; then
    printf "%-14s %s\n" "$(name_ja "$cat")" "(スキップ)"
  else
    printf "%-14s %5s %5s %5s %5s   -%s\n" "$(name_ja "$cat")" \
      "$(jq -r '.counts.CRITICAL // 0' <<< "$row")" \
      "$(jq -r '.counts.HIGH // 0' <<< "$row")" \
      "$(jq -r '.counts.MEDIUM // 0' <<< "$row")" \
      "$(jq -r '.counts.LOW // 0' <<< "$row")" \
      "$(jq -r '.deduction' <<< "$row")"
  fi
done
echo "----------------------------------------------"
score=$(jq -r '.total_score' "$SUMMARY")
rank=$(jq -r '.rank' "$SUMMARY")
echo "総合スコア: ${score} / 100   ランク: ${rank}"
echo "詳細: $SUMMARY"
echo "=============================================="
