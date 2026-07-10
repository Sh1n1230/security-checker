#!/usr/bin/env bash
# security-checker: 汎用セキュリティ評価CLI
# 使い方: ./check.sh [対象ディレクトリ] [--url <URL>] [--min-score N] [--check-updates]
# --check-updates: 使用ツール(gitleaks/semgrep/osv-scanner/trivy)の最新版チェックを追加実行
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
REPORT_DIR="$SCRIPT_DIR/reports"

TARGET="."
URL=""
MIN_SCORE=""
CHECK_UPDATES=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) URL="$2"; shift 2 ;;
    --min-score) MIN_SCORE="$2"; shift 2 ;;
    --check-updates) CHECK_UPDATES=1; shift ;;
    -h|--help)
      sed -n '2,3p' "$0"; exit 0 ;;
    *) TARGET="$1"; shift ;;
  esac
done

TARGET="$(cd "$TARGET" 2>/dev/null && pwd)" || { echo "エラー: 対象ディレクトリが見つかりません" >&2; exit 2; }
mkdir -p "$REPORT_DIR"
rm -f "$REPORT_DIR"/*.json

echo "=== security-checker ==="
echo "対象: $TARGET"
[[ -n "$URL" ]] && echo "URL : $URL"
echo ""

# --- 必須ツールチェック ---
if ! command -v jq >/dev/null 2>&1; then
  echo "エラー: jq が必要です。 brew install jq" >&2
  exit 2
fi

missing=()
for tool in gitleaks semgrep osv-scanner trivy; do
  command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  echo "注意: 次のツールが未インストールのため該当カテゴリはスキップされます:"
  for t in "${missing[@]}"; do echo "  - $t  (brew install $t)"; done
  echo ""
fi

export TARGET REPORT_DIR

run_scan() {
  local name="$1" script="$2"
  echo "--- $name ---"
  bash "$LIB_DIR/$script"
  echo ""
}

run_scan "シークレット検出 (gitleaks)"   scan_secrets.sh
run_scan "コード静的解析 (semgrep)"      scan_code.sh
run_scan "依存パッケージCVE (osv-scanner)" scan_deps.sh
run_scan "設定ファイル検査 (trivy)"      scan_config.sh
if [[ -n "$URL" ]]; then
  export URL
  run_scan "Webサービス検査 (curl)" scan_web.sh
fi

if [[ "$CHECK_UPDATES" -eq 1 ]]; then
  echo "--- ツール更新チェック ---"
  bash "$LIB_DIR/check_tool_updates.sh"
  echo ""
fi

# --- スコア集計 ---
bash "$LIB_DIR/score.sh"
score=$(jq -r '.total_score' "$REPORT_DIR/summary.json")

if [[ -n "$MIN_SCORE" ]]; then
  if [[ "$score" -lt "$MIN_SCORE" ]]; then
    echo "NG: スコア $score は基準値 $MIN_SCORE 未満です"
    exit 1
  fi
  echo "OK: スコア $score は基準値 $MIN_SCORE 以上です"
fi
