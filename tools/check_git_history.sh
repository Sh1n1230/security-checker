#!/usr/bin/env bash
# gitリポジトリの「全履歴」からシークレット漏洩を検査する。
# 現在のファイルから消していても、過去のコミットに残っていれば検出する。
# 使い方: ./check_git_history.sh <gitリポジトリのパス>
set -uo pipefail

REPO="${1:?使い方: ./check_git_history.sh <gitリポジトリのパス>}"

if [[ ! -d "$REPO/.git" ]]; then
  echo "エラー: $REPO はgitリポジトリではありません" >&2
  exit 2
fi

echo "=== git履歴のシークレット検査: $REPO ==="

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "エラー: gitleaks が必要です。 brew install gitleaks" >&2
  exit 2
fi

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

# --no-git を付けない = コミット履歴全体を走査する
gitleaks detect --source "$REPO" --report-format json --report-path "$TMP" --exit-code 0 >/dev/null 2>&1
[[ -s "$TMP" ]] || echo '[]' > "$TMP"

count=$(jq 'length' "$TMP")
if [[ "$count" -eq 0 ]]; then
  echo "✅ 履歴からシークレットは見つかりませんでした"
  exit 0
fi

echo "❌ 履歴に ${count} 件のシークレットが見つかりました:"
jq -r '.[] | "  - \(.RuleID)  \(.File):\(.StartLine)  (commit \(.Commit[0:8]))"' "$TMP" | sort -u | head -20
echo ""
echo "対処:"
echo "  1. 該当のキー/トークンを直ちに無効化・再発行する(履歴を消しても漏れた事実は消えない)"
echo "  2. 公開リポジトリなら履歴の書き換えも検討: git filter-repo または BFG Repo-Cleaner"
exit 1
