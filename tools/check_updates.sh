#!/usr/bin/env bash
# OS・Homebrewパッケージの更新状況とバックアップ状態を検査する。
# 古いソフトウェアの放置は既知脆弱性の放置と同じ。
# 使い方: ./check_updates.sh
set -uo pipefail

issues=0
echo "=== 更新・バックアップ状態の検査 ==="

# macOS のアップデート
echo ""
echo "--- macOS ---"
updates=$(softwareupdate -l 2>&1)
if grep -q 'No new software available' <<< "$updates"; then
  echo "  ✅ OSは最新です"
else
  count=$(grep -c '^\* Label' <<< "$updates" || true)
  echo "  ⚠️  未適用のアップデートが ${count:-?} 件あります"
  grep '^\* Label' <<< "$updates" | sed 's/^\* Label: /       - /' | head -5
  echo "       → softwareupdate -i -a または システム設定から適用"
  issues=$((issues+1))
fi

# Homebrew
echo ""
echo "--- Homebrew ---"
if command -v brew >/dev/null 2>&1; then
  outdated=$(brew outdated --quiet 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$outdated" -eq 0 ]]; then
    echo "  ✅ brewパッケージは最新です"
  else
    echo "  ⚠️  古いパッケージが ${outdated} 個あります → brew upgrade"
    brew outdated --quiet 2>/dev/null | head -5 | sed 's/^/       - /'
    issues=$((issues+1))
  fi
else
  echo "  (Homebrew なし)"
fi

# Time Machine バックアップ
echo ""
echo "--- バックアップ (Time Machine) ---"
last_backup=$(tmutil latestbackup 2>/dev/null || true)
if [[ -n "$last_backup" ]]; then
  echo "  ✅ 最新バックアップ: $(basename "$last_backup")"
else
  echo "  ⚠️  Time Machine のバックアップが見つかりません"
  echo "       → ランサムウェア・故障対策としてバックアップ手段の確保を(Time Machine以外を使っているなら無視可)"
  issues=$((issues+1))
fi

echo ""
if [[ $issues -gt 0 ]]; then
  echo "結果: ⚠️ ${issues} 件の確認事項があります"
  exit 1
fi
echo "結果: ✅ 問題ありません"
