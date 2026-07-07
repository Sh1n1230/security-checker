#!/usr/bin/env bash
# シェル履歴・dotfiles・環境変数にシークレットが漏れていないか検査する。読み取り専用。
# 使い方: ./check_shell_env.sh
set -uo pipefail

issues=0
# よくあるシークレットのパターン(トークン形式 + 「変数名=値」形式のコマンドライン直書き)
PATTERN='AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[bp]-[0-9A-Za-z-]{20,}|sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY|(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN)=[^ $]{8,}'

echo "=== シェル履歴・環境のシークレット検査 ==="

section() { echo ""; echo "--- $1 ---"; }

# シェル履歴
section "シェル履歴"
found=0
for h in "$HOME/.zsh_history" "$HOME/.bash_history"; do
  [[ -f "$h" ]] || continue
  hits=$(grep -acE "$PATTERN" "$h" 2>/dev/null || true)
  if [[ "${hits:-0}" -gt 0 ]]; then
    echo "  ❌ $h に ${hits} 行のシークレットらしき記録"
    grep -aE "$PATTERN" "$h" 2>/dev/null | head -3 | sed -E 's/^: [0-9]+:[0-9]+;//; s/(.{60}).*/\1.../; s/^/       例: /'
    echo "       → 該当行を削除するか履歴をクリア。コマンドラインに直接秘密を書かない"
    issues=$((issues+1)); found=1
  fi
done
[[ $found -eq 0 ]] && echo "  ✅ 問題なし"

# dotfiles (エクスポートの直書き)
section "dotfiles (~/.zshrc 等)"
found=0
for f in "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.zshenv" "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile"; do
  [[ -f "$f" ]] || continue
  hits=$(grep -acE "$PATTERN" "$f" 2>/dev/null || true)
  if [[ "${hits:-0}" -gt 0 ]]; then
    echo "  ⚠️  $f にシークレットらしき記述が ${hits} 行"
    echo "       → 直書きせず、direnv や macOS キーチェーン (security add-generic-password) の利用を検討"
    issues=$((issues+1)); found=1
  fi
done
[[ $found -eq 0 ]] && echo "  ✅ 問題なし"

# 現在の環境変数 (値そのものは表示しない)
section "現在の環境変数"
found=0
while IFS= read -r name; do
  echo "  ⚠️  環境変数 $name が設定されています(必要なものか確認。値は表示していません)"
  found=1
done < <(env | grep -oE '^[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|API_KEY)[A-Z0-9_]*' | sort -u | head -10)
[[ $found -eq 0 ]] && echo "  ✅ シークレットらしき環境変数はありません"

echo ""
if [[ $issues -gt 0 ]]; then
  echo "結果: ❌ ${issues} 件の問題があります"
  exit 1
fi
echo "結果: ✅ 問題は見つかりませんでした"
