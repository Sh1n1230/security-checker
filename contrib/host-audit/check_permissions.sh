#!/usr/bin/env bash
# 危険なファイル権限を検査する。
# 使い方: ./check_permissions.sh [対象ディレクトリ]   (省略時はホームの重要箇所のみ)
set -uo pipefail

TARGET="${1:-}"
issues=0

section() { echo ""; echo "--- $1 ---"; }
report() { echo "  ❌ $1"; issues=$((issues+1)); }

# GNU/BSD 両対応のファイル権限取得
file_perm() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

echo "=== ファイル権限検査 ==="

# ~/.ssh の権限 (秘密鍵は 600、ディレクトリは 700 が原則)
section "~/.ssh"
if [[ -d "$HOME/.ssh" ]]; then
  perm=$(file_perm "$HOME/.ssh")
  [[ "$perm" != "700" ]] && report "~/.ssh の権限が $perm (700 にすべき): chmod 700 ~/.ssh"
  while IFS= read -r key; do
    kperm=$(file_perm "$key")
    if [[ "$kperm" != "600" && "$kperm" != "400" ]]; then
      report "秘密鍵 $key の権限が $kperm (600 にすべき): chmod 600 '$key'"
    fi
  done < <(grep -rlE 'BEGIN .*PRIVATE KEY' "$HOME/.ssh" 2>/dev/null)
  [[ $issues -eq 0 ]] && echo "  ✅ 問題なし"
else
  echo "  (~/.ssh なし)"
fi

# 認証情報系ファイルの権限
section "認証情報ファイル"
found=0
for f in "$HOME/.aws/credentials" "$HOME/.netrc" "$HOME/.npmrc" "$HOME/.pgpass" "$HOME/.docker/config.json"; do
  [[ -f "$f" ]] || continue
  found=1
  perm=$(file_perm "$f")
  if [[ "$perm" =~ [1-7]$ || "$perm" =~ [1-7].$ ]]; then
    report "$f が他ユーザーから読める権限 $perm: chmod 600 '$f'"
  else
    echo "  ✅ $f ($perm)"
  fi
done
[[ $found -eq 0 ]] && echo "  (該当ファイルなし)"

# 対象ディレクトリの world-writable / 見落としがちな秘密ファイル
if [[ -n "$TARGET" ]]; then
  section "$TARGET 内の検査"
  while IFS= read -r f; do
    report "誰でも書き込めるファイル: $f  → chmod o-w '$f'"
  done < <(find "$TARGET" -type f -perm -o+w -not -path '*/.git/*' 2>/dev/null | head -20)

  while IFS= read -r f; do
    echo "  ⚠️  秘密情報の可能性: $f (コミット対象になっていないか確認)"
  done < <(find "$TARGET" \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' \) -not -path '*/.git/*' -not -name '*.example' 2>/dev/null | head -20)
fi

echo ""
if [[ $issues -gt 0 ]]; then
  echo "結果: ❌ ${issues} 件の権限問題があります"
  exit 1
else
  echo "結果: ✅ 権限の問題は見つかりませんでした"
fi
