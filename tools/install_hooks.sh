#!/usr/bin/env bash
# 対象リポジトリに pre-commit フックを導入し、コミット前にシークレット検査を自動実行する。
# 使い方: ./install_hooks.sh <gitリポジトリのパス>
set -uo pipefail

REPO="${1:?使い方: ./install_hooks.sh <gitリポジトリのパス>}"
HOOK_DIR="$REPO/.git/hooks"

if [[ ! -d "$HOOK_DIR" ]]; then
  echo "エラー: $REPO はgitリポジトリではありません" >&2
  exit 2
fi

HOOK="$HOOK_DIR/pre-commit"
if [[ -f "$HOOK" ]]; then
  echo "既存の pre-commit フックがあります: $HOOK"
  echo "上書きせず終了します。手動で統合してください。"
  exit 1
fi

cat > "$HOOK" <<'EOF'
#!/usr/bin/env bash
# security-checker が導入したフック: コミット前にステージ済みの変更をシークレット検査
set -uo pipefail

if command -v gitleaks >/dev/null 2>&1; then
  if ! gitleaks protect --staged --exit-code 1 >/dev/null 2>&1; then
    echo "❌ コミットにシークレットが含まれている可能性があります (gitleaks)"
    echo "   詳細: gitleaks protect --staged --verbose"
    echo "   誤検知なら: git commit --no-verify"
    exit 1
  fi
else
  # gitleaks が無い場合の簡易パターン検査
  if git diff --cached -U0 | grep -E '^\+' | grep -qE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[bp]-[0-9A-Za-z-]{20,}|-----BEGIN .*PRIVATE KEY'; then
    echo "❌ コミットにシークレットらしき文字列が含まれています"
    echo "   誤検知なら: git commit --no-verify"
    exit 1
  fi
fi
exit 0
EOF
chmod +x "$HOOK"

echo "✅ pre-commit フックを導入しました: $HOOK"
if command -v gitleaks >/dev/null 2>&1; then
  echo "   gitleaks によるシークレット検査がコミット毎に走ります"
else
  echo "   ⚠️ gitleaks が未インストールのため簡易パターン検査で動作します (brew install gitleaks 推奨)"
fi
