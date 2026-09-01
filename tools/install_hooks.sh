#!/usr/bin/env bash
# 対象リポジトリに security-checker の git フックを導入する。
#
# 導入されるもの (tools/hooks/ の実体をコピーする):
#   pre-commit … コミット前にステージ済みの変更をシークレット検査 (gitleaks)
#   pre-push   … 保護ブランチへの直接 push と force push を止める
#
# git のフックなので、人間の操作にも任意の AI エージェントの操作にも等しく効く。
# ただし --no-verify で外せるため最終防御ではない (docs/DESIGN.md §31.6)。
#
# 使い方: ./install_hooks.sh [gitリポジトリのパス]   (省略時は現在のリポジトリ)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/hooks"
MARKER="security-checker-hook:"
HOOKS=(pre-commit pre-push)

REPO="${1:-$(git rev-parse --show-toplevel 2>/dev/null || true)}"
if [[ -z "$REPO" ]]; then
  echo "エラー: gitリポジトリのパスを指定してください" >&2
  exit 2
fi

HOOK_DIR="$(git -C "$REPO" rev-parse --git-path hooks 2>/dev/null || true)"
if [[ -z "$HOOK_DIR" ]]; then
  echo "エラー: $REPO はgitリポジトリではありません" >&2
  exit 2
fi
# rev-parse --git-path はリポジトリからの相対パスを返すことがある
[[ "$HOOK_DIR" == /* ]] || HOOK_DIR="$REPO/$HOOK_DIR"
mkdir -p "$HOOK_DIR"

installed=0
skipped=0

for name in "${HOOKS[@]}"; do
  src="$SRC_DIR/$name"
  dst="$HOOK_DIR/$name"

  if [[ ! -f "$src" ]]; then
    echo "エラー: $src が見つかりません" >&2
    exit 2
  fi

  # 他人が置いたフックは絶対に上書きしない。自分が入れたものだけ更新する
  if [[ -e "$dst" ]] && ! grep -q "$MARKER" "$dst" 2>/dev/null; then
    echo "⏭️  $name: 既存のフックがあるため上書きしません ($dst)"
    echo "     手動で統合してください。参照元: $src"
    skipped=$((skipped + 1))
    continue
  fi

  cp "$src" "$dst"
  chmod +x "$dst"
  echo "✅ $name を導入しました"
  installed=$((installed + 1))
done

echo ""
echo "導入 ${installed} 件 / スキップ ${skipped} 件  → $HOOK_DIR"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "⚠️  gitleaks が未インストールのため pre-commit は簡易パターン検査で動作します (brew install gitleaks 推奨)"
fi

[[ "$skipped" -eq 0 ]] || exit 1
exit 0
