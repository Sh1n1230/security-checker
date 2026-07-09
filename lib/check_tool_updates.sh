#!/usr/bin/env bash
# 使用ツール(gitleaks / semgrep / osv-scanner / trivy)のセルフアップデートチェック
# インストール済みバージョンと最新版(GitHub Releases / PyPI)を比較し、警告のみ表示する。
# スコアには影響しない。単体実行も可能。
set -uo pipefail

check_tool() {
  local name="$1" version_cmd="$2" installed="$3" latest="$4" upgrade_hint="$5"

  if [[ -z "$installed" ]]; then
    echo "  - ${name}: 未インストール"
    return 0
  fi

  if [[ -z "$latest" ]]; then
    echo "  - ${name} ${installed}: 最新版を確認できませんでした(オフラインまたはAPI制限)"
    return 0
  fi

  local top
  top="$(printf '%s\n%s\n' "$installed" "$latest" | sort -V | tail -n1)"
  if [[ "$top" == "$installed" ]]; then
    echo "  - ✅ ${name} ${installed}(最新)"
  else
    echo "  - ⚠️ ${name} ${installed} → 最新 ${latest}(更新推奨: ${upgrade_hint})"
  fi
}

fetch_github_latest() {
  # $1: owner/repo
  local repo="$1" json tag
  json="$(curl -sL --max-time 5 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null)" || return 1
  [[ -z "$json" ]] && return 1
  if command -v jq >/dev/null 2>&1; then
    tag="$(printf '%s' "$json" | jq -r '.tag_name // empty' 2>/dev/null)"
  else
    tag="$(printf '%s' "$json" | grep -o '"tag_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')"
  fi
  [[ -z "$tag" || "$tag" == "null" ]] && return 1
  printf '%s' "${tag#v}"
}

fetch_pypi_latest() {
  # $1: package name
  local pkg="$1" json ver
  json="$(curl -sL --max-time 5 "https://pypi.org/pypi/${pkg}/json" 2>/dev/null)" || return 1
  [[ -z "$json" ]] && return 1
  if command -v jq >/dev/null 2>&1; then
    ver="$(printf '%s' "$json" | jq -r '.info.version // empty' 2>/dev/null)"
  else
    ver="$(printf '%s' "$json" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')"
  fi
  [[ -z "$ver" || "$ver" == "null" ]] && return 1
  printf '%s' "$ver"
}

echo "使用ツールのバージョンを確認しています..."

# --- gitleaks ---
if command -v gitleaks >/dev/null 2>&1; then
  gl_installed="$(gitleaks version 2>/dev/null | tr -d '[:space:]')"
else
  gl_installed=""
fi
gl_latest=""
[[ -n "$gl_installed" ]] && gl_latest="$(fetch_github_latest gitleaks/gitleaks || true)"
check_tool "gitleaks" "gitleaks version" "$gl_installed" "$gl_latest" "brew upgrade gitleaks"

# --- semgrep ---
if command -v semgrep >/dev/null 2>&1; then
  sg_installed="$(semgrep --version 2>/dev/null | tr -d '[:space:]')"
else
  sg_installed=""
fi
sg_latest=""
[[ -n "$sg_installed" ]] && sg_latest="$(fetch_pypi_latest semgrep || true)"
check_tool "semgrep" "semgrep --version" "$sg_installed" "$sg_latest" "pip install -U semgrep"

# --- osv-scanner ---
if command -v osv-scanner >/dev/null 2>&1; then
  ov_installed="$(osv-scanner --version 2>/dev/null | head -n1 | sed -E 's/^osv-scanner version:[[:space:]]*//' | tr -d '[:space:]')"
else
  ov_installed=""
fi
ov_latest=""
[[ -n "$ov_installed" ]] && ov_latest="$(fetch_github_latest google/osv-scanner || true)"
check_tool "osv-scanner" "osv-scanner --version" "$ov_installed" "$ov_latest" "brew upgrade osv-scanner"

# --- trivy ---
if command -v trivy >/dev/null 2>&1; then
  tv_installed="$(trivy --version 2>/dev/null | head -n1 | sed -E 's/^Version:[[:space:]]*//' | tr -d '[:space:]')"
else
  tv_installed=""
fi
tv_latest=""
[[ -n "$tv_installed" ]] && tv_latest="$(fetch_github_latest aquasecurity/trivy || true)"
check_tool "trivy" "trivy --version" "$tv_installed" "$tv_latest" "brew upgrade trivy"

exit 0
