#!/usr/bin/env bash
# CI (Linux x86_64) 用に、スキャナを固定したバージョンで <インストール先> に入れる。
#
#   scripts/install-scanners.sh <インストール先ディレクトリ>
#
# action.yml と自リポジトリのワークフローから呼ぶ。
#
# 「最新版」を取りに行かない。スキャナのリリースが乗っ取られると、悪性のバイナリが
# 次の CI でそのまま動いてしまうため (2026-03 の trivy v0.69.4 と同じ経路)。
# チェックサムもリリースから取らずにここへ書く。同じリリースのチェックサムは、
# リリースごと差し替えられた場合に役に立たない。
#
# 更新するときは、公開から 7 日以上経った版を選び (Dependabot の cooldown と同じ考え方)、
# 公式のチェックサムファイルの値と、ダウンロードしたファイルの sha256 が一致することを確かめてから書き換える。
set -euo pipefail

GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb # gitleaks_8.30.1_linux_x64.tar.gz
TRIVY_VERSION=0.75.0
TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f # trivy_0.75.0_Linux-64bit.tar.gz
OSV_SCANNER_VERSION=2.6.0
OSV_SCANNER_SHA256=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 # osv-scanner_linux_amd64
# PyPI は同じ版のファイルを差し替えられないため、版の固定で「新しい悪性の版」を避けられる
SEMGREP_VERSION=1.179.0

if [[ $# -ne 1 ]]; then
  echo "使い方: $0 <インストール先ディレクトリ>" >&2
  exit 2
fi
bin_dir=$1
mkdir -p "$bin_dir"
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

# download <URL> <保存先> <sha256>: 取得し、固定した sha256 と一致しなければ失敗する
download() {
  curl -fsSL -o "$2" "$1"
  echo "$3  $2" | sha256sum -c --quiet -
}

download "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
  "$work_dir/gitleaks.tar.gz" "$GITLEAKS_SHA256"
tar xzf "$work_dir/gitleaks.tar.gz" -C "$bin_dir" gitleaks

download "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
  "$work_dir/trivy.tar.gz" "$TRIVY_SHA256"
tar xzf "$work_dir/trivy.tar.gz" -C "$bin_dir" trivy

download "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
  "$work_dir/osv-scanner" "$OSV_SCANNER_SHA256"
install -m 0755 "$work_dir/osv-scanner" "$bin_dir/osv-scanner"

uv tool install --quiet "semgrep==${SEMGREP_VERSION}"

# `| head` で切り詰めない。head が先にパイプを閉じると SIGPIPE になり、pipefail で失敗するため
"$bin_dir/gitleaks" version
"$bin_dir/trivy" --version
"$bin_dir/osv-scanner" --version
