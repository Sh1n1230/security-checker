# スキャナの版と sha256 の唯一の置き場所。action.yml・自リポジトリの workflow・Dockerfile は
# すべて scripts/install-scanners.sh 経由でここを読む (版が経路ごとに食い違わないようにする)。
#
# sha256 はリリースから取らずにここへ書く。同じリリースのチェックサムファイルは、
# リリースごと差し替えられた場合に役に立たないため (2026-03 の trivy v0.69.4 と同じ経路)。
#
# 更新の手順:
#   1. 公開から 7 日以上経った版を選ぶ (Dependabot の cooldown と同じ考え方)
#   2. 公式のチェックサムファイルの値と、実際にダウンロードしたファイルの sha256 が一致することを確かめる
#   3. 版と amd64 / arm64 の sha256 をそろえて書き換える
#      (tests/unit/test_scanner_versions.py が形式と参照のずれを検査する)
#
# このファイルは bash から source する。代入以外を書かない。

PINNED_GITLEAKS_VERSION=8.30.1
GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb # gitleaks_8.30.1_linux_x64.tar.gz
GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 # gitleaks_8.30.1_linux_arm64.tar.gz

PINNED_TRIVY_VERSION=0.75.0
TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f # trivy_0.75.0_Linux-64bit.tar.gz
TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3 # trivy_0.75.0_Linux-ARM64.tar.gz

PINNED_OSV_SCANNER_VERSION=2.6.0
OSV_SCANNER_SHA256_AMD64=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108 # osv-scanner_linux_amd64
OSV_SCANNER_SHA256_ARM64=2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4 # osv-scanner_linux_arm64

# PyPI は同じ版のファイルを差し替えられないため、版の固定で「新しい悪性の版」を避けられる
PINNED_SEMGREP_VERSION=1.179.0
