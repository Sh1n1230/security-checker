#!/usr/bin/env bash
# macOS本体のセキュリティ設定を監査する。読み取り専用(設定は変更しない)。
# 使い方: ./audit_macos.sh
set -uo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
  echo "macOS 専用のためスキップします"
  exit 0
fi

pass=0; fail=0; warn=0

ok()   { echo "  ✅ $1"; pass=$((pass+1)); }
ng()   { echo "  ❌ $1"; echo "     → $2"; fail=$((fail+1)); }
warn() { echo "  ⚠️  $1"; echo "     → $2"; warn=$((warn+1)); }

echo "=== macOS セキュリティ監査 ==="
echo ""

# FileVault (ディスク暗号化)
if fdesetup status 2>/dev/null | grep -q "On"; then
  ok "FileVault(ディスク暗号化)が有効"
else
  ng "FileVaultが無効" "システム設定 > プライバシーとセキュリティ > FileVault で有効化(盗難時のデータ保護)"
fi

# ファイアウォール
if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled"; then
  ok "ファイアウォールが有効"
else
  ng "ファイアウォールが無効" "システム設定 > ネットワーク > ファイアウォール で有効化"
fi

# SIP (System Integrity Protection)
if csrutil status 2>/dev/null | grep -qi "enabled"; then
  ok "SIP(システム整合性保護)が有効"
else
  ng "SIPが無効" "リカバリモードで csrutil enable を実行(OS改ざん防止)"
fi

# Gatekeeper
if spctl --status 2>/dev/null | grep -q "enabled"; then
  ok "Gatekeeper(未署名アプリのブロック)が有効"
else
  ng "Gatekeeperが無効" "sudo spctl --master-enable で有効化"
fi

# 自動アップデート
if [[ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo 0)" == "1" ]]; then
  ok "ソフトウェアアップデートの自動確認が有効"
else
  warn "アップデートの自動確認が無効" "システム設定 > 一般 > ソフトウェアアップデート で有効化推奨"
fi

# スクリーンセーバー解除にパスワード要求
if [[ "$(sysadminctl -screenLock status 2>&1 | grep -c 'off')" == "0" ]]; then
  ok "スクリーンロックにパスワードが必要"
else
  warn "スクリーンロックのパスワード要求が無効の可能性" "システム設定 > ロック画面 で確認"
fi

# リモートログイン (SSH)
if systemsetup -getremotelogin 2>/dev/null | grep -qi "On"; then
  warn "リモートログイン(SSH)が有効" "不要なら システム設定 > 一般 > 共有 でオフに"
else
  ok "リモートログイン(SSH)は無効"
fi

# 共有サービス
sharing=$(launchctl list 2>/dev/null | grep -cE 'com.apple.(smbd|AppleFileServer|ScreensharingAgent)' || true)
if [[ "$sharing" -gt 0 ]]; then
  warn "ファイル共有/画面共有サービスが動作中" "不要なら システム設定 > 一般 > 共有 でオフに"
else
  ok "ファイル共有/画面共有は無効"
fi

echo ""
echo "結果: ✅ $pass  ❌ $fail  ⚠️ $warn"
[[ $fail -gt 0 ]] && exit 1 || exit 0
