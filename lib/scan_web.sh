#!/usr/bin/env bash
# curl による稼働中Webサービスのヘッダー/HTTPS検査 → reports/web.json (正規化形式)
# 自分のサービスへの確認のみを想定。攻撃的スキャンは行わない。
set -uo pipefail

OUT="$REPORT_DIR/web.json"
findings="[]"

add_finding() { # severity message
  findings=$(jq -c --arg s "$1" --arg m "$2" --arg l "$URL" \
    '. + [{severity:$s, message:$m, location:$l}]' <<< "$findings")
}

headers=$(curl -sSL -D - -o /dev/null --max-time 15 "$URL" 2>/dev/null | tr -d '\r')
if [[ -z "$headers" ]]; then
  echo '{"category":"web","skipped":true,"findings":[]}' > "$OUT"
  echo "スキップ (URLに接続できませんでした)"
  exit 0
fi

# HTTPS 強制チェック
if [[ "$URL" == http://* ]]; then
  final_url=$(curl -sSL -o /dev/null -w '%{url_effective}' --max-time 15 "$URL" 2>/dev/null)
  [[ "$final_url" != https://* ]] && add_finding HIGH "HTTPSへリダイレクトされていません"
fi

has_header() { grep -qi "^$1:" <<< "$headers"; }

has_header "strict-transport-security" || add_finding MEDIUM "HSTSヘッダーがありません (Strict-Transport-Security)"
has_header "content-security-policy"   || add_finding MEDIUM "CSPヘッダーがありません (Content-Security-Policy)"
has_header "x-content-type-options"    || add_finding LOW    "X-Content-Type-Options: nosniff がありません"
if ! has_header "x-frame-options" && ! grep -qi "frame-ancestors" <<< "$headers"; then
  add_finding LOW "クリックジャッキング対策がありません (X-Frame-Options / frame-ancestors)"
fi
has_header "referrer-policy"           || add_finding LOW    "Referrer-Policyヘッダーがありません"

# サーバーバージョン漏洩
server=$(grep -i '^server:' <<< "$headers" | tail -1 | cut -d' ' -f2-)
if [[ "$server" =~ [0-9] ]]; then
  add_finding LOW "Serverヘッダーがバージョンを漏らしています: $server"
fi
if grep -qi '^x-powered-by:' <<< "$headers"; then
  add_finding LOW "X-Powered-Byヘッダーが技術情報を漏らしています"
fi

jq -n --argjson f "$findings" '{category:"web", skipped:false, findings:$f}' > "$OUT"
echo "検出: $(jq length <<< "$findings") 件"
