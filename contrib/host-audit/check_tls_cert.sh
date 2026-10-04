#!/usr/bin/env bash
# 自分のサイトのTLS証明書の有効期限と設定を検査する。
# 使い方: ./check_tls_cert.sh <ドメイン> [しきい値日数(既定30)]
set -uo pipefail

DOMAIN="${1:?使い方: ./check_tls_cert.sh <ドメイン> [しきい値日数]}"
THRESHOLD_DAYS="${2:-30}"
DOMAIN="${DOMAIN#https://}"; DOMAIN="${DOMAIN%%/*}"

echo "=== TLS証明書検査: $DOMAIN ==="

cert=$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -enddate -subject -issuer 2>/dev/null)
if [[ -z "$cert" ]]; then
  echo "❌ 証明書を取得できませんでした($DOMAIN:443 に接続不可、または証明書なし)"
  exit 2
fi

end_date=$(grep '^notAfter=' <<< "$cert" | cut -d= -f2-)
if [[ "$(uname)" == "Darwin" ]]; then
  end_epoch=$(date -j -f '%b %e %T %Y %Z' "$end_date" +%s 2>/dev/null)
else
  end_epoch=$(date -d "$end_date" +%s 2>/dev/null)
fi
now_epoch=$(date +%s)
days_left=$(( (end_epoch - now_epoch) / 86400 ))

echo "発行先 : $(grep '^subject=' <<< "$cert" | cut -d= -f2-)"
echo "発行者 : $(grep '^issuer=' <<< "$cert" | sed 's/^issuer=//' | head -c 80)"
echo "期限   : $end_date (残り ${days_left} 日)"

status=0
if [[ $days_left -lt 0 ]]; then
  echo "❌ 証明書が期限切れです。直ちに更新してください"
  status=1
elif [[ $days_left -lt $THRESHOLD_DAYS ]]; then
  echo "⚠️  期限まで ${THRESHOLD_DAYS} 日を切っています。更新の準備を"
  status=1
else
  echo "✅ 期限に問題ありません"
fi

# 古いTLSバージョンの受け入れチェック
for ver in tls1 tls1_1; do
  if echo | openssl s_client -"$ver" -connect "$DOMAIN:443" 2>/dev/null | grep -q 'BEGIN CERTIFICATE'; then
    echo "❌ 古いプロトコル ${ver/tls/TLS } を受け付けています。サーバー設定で無効化を"
    status=1
  fi
done
[[ $status -eq 0 ]] && echo "✅ 古いTLS(1.0/1.1)は無効です"

exit $status
