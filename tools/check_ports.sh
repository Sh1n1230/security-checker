#!/usr/bin/env bash
# 待ち受け中のポートとプロセスを棚卸しし、外部公開されているものを警告する。
# 使い方: ./check_ports.sh
set -uo pipefail

echo "=== 開いているポートの棚卸し ==="
echo ""

# LISTEN 中の TCP ソケット一覧
listening=$(lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | tail -n +2)

if [[ -z "$listening" ]]; then
  echo "待ち受け中のポートはありません"
  exit 0
fi

printf "%-20s %-8s %-25s %s\n" "プロセス" "PID" "待ち受けアドレス" "公開範囲"
echo "--------------------------------------------------------------------------"

external=0
while IFS= read -r line; do
  cmd=$(awk '{print $1}' <<< "$line")
  pid=$(awk '{print $2}' <<< "$line")
  addr=$(awk '{print $9}' <<< "$line")
  case "$addr" in
    127.0.0.1:*|\[::1\]:*|localhost:*)
      scope="ローカルのみ" ;;
    \*:*|0.0.0.0:*|\[::\]:*)
      scope="⚠️ 全インターフェース(外部から到達可能な可能性)"
      external=$((external+1)) ;;
    *)
      scope="特定アドレス" ;;
  esac
  printf "%-20s %-8s %-25s %s\n" "$cmd" "$pid" "$addr" "$scope"
done <<< "$listening"

echo ""
if [[ $external -gt 0 ]]; then
  echo "⚠️ 全インターフェースで待ち受け中のポートが ${external} 件あります。"
  echo "   開発サーバー等は 127.0.0.1 にバインドするか、不要なら停止してください。"
  echo "   (macOSのファイアウォールやルーターのNAT内なら直ちに危険とは限りません)"
  exit 1
else
  echo "✅ 外部に公開されているポートはありません(すべてローカル待ち受け)"
fi
