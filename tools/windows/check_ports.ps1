<#
  待ち受け中のTCPポートとプロセスを棚卸しし、外部公開されているものを警告する。読み取り専用。
  使い方: pwsh -File ./check_ports.ps1
#>

Write-Host "=== 開いているポートの棚卸し ==="
Write-Host ""

try {
    $listening = Get-NetTCPConnection -State Listen -ErrorAction Stop
} catch {
    Write-Host "Get-NetTCPConnection が利用できないためスキップします"
    exit 0
}

if (-not $listening -or $listening.Count -eq 0) {
    Write-Host "待ち受け中のポートはありません"
    exit 0
}

"{0,-20} {1,-8} {2,-30} {3}" -f "プロセス", "PID", "待ち受けアドレス", "公開範囲" | Write-Host
Write-Host ("-" * 90)

$external = 0
$rows = $listening | Sort-Object LocalPort

foreach ($conn in $rows) {
    $procName = "?"
    try {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
        $procName = $proc.ProcessName
    } catch { }

    $addr = "$($conn.LocalAddress):$($conn.LocalPort)"

    switch -Regex ($conn.LocalAddress) {
        '^(127\.0\.0\.1|::1)$' {
            $scope = "ローカルのみ"
        }
        '^(0\.0\.0\.0|::)$' {
            $scope = "⚠️ 全インターフェース(外部から到達可能な可能性)"
            $external++
        }
        default {
            $scope = "特定アドレス"
        }
    }

    "{0,-20} {1,-8} {2,-30} {3}" -f $procName, $conn.OwningProcess, $addr, $scope | Write-Host
}

Write-Host ""
if ($external -gt 0) {
    Write-Host "⚠️ 全インターフェースで待ち受け中のポートが ${external} 件あります。"
    Write-Host "   開発サーバー等は 127.0.0.1 にバインドするか、不要なら停止してください。"
    Write-Host "   (Windowsファイアウォールやルーターの NAT 内なら直ちに危険とは限りません)"
    exit 1
} else {
    Write-Host "✅ 外部に公開されているポートはありません(すべてローカル待ち受け)"
    exit 0
}
