<#
  自分のサイトのTLS証明書の有効期限と設定を検査する。読み取り専用。
  使い方: pwsh -File ./check_tls_cert.ps1 -Domain example.com [-ThresholdDays 30]
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Domain,
    [int]$ThresholdDays = 30
)

$Domain = $Domain -replace '^https://', ''
$Domain = ($Domain -split '/')[0]

Write-Host "=== TLS証明書検査: $Domain ==="

function Get-RemoteCertificate {
    param([string]$Host_, [int]$Port = 443, [System.Security.Authentication.SslProtocols]$Protocol = [System.Security.Authentication.SslProtocols]::None)

    $tcp = $null
    $ssl = $null
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcp.ConnectAsync($Host_, $Port)
        if (-not $connectTask.Wait(8000)) {
            throw "接続タイムアウト"
        }
        $ssl = New-Object System.Net.Security.SslStream(
            $tcp.GetStream(), $false,
            ([System.Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$ch,$e) $true })
        )
        if ($Protocol -eq [System.Security.Authentication.SslProtocols]::None) {
            $ssl.AuthenticateAsClient($Host_)
        } else {
            $ssl.AuthenticateAsClient($Host_, $null, $Protocol, $false)
        }
        $cert = $ssl.RemoteCertificate
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
    } finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Dispose() }
    }
}

$cert = $null
try {
    $cert = Get-RemoteCertificate -Host_ $Domain -Port 443
} catch {
    Write-Host "❌ 証明書を取得できませんでした($($Domain):443 に接続不可、または証明書なし)"
    Write-Host "   詳細: $($_.Exception.Message)"
    exit 2
}

if (-not $cert) {
    Write-Host "❌ 証明書を取得できませんでした($($Domain):443 に接続不可、または証明書なし)"
    exit 2
}

$endDate = $cert.NotAfter
$daysLeft = [int](($endDate - (Get-Date)).TotalDays)

Write-Host "発行先 : $($cert.Subject)"
Write-Host "発行者 : $($cert.Issuer)"
Write-Host "期限   : $($endDate.ToString('yyyy-MM-dd HH:mm:ss')) (残り ${daysLeft} 日)"

$status = 0
if ($daysLeft -lt 0) {
    Write-Host "❌ 証明書が期限切れです。直ちに更新してください"
    $status = 1
} elseif ($daysLeft -lt $ThresholdDays) {
    Write-Host "⚠️  期限まで ${ThresholdDays} 日を切っています。更新の準備を"
    $status = 1
} else {
    Write-Host "✅ 期限に問題ありません"
}

# 古いTLSバージョンの受け入れチェック
$oldProtocols = @{
    'TLS 1.0' = [System.Security.Authentication.SslProtocols]::Tls
    'TLS 1.1' = [System.Security.Authentication.SslProtocols]::Tls11
}
$oldFound = $false
foreach ($name in $oldProtocols.Keys) {
    try {
        $oldCert = Get-RemoteCertificate -Host_ $Domain -Port 443 -Protocol $oldProtocols[$name]
        if ($oldCert) {
            Write-Host "❌ 古いプロトコル ${name} を受け付けています。サーバー設定で無効化を"
            $status = 1
            $oldFound = $true
        }
    } catch {
        # OS側で無効化されている、またはサーバー側で拒否された場合はここに来る(確認不可/正常に無効)
        Write-Host "  (${name}: 確認不可、または受け付けられませんでした — $($_.Exception.Message))"
    }
}
if (-not $oldFound) {
    Write-Host "✅ 古いTLS(1.0/1.1)は無効です(または確認不可)"
}

exit $status
