# Invoke-WebRequest による稼働中Webサービスのヘッダー/HTTPS検査 → reports/web.json (正規化形式)
# 自分のサービスへの確認のみを想定。攻撃的スキャンは行わない。
# 使い方: check.ps1 から $env:URL / $env:REPORT_DIR を設定した上で呼び出す
$ErrorActionPreference = "Continue"

$OUT = Join-Path $env:REPORT_DIR "web.json"
$URL = $env:URL

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

$findings = @()
function Add-Finding($Severity, $Message) {
    $script:findings += [ordered]@{
        severity = $Severity
        message  = $Message
        location = $URL
    }
}

$response = $null
try {
    $response = Invoke-WebRequest -Uri $URL -SkipHttpErrorCheck -TimeoutSec 15 -MaximumRedirection 10 -ErrorAction Stop
} catch {
    $response = $null
}

if (-not $response) {
    Write-JsonUtf8 $OUT ([ordered]@{ category = "web"; skipped = $true; findings = @() })
    Write-Output "スキップ (URLに接続できませんでした)"
    exit 0
}

$headers = $response.Headers

function Has-Header($Name) {
    return ($headers.Keys | Where-Object { $_ -ieq $Name }) -ne $null
}

function Get-HeaderValue($Name) {
    $key = $headers.Keys | Where-Object { $_ -ieq $Name } | Select-Object -First 1
    if ($key) {
        $val = $headers[$key]
        if ($val -is [array]) { return ($val -join ", ") }
        return $val
    }
    return $null
}

# HTTPS 強制チェック
if ($URL -like "http://*") {
    $finalUrl = $URL
    try {
        if ($response.BaseResponse -and $response.BaseResponse.RequestMessage -and $response.BaseResponse.RequestMessage.RequestUri) {
            $finalUrl = $response.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
        }
    } catch {}
    if ($finalUrl -notlike "https://*") {
        Add-Finding "HIGH" "HTTPSへリダイレクトされていません"
    }
}

if (-not (Has-Header "strict-transport-security")) {
    Add-Finding "MEDIUM" "HSTSヘッダーがありません (Strict-Transport-Security)"
}
if (-not (Has-Header "content-security-policy")) {
    Add-Finding "MEDIUM" "CSPヘッダーがありません (Content-Security-Policy)"
}
if (-not (Has-Header "x-content-type-options")) {
    Add-Finding "LOW" "X-Content-Type-Options: nosniff がありません"
}

$hasFrameAncestors = $false
$cspVal = Get-HeaderValue "content-security-policy"
if ($cspVal -and $cspVal -imatch "frame-ancestors") { $hasFrameAncestors = $true }
if (-not (Has-Header "x-frame-options") -and -not $hasFrameAncestors) {
    Add-Finding "LOW" "クリックジャッキング対策がありません (X-Frame-Options / frame-ancestors)"
}

if (-not (Has-Header "referrer-policy")) {
    Add-Finding "LOW" "Referrer-Policyヘッダーがありません"
}

# サーバーバージョン漏洩
$server = Get-HeaderValue "server"
if ($server -and $server -match "[0-9]") {
    Add-Finding "LOW" "Serverヘッダーがバージョンを漏らしています: $server"
}
if (Has-Header "x-powered-by") {
    Add-Finding "LOW" "X-Powered-Byヘッダーが技術情報を漏らしています"
}

$result = [ordered]@{
    category = "web"
    skipped  = $false
    findings = @($findings)
}
Write-JsonUtf8 $OUT $result

Write-Output "検出: $($findings.Count) 件"
