# semgrep によるコード静的解析 → reports/code.json (正規化形式)
# 使い方: check.ps1 から $env:TARGET / $env:REPORT_DIR を設定した上で呼び出す
$ErrorActionPreference = "Continue"

$OUT = Join-Path $env:REPORT_DIR "code.json"

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

if (-not (Get-Command semgrep -ErrorAction SilentlyContinue)) {
    Write-JsonUtf8 $OUT ([ordered]@{ category = "code"; skipped = $true; findings = @() })
    Write-Output "スキップ (semgrep 未インストール)"
    exit 0
}

$RAW = Join-Path $env:REPORT_DIR "code_raw.json"
# 注: --config auto は近年の semgrep では --metrics=off と併用不可のため p/default を使う
& semgrep scan --config p/default --json --quiet --metrics=off "$env:TARGET" 2> $null | Out-File -FilePath $RAW -Encoding utf8

if (-not (Test-Path $RAW) -or (Get-Item $RAW).Length -eq 0) {
    [System.IO.File]::WriteAllText($RAW, '{"results":[]}', [System.Text.UTF8Encoding]::new($false))
}

# 注: PowerShell の変数名は大文字小文字を区別しないため $RAW と別名にする
$data = $null
try {
    $data = Get-Content -Raw -Path $RAW | ConvertFrom-Json
} catch {
    $data = [pscustomobject]@{ results = @() }
}
$resultsArr = @()
if ($data -and $data.PSObject.Properties.Name -contains "results" -and $data.results) {
    $resultsArr = @($data.results)
}

$findings = @()
foreach ($item in $resultsArr) {
    $sev = $item.extra.severity
    if ($sev -eq "ERROR") { $mapped = "HIGH" }
    elseif ($sev -eq "WARNING") { $mapped = "MEDIUM" }
    else { $mapped = "LOW" }

    $checkIdParts = $item.check_id -split '\.'
    $message = $checkIdParts[$checkIdParts.Length - 1]

    $findings += [ordered]@{
        severity = $mapped
        message  = $message
        location = "$($item.path):$($item.start.line)"
    }
}

$result = [ordered]@{
    category = "code"
    skipped  = $false
    findings = @($findings)
}
Write-JsonUtf8 $OUT $result

Write-Output "検出: $($findings.Count) 件"
