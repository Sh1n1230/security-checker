# trivy による設定ファイル(Dockerfile, CI, IaC等)検査 → reports/config.json (正規化形式)
# 使い方: check.ps1 から $env:TARGET / $env:REPORT_DIR を設定した上で呼び出す
$ErrorActionPreference = "Continue"

$OUT = Join-Path $env:REPORT_DIR "config.json"

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

if (-not (Get-Command trivy -ErrorAction SilentlyContinue)) {
    Write-JsonUtf8 $OUT ([ordered]@{ category = "config"; skipped = $true; findings = @() })
    Write-Output "スキップ (trivy 未インストール)"
    exit 0
}

$RAW = Join-Path $env:REPORT_DIR "config_raw.json"
& trivy fs --scanners misconfig --format json --quiet "$env:TARGET" 2> $null | Out-File -FilePath $RAW -Encoding utf8

# 注: PowerShell の変数名は大文字小文字を区別しないため $RAW と別名にする
$data = $null
try {
    $data = Get-Content -Raw -Path $RAW | ConvertFrom-Json
} catch {
    $data = $null
}
if (-not $data -or -not ($data.PSObject.Properties.Name -contains "Results")) {
    $data = [pscustomobject]@{ Results = @() }
}
$resultsArr = @()
if ($data.Results) { $resultsArr = @($data.Results) }

$findings = @()
foreach ($res in $resultsArr) {
    $target = $res.Target
    $miscs = @()
    if ($res.Misconfigurations) { $miscs = @($res.Misconfigurations) }
    foreach ($m in $miscs) {
        $sev = $m.Severity
        if (-not $sev) { $sev = "LOW" }
        $findings += [ordered]@{
            severity = $sev
            message  = "$($m.ID): $($m.Title)"
            location = $target
        }
    }
}

$result = [ordered]@{
    category = "config"
    skipped  = $false
    findings = @($findings)
}
Write-JsonUtf8 $OUT $result

Write-Output "検出: $($findings.Count) 件"
