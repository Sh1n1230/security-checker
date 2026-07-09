# gitleaks によるシークレット検出 → reports/secrets.json (正規化形式)
# 使い方: check.ps1 から $env:TARGET / $env:REPORT_DIR を設定した上で呼び出す
$ErrorActionPreference = "Continue"

$OUT = Join-Path $env:REPORT_DIR "secrets.json"

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-JsonUtf8 $OUT ([ordered]@{ category = "secrets"; skipped = $true; findings = @() })
    Write-Output "スキップ (gitleaks 未インストール)"
    exit 0
}

$RAW = Join-Path $env:REPORT_DIR "secrets_raw.json"
& gitleaks detect --no-git --source "$env:TARGET" --report-format json --report-path "$RAW" --exit-code 0 *> $null

if (-not (Test-Path $RAW) -or (Get-Item $RAW).Length -eq 0) {
    [System.IO.File]::WriteAllText($RAW, "[]", [System.Text.UTF8Encoding]::new($false))
}

# 注: PowerShell の変数名は大文字小文字を区別しないため $RAW と別名にする
$data = $null
try {
    $data = Get-Content -Raw -Path $RAW | ConvertFrom-Json
} catch {
    $data = @()
}
if ($null -eq $data) { $data = @() }
$rawArr = @($data)

$findings = @()
foreach ($item in $rawArr) {
    $findings += [ordered]@{
        severity = "CRITICAL"
        message  = "シークレット検出: " + $item.RuleID
        location = "$($item.File):$($item.StartLine)"
    }
}

$result = [ordered]@{
    category = "secrets"
    skipped  = $false
    findings = @($findings)
}
Write-JsonUtf8 $OUT $result

Write-Output "検出: $($findings.Count) 件"
