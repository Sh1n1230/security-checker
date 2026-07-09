<#
security-checker: 汎用セキュリティ評価CLI (PowerShell 7版)
使い方: pwsh ./check.ps1 [対象ディレクトリ] [-Url <URL>] [-MinScore N] [-CheckUpdates]
#>
param(
    [Parameter(Position = 0)]
    [string]$TargetDir = ".",
    [string]$Url,
    [int]$MinScore,
    [switch]$CheckUpdates
)

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibDir = Join-Path $ScriptDir "lib"
$ReportDir = Join-Path $ScriptDir "reports"

function Write-JsonUtf8($Path, $Object) {
    $json = $Object | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

# --- 対象ディレクトリの解決 ---
$resolved = $null
try {
    $resolved = Resolve-Path -Path $TargetDir -ErrorAction Stop
} catch {
    $resolved = $null
}
if (-not $resolved) {
    Write-Error "エラー: 対象ディレクトリが見つかりません"
    exit 2
}
$Target = $resolved.Path

New-Item -ItemType Directory -Force -Path $ReportDir | Out-Null
Get-ChildItem -Path $ReportDir -Filter "*.json" -File -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

Write-Output "=== security-checker ==="
Write-Output "対象: $Target"
if ($Url) { Write-Output "URL : $Url" }
Write-Output ""

# --- 必須ツールチェック ---
# (jqは使用しない。PowerShellのConvertFrom-Json / ConvertTo-Jsonで代替する)

$missing = @()
foreach ($tool in @("gitleaks", "semgrep", "osv-scanner", "trivy")) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $missing += $tool
    }
}
if ($missing.Count -gt 0) {
    Write-Output "注意: 次のツールが未インストールのため該当カテゴリはスキップされます:"
    foreach ($t in $missing) {
        $hint = switch ($t) {
            "gitleaks"    { "winget install Gitleaks.Gitleaks  (または scoop install gitleaks)" }
            "semgrep"     { "pip install semgrep  (winget未対応。pipx install semgrep も可)" }
            "osv-scanner" { "winget install Google.OSVScanner  (または scoop install osv-scanner)" }
            "trivy"       { "winget install AquaSecurity.Trivy  (または scoop install trivy)" }
            default       { "winget install $t  (または scoop install $t)" }
        }
        Write-Output "  - $t  ($hint)"
    }
    Write-Output ""
}

$env:TARGET = $Target
$env:REPORT_DIR = $ReportDir

function Invoke-Scan($Name, $ScriptName) {
    Write-Output "--- $Name ---"
    & pwsh -NoProfile -File (Join-Path $LibDir $ScriptName)
    Write-Output ""
}

Invoke-Scan "シークレット検出 (gitleaks)" "scan_secrets.ps1"
Invoke-Scan "コード静的解析 (semgrep)" "scan_code.ps1"
Invoke-Scan "依存パッケージCVE (osv-scanner)" "scan_deps.ps1"
Invoke-Scan "設定ファイル検査 (trivy)" "scan_config.ps1"
if ($Url) {
    $env:URL = $Url
    Invoke-Scan "Webサービス検査 (curl)" "scan_web.ps1"
}

# --- ツール更新チェック ---
if ($CheckUpdates) {
    $updateScript = Join-Path $LibDir "check_tool_updates.ps1"
    if (Test-Path $updateScript) {
        Write-Output "--- ツール更新チェック ---"
        & pwsh -NoProfile -File $updateScript
        Write-Output ""
    } else {
        Write-Output "ツール更新チェックは未実装です (Phase 3で対応予定)"
    }
}

# --- スコア集計 ---
& pwsh -NoProfile -File (Join-Path $LibDir "score.ps1")

$summaryPath = Join-Path $ReportDir "summary.json"
$summary = Get-Content -Raw -Path $summaryPath | ConvertFrom-Json
$score = $summary.total_score

if ($PSBoundParameters.ContainsKey("MinScore")) {
    if ($score -lt $MinScore) {
        Write-Output "NG: スコア $score は基準値 $MinScore 未満です"
        exit 1
    }
    Write-Output "OK: スコア $score は基準値 $MinScore 以上です"
}
