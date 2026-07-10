<#
使用ツール(gitleaks / semgrep / osv-scanner / trivy)のセルフアップデートチェック (PowerShell版)
インストール済みバージョンと最新版(GitHub Releases / PyPI)を比較し、警告のみ表示する。
スコアには影響しない。単体実行も可能。
#>
$ErrorActionPreference = "Continue"

function Get-GitHubLatestVersion {
    param([string]$Repo)
    try {
        $resp = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -TimeoutSec 5 -ErrorAction Stop
        $tag = $resp.tag_name
        if (-not $tag) { return $null }
        return $tag.TrimStart("v")
    } catch {
        return $null
    }
}

function Get-PyPiLatestVersion {
    param([string]$Package)
    try {
        $resp = Invoke-RestMethod -Uri "https://pypi.org/pypi/$Package/json" -TimeoutSec 5 -ErrorAction Stop
        $ver = $resp.info.version
        if (-not $ver) { return $null }
        return $ver
    } catch {
        return $null
    }
}

function Test-ToolUpToDate {
    param([string]$Installed, [string]$Latest)
    # $true: 最新, $false: 更新あり, $null: 比較不能
    try {
        $vInstalled = [version]$Installed
        $vLatest = [version]$Latest
        return ($vInstalled -ge $vLatest)
    } catch {
        if ($Installed -eq $Latest) { return $true }
        return $null
    }
}

function Show-ToolStatus {
    param([string]$Name, [string]$Installed, [string]$Latest, [string]$UpgradeHint)

    if (-not $Installed) {
        Write-Output "  - ${Name}: 未インストール"
        return
    }

    if (-not $Latest) {
        Write-Output "  - ${Name} ${Installed}: 最新版を確認できませんでした(オフラインまたはAPI制限)"
        return
    }

    $result = Test-ToolUpToDate -Installed $Installed -Latest $Latest
    if ($result -eq $true) {
        Write-Output "  - ✅ ${Name} ${Installed}(最新)"
    } elseif ($result -eq $false) {
        Write-Output "  - ⚠️ ${Name} ${Installed} → 最新 ${Latest}(更新推奨: ${UpgradeHint})"
    } else {
        if ($Installed -ne $Latest) {
            Write-Output "  - ⚠️ ${Name} ${Installed} → 最新 ${Latest}(更新推奨: ${UpgradeHint})"
        } else {
            Write-Output "  - ✅ ${Name} ${Installed}(最新)"
        }
    }
}

Write-Output "使用ツールのバージョンを確認しています..."

# --- gitleaks ---
$glInstalled = $null
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
    $glInstalled = (gitleaks version 2>$null | Out-String).Trim()
}
$glLatest = $null
if ($glInstalled) { $glLatest = Get-GitHubLatestVersion -Repo "gitleaks/gitleaks" }
Show-ToolStatus -Name "gitleaks" -Installed $glInstalled -Latest $glLatest -UpgradeHint "winget upgrade Gitleaks.Gitleaks"

# --- semgrep ---
$sgInstalled = $null
if (Get-Command semgrep -ErrorAction SilentlyContinue) {
    $sgInstalled = (semgrep --version 2>$null | Out-String).Trim()
}
$sgLatest = $null
if ($sgInstalled) { $sgLatest = Get-PyPiLatestVersion -Package "semgrep" }
Show-ToolStatus -Name "semgrep" -Installed $sgInstalled -Latest $sgLatest -UpgradeHint "pip install -U semgrep"

# --- osv-scanner ---
$ovInstalled = $null
if (Get-Command osv-scanner -ErrorAction SilentlyContinue) {
    $rawOv = (osv-scanner --version 2>$null | Out-String)
    $firstLine = ($rawOv -split "`r?`n")[0]
    $ovInstalled = ($firstLine -replace '^osv-scanner version:\s*', '').Trim()
}
$ovLatest = $null
if ($ovInstalled) { $ovLatest = Get-GitHubLatestVersion -Repo "google/osv-scanner" }
Show-ToolStatus -Name "osv-scanner" -Installed $ovInstalled -Latest $ovLatest -UpgradeHint "winget upgrade Google.OSVScanner"

# --- trivy ---
$tvInstalled = $null
if (Get-Command trivy -ErrorAction SilentlyContinue) {
    $rawTv = (trivy --version 2>$null | Out-String)
    $firstLine = ($rawTv -split "`r?`n")[0]
    $tvInstalled = ($firstLine -replace '^Version:\s*', '').Trim()
}
$tvLatest = $null
if ($tvInstalled) { $tvLatest = Get-GitHubLatestVersion -Repo "aquasecurity/trivy" }
Show-ToolStatus -Name "trivy" -Installed $tvInstalled -Latest $tvLatest -UpgradeHint "winget upgrade AquaSecurity.Trivy"

exit 0
