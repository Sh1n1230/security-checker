<#
  Windows環境系セキュリティチェックを一括実行する。タスクスケジューラ等での定期実行を想定。読み取り専用。
  使い方: pwsh -File ./run_all.ps1 [-Project <検査対象プロジェクトのパス>] [-Domain example.com]
#>

param(
    [string]$Project = "",
    [string]$Domain = ""
)

$DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

$total = 0
$failed = 0
$failures = @()

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    $script:total++
    Write-Host ""
    Write-Host "════════ $Name ════════"
    & $Action
    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        $script:failed++
        $script:failures += $Name
    }
}

Invoke-Check "Windows設定監査" { pwsh -NoProfile -File (Join-Path $DIR "audit_windows.ps1") }
Invoke-Check "開放ポート" { pwsh -NoProfile -File (Join-Path $DIR "check_ports.ps1") }

if ($Project -ne "") {
    Invoke-Check "ファイル権限" { pwsh -NoProfile -File (Join-Path $DIR "check_permissions.ps1") -Target $Project }
} else {
    Invoke-Check "ファイル権限" { pwsh -NoProfile -File (Join-Path $DIR "check_permissions.ps1") }
}

Invoke-Check "シェル履歴/環境変数" { pwsh -NoProfile -File (Join-Path $DIR "check_shell_env.ps1") }
Invoke-Check "更新状態" { pwsh -NoProfile -File (Join-Path $DIR "check_updates.ps1") }

if ($Project -ne "" -and (Test-Path (Join-Path $Project ".git"))) {
    $bashCmd = Get-Command bash -ErrorAction SilentlyContinue
    $gitHistoryScript = Join-Path (Split-Path -Parent $DIR) "check_git_history.sh"
    if ($bashCmd -and (Test-Path $gitHistoryScript)) {
        Invoke-Check "git履歴の漏洩" { bash $gitHistoryScript $Project; $global:LASTEXITCODE = $LASTEXITCODE }
    } else {
        Write-Host ""
        Write-Host "════════ git履歴の漏洩 ════════"
        Write-Host "  ⚠️  bash が見つからない、または check_git_history.sh が存在しないためスキップします"
    }
}

if ($Domain -ne "") {
    Invoke-Check "TLS証明書" { pwsh -NoProfile -File (Join-Path $DIR "check_tls_cert.ps1") -Domain $Domain }
}

Write-Host ""
Write-Host "══════════════ 総括 ══════════════"
Write-Host "実行: ${total} 件 / 要対応: ${failed} 件"
if ($failed -gt 0) {
    foreach ($f in $failures) { Write-Host "  ❌ $f" }
    exit 1
}
Write-Host "✅ すべてのチェックを通過しました"
exit 0
