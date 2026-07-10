<#
  PowerShell履歴・プロファイル・環境変数にシークレットが漏れていないか検査する。読み取り専用。
  使い方: pwsh -File ./check_shell_env.ps1
#>

$issues = 0
# よくあるシークレットのパターン(トークン形式 + 「変数名=値」形式の直書き)
$Pattern = 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[bp]-[0-9A-Za-z-]{20,}|sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9-]{20,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY|(PASSWORD|PASSWD|SECRET|API_KEY|TOKEN)=[^ $]{8,}'

Write-Host "=== シェル履歴・環境のシークレット検査 ==="

function Section([string]$name) {
    Write-Host ""
    Write-Host "--- $name ---"
}

# PSReadLine 履歴
Section "PSReadLine 履歴"
$found = 0
try {
    $histPath = (Get-PSReadLineOption -ErrorAction Stop).HistorySavePath
} catch {
    $histPath = $null
}
if ($histPath -and (Test-Path $histPath)) {
    $content = Get-Content -Path $histPath -ErrorAction SilentlyContinue
    $hits = $content | Select-String -Pattern $Pattern -AllMatches
    if ($hits.Count -gt 0) {
        Write-Host "  ❌ $histPath に $($hits.Count) 行のシークレットらしき記録"
        $hits | Select-Object -First 3 | ForEach-Object {
            $line = $_.Line
            if ($line.Length -gt 60) { $line = $line.Substring(0, 60) + "..." }
            Write-Host "       例: $line"
        }
        Write-Host "       → 該当行を削除するか履歴をクリア。コマンドラインに直接秘密を書かない"
        $issues++
        $found = 1
    }
} else {
    Write-Host "  (履歴ファイルが見つかりません)"
    $found = 1
}
if ($found -eq 0) { Write-Host "  ✅ 問題なし" }

# プロファイルファイル
Section "PowerShell プロファイル"
$found = 0
$profilePaths = @(
    $PROFILE.AllUsersAllHosts,
    $PROFILE.AllUsersCurrentHost,
    $PROFILE.CurrentUserAllHosts,
    $PROFILE.CurrentUserCurrentHost
) | Select-Object -Unique

foreach ($f in $profilePaths) {
    if (-not $f -or -not (Test-Path $f -PathType Leaf)) { continue }
    $content = Get-Content -Path $f -ErrorAction SilentlyContinue
    $hits = $content | Select-String -Pattern $Pattern -AllMatches
    if ($hits.Count -gt 0) {
        Write-Host "  ⚠️  $f にシークレットらしき記述が $($hits.Count) 行"
        Write-Host "       → 直書きせず、環境変数管理ツールや Windows 資格情報マネージャーの利用を検討"
        $issues++
        $found = 1
    }
}
if ($found -eq 0) { Write-Host "  ✅ 問題なし" }

# 現在の環境変数 (値そのものは表示しない)
Section "現在の環境変数"
$found = 0
Get-ChildItem Env: | Where-Object { $_.Name -match '(SECRET|TOKEN|PASSWORD|API_KEY)' } | Select-Object -First 10 | ForEach-Object {
    Write-Host "  ⚠️  環境変数 $($_.Name) が設定されています(必要なものか確認。値は表示していません)"
    $found = 1
}
if ($found -eq 0) { Write-Host "  ✅ シークレットらしき環境変数はありません" }

Write-Host ""
if ($issues -gt 0) {
    Write-Host "結果: ❌ ${issues} 件の問題があります"
    exit 1
}
Write-Host "結果: ✅ 問題は見つかりませんでした"
exit 0
