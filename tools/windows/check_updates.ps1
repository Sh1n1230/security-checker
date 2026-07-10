<#
  winget パッケージおよび Windows Update (HotFix) の更新状況を検査する。読み取り専用。
  使い方: pwsh -File ./check_updates.ps1
#>

$issues = 0
Write-Host "=== 更新状態の検査 ==="

# winget パッケージ
Write-Host ""
Write-Host "--- winget パッケージ ---"
$wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
if ($wingetCmd) {
    try {
        $out = winget upgrade --accept-source-agreements 2>&1 | Out-String
        $lines = $out -split "`r?`n"
        # 区切り線(ダッシュのみの行)を探し、その次の行からをパッケージ行とみなす(表示言語非依存)
        $sepIdx = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^-{5,}$') { $sepIdx = $i; break }
        }
        if ($out -match 'No installed package|No applicable update|利用可能な更新はありません|インストール済みのパッケージが見つかりません') {
            Write-Host "  ✅ 更新可能なパッケージはありません"
        } elseif ($sepIdx -ge 0) {
            $pkgLines = @()
            for ($i = $sepIdx + 1; $i -lt $lines.Count; $i++) {
                $l = $lines[$i].Trim()
                if ($l -eq '' -or $l -match '^\d+\s' -or $l -match '^-+$') { continue }
                $pkgLines += $l
            }
            if ($pkgLines.Count -eq 0) {
                Write-Host "  ✅ 更新可能なパッケージはありません"
            } else {
                Write-Host "  ⚠️  更新可能なパッケージが $($pkgLines.Count) 件あります → winget upgrade --all"
                $pkgLines | Select-Object -First 5 | ForEach-Object { Write-Host "       - $_" }
                $issues++
            }
        } else {
            Write-Host "  ⚠️  winget upgrade の出力を解析できませんでした(手動確認推奨)"
        }
    } catch {
        Write-Host "  ⚠️  winget upgrade の実行に失敗しました: $($_.Exception.Message)"
    }
} else {
    Write-Host "  (winget なし。スキップします)"
}

# Windows Update (HotFix)
Write-Host ""
Write-Host "--- Windows Update 適用履歴 ---"
try {
    $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
    $latest = $hotfixes | Where-Object { $_.InstalledOn } | Select-Object -First 1
    if ($latest) {
        $days = (New-TimeSpan -Start $latest.InstalledOn -End (Get-Date)).Days
        if ($days -le 60) {
            Write-Host "  ✅ 最終更新適用日: $($latest.InstalledOn.ToString('yyyy-MM-dd')) (${days}日前)"
        } else {
            Write-Host "  ⚠️  最終更新適用日: $($latest.InstalledOn.ToString('yyyy-MM-dd')) (${days}日前、60日以上更新なし)"
            Write-Host "       → 設定 > Windows Update から更新を確認してください"
            $issues++
        }
    } else {
        Write-Host "  ⚠️  更新適用日の情報を取得できませんでした"
    }
} catch {
    Write-Host "  ⚠️  Get-HotFix の実行に失敗しました: $($_.Exception.Message)"
}

Write-Host ""
if ($issues -gt 0) {
    Write-Host "結果: ⚠️ ${issues} 件の確認事項があります"
    exit 1
}
Write-Host "結果: ✅ 問題ありません"
exit 0
