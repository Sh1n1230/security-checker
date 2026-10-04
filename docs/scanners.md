# スキャナ

スキャナは「機械的な事実」(候補) を出し、LLM はその候補を判定するだけです。
LLM に脆弱性を探させないのは、見つけた・見つけないの再現性が無くなるためです。

| スキャナ | カテゴリ | 何を見るか | 導入 |
|---|---|---|---|
| semgrep | `sast` | コードのパターン | `brew install semgrep` / `pipx install semgrep` |
| gitleaks | `secret` | シークレットの直書き | `brew install gitleaks` |
| osv-scanner | `dependency` | 依存の既知脆弱性 (OSV データベース) | `brew install osv-scanner` |
| trivy | `config` / `dependency` | IaC・Dockerfile・Kubernetes の誤設定、依存の脆弱性 | `brew install trivy` |

無効にするには `scanners.<name>.enabled: false`。

## 状態を必ず区別する

| 状態 | 意味 | 扱い |
|---|---|---|
| `ok` | 実行できた (0 件を含む) | |
| `skipped` | 導入されていない・対象が無い | 警告。スコアは `partial` |
| `failed` | 異常終了・タイムアウト・出力が壊れている | **エラー**。`strict` なら exit 3。SARIF はアップロードしない |

v1 には「スキャナが失敗しても 0 件の成功として扱われ、満点に見える」欠陥がありました。
v2 は `skipped` と `failed` を型で分け、どちらもレポートの冒頭に出します。

## 個別の注意

### semgrep

- `scanners.semgrep.config` は `p/default` のようなルールセットか、ルールファイルのパス。
- 生出力は `raw/semgrep.json` に、パスを相対にして保存します。

### gitleaks

- **検出値はマスクしてから**候補・生出力・LLM へのプロンプトに載せます (`xoxb****` のように形式だけ残す)。
  漏洩したシークレットを第三者 (外部 LLM) に再送しないためです。
- gitleaks 8.19 以降は `gitleaks dir`、それ以前は `detect --no-git` を使います。

### osv-scanner

- `osv-scanner scan source --recursive` を実行します。依存の問い合わせのため、
  **パッケージ名とバージョンが OSV の API に送られます** (コードは送りません)。
- 同じ脆弱性の別名 (PYSEC / GHSA / CVE) は 1 件にまとめます。別名ごとに候補を作ると、
  同じ問題が何度もレビューされ、何度も PR に出るためです。
- 終了コード 128 (マニフェストが無い) は「対象が無い」なので `skipped` にします。
- 重大度が分からない脆弱性は `medium` として扱い、そのことをメッセージに書きます
  (`info` にするとゲートから消えるため)。

### trivy

- `scanners: [config]` で誤設定、`[vuln]` で依存の脆弱性を見ます (osv と重なるので、どちらかで足ります)。
- **`secret` は受け付けません。** trivy のシークレット検出は検出値を出力に含めるため、生出力に値が残ります。
  シークレットはマスク処理のある gitleaks で見てください。
- オフライン環境では `extra_args: ["--offline-scan", "--skip-check-update"]` などを渡します。

## 自作のスキャナを足す

`security_checker.scanners` の entry point に登録すると、内蔵と同じように使えます。
適合性は公開の契約テストで確かめられます。

```python
from security_checker.testing import ScannerContractTests


class TestMyScanner(ScannerContractTests):
    def make_scanner(self):
        return MyScanner(MyConfig())

    def populate(self, root):  # 任意: 検出させたいファイルを置く
        (root / "app.py").write_text("...")
```

検証する契約: ツールが無ければ `skipped` を返す / `failed` には理由がある / 候補 ID が run 内で一意で、
2 回走らせても変わらない / パスが検査対象の外を指さない / 生出力は `raw_dir` に書く。
