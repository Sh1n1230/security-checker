# 複数のリポジトリへの導入と、必須チェックにするまで

security-checker を複数のリポジトリに入れ、最終的にマージの必須条件 (required check) にするための手順です。
**いきなり必須にしないでください。** 初回の検出 (過去の負債) で、全リポジトリの PR が止まります。

workflow の書き方そのものは [github-actions.md](github-actions.md) にあります。

## 前提

- action は**コミット SHA で固定**します。タグは付け替えられます。
- 各リポジトリに `.github/dependabot.yml` (`package-ecosystem: github-actions`) を置き、
  security-checker の新しいリリースに SHA ごと追随させます。

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 7 # 公開直後の版を避ける (セキュリティ更新は対象外)
```

## 導入の順番

1. **security-checker 自身**: 自己検査が、検出ゼロか、理由を書いた抑止だけになっていることを確かめる。
2. **公開リポジトリ**: Code Scanning (SARIF の登録) が使えるので、`upload-sarif: true` (既定) のまま入れる。
3. **非公開リポジトリ**: GitHub Advanced Security (Code Security) が無ければ SARIF を登録できません。
   `upload-sarif: false` で入れ、結果は PR コメントと Step Summary で見ます。
4. **LLM / MCP を使うリポジトリ**: 検出が多くなりやすいので最後にします。LLM レビューを使う場合は、
   Reviewer の API キーを Actions のシークレットに置き、`budget.max_usd` を決めてから有効にします。

どのリポジトリでも [ci/security.yml](../ci/security.yml) をコピーします。`pull_request`・`push` に加えて、
週 1 回の `schedule` と手動実行の `workflow_dispatch` が入っています。PR は差分だけを見るため、
依存の脆弱性はマニフェスト / ロックファイルを変えた PR にしか出ません。新しく公開された脆弱性は定期実行で拾います。

- `pull_request_target` は使わないでください。fork のコードを書き込み権限とシークレット付きで動かすことになります。
- fork からの PR の扱いは [github-actions.md の 5 章](github-actions.md#5-fork-からの-pr) を参照してください。
  fork PR ではスキャンだけを行い、コメントと SARIF の登録はスキップします (黙って緑にはしません)。

## 初回のノイズの片づけ方

1. `workflow_dispatch` (既定ブランチでは全件の検査になる) か、手元の `security-checker scan . --full` で、全件を出します。
2. 次の順に片づけます。
   - **シークレット**: 値の失効と再発行を先に行い、それからファイルを消します。
     履歴に残るので、消しただけでは済みません。
   - **依存の脆弱性**: Dependabot の更新 PR を取り込みます。直せないものは、リポジトリの
     `osv-scanner.toml` に**期限つきで**書いて抑止します。

     ```toml
     [[IgnoredVulns]]
     id = "GHSA-xxxx-xxxx-xxxx"
     ignoreUntil = 2027-01-31
     reason = "到達しない経路でしか使っていない。上流の修正版を待つ"
     ```

   - **GitHub Actions の指摘**: SHA 固定と `permissions` の明示は機械的に直せます。
   - **それ以外で今すぐ直せないもの**: baseline に入れ、新しく出たものだけをゲートにします。
     baseline に入れたものは、別に Issue を立てて追います。

     ```sh
     security-checker baseline update     # .security-checker-baseline.json を書く
     ```

     ```yaml
     # security-checker.yml
     policy:
       baseline: .security-checker-baseline.json
     ```

3. **`target.exclude` を広げて黙らせないでください。** 除外する場合は、理由を設定ファイルのコメントに書きます。

## 必須チェックにするまで

1. **観察 (1〜2 週間)**: `fail-on: high` (既定) のまま、必須にはしません。誤って失敗した PR があれば、
   ルールか抑止を直します。
2. **必須化**: 観察期間中に誤った失敗が無くなったリポジトリから、Ruleset の
   「Require status checks to pass」に workflow「Security Check」の `security` job を加えます。
   **workflow に `paths` の絞り込みを付けないでください。** 対象外の PR で必須チェックが出ず、マージできなくなります。
3. **Code Scanning のマージ条件** (公開リポジトリ): Ruleset の「Require code scanning results」に
   tool `security-checker` を加えます。閾値の考え方は [github-actions.md の 6 章](github-actions.md#6-code-scanning-をマージゲートにする) を参照してください。
4. **戻し方**: 必須化の後に誤った失敗が続く場合は、Ruleset を外さず、そのリポジトリだけ一時的に
   `fail-on: critical` に下げ、原因を Issue にします。
