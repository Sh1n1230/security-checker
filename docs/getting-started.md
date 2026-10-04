# はじめに

スキャナ (semgrep / gitleaks / osv-scanner / trivy) の検出を、独立した LLM に**第三者として**
レビューさせ、誤検知を減らした結果を出すツールです。コードは書き換えません。

## 1. インストール

Python 3.11 以上が必要です。

```sh
uv tool install git+https://github.com/Sh1n1230/security-checker   # コマンド名は security-checker
```

> PyPI への公開は準備中です (配布名は `security-checker` が既に使われているため別名になる予定)。
> 公開後は `uv tool install <配布名>` / `pipx install <配布名>` で入ります。

スキャナは別に入れます。入っていないスキャナは **skipped** として明示され、
「検査できなかった」ことがレポートに残ります (「0 件」とは区別されます)。

```sh
brew install semgrep gitleaks osv-scanner trivy
```

スキャナ同梱の Docker イメージも使えます ([Dockerfile](../Dockerfile))。

```sh
docker build -t security-checker .
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" security-checker scan .
```

## 2. LLM を使わずに試す

```sh
security-checker scan .
```

スキャナを動かして結果を正規化し、`.security-checker/` に `report.json` と `report.md` を書きます。
**何も外部に送りません。** ここで出るのは「判定前の候補」で、誤検知を含みます。

## 3. Reviewer を設定する

```sh
security-checker init
```

この環境で**実際に使えるもの** (非対話で動くコマンド、API キーの環境変数) を検出して
`security-checker.yml` を生成します。既定の Reviewer はありません。特定のサービスを標準として
押し付けないためです。使いたいものが検出されない場合は [providers.md](providers.md) を見てください。

設定したら、まず疎通を確かめます。

```sh
security-checker providers check          # 設定・疎通・構造化出力の往復を確認 (合成コードを 1 件送る)
```

## 4. レビューする

```sh
security-checker review . --dry-run       # 送信予定の内容を全部見る (送らない)
security-checker review . --estimate      # 何回呼んで、いくらかかるかの見積り (送らない)
security-checker review .
```

PR の変更分だけを見るなら:

```sh
security-checker review . --base origin/main
```

## 5. 結果を読む

判定は次のどれかになります。

| status | 意味 | CI を落とすか |
|---|---|---|
| `confirmed` | Reviewer が脆弱と判断し、一致度も高い | `policy.fail_on` 以上なら落とす |
| `likely` | 脆弱の可能性が高い | 同上 |
| **`review_required`** | **判断が割れた・確信度が低い。人間が見るべきもの** | 落とさない |
| `false_positive` | 誤検知と判断 | 落とさない (PR にも出さない) |
| `inconclusive` / `error` / `not_reviewed` | 判定できなかった | 「問題なし」ではない |

`review_required` は `confirmed` のすぐ後に表示します。割れた判断こそ人間が見るべきだからです。

1 件の判定の根拠をすべて見るには:

```sh
security-checker explain <候補 ID の先頭数文字>
```

各 Reviewer の判断理由と、その判定に至った全呼び出しの記録 (トレース) を表示します。

## 6. 既存のリポジトリに入れる

最初の実行で過去の指摘がまとめて出たら、いったん baseline に記録できます。

```sh
security-checker baseline update
```

記録した候補は `suppressed` としてレポートに残り、レビューとゲートの対象から外れます。
新しく増えたものだけが CI を落とします。個別に外すなら `.security-checker-ignore` か
コード内の注釈を使います ([configuration.md](configuration.md#抑制))。

## 次に読むもの

- [configuration.md](configuration.md) — 設定の全項目
- [github-actions.md](github-actions.md) — PR ごとに動かす
- [aggregation.md](aggregation.md) — 複数の Reviewer の結果をどうまとめるか
- [security-model.md](security-model.md) — 何が外部に送られるか
