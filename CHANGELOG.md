# Changelog

## [2.1.0](https://github.com/Sh1n1230/security-checker/compare/v2.0.0...v2.1.0) (2026-10-10)


### Features

* Python 3.14 に対応する ([#60](https://github.com/Sh1n1230/security-checker/issues/60)) ([90895c4](https://github.com/Sh1n1230/security-checker/commit/90895c41ba262c4345d0cd8a9a81a987d66d97c5))


### Bug Fixes

* **providers:** process transport の出力を上限つきで読み、メモリに溜めない ([#63](https://github.com/Sh1n1230/security-checker/issues/63)) ([5a2b1e3](https://github.com/Sh1n1230/security-checker/commit/5a2b1e3eef750d58bf59033fb345d7ba27c9a0cf))
* **report:** report.md と PR コメントで LLM 出力の Markdown/HTML を同じ規則で無害化する ([#58](https://github.com/Sh1n1230/security-checker/issues/58)) ([0ff5aa5](https://github.com/Sh1n1230/security-checker/commit/0ff5aa5c6b1a9cd1dd5bcb487f2382cd99a7e837))
* **scanners:** untrusted-target では検査対象のスキャナ設定を読ませない ([#61](https://github.com/Sh1n1230/security-checker/issues/61)) ([bfafbc3](https://github.com/Sh1n1230/security-checker/commit/bfafbc331cc3784bd99063dab7f3c80c1dc109ce))
* Windows で動かない箇所を直し、macOS / Windows でも CI を回す ([#65](https://github.com/Sh1n1230/security-checker/issues/65)) ([0b63f42](https://github.com/Sh1n1230/security-checker/commit/0b63f428dcb90ad061b065d8fd6de9f0a15d5e05))
* スキャナの版と sha256 を 1 か所に固定し、action・CI・Docker で共有する ([#72](https://github.com/Sh1n1230/security-checker/issues/72)) ([659b109](https://github.com/Sh1n1230/security-checker/commit/659b1091a4715aae2affa41542a7116909755141))

## [2.0.0](https://github.com/Sh1n1230/security-checker/compare/v1.1.0...v2.0.0) (2026-10-05)


### Features

* **eval:** eval コマンド — 精度を測れるようにする ([#21](https://github.com/Sh1n1230/security-checker/issues/21)) ([5729f4b](https://github.com/Sh1n1230/security-checker/commit/5729f4b33f898f7a97f2c24729d895f928af0f03))
* P4〜P6 — GitHub 統合・品質・公開準備 ([#35](https://github.com/Sh1n1230/security-checker/issues/35)) ([3ce8122](https://github.com/Sh1n1230/security-checker/commit/3ce8122510ab23e45e425736ac9cde59fe488a58))


### Bug Fixes

* __version__ を pyproject.toml から取り、リリース時の食い違いをなくす ([#38](https://github.com/Sh1n1230/security-checker/issues/38)) ([839f4ae](https://github.com/Sh1n1230/security-checker/commit/839f4aee8a6acc3a20506a9b0d572f8df001e610))


### Documentation

* リリースのたびにずれるバージョン表記をなくし、eval の状況を反映する ([#34](https://github.com/Sh1n1230/security-checker/issues/34)) ([07f9d53](https://github.com/Sh1n1230/security-checker/commit/07f9d53d8f10cb5591fa8a97eb789623dbaee47d))
