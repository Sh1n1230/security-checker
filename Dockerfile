# security-checker v2 の実行イメージ (設計書 §21.1)。
# スキャナを同梱し、利用者側でのツール導入とバージョン差異をなくす。
#
#   docker build -t security-checker .
#   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" security-checker scan .
#
# GHCR への公開 (ghcr.io/sh1n1230/security-checker) は P6 で行う。
# それまでの GitHub Action は composite (action.yml) で配る。
FROM python:3.12-slim AS base

# スキャナの版。空なら scripts/scanner-versions.sh に固定した版 (sha256 も固定) を入れる。
# `--build-arg GITLEAKS_VERSION=x.y.z` などで上書きした場合は、リリース側のチェックサムで検証する
ARG GITLEAKS_VERSION=""
ARG TRIVY_VERSION=""
ARG OSV_SCANNER_VERSION=""
ARG SEMGREP_VERSION=""

# git は diff モード (merge-base) に必要
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# composite action と同じスクリプトで入れる (経路ごとに版が食い違わないようにする)。
# install スクリプトを `curl | sh` で実行しない (検証せずに実行することになるため)
COPY scripts/scanner-versions.sh scripts/install-scanners.sh /tmp/scanners/
RUN /tmp/scanners/install-scanners.sh /usr/local/bin && rm -rf /tmp/scanners

# 依存は uv.lock に固定した版をハッシュ検証つきで入れる (`pip install .` だとビルドした日の最新版になる)。
# uv はロックファイルを requirements 形式に書き出すためだけに使い、イメージには残さない
COPY --from=ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 /uv /usr/local/bin/uv

WORKDIR /opt/security-checker
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN set -eux; \
    uv export --frozen --no-dev --no-emit-project --format requirements-txt -o /tmp/requirements.txt; \
    pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt; \
    pip install --no-cache-dir --no-deps .; \
    rm /tmp/requirements.txt /usr/local/bin/uv; \
    security-checker version

# マウントしたリポジトリの所有者が実行ユーザーと異なっても git が拒否しないようにする。
# `docker run -u` で任意の uid にしても効くよう、system 設定に書く
RUN git config --system --add safe.directory '*'

# 実行時は root で動かさない。マウントしたリポジトリを読み、レポートを書くだけ
RUN useradd --create-home --uid 10001 checker
USER checker
ENV SEMGREP_SEND_METRICS=off HOME=/tmp

WORKDIR /src
ENTRYPOINT ["security-checker"]
CMD ["--help"]
