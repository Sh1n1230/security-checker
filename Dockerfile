# security-checker v2 の実行イメージ (設計書 §21.1)。
# スキャナを同梱し、利用者側でのツール導入とバージョン差異をなくす。
#
#   docker build -t security-checker .
#   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/src" security-checker scan .
#
# GHCR への公開 (ghcr.io/sh1n1230/security-checker) は P6 で行う。
# それまでの GitHub Action は composite (action.yml) で配る。
FROM python:3.12-slim AS base

ARG GITLEAKS_VERSION=8.30.1
ARG SEMGREP_VERSION=1.168.0
ARG TRIVY_VERSION=0.75.0
ARG OSV_SCANNER_VERSION=2.6.0

# git は diff モード (merge-base) に必要
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# gitleaks は公式リリースのバイナリをチェックサム付きで取得する。
# install スクリプトを `curl | sh` で実行しない (検証せずに実行することになるため)
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) ga=x64 ;; arm64) ga=arm64 ;; *) echo "unsupported: $arch"; exit 1 ;; esac; \
    base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"; \
    file="gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"; \
    curl -fsSLO "${base}/${file}"; \
    curl -fsSL "${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" | grep " ${file}\$" | sha256sum -c -; \
    tar xzf "${file}" -C /usr/local/bin gitleaks; \
    rm "${file}"; \
    gitleaks version

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) ta=64bit ;; arm64) ta=ARM64 ;; esac; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    file="trivy_${TRIVY_VERSION}_Linux-${ta}.tar.gz"; \
    curl -fsSLO "${base}/${file}"; \
    curl -fsSL "${base}/trivy_${TRIVY_VERSION}_checksums.txt" | grep " ${file}\$" | sha256sum -c -; \
    tar xzf "${file}" -C /usr/local/bin trivy; \
    rm "${file}"; \
    base="https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}"; \
    file="osv-scanner_linux_${arch}"; \
    curl -fsSLO "${base}/${file}"; \
    curl -fsSL "${base}/osv-scanner_SHA256SUMS" | grep " ${file}\$" | sha256sum -c -; \
    install -m 0755 "${file}" /usr/local/bin/osv-scanner; \
    rm "${file}"; \
    trivy --version; osv-scanner --version

RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

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
