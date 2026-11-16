"""RepoFacts の推定 (設計書 §8.1).

「この関数はインターネットに露出しているか」を LLM が判断するための材料。
推測できないものは None のままにする (埋めない)。
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path

from security_checker.models.task import RepoFacts
from security_checker.scanners.filters import is_excluded

LANGUAGE_BY_SUFFIX = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rs": "Rust",
    ".cs": "C#",
    ".sh": "Shell",
    ".ps1": "PowerShell",
}

# マニフェストに現れたら、そのフレームワークを使っているとみなす文字列
FRAMEWORK_MARKERS = {
    "requirements.txt": ["flask", "django", "fastapi", "tornado", "aiohttp", "sqlalchemy"],
    "pyproject.toml": ["flask", "django", "fastapi", "tornado", "aiohttp", "sqlalchemy"],
    "package.json": ["express", "next", "nest", "koa", "fastify", "react", "vue"],
    "Gemfile": ["rails", "sinatra"],
    "go.mod": ["gin-gonic", "echo", "fiber"],
    "composer.json": ["laravel", "symfony"],
    "pom.xml": ["spring"],
    "build.gradle": ["spring"],
}

DEPLOYMENT_FILES = {
    "Dockerfile": "Dockerfile",
    "docker-compose.yml": "docker-compose",
    "docker-compose.yaml": "docker-compose",
    "serverless.yml": "serverless",
    "template.yaml": "serverless (SAM)",
    "Procfile": "Procfile",
}

ENTRYPOINT_NAMES = {
    "main.py",
    "app.py",
    "wsgi.py",
    "asgi.py",
    "manage.py",
    "server.py",
    "index.js",
    "server.js",
    "app.js",
    "main.go",
    "main.rs",
}

#: 認証の仕組みを入れていると分かる依存 (マニフェストに現れたら has_auth_layer: true).
#: ファイル名の部分一致 (AUTHORS・oauth など) では決めない (#303)
AUTH_DEPENDENCIES = {
    "requirements.txt": [
        "flask-login",
        "flask-jwt-extended",
        "django-allauth",
        "djangorestframework-simplejwt",
        "authlib",
        "fastapi-users",
        "python-jose",
        "pyjwt",
    ],
    "pyproject.toml": [
        "flask-login",
        "flask-jwt-extended",
        "django-allauth",
        "djangorestframework-simplejwt",
        "authlib",
        "fastapi-users",
        "python-jose",
        "pyjwt",
    ],
    "package.json": ["passport", "next-auth", "jsonwebtoken", "express-session", "@auth/core"],
    "Gemfile": ["devise", "omniauth", "jwt"],
    "go.mod": ["golang-jwt", "go-oidc", "goth"],
    "composer.json": ["laravel/sanctum", "laravel/passport", "tymon/jwt-auth"],
    "pom.xml": ["spring-boot-starter-security", "spring-security"],
    "build.gradle": ["spring-boot-starter-security", "spring-security"],
}
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
MAX_FILES = 4000
#: プロンプトに載せる入口ファイルの数
MAX_ENTRYPOINTS = 10


def _directory_excluded(relative: str, patterns: list[str]) -> bool:
    """ディレクトリの配下がすべて除外されるか (`vendor/**` や `tests` に一致するか)."""
    return is_excluded(f"{relative}/\0", patterns)


def collect_repo_facts(root: Path, exclude: Sequence[str] = ()) -> RepoFacts:
    """リポジトリを 1 度だけ走査して事実を集める (候補ごとに再計算しない).

    - 除外は検査対象からの相対パスで判定する (対象そのものが build/ の下にあっても空にしない)
    - 除外ディレクトリの中には降りない。`target.exclude` も同じ解釈 (is_excluded) で効かせる
    - 名前順に走査し、MAX_FILES での打ち切り位置を実行環境に依存させない
    """
    languages: dict[str, int] = {}
    entrypoints: list[str] = []
    deployment: list[str] = []
    manifests: list[Path] = []
    files, truncated = _list_files(root, list(exclude))

    for path, relative in files:
        name = path.name
        language = LANGUAGE_BY_SUFFIX.get(path.suffix)
        if language:
            languages[language] = languages.get(language, 0) + 1
        if name in ENTRYPOINT_NAMES and len(entrypoints) < MAX_ENTRYPOINTS:
            entrypoints.append(relative)
        hint = DEPLOYMENT_FILES.get(name)
        if hint is not None and hint not in deployment:
            deployment.append(hint)
        if name in FRAMEWORK_MARKERS:
            manifests.append(path)

    frameworks, auth_hit = _read_manifests(manifests)

    ordered_languages = [
        language for language, _ in sorted(languages.items(), key=lambda item: (-item[1], item[0]))
    ]
    return RepoFacts(
        languages=ordered_languages[:6],
        frameworks=sorted(frameworks)[:8],
        entrypoints=sorted(entrypoints),
        has_auth_layer=True if auth_hit else None,
        is_public_repo=None,
        deployment_hints=deployment,
        truncated=truncated,
    )


def _list_files(root: Path, patterns: list[str]) -> tuple[list[tuple[Path, str]], bool]:
    """検査対象のファイルを (パス, 対象からの相対パス) で名前順に返す.

    MAX_FILES で打ち切ったら 2 つ目の戻り値が True。除外ディレクトリの中には降りない。
    """
    found: list[tuple[Path, str]] = []
    for current, dirs, files in os.walk(root):
        base = Path(current)
        relative_dir = base.relative_to(root)
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in SKIP_DIRS
            and not (patterns and _directory_excluded((relative_dir / d).as_posix(), patterns))
        )
        for name in sorted(files):
            relative = (relative_dir / name).as_posix()
            if patterns and is_excluded(relative, patterns):
                continue
            if len(found) >= MAX_FILES:
                return found, True
            path = base / name
            if path.is_file():
                found.append((path, relative))
    return found, False


def _read_manifests(manifests: list[Path]) -> tuple[list[str], bool]:
    """依存の宣言から、フレームワークの名前と、認証ライブラリがあるかを読む."""
    frameworks: list[str] = []
    auth_hit = False
    for manifest in manifests:
        try:
            content = manifest.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for marker in FRAMEWORK_MARKERS[manifest.name]:
            if marker in content and marker not in frameworks:
                frameworks.append(marker)
        if any(dependency in content for dependency in AUTH_DEPENDENCIES[manifest.name]):
            auth_hit = True
    return frameworks, auth_hit
