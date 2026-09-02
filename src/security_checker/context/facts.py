"""RepoFacts の推定 (設計書 §8.1).

「この関数はインターネットに露出しているか」を LLM が判断するための材料。
推測できないものは None のままにする (埋めない)。
"""

from __future__ import annotations

from pathlib import Path

from security_checker.models.task import RepoFacts

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

AUTH_MARKERS = ("auth", "login", "session", "jwt", "oauth", "permission")
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build"}
MAX_FILES = 4000


def collect_repo_facts(root: Path) -> RepoFacts:
    """リポジトリを 1 度だけ走査して事実を集める (候補ごとに再計算しない)."""
    languages: dict[str, int] = {}
    entrypoints: list[str] = []
    deployment: list[str] = []
    manifests: list[Path] = []
    auth_hit = False
    seen = 0

    for path in root.rglob("*"):
        if seen >= MAX_FILES:
            break
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        seen += 1
        name = path.name
        relative = path.relative_to(root).as_posix()

        language = LANGUAGE_BY_SUFFIX.get(path.suffix)
        if language:
            languages[language] = languages.get(language, 0) + 1
        if name in ENTRYPOINT_NAMES and len(entrypoints) < 10:
            entrypoints.append(relative)
        if name in DEPLOYMENT_FILES:
            hint = DEPLOYMENT_FILES[name]
            if hint not in deployment:
                deployment.append(hint)
        if name in FRAMEWORK_MARKERS:
            manifests.append(path)
        if not auth_hit and any(marker in relative.lower() for marker in AUTH_MARKERS):
            auth_hit = True

    frameworks: list[str] = []
    for manifest in manifests:
        try:
            content = manifest.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for marker in FRAMEWORK_MARKERS[manifest.name]:
            if marker in content and marker not in frameworks:
                frameworks.append(marker)

    ordered_languages = [
        language for language, _ in sorted(languages.items(), key=lambda item: -item[1])
    ]
    return RepoFacts(
        languages=ordered_languages[:6],
        frameworks=sorted(frameworks)[:8],
        entrypoints=sorted(entrypoints),
        has_auth_layer=True if auth_hit else None,
        is_public_repo=None,
        deployment_hints=deployment,
    )
