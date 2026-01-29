#!/usr/bin/env python3
"""
Stack Detection Module - Detects project stack by analyzing indicator files.
No code execution - simple file existence checks only.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional


def detect_stack(repo_path: str) -> Dict[str, Any]:
    """Detect project stack from indicator files."""
    path = Path(repo_path)
    result = {
        "primary_language": None,
        "frameworks": [],
        "has_tests": False,
        "has_ci": False,
        "has_docker": False,
    }

    lang_info = _detect_language(path)
    result["primary_language"] = lang_info["language"]
    result["frameworks"] = lang_info["frameworks"]
    result["has_tests"] = _detect_tests(path, result["primary_language"])
    result["has_ci"] = _detect_ci(path)
    result["has_docker"] = _detect_docker(path)

    return result


def _detect_language(path: Path) -> Dict[str, Any]:
    """Detect primary language and frameworks."""
    language = None
    frameworks = []

    # Python
    if any((path / f).exists() for f in ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"]):
        language = "Python"
        frameworks.extend(_detect_python_frameworks(path))

    # Node.js
    if (path / "package.json").exists():
        if language is None:
            language = "JavaScript/TypeScript"
        frameworks.extend(_detect_node_frameworks(path))

    # Go
    if (path / "go.mod").exists():
        if language is None:
            language = "Go"

    # Rust
    if (path / "Cargo.toml").exists():
        if language is None:
            language = "Rust"

    return {"language": language or "Unknown", "frameworks": frameworks}


def _detect_python_frameworks(path: Path) -> List[str]:
    """Detect Python frameworks from requirements."""
    frameworks = []
    content = ""
    for f in ["requirements.txt", "pyproject.toml", "setup.py"]:
        if (path / f).exists():
            try:
                content += (path / f).read_text(errors="ignore").lower()
            except Exception:
                pass

    patterns = {
        "django": "Django", "flask": "Flask", "fastapi": "FastAPI",
        "pytest": "pytest", "sqlalchemy": "SQLAlchemy", "pandas": "pandas",
        "numpy": "numpy", "celery": "Celery"
    }
    for pattern, name in patterns.items():
        if pattern in content and name not in frameworks:
            frameworks.append(name)
    return frameworks


def _detect_node_frameworks(path: Path) -> List[str]:
    """Detect Node.js frameworks from package.json."""
    frameworks = []
    pkg = path / "package.json"
    if not pkg.exists():
        return frameworks
    try:
        content = pkg.read_text(errors="ignore").lower()
    except Exception:
        return frameworks

    patterns = {
        "react": "React", "vue": "Vue.js", "angular": "Angular",
        "express": "Express", "next": "Next.js", "jest": "Jest",
        "typescript": "TypeScript", "tailwindcss": "Tailwind CSS"
    }
    for pattern, name in patterns.items():
        if f'"{pattern}' in content and name not in frameworks:
            frameworks.append(name)
    return frameworks


def _detect_tests(path: Path, language: Optional[str]) -> bool:
    """Detect if test infrastructure is present."""
    test_dirs = ["tests", "test", "spec", "__tests__"]
    for d in test_dirs:
        if (path / d).exists() and (path / d).is_dir():
            return True

    test_files = ["pytest.ini", "conftest.py", "jest.config.js", "jest.config.ts"]
    for f in test_files:
        if (path / f).exists():
            return True
    return False


def _detect_ci(path: Path) -> bool:
    """Detect if CI/CD configuration is present."""
    ci_indicators = [
        ".github/workflows", ".gitlab-ci.yml", ".circleci",
        ".travis.yml", "Jenkinsfile", "azure-pipelines.yml"
    ]
    for indicator in ci_indicators:
        p = path / indicator
        if p.exists():
            if p.is_dir():
                try:
                    if any(p.iterdir()):
                        return True
                except Exception:
                    pass
            else:
                return True
    return False


def _detect_docker(path: Path) -> bool:
    """Detect if Docker configuration is present."""
    docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]
    for f in docker_files:
        if (path / f).exists():
            return True
    return False
