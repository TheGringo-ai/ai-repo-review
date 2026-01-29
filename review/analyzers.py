"""
Static code analyzers for repo-review tool.

Performs read-only static analysis on repository code.
NO code execution - only file pattern matching and content analysis.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional


# Severity levels
SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"


def run_all_analyzers(clone_path: str, stack_info: Dict[str, Any], verbose: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """
    Run all static analyzers on the cloned repository.

    Args:
        clone_path: Path to the cloned repository
        stack_info: Dictionary with detected stack information
        verbose: Enable verbose output

    Returns:
        Dictionary with analyzer results grouped by category
    """
    results = {
        "security": [],
        "dependencies": [],
        "code_quality": [],
        "configuration": [],
    }

    clone_path = Path(clone_path)

    # Run general analyzers (all projects)
    results["security"].extend(_check_env_files(clone_path, verbose))
    results["security"].extend(_check_hardcoded_secrets(clone_path, verbose))
    results["code_quality"].extend(_check_broad_exception_handling(clone_path, verbose))

    # Run Python-specific analyzers
    primary_lang = stack_info.get("primary_language", "").lower()
    if primary_lang == "python":
        results["dependencies"].extend(_check_python_dependencies(clone_path, verbose))
        results["code_quality"].extend(_check_python_patterns(clone_path, verbose))

    # Run Node/JavaScript-specific analyzers
    if "javascript" in primary_lang or "typescript" in primary_lang:
        results["dependencies"].extend(_check_node_dependencies(clone_path, verbose))
        results["code_quality"].extend(_check_javascript_patterns(clone_path, verbose))

    # Run configuration analyzers
    results["configuration"].extend(_check_configuration_issues(clone_path, stack_info, verbose))

    return results


# ============================================================================
# Security Analyzers
# ============================================================================

def _check_env_files(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check for .env files committed to repository."""
    findings = []

    env_patterns = [".env", ".env.local", ".env.production", ".env.development"]

    for pattern in env_patterns:
        for env_file in clone_path.rglob(pattern):
            # Skip node_modules and virtual environments
            if _should_skip_path(env_file):
                continue

            findings.append({
                "severity": SEVERITY_HIGH,
                "file": str(env_file.relative_to(clone_path)),
                "description": f"Environment file '{pattern}' found in repository. This may contain secrets.",
                "recommendation": "Add to .gitignore and use environment variables or secret managers.",
            })

            if verbose:
                print(f"      [!] Found env file: {env_file}")

    return findings


def _check_hardcoded_secrets(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check for hardcoded secrets patterns in code files."""
    findings = []

    # Patterns that suggest hardcoded secrets
    secret_patterns = [
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', "API key"),
        (r'(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\'][a-zA-Z0-9_\-]{20,}["\']', "Secret key"),
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', "Password"),
        (r'(?i)(private[_-]?key)\s*[=:]\s*["\']-----BEGIN', "Private key"),
        (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}', "Bearer token"),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']AKIA[A-Z0-9]{16}["\']', "AWS Access Key"),
        (r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\'][a-zA-Z0-9/+=]{40}["\']', "AWS Secret Key"),
        (r'(?i)(firebase[_-]?api[_-]?key)\s*[=:]\s*["\']AIza[a-zA-Z0-9_\-]{35}["\']', "Firebase API Key"),
        (r'(?i)(gh[ps]_[a-zA-Z0-9]{36})', "GitHub Token"),
        (r'(?i)(sk-[a-zA-Z0-9]{48})', "OpenAI API Key"),
    ]

    code_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".sh", ".yaml", ".yml", ".json"}

    for code_file in clone_path.rglob("*"):
        if not code_file.is_file():
            continue
        if code_file.suffix not in code_extensions:
            continue
        if _should_skip_path(code_file):
            continue

        try:
            content = code_file.read_text(encoding="utf-8", errors="ignore")

            for pattern, secret_type in secret_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    # Find line number
                    line_num = _find_line_number(content, pattern)

                    findings.append({
                        "severity": SEVERITY_HIGH,
                        "file": str(code_file.relative_to(clone_path)),
                        "line": line_num,
                        "description": f"Potential {secret_type} found in code.",
                        "recommendation": "Move secrets to environment variables or secret managers.",
                    })

                    if verbose:
                        print(f"      [!] Found pattern in: {code_file}")

        except (IOError, OSError):
            pass  # Skip files that can't be read

    return findings


# ============================================================================
# Python Dependency Analyzers
# ============================================================================

def _check_python_dependencies(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check Python dependencies for known issues."""
    findings = []

    # Check requirements.txt
    requirements_file = clone_path / "requirements.txt"
    if not requirements_file.exists():
        # Try common alternatives
        for alt in ["requirements/base.txt", "requirements/production.txt", "pyproject.toml"]:
            alt_path = clone_path / alt
            if alt_path.exists():
                requirements_file = alt_path
                break

    if not requirements_file.exists():
        findings.append({
            "severity": SEVERITY_LOW,
            "file": "requirements.txt",
            "description": "No requirements.txt found. Dependencies may not be pinned.",
            "recommendation": "Create requirements.txt with pinned versions for reproducible builds.",
        })
        return findings

    try:
        content = requirements_file.read_text()

        # Known outdated/deprecated packages
        outdated_patterns = [
            {
                "pattern": r"^python-jose\b",
                "package": "python-jose",
                "severity": SEVERITY_MEDIUM,
                "description": "python-jose is deprecated. Consider using python-jose[cryptography] or PyJWT.",
                "recommendation": "Migrate to PyJWT or ensure python-jose[cryptography] is used.",
            },
            {
                "pattern": r"^bleach\b",
                "package": "bleach",
                "severity": SEVERITY_MEDIUM,
                "description": "bleach is deprecated and in maintenance mode.",
                "recommendation": "Consider using nh3 or other HTML sanitization alternatives.",
            },
            {
                "pattern": r"^pyjwt\s*==\s*[01]\.",
                "package": "PyJWT",
                "severity": SEVERITY_HIGH,
                "description": "PyJWT version 1.x has known security vulnerabilities.",
                "recommendation": "Upgrade to PyJWT >= 2.0.0.",
            },
            {
                "pattern": r"^django\s*==\s*[12]\.",
                "package": "Django",
                "severity": SEVERITY_HIGH,
                "description": "Django 1.x/2.x is end-of-life and no longer receives security updates.",
                "recommendation": "Upgrade to Django 3.2 LTS or 4.x.",
            },
            {
                "pattern": r"^flask\s*==\s*0\.",
                "package": "Flask",
                "severity": SEVERITY_MEDIUM,
                "description": "Flask 0.x is outdated.",
                "recommendation": "Upgrade to Flask 2.x or later.",
            },
            {
                "pattern": r"^requests\s*==\s*2\.[0-9]\.",
                "package": "requests",
                "severity": SEVERITY_LOW,
                "description": "Older version of requests may have security issues.",
                "recommendation": "Upgrade to requests >= 2.25.0.",
            },
            {
                "pattern": r"^urllib3\s*==\s*1\.[012][0-5]?\.",
                "package": "urllib3",
                "severity": SEVERITY_MEDIUM,
                "description": "Older urllib3 versions have known vulnerabilities.",
                "recommendation": "Upgrade to urllib3 >= 1.26.0.",
            },
            {
                "pattern": r"^cryptography\s*==\s*[0-2]\.",
                "package": "cryptography",
                "severity": SEVERITY_HIGH,
                "description": "Old cryptography versions have security vulnerabilities.",
                "recommendation": "Upgrade to cryptography >= 3.3.0.",
            },
            {
                "pattern": r"^pyrebase\b",
                "package": "Pyrebase",
                "severity": SEVERITY_LOW,
                "description": "Pyrebase has compatibility issues with newer Python/dependencies.",
                "recommendation": "Use Firebase Admin SDK for server-side operations.",
            },
        ]

        for item in outdated_patterns:
            if re.search(item["pattern"], content, re.MULTILINE | re.IGNORECASE):
                findings.append({
                    "severity": item["severity"],
                    "file": str(requirements_file.relative_to(clone_path)),
                    "description": f"[{item['package']}] {item['description']}",
                    "recommendation": item["recommendation"],
                })

                if verbose:
                    print(f"      [!] Outdated package: {item['package']}")

        # Check for unpinned versions
        unpinned_count = 0
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("-"):
                if "==" not in line and ">=" not in line and "<=" not in line:
                    unpinned_count += 1

        if unpinned_count > 3:
            findings.append({
                "severity": SEVERITY_LOW,
                "file": str(requirements_file.relative_to(clone_path)),
                "description": f"{unpinned_count} packages have unpinned versions.",
                "recommendation": "Pin package versions for reproducible builds.",
            })

    except Exception as e:
        if verbose:
            print(f"      [!] Error reading requirements: {e}")

    return findings


def _check_python_patterns(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check for problematic Python code patterns."""
    findings = []

    patterns_to_check = [
        {
            "pattern": r"\bdatetime\.utcnow\(\)",
            "severity": SEVERITY_LOW,
            "description": "datetime.utcnow() is deprecated in Python 3.12+.",
            "recommendation": "Use datetime.now(timezone.utc) instead.",
        },
        {
            "pattern": r"from\s+Crypto\.",
            "severity": SEVERITY_MEDIUM,
            "description": "PyCrypto (Crypto) is deprecated and unmaintained.",
            "recommendation": "Use pycryptodome or cryptography library instead.",
        },
        {
            "pattern": r"subprocess\.call\([^)]*shell\s*=\s*True",
            "severity": SEVERITY_MEDIUM,
            "description": "subprocess.call with shell=True can be a security risk.",
            "recommendation": "Use shell=False and pass command as a list.",
        },
        {
            "pattern": r"os\.system\(",
            "severity": SEVERITY_MEDIUM,
            "description": "os.system() is deprecated and can be a security risk.",
            "recommendation": "Use subprocess module instead.",
        },
        {
            "pattern": r"pickle\.loads?\(",
            "severity": SEVERITY_MEDIUM,
            "description": "pickle.load/loads can execute arbitrary code.",
            "recommendation": "Use JSON or other safe serialization formats for untrusted data.",
        },
        {
            "pattern": r"eval\([^)]*\)",
            "severity": SEVERITY_HIGH,
            "description": "eval() can execute arbitrary code.",
            "recommendation": "Use ast.literal_eval() for safe evaluation or avoid eval entirely.",
        },
        {
            "pattern": r"exec\([^)]*\)",
            "severity": SEVERITY_HIGH,
            "description": "exec() can execute arbitrary code.",
            "recommendation": "Avoid exec() or ensure input is strictly validated.",
        },
    ]

    for py_file in clone_path.rglob("*.py"):
        if _should_skip_path(py_file):
            continue

        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            for item in patterns_to_check:
                if re.search(item["pattern"], content):
                    line_num = _find_line_number(content, item["pattern"])
                    findings.append({
                        "severity": item["severity"],
                        "file": str(py_file.relative_to(clone_path)),
                        "line": line_num,
                        "description": item["description"],
                        "recommendation": item["recommendation"],
                    })

                    if verbose:
                        print(f"      [!] Pattern issue in: {py_file}")

        except Exception:
            pass

    return findings


# ============================================================================
# Node/JavaScript Dependency Analyzers
# ============================================================================

def _check_node_dependencies(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check Node.js dependencies for known issues."""
    findings = []

    package_json = clone_path / "package.json"
    if not package_json.exists():
        return findings

    try:
        import json
        content = package_json.read_text()
        pkg = json.loads(content)

        all_deps = {}
        all_deps.update(pkg.get("dependencies", {}))
        all_deps.update(pkg.get("devDependencies", {}))

        # Known vulnerable/deprecated packages
        vulnerable_patterns = [
            {
                "package": "lodash",
                "version_pattern": r"^[0-3]\.",
                "severity": SEVERITY_HIGH,
                "description": "Lodash versions < 4.17.21 have prototype pollution vulnerabilities.",
                "recommendation": "Upgrade to lodash >= 4.17.21.",
            },
            {
                "package": "minimist",
                "version_pattern": r"^[01]\.[01]\.",
                "severity": SEVERITY_MEDIUM,
                "description": "minimist < 1.2.6 has prototype pollution vulnerability.",
                "recommendation": "Upgrade to minimist >= 1.2.6.",
            },
            {
                "package": "axios",
                "version_pattern": r"^0\.[0-9]\.",
                "severity": SEVERITY_MEDIUM,
                "description": "Older axios versions may have SSRF vulnerabilities.",
                "recommendation": "Upgrade to axios >= 0.21.1.",
            },
            {
                "package": "node-fetch",
                "version_pattern": r"^[12]\.",
                "severity": SEVERITY_LOW,
                "description": "node-fetch 2.x is in maintenance mode.",
                "recommendation": "Consider upgrading to node-fetch 3.x or use native fetch.",
            },
            {
                "package": "request",
                "version_pattern": r".*",
                "severity": SEVERITY_MEDIUM,
                "description": "request package is deprecated.",
                "recommendation": "Migrate to axios, node-fetch, or got.",
            },
            {
                "package": "moment",
                "version_pattern": r".*",
                "severity": SEVERITY_LOW,
                "description": "moment.js is in maintenance mode.",
                "recommendation": "Consider using date-fns, dayjs, or Luxon.",
            },
            {
                "package": "express",
                "version_pattern": r"^[0-3]\.",
                "severity": SEVERITY_HIGH,
                "description": "Express 3.x and below are end-of-life.",
                "recommendation": "Upgrade to Express 4.x or 5.x.",
            },
            {
                "package": "jquery",
                "version_pattern": r"^[12]\.",
                "severity": SEVERITY_MEDIUM,
                "description": "jQuery 1.x/2.x have known XSS vulnerabilities.",
                "recommendation": "Upgrade to jQuery >= 3.5.0.",
            },
            {
                "package": "serialize-javascript",
                "version_pattern": r"^[0-4]\.",
                "severity": SEVERITY_HIGH,
                "description": "serialize-javascript < 5.0.0 has RCE vulnerability.",
                "recommendation": "Upgrade to serialize-javascript >= 5.0.0.",
            },
        ]

        for item in vulnerable_patterns:
            if item["package"] in all_deps:
                version = all_deps[item["package"]]
                # Remove ^ or ~ from version
                clean_version = re.sub(r'^[\^~]', '', version)

                if re.match(item["version_pattern"], clean_version):
                    findings.append({
                        "severity": item["severity"],
                        "file": "package.json",
                        "description": f"[{item['package']}] {item['description']}",
                        "recommendation": item["recommendation"],
                    })

                    if verbose:
                        print(f"      [!] Vulnerable package: {item['package']}@{version}")

        # Check for missing lock file
        has_lock = (clone_path / "package-lock.json").exists() or (clone_path / "yarn.lock").exists() or (clone_path / "pnpm-lock.yaml").exists()
        if not has_lock:
            findings.append({
                "severity": SEVERITY_LOW,
                "file": "package.json",
                "description": "No lock file found (package-lock.json, yarn.lock, or pnpm-lock.yaml).",
                "recommendation": "Add a lock file for reproducible builds.",
            })

    except Exception as e:
        if verbose:
            print(f"      [!] Error reading package.json: {e}")

    return findings


def _check_javascript_patterns(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check for problematic JavaScript/TypeScript patterns."""
    findings = []

    patterns_to_check = [
        {
            "pattern": r"\bdocument\.write\(",
            "severity": SEVERITY_MEDIUM,
            "description": "document.write() can be a security risk and causes performance issues.",
            "recommendation": "Use DOM manipulation methods instead.",
        },
        {
            "pattern": r"innerHTML\s*=\s*[^;]+(?:req|user|input|data)",
            "severity": SEVERITY_HIGH,
            "description": "innerHTML with dynamic content can lead to XSS.",
            "recommendation": "Use textContent or sanitize input before using innerHTML.",
        },
        {
            "pattern": r"\beval\s*\(",
            "severity": SEVERITY_HIGH,
            "description": "eval() can execute arbitrary code.",
            "recommendation": "Avoid eval() or use safer alternatives.",
        },
        {
            "pattern": r"new\s+Function\s*\(",
            "severity": SEVERITY_MEDIUM,
            "description": "new Function() is similar to eval() and can be a security risk.",
            "recommendation": "Avoid dynamic code execution.",
        },
        {
            "pattern": r"dangerouslySetInnerHTML",
            "severity": SEVERITY_MEDIUM,
            "description": "dangerouslySetInnerHTML can lead to XSS if not properly sanitized.",
            "recommendation": "Ensure content is sanitized before using dangerouslySetInnerHTML.",
        },
    ]

    js_extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs"}

    for js_file in clone_path.rglob("*"):
        if not js_file.is_file():
            continue
        if js_file.suffix not in js_extensions:
            continue
        if _should_skip_path(js_file):
            continue

        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")

            for item in patterns_to_check:
                if re.search(item["pattern"], content, re.IGNORECASE):
                    line_num = _find_line_number(content, item["pattern"])
                    findings.append({
                        "severity": item["severity"],
                        "file": str(js_file.relative_to(clone_path)),
                        "line": line_num,
                        "description": item["description"],
                        "recommendation": item["recommendation"],
                    })

                    if verbose:
                        print(f"      [!] JS pattern issue in: {js_file}")

        except Exception:
            pass

    return findings


# ============================================================================
# Code Quality Analyzers
# ============================================================================

def _check_broad_exception_handling(clone_path: Path, verbose: bool = False) -> List[Dict[str, Any]]:
    """Check for overly broad exception handling."""
    findings = []

    # Python bare except
    python_pattern = r"except\s*:"

    for py_file in clone_path.rglob("*.py"):
        if _should_skip_path(py_file):
            continue

        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")

            matches = list(re.finditer(python_pattern, content))
            if matches:
                for match in matches[:3]:  # Limit to first 3 occurrences
                    line_num = content[:match.start()].count('\n') + 1
                    findings.append({
                        "severity": SEVERITY_LOW,
                        "file": str(py_file.relative_to(clone_path)),
                        "line": line_num,
                        "description": "Bare 'except:' catches all exceptions including KeyboardInterrupt.",
                        "recommendation": "Use 'except Exception:' or catch specific exceptions.",
                    })

                    if verbose:
                        print(f"      [!] Bare except in: {py_file}:{line_num}")

        except (IOError, OSError):
            pass

    # JavaScript catch without error parameter
    js_pattern = r"catch\s*\(\s*\)\s*\{"

    for js_file in clone_path.rglob("*.js"):
        if _should_skip_path(js_file):
            continue

        try:
            content = js_file.read_text(encoding="utf-8", errors="ignore")

            if re.search(js_pattern, content):
                line_num = _find_line_number(content, js_pattern)
                findings.append({
                    "severity": SEVERITY_LOW,
                    "file": str(js_file.relative_to(clone_path)),
                    "line": line_num,
                    "description": "Empty catch block ignores errors.",
                    "recommendation": "Log errors or handle them appropriately.",
                })

                if verbose:
                    print(f"      [!] Empty catch in: {js_file}")

        except Exception:
            pass

    return findings


# ============================================================================
# Configuration Analyzers
# ============================================================================

def _check_configuration_issues(clone_path: Path, stack_info: Dict[str, Any], verbose: bool = False) -> List[Dict[str, Any]]:
    """Check for configuration issues."""
    findings = []

    # Check for debug mode in production config
    debug_patterns = [
        (r'DEBUG\s*=\s*True', ".py"),
        (r'"debug"\s*:\s*true', ".json"),
        (r'debug:\s*true', ".yaml"),
        (r'debug:\s*true', ".yml"),
    ]

    for pattern, ext in debug_patterns:
        for config_file in clone_path.rglob(f"*{ext}"):
            if _should_skip_path(config_file):
                continue
            if "test" in str(config_file).lower():
                continue

            try:
                content = config_file.read_text(encoding="utf-8", errors="ignore")

                if re.search(pattern, content, re.IGNORECASE):
                    findings.append({
                        "severity": SEVERITY_MEDIUM,
                        "file": str(config_file.relative_to(clone_path)),
                        "description": "Debug mode appears to be enabled.",
                        "recommendation": "Ensure DEBUG is disabled in production configurations.",
                    })

                    if verbose:
                        print(f"      [!] Debug mode in: {config_file}")

            except Exception:
                pass

    # Check for .gitignore
    gitignore = clone_path / ".gitignore"
    if not gitignore.exists():
        findings.append({
            "severity": SEVERITY_LOW,
            "file": ".gitignore",
            "description": "No .gitignore file found.",
            "recommendation": "Add a .gitignore to prevent committing sensitive files.",
        })
    else:
        try:
            content = gitignore.read_text()

            # Check if common patterns are ignored
            should_ignore = [".env", "node_modules", "__pycache__", "*.pyc"]
            missing = [p for p in should_ignore if p not in content]

            if missing and len(missing) > 2:
                findings.append({
                    "severity": SEVERITY_LOW,
                    "file": ".gitignore",
                    "description": f".gitignore may be missing common patterns: {', '.join(missing[:3])}",
                    "recommendation": "Review and update .gitignore for your stack.",
                })

        except Exception:
            pass

    # Check for Dockerfile security
    dockerfile = clone_path / "Dockerfile"
    if dockerfile.exists():
        try:
            content = dockerfile.read_text()

            if "FROM" in content and "latest" in content:
                findings.append({
                    "severity": SEVERITY_LOW,
                    "file": "Dockerfile",
                    "description": "Using 'latest' tag for base image.",
                    "recommendation": "Pin base image to specific version for reproducible builds.",
                })

            if re.search(r"USER\s+root", content, re.IGNORECASE):
                findings.append({
                    "severity": SEVERITY_MEDIUM,
                    "file": "Dockerfile",
                    "description": "Container may run as root user.",
                    "recommendation": "Create and use a non-root user in the container.",
                })

        except Exception:
            pass

    return findings


# ============================================================================
# Helper Functions
# ============================================================================

def _should_skip_path(path: Path) -> bool:
    """Check if a path should be skipped during analysis."""
    skip_patterns = [
        "node_modules",
        "venv",
        ".venv",
        "env",
        "__pycache__",
        ".git",
        "dist",
        "build",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        "site-packages",
        "vendor",
        ".next",
        ".nuxt",
    ]

    parts = path.parts
    return any(skip in parts for skip in skip_patterns)


def _find_line_number(content: str, pattern: str) -> Optional[int]:
    """Find the line number where a pattern first matches."""
    match = re.search(pattern, content, re.IGNORECASE)
    if match:
        return content[:match.start()].count('\n') + 1
    return None
