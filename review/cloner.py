#!/usr/bin/env python3
"""
Repository Cloner - Safe, read-only cloning for public GitHub repos.
"""

import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

CLONE_TIMEOUT_SECONDS = 120


def validate_github_url(url: str) -> bool:
    """Validate that URL is a public GitHub repository."""
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    if parsed.netloc != 'github.com':
        return False
    path_parts = [p for p in parsed.path.strip('/').split('/') if p]
    if len(path_parts) < 2:
        return False
    return True


def extract_repo_name(url: str) -> Optional[str]:
    """Extract repository name from GitHub URL."""
    if not url:
        return None
    parsed = urlparse(url)
    path_parts = [p for p in parsed.path.strip('/').split('/') if p]
    if len(path_parts) < 2:
        return None
    repo_name = path_parts[1]
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]
    return repo_name


def clone_repo(url: str, verbose: bool = False) -> Optional[Path]:
    """Clone a public GitHub repo to a temporary directory (shallow, read-only)."""
    if not validate_github_url(url):
        print(f"[ERROR] Invalid GitHub URL: {url}")
        return None

    repo_name = extract_repo_name(url)
    if not repo_name:
        return None

    temp_dir = tempfile.mkdtemp(prefix=f"repo-review-{repo_name}-")
    clone_path = Path(temp_dir) / repo_name

    cmd = ['git', 'clone', '--depth=1', '--single-branch', url, str(clone_path)]

    if verbose:
        print(f"      Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS)
        if result.returncode != 0:
            print(f"[ERROR] Git clone failed: {result.stderr}")
            cleanup_repo(Path(temp_dir))
            return None
        if verbose:
            print(f"      Cloned to: {clone_path}")
        return clone_path
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Clone timed out after {CLONE_TIMEOUT_SECONDS} seconds")
        cleanup_repo(Path(temp_dir))
        return None
    except Exception as e:
        print(f"[ERROR] Clone failed: {e}")
        cleanup_repo(Path(temp_dir))
        return None


def cleanup_repo(path: Path) -> bool:
    """Remove cloned repository and temp directory."""
    if not path:
        return False
    try:
        target = path.parent if path.parent.name.startswith('repo-review-') else path
        if target.exists():
            shutil.rmtree(target)
            return True
        return False
    except Exception:
        return False
