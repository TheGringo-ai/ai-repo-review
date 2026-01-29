"""
Review Router - Handles repository analysis requests.
"""

import sys
from pathlib import Path

from fastapi import APIRouter, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

# Add parent directory to path for review module imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from review.cloner import clone_repo, cleanup_repo, validate_github_url
from review.detector import detect_stack
from review.analyzers import run_all_analyzers
from review.reporter import generate_report

router = APIRouter(tags=["Review"])

# Templates
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the main repository review page."""
    return templates.TemplateResponse("index.html", {"request": request})


@router.post("/analyze", response_class=PlainTextResponse)
async def analyze_repository(repo_url: str = Form(...)):
    """
    Analyze a public GitHub repository and return a Markdown report.

    Args:
        repo_url: Public GitHub repository URL (e.g., https://github.com/owner/repo)

    Returns:
        Markdown formatted analysis report
    """
    # Validate URL
    if not validate_github_url(repo_url):
        raise HTTPException(
            status_code=400,
            detail="Invalid GitHub URL. Please provide a valid public GitHub repository URL."
        )

    # Clone repository
    clone_path = clone_repo(repo_url, verbose=False)
    if not clone_path:
        raise HTTPException(
            status_code=400,
            detail="Failed to clone repository. Make sure it's a public repository."
        )

    try:
        # Detect stack
        stack_info = detect_stack(str(clone_path))

        # Run analyzers
        analysis_results = run_all_analyzers(str(clone_path), stack_info, verbose=False)

        # Generate report (without AI analysis for now - can be added later)
        report = generate_report(
            repo_url=repo_url,
            stack_info=stack_info,
            analysis_results=analysis_results,
            ai_insights=None
        )

        return report

    finally:
        # Always cleanup the cloned repository
        cleanup_repo(clone_path)
