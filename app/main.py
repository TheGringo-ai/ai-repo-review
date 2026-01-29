"""
AI Repo Review - Standalone FastAPI Application

A read-only repository analysis tool for public GitHub repositories.
"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path

from app.routers import review

# Create FastAPI app
app = FastAPI(
    title="AI Repo Review",
    description="Analyze public GitHub repositories for security vulnerabilities, outdated dependencies, and code quality issues.",
    version="1.0.0",
)

# Get the app directory
APP_DIR = Path(__file__).parent

# Mount static files if they exist
static_dir = APP_DIR / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Include routers
app.include_router(review.router)


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "ai-repo-review"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
