#!/usr/bin/env python3
"""
AI Review Module - Standalone version without external dependencies.

AI analysis is optional and disabled by default in this standalone version.
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional, List

# AI is disabled in standalone version
GEMINI_AVAILABLE = False


def get_ai_analysis(
    clone_path: Path,
    stack_info: Dict[str, Any],
    analysis_results: Dict[str, List[Dict]]
) -> Optional[Dict[str, Any]]:
    """
    Get AI analysis of the repository.

    Returns structured insights or None if AI is unavailable.

    Note: In this standalone version, AI analysis is disabled.
    """
    if not GEMINI_AVAILABLE:
        return None

    return None


def _build_context(
    clone_path: Path,
    stack_info: Dict[str, Any],
    analysis_results: Dict[str, List[Dict]]
) -> str:
    """Build context string for AI."""
    lines = []

    # Stack info
    lines.append(f"Language: {stack_info.get('primary_language', 'Unknown')}")
    lines.append(f"Frameworks: {', '.join(stack_info.get('frameworks', [])) or 'None'}")
    lines.append(f"Has Tests: {stack_info.get('has_tests', False)}")
    lines.append(f"Has CI: {stack_info.get('has_ci', False)}")
    lines.append("")

    # Existing findings
    lines.append("EXISTING FINDINGS:")
    for category, findings in analysis_results.items():
        if findings:
            lines.append(f"\n{category.upper()}:")
            for f in findings[:5]:  # Limit per category
                lines.append(f"  - [{f.get('severity', '?')}] {f.get('description', '')}")

    # Sample files (limited)
    lines.append("\nKEY FILES PRESENT:")
    path = Path(clone_path)
    key_files = ["README.md", "requirements.txt", "package.json", "Dockerfile", ".env.example"]
    for kf in key_files:
        if (path / kf).exists():
            lines.append(f"  - {kf}")

    return "\n".join(lines)


def _parse_ai_response(response: str) -> Dict[str, Any]:
    """Parse AI response into structured format."""
    result = {
        "summary": "",
        "recommendations": [],
        "risk_areas": []
    }

    if not response:
        return result

    lines = response.strip().split("\n")
    current_section = None

    for line in lines:
        line = line.strip()
        if not line:
            continue

        if line.startswith("SUMMARY:"):
            current_section = "summary"
            continue
        elif line.startswith("RECOMMENDATIONS:"):
            current_section = "recommendations"
            continue
        elif line.startswith("RISK_AREAS:"):
            current_section = "risk_areas"
            continue

        if current_section == "summary":
            result["summary"] += line + " "
        elif current_section == "recommendations":
            if line[0].isdigit() and "." in line[:3]:
                # Parse "1. Title - Description"
                parts = line.split(" - ", 1)
                title = parts[0].lstrip("0123456789. ")
                desc = parts[1] if len(parts) > 1 else ""
                result["recommendations"].append({
                    "title": title,
                    "description": desc
                })
        elif current_section == "risk_areas":
            if line.startswith("-"):
                line = line.lstrip("- ")
                if ":" in line:
                    area, desc = line.split(":", 1)
                    result["risk_areas"].append({
                        "area": area.strip(),
                        "description": desc.strip()
                    })

    result["summary"] = result["summary"].strip()
    return result


if __name__ == "__main__":
    # Test parsing
    test_response = """
SUMMARY:
This is a test summary of the repository.

RECOMMENDATIONS:
1. Fix security issue - Critical vulnerability found
2. Update dependencies - Several outdated packages
3. Add tests - No test coverage detected

RISK_AREAS:
- Security: Hardcoded credentials found
- Reliability: No error handling
"""
    parsed = _parse_ai_response(test_response)
    print("Parsed AI response:")
    print(f"  Summary: {parsed['summary']}")
    print(f"  Recommendations: {len(parsed['recommendations'])}")
    print(f"  Risk Areas: {len(parsed['risk_areas'])}")
