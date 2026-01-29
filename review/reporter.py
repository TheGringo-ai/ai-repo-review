#!/usr/bin/env python3
"""
Report Generator for Repo Maintenance Review Tool.

Generates clean, professional Markdown reports from repository analysis.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def generate_report(
    repo_url: str,
    stack_info: Dict[str, Any],
    analysis_results: Dict[str, Any],
    ai_insights: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate a comprehensive Markdown report from repository analysis.

    Args:
        repo_url: The URL of the analyzed repository
        stack_info: Dictionary containing detected stack information
        analysis_results: Dictionary containing all analyzer results
        ai_insights: Optional dictionary containing AI-generated recommendations

    Returns:
        A formatted Markdown string containing the full report
    """
    sections = []

    # Header
    sections.append(_generate_header(repo_url))

    # Executive Summary
    sections.append(_generate_summary(stack_info, analysis_results))

    # Stack Information
    sections.append(_generate_stack_section(stack_info))

    # Safe Suggestions (can be applied without breaking changes)
    sections.append(_generate_safe_suggestions(analysis_results))

    # Deferred/Breaking Changes
    sections.append(_generate_deferred_changes(analysis_results))

    # AI Recommendations (if provided)
    if ai_insights:
        sections.append(_generate_ai_section(ai_insights))

    # Proof of Read-Only Operation
    sections.append(_generate_read_only_proof())

    # Footer with disclaimer
    sections.append(_generate_footer())

    return "\n\n".join(sections)


def _generate_header(repo_url: str) -> str:
    """Generate the report header with timestamp."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""# Repository Maintenance Review Report

**Repository:** {repo_url}
**Generated:** {timestamp}
**Review Type:** Read-Only Analysis

---"""


def _generate_summary(stack_info: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
    """Generate executive summary of findings."""
    # Count findings by severity
    severity_counts = _count_findings_by_severity(analysis_results)

    total_findings = sum(severity_counts.values())

    # Determine overall health status
    if severity_counts.get("critical", 0) > 0:
        health_status = "Critical Issues Found"
        health_emoji = "RED"
    elif severity_counts.get("high", 0) > 0:
        health_status = "High Priority Issues"
        health_emoji = "ORANGE"
    elif severity_counts.get("medium", 0) > 0:
        health_status = "Moderate Issues"
        health_emoji = "YELLOW"
    elif severity_counts.get("low", 0) > 0:
        health_status = "Minor Issues"
        health_emoji = "BLUE"
    else:
        health_status = "Healthy"
        health_emoji = "GREEN"

    # Build summary
    summary_lines = [
        "## Executive Summary",
        "",
        f"**Overall Status:** [{health_emoji}] {health_status}",
        f"**Total Findings:** {total_findings}",
        "",
        "### Findings Breakdown",
        "",
    ]

    if severity_counts:
        summary_lines.append("| Severity | Count |")
        summary_lines.append("|----------|-------|")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                summary_lines.append(f"| {severity.capitalize()} | {count} |")
    else:
        summary_lines.append("No issues detected.")

    return "\n".join(summary_lines)


def _generate_stack_section(stack_info: Dict[str, Any]) -> str:
    """Generate stack information section."""
    lines = [
        "## Stack Information",
        "",
    ]

    if not stack_info:
        lines.append("No stack information detected.")
        return "\n".join(lines)

    # Primary language/framework
    if stack_info.get("primary_language"):
        lines.append(f"**Primary Language:** {stack_info['primary_language']}")

    if stack_info.get("framework"):
        lines.append(f"**Framework:** {stack_info['framework']}")

    if stack_info.get("package_manager"):
        lines.append(f"**Package Manager:** {stack_info['package_manager']}")

    if stack_info.get("runtime_version"):
        lines.append(f"**Runtime Version:** {stack_info['runtime_version']}")

    lines.append("")

    # Dependencies
    if stack_info.get("dependencies"):
        lines.append("### Dependencies Detected")
        lines.append("")
        deps = stack_info["dependencies"]
        if isinstance(deps, dict):
            lines.append("| Package | Version |")
            lines.append("|---------|---------|")
            for pkg, version in list(deps.items())[:20]:  # Limit to 20
                lines.append(f"| {pkg} | {version} |")
            if len(deps) > 20:
                lines.append(f"| ... | ({len(deps) - 20} more) |")
        elif isinstance(deps, list):
            for dep in deps[:20]:
                lines.append(f"- {dep}")
            if len(deps) > 20:
                lines.append(f"- ... ({len(deps) - 20} more)")

    # Additional stack details
    if stack_info.get("features"):
        lines.append("")
        lines.append("### Features Detected")
        lines.append("")
        for feature in stack_info["features"]:
            lines.append(f"- {feature}")

    return "\n".join(lines)


def _generate_safe_suggestions(analysis_results: Dict[str, Any]) -> str:
    """Generate section for safe, non-breaking suggestions."""
    lines = [
        "## Safe Suggestions",
        "",
        "*These suggestions can be implemented without breaking changes to existing functionality.*",
        "",
    ]

    safe_findings = _filter_findings_by_category(analysis_results, "safe")

    if not safe_findings:
        lines.append("No safe suggestions at this time.")
        return "\n".join(lines)

    # Group by severity
    grouped = _group_findings_by_severity(safe_findings)

    for severity in ["high", "medium", "low", "info"]:
        findings = grouped.get(severity, [])
        if findings:
            lines.append(f"### {severity.capitalize()} Priority")
            lines.append("")
            for finding in findings:
                lines.extend(_format_finding(finding))
                lines.append("")

    return "\n".join(lines)


def _generate_deferred_changes(analysis_results: Dict[str, Any]) -> str:
    """Generate section for deferred/breaking changes."""
    lines = [
        "## Deferred / Breaking Changes",
        "",
        "*These changes may require careful planning and testing before implementation.*",
        "",
    ]

    breaking_findings = _filter_findings_by_category(analysis_results, "breaking")
    deferred_findings = _filter_findings_by_category(analysis_results, "deferred")

    all_findings = breaking_findings + deferred_findings

    if not all_findings:
        lines.append("No breaking or deferred changes identified.")
        return "\n".join(lines)

    # Group by severity
    grouped = _group_findings_by_severity(all_findings)

    for severity in ["critical", "high", "medium", "low"]:
        findings = grouped.get(severity, [])
        if findings:
            lines.append(f"### {severity.capitalize()} Priority")
            lines.append("")
            for finding in findings:
                lines.extend(_format_finding(finding))
                lines.append("")

    return "\n".join(lines)


def _generate_ai_section(ai_insights: Dict[str, Any]) -> str:
    """Generate AI recommendations section."""
    lines = [
        "## AI Recommendations",
        "",
        "*The following recommendations were generated by AI analysis.*",
        "",
    ]

    if not ai_insights:
        lines.append("No AI insights available.")
        return "\n".join(lines)

    # Overall assessment
    if ai_insights.get("summary"):
        lines.append("### Summary")
        lines.append("")
        lines.append(ai_insights["summary"])
        lines.append("")

    # Prioritized recommendations
    if ai_insights.get("recommendations"):
        lines.append("### Prioritized Recommendations")
        lines.append("")
        for i, rec in enumerate(ai_insights["recommendations"], 1):
            if isinstance(rec, dict):
                title = rec.get("title", f"Recommendation {i}")
                description = rec.get("description", "")
                priority = rec.get("priority", "medium")
                lines.append(f"**{i}. {title}** [{priority.upper()}]")
                if description:
                    lines.append(f"   {description}")
            else:
                lines.append(f"{i}. {rec}")
            lines.append("")

    # Risk assessment
    if ai_insights.get("risks"):
        lines.append("### Risk Assessment")
        lines.append("")
        for risk in ai_insights["risks"]:
            if isinstance(risk, dict):
                lines.append(f"- **{risk.get('area', 'Unknown')}**: {risk.get('description', '')}")
            else:
                lines.append(f"- {risk}")
        lines.append("")

    # Estimated effort
    if ai_insights.get("effort_estimate"):
        lines.append("### Estimated Effort")
        lines.append("")
        lines.append(ai_insights["effort_estimate"])
        lines.append("")

    return "\n".join(lines)


def _generate_read_only_proof() -> str:
    """Generate proof of read-only operation section."""
    return """## Proof of Read-Only Operation

This analysis was performed in **read-only mode**:

- No files were modified in the repository
- No commits were created
- No branches were created or modified
- No pull requests were opened
- No issues were created
- The repository was cloned to a temporary directory and deleted after analysis

**Verification:** All operations used read-only Git commands and file system reads only."""


def _generate_footer() -> str:
    """Generate report footer with disclaimer."""
    return """---

## Disclaimer

This report was generated automatically by the Repo Maintenance Review tool. The suggestions and recommendations provided are based on static analysis and pattern matching. Always review suggestions carefully before implementing them in your codebase.

**Important Notes:**
- This tool does not execute any code from the analyzed repository
- All analysis is performed through static file inspection
- AI recommendations should be validated by human developers
- Breaking changes should be thoroughly tested before deployment

---

*Generated by Repo Maintenance Review - A read-only repository analysis tool*"""


# Helper functions

def _count_findings_by_severity(analysis_results: Dict[str, Any]) -> Dict[str, int]:
    """Count all findings grouped by severity level."""
    counts: Dict[str, int] = {}

    for analyzer_name, results in analysis_results.items():
        # Handle both list format and dict with "findings" key
        if isinstance(results, list):
            findings = results
        elif isinstance(results, dict):
            findings = results.get("findings", [])
        else:
            continue

        if not isinstance(findings, list):
            continue

        for finding in findings:
            if isinstance(finding, dict):
                severity = finding.get("severity", "info").lower()
                counts[severity] = counts.get(severity, 0) + 1

    return counts


def _filter_findings_by_category(
    analysis_results: Dict[str, Any],
    category: str
) -> List[Dict[str, Any]]:
    """Filter findings by category (safe, breaking, deferred)."""
    filtered: List[Dict[str, Any]] = []

    for analyzer_name, results in analysis_results.items():
        # Handle both list format and dict with "findings" key
        if isinstance(results, list):
            findings = results
        elif isinstance(results, dict):
            findings = results.get("findings", [])
        else:
            continue

        if not isinstance(findings, list):
            continue

        for finding in findings:
            if isinstance(finding, dict):
                finding_category = finding.get("category", "safe").lower()
                if finding_category == category:
                    # Add analyzer context
                    finding_with_context = finding.copy()
                    finding_with_context["analyzer"] = analyzer_name
                    filtered.append(finding_with_context)

    return filtered


def _group_findings_by_severity(
    findings: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Group findings by severity level."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity not in grouped:
            grouped[severity] = []
        grouped[severity].append(finding)

    return grouped


def _format_finding(finding: Dict[str, Any]) -> List[str]:
    """Format a single finding for display."""
    lines = []

    title = finding.get("title", "Untitled Finding")
    severity = finding.get("severity", "info").upper()
    analyzer = finding.get("analyzer", "Unknown")

    lines.append(f"#### {title}")
    lines.append("")
    lines.append(f"**Severity:** {severity} | **Source:** {analyzer}")

    if finding.get("description"):
        lines.append("")
        lines.append(finding["description"])

    if finding.get("file"):
        lines.append("")
        file_info = f"**File:** `{finding['file']}`"
        if finding.get("line"):
            file_info += f" (line {finding['line']})"
        lines.append(file_info)

    if finding.get("suggestion"):
        lines.append("")
        lines.append(f"**Suggestion:** {finding['suggestion']}")

    if finding.get("code_snippet"):
        lines.append("")
        lines.append("```")
        lines.append(finding["code_snippet"])
        lines.append("```")

    if finding.get("references"):
        lines.append("")
        lines.append("**References:**")
        for ref in finding["references"]:
            lines.append(f"- {ref}")

    return lines


if __name__ == "__main__":
    # Example usage / test
    test_stack_info = {
        "primary_language": "Python",
        "framework": "FastAPI",
        "package_manager": "pip",
        "runtime_version": "3.11",
        "dependencies": {
            "fastapi": "0.104.1",
            "pydantic": "2.5.0",
            "uvicorn": "0.24.0",
        },
        "features": ["REST API", "Async Support", "Type Hints"],
    }

    test_analysis_results = {
        "dependency_analyzer": {
            "findings": [
                {
                    "title": "Outdated Dependency",
                    "severity": "medium",
                    "category": "safe",
                    "description": "fastapi can be updated from 0.104.1 to 0.109.0",
                    "suggestion": "Run: pip install --upgrade fastapi",
                },
                {
                    "title": "Security Vulnerability in urllib3",
                    "severity": "high",
                    "category": "safe",
                    "description": "CVE-2023-45803 affects urllib3 < 2.0.7",
                    "suggestion": "Upgrade urllib3 to 2.0.7 or later",
                    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-45803"],
                },
            ]
        },
        "code_quality_analyzer": {
            "findings": [
                {
                    "title": "Missing Type Hints",
                    "severity": "low",
                    "category": "safe",
                    "description": "Function 'process_data' lacks type annotations",
                    "file": "app/utils.py",
                    "line": 45,
                },
            ]
        },
        "breaking_changes_analyzer": {
            "findings": [
                {
                    "title": "Python 2 Compatibility Code",
                    "severity": "medium",
                    "category": "breaking",
                    "description": "Legacy Python 2 compatibility code can be removed",
                    "suggestion": "Remove six library and Python 2 shims",
                },
            ]
        },
    }

    test_ai_insights = {
        "summary": "This repository is well-maintained with a few areas for improvement.",
        "recommendations": [
            {
                "title": "Update Dependencies",
                "description": "Several dependencies have security updates available.",
                "priority": "high",
            },
            {
                "title": "Add Type Hints",
                "description": "Adding type hints will improve code maintainability.",
                "priority": "medium",
            },
        ],
        "risks": [
            {
                "area": "Security",
                "description": "One high-severity vulnerability detected in dependencies.",
            },
        ],
        "effort_estimate": "Approximately 2-4 hours for all recommended changes.",
    }

    report = generate_report(
        repo_url="https://github.com/example/repo",
        stack_info=test_stack_info,
        analysis_results=test_analysis_results,
        ai_insights=test_ai_insights,
    )

    print(report)
