import subprocess
import json
import os
import tempfile
from radon.complexity import cc_visit
from radon.metrics import mi_visit

def run_quality_analysis(code_content: str) -> dict:
    """
    Runs code quality tools: Pylint, Radon (Complexity/Maintainability), and Mypy (Type checking).
    Returns findings and overall complexity metrics.
    """
    findings = []
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(code_content)
        temp_file_path = temp_file.name

    try:
        # 1. Radon Complexity & Maintainability Metrics
        metrics = _run_radon_metrics(code_content)
        findings.extend(metrics.get("complexity_findings", []))

        # 2. Pylint Scan
        findings.extend(_run_pylint(temp_file_path))

        # 3. Mypy Type Analysis
        findings.extend(_run_mypy(temp_file_path))

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    return {
        "quality_findings": findings,
        "cyclomatic_complexity": metrics.get("average_complexity", 1.0),
        "maintainability_index": metrics.get("maintainability_score", 100.0)
    }


def _run_radon_metrics(code_content: str) -> dict:
    """Calculates Cyclomatic Complexity and Maintainability Index using Radon."""
    findings = []
    total_complexity = 0
    blocks_count = 0

    try:
        # Cyclomatic Complexity
        blocks = cc_visit(code_content)
        for block in blocks:
            total_complexity += block.complexity
            blocks_count += 1
            if block.complexity > 5:
                findings.append({
                    "id": len(findings) + 1,
                    "title": f"High Complexity Function: {block.name}",
                    "severity": "MEDIUM",
                    "severity_score": 5.0,
                    "flagged_by": "Radon Complexity Scanner",
                    "line_number": block.lineno,
                    "context": f"Function '{block.name}' has a Cyclomatic Complexity of {block.complexity}.",
                    "simple_explanation": "This function has too many nested conditions or logic paths, making it hard to test and maintain.",
                    "business_impact": "High complexity increases bug risk and developer onboarding time.",
                    "remediation": "Break down this function into smaller, single-purpose helper functions."
                })

        # Maintainability Index
        mi_score = mi_visit(code_content, multi=True)
    except Exception:
        mi_score = 100.0

    avg_complexity = round(total_complexity / blocks_count, 2) if blocks_count > 0 else 1.0

    return {
        "complexity_findings": findings,
        "average_complexity": avg_complexity,
        "maintainability_score": round(mi_score, 2)
    }


def _run_pylint(file_path: str) -> list:
    """Executes Pylint analysis."""
    findings = []
    try:
        cmd = ["pylint", "--output-format=json", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            data = json.loads(result.stdout)
            for item in data:
                if item.get("type") in ["error", "warning"]:
                    findings.append({
                        "id": len(findings) + 1,
                        "title": f"Pylint: {item.get('symbol')}",
                        "severity": "HIGH" if item.get("type") == "error" else "LOW",
                        "severity_score": 6.0 if item.get("type") == "error" else 3.0,
                        "flagged_by": "Pylint Quality Agent",
                        "line_number": item.get("line"),
                        "context": item.get("message"),
                        "simple_explanation": "Code violation or style issue flagged by Python standards.",
                        "business_impact": "Decreases code readability and maintainability over time.",
                        "remediation": f"Refactor code to fix standard convention: {item.get('symbol')}"
                    })
    except Exception:
        pass
    return findings


def _run_mypy(file_path: str) -> list:
    """Executes Mypy type checker."""
    findings = []
    try:
        cmd = ["mypy", "--hide-error-codes", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            for line in result.stdout.splitlines():
                if ": error:" in line:
                    parts = line.split(":")
                    line_num = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
                    msg = ":".join(parts[2:]).strip() if len(parts) > 2 else line
                    findings.append({
                        "id": len(findings) + 1,
                        "title": "Mypy: Static Type Error",
                        "severity": "MEDIUM",
                        "severity_score": 5.0,
                        "flagged_by": "Mypy Type Checker",
                        "line_number": line_num,
                        "context": msg,
                        "simple_explanation": "Type mismatch found during static analysis.",
                        "business_impact": "Type mismatches can trigger unexpected runtime crashes.",
                        "remediation": "Add explicit type hints or fix object assignment types."
                    })
    except Exception:
        pass
    return findings

# Alias for main.py compatibility
run_code_quality_agent = run_quality_analysis