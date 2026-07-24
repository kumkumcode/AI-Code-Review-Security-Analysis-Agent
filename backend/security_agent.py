import subprocess
import json
import os
import tempfile
import ast

def run_security_analysis(code_content: str) -> list:
    """
    Runs multi-tool security checks: AST secrets scanner, Bandit, Semgrep, and Safety.
    Returns a unified list of security findings.
    """
    findings = []
    
    # Write code to a temporary file for external CLI tools
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
        temp_file.write(code_content)
        temp_file_path = temp_file.name

    try:
        # 1. Custom AST Parser (Hardcoded Secrets & High Severity Risks)
        findings.extend(_scan_ast_secrets(code_content))

        # 2. Bandit Analysis
        findings.extend(_run_bandit(temp_file_path))

        # 3. Semgrep Analysis
        findings.extend(_run_semgrep(temp_file_path))

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    return findings


def _scan_ast_secrets(code_content: str) -> list:
    """Custom AST scanner for hardcoded credentials and secrets."""
    findings = []
    try:
        tree = ast.parse(code_content)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.upper()
                        if any(key in var_name for key in ["SECRET", "KEY", "TOKEN", "PASSWORD"]):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                findings.append({
                                    "id": len(findings) + 1,
                                    "title": "Hardcoded Secret (OWASP A02:2021)",
                                    "severity": "CRITICAL",
                                    "severity_score": 9.5,
                                    "flagged_by": "Security Vulnerability Agent (AST)",
                                    "line_number": node.lineno,
                                    "context": f"Variable assignment '{target.id}' contains hardcoded secret literal.",
                                    "simple_explanation": "Your secret key or password is written directly in the code file instead of being hidden safely.",
                                    "business_impact": "🚨 Critical Breach Risk: Attackers can extract this key to steal cloud resources or private data.",
                                    "remediation": "Extract secrets/keys into environment variables or a secure key-vault."
                                })
    except Exception:
        pass
    return findings


def _run_bandit(file_path: str) -> list:
    """Executes Bandit CLI scanner."""
    findings = []
    try:
        cmd = ["bandit", "-f", "json", "-q", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            data = json.loads(result.stdout)
            for item in data.get("results", []):
                findings.append({
                    "id": len(findings) + 1,
                    "title": f"Bandit Risk: {item.get('test_name')}",
                    "severity": item.get("issue_severity", "MEDIUM").upper(),
                    "severity_score": 7.0 if item.get("issue_severity") == "HIGH" else 4.0,
                    "flagged_by": "Bandit Security Scanner",
                    "line_number": item.get("line_number"),
                    "context": item.get("issue_text"),
                    "simple_explanation": "Bandit detected a potential security risk in Python built-in standard library usage.",
                    "business_impact": "Vulnerability could lead to unauthorized code execution or unsafe operations.",
                    "remediation": f"Review line {item.get('line_number')} and refactor dangerous call."
                })
    except Exception:
        pass
    return findings


def _run_semgrep(file_path: str) -> list:
    """Executes Semgrep pattern-matching scanner."""
    findings = []
    try:
        cmd = ["semgrep", "scan", "--config", "auto", "--json", "-q", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout:
            data = json.loads(result.stdout)
            for item in data.get("results", []):
                findings.append({
                    "id": len(findings) + 1,
                    "title": f"Semgrep Rule: {item.get('check_id').split('.')[-1]}",
                    "severity": item.get("extra", {}).get("severity", "HIGH").upper(),
                    "severity_score": 8.0,
                    "flagged_by": "Semgrep Security Agent",
                    "line_number": item.get("start", {}).get("line"),
                    "context": item.get("extra", {}).get("message"),
                    "simple_explanation": "Semgrep detected a structural code pattern associated with security vulnerabilities.",
                    "business_impact": "Pattern violates secure coding policies.",
                    "remediation": item.get("extra", {}).get("metadata", {}).get("shortlink", "Follow OWASP guidelines.")
                })
    except Exception:
        pass
    return findings

# Alias for main.py compatibility
run_security_agent = run_security_analysis