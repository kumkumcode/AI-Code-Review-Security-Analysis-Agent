import ast
import os
import re

class VulnerabilityScoreEngine:
    """Calculates granular risk scores (0.0 - 10.0) based on severity metrics."""
    
    BASE_SCORES = {
        "SQL Injection Risk (OWASP A03:2021)": 8.8,
        "Hardcoded Secret (OWASP A02:2021)": 9.5,
        "High Cognitive Complexity": 4.5,
        "Empty Catch / Exception Suppression": 5.0,
    }

    @classmethod
    def calculate_score(cls, category, depth=1):
        base = cls.BASE_SCORES.get(category, 3.0)
        if "Complexity" in category:
            score = min(10.0, base + (depth * 0.5))
        else:
            score = base
            
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return round(score, 1), severity


class StructuralASTEngine:
    def __init__(self, file_path):
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Target path not found: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            self.source_code = f.read()
        self.findings = []

    def scan_python(self):
        """Full Python AST scanning for OWASP vulnerabilities and code complexity."""
        try:
            tree = ast.parse(self.source_code)
        except SyntaxError as e:
            self.findings.append({
                "type": "Syntax Error",
                "category": "Unparseable Python Syntax",
                "line": e.lineno or 1,
                "context": f"Syntax error preventing full AST parse: {e.msg}",
                "score": 3.0,
                "severity": "LOW"
            })
            return

        # Track dynamically constructed SQL variables
        formatted_sql_vars = set()

        for node in ast.walk(tree):
            # OWASP A02: Hardcoded Secrets
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Track formatted strings assigned to variable names containing 'query' or 'sql'
                        if any(k in target.id.lower() for k in ["query", "sql", "stmt"]):
                            if isinstance(node.value, (ast.JoinedStr, ast.BinOp)):
                                formatted_sql_vars.add(target.id)
                        
                        if any(k in target.id.upper() for k in ["SECRET", "KEY", "TOKEN", "PASSWORD"]):
                            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                cat = "Hardcoded Secret (OWASP A02:2021)"
                                score, sev = VulnerabilityScoreEngine.calculate_score(cat)
                                self.findings.append({
                                    "type": "Security Vulnerability",
                                    "category": cat,
                                    "line": node.lineno,
                                    "context": f"Variable assignment '{target.id}' contains hardcoded secret literal.",
                                    "score": score,
                                    "severity": sev
                                })

            # OWASP A03: SQL Injection via cursor/db calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr in ['execute', 'raw', 'query']:
                    if node.args:
                        first_arg = node.args[0]
                        # Direct formatted string OR passing a variable containing formatted SQL string
                        is_dynamic_str = isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
                        is_dynamic_var = isinstance(first_arg, ast.Name) and first_arg.id in formatted_sql_vars

                        if is_dynamic_str or is_dynamic_var:
                            cat = "SQL Injection Risk (OWASP A03:2021)"
                            score, sev = VulnerabilityScoreEngine.calculate_score(cat)
                            self.findings.append({
                                "type": "Security Vulnerability",
                                "category": cat,
                                "line": node.lineno,
                                "context": f"Dynamic string query executed via '{node.func.attr}'.",
                                "score": score,
                                "severity": sev
                            })

            # Code Smell: Deep Cognitive Complexity
            if isinstance(node, ast.FunctionDef):
                max_depth = 0
                for sub_node in ast.walk(node):
                    if isinstance(sub_node, ast.If):
                        current_depth = 1
                        for child in ast.walk(sub_node):
                            if isinstance(child, ast.If) and child != sub_node:
                                current_depth += 1
                        max_depth = max(max_depth, current_depth)

                if max_depth >= 3:
                    cat = "High Cognitive Complexity"
                    score, sev = VulnerabilityScoreEngine.calculate_score(cat, depth=max_depth)
                    self.findings.append({
                        "type": "Code Smell",
                        "category": cat,
                        "line": node.lineno,
                        "context": f"Function '{node.name}' has nested control blocks up to depth {max_depth}.",
                        "score": score,
                        "severity": sev
                    })

    def scan_java(self):
        """Structured lexical scanning for Java source files."""
        lines = self.source_code.splitlines()
        
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()

            # OWASP A03: SQL Injection (Concatenation in query strings)
            if re.search(r'(SELECT|INSERT|UPDATE|DELETE).*\+', clean_line, re.IGNORECASE):
                cat = "SQL Injection Risk (OWASP A03:2021)"
                score, sev = VulnerabilityScoreEngine.calculate_score(cat)
                self.findings.append({
                    "type": "Security Vulnerability",
                    "category": cat,
                    "line": idx,
                    "context": "Unparameterized SQL statement built using dynamic string concatenation.",
                    "score": score,
                    "severity": sev
                })

            # OWASP A02: Hardcoded Secrets (Matches static fields, local vars, constants)
            if re.search(r'(SECRET|PASSWORD|API_KEY|TOKEN)\s*=|\:', clean_line, re.IGNORECASE):
                if '"' in clean_line or "'" in clean_line:
                    cat = "Hardcoded Secret (OWASP A02:2021)"
                    score, sev = VulnerabilityScoreEngine.calculate_score(cat)
                    self.findings.append({
                        "type": "Security Vulnerability",
                        "category": cat,
                        "line": idx,
                        "context": "Sensitive credentials assigned directly to literal string.",
                        "score": score,
                        "severity": sev
                    })

            # Code Smell: Empty Catch Block (Single or multi-line)
            if "catch" in clean_line:
                # Inspect window around catch line for empty block body
                window_lines = [l.strip() for l in lines[idx-1:min(idx+3, len(lines))]]
                window_str = " ".join(window_lines)
                if re.search(r'catch\s*\([^\)]+\)\s*\{\s*\}', window_str):
                    cat = "Empty Catch / Exception Suppression"
                    score, sev = VulnerabilityScoreEngine.calculate_score(cat)
                    self.findings.append({
                        "type": "Code Smell",
                        "category": cat,
                        "line": idx,
                        "context": "Swallowed exception caught without logging or handling mechanism.",
                        "score": score,
                        "severity": sev
                    })

            # Code Smell: Deeply Nested Blocks
            if clean_line.startswith("if") and ("(" in clean_line):
                nest_count = 0
                for lookahead in lines[idx-1:min(idx+12, len(lines))]:
                    if "if" in lookahead:
                        nest_count += 1
                if nest_count >= 3:
                    cat = "High Cognitive Complexity"
                    score, sev = VulnerabilityScoreEngine.calculate_score(cat, depth=nest_count)
                    self.findings.append({
                        "type": "Code Smell",
                        "category": cat,
                        "line": idx,
                        "context": f"Control structure contains deeply nested conditional logic (approx depth: {nest_count}).",
                        "score": score,
                        "severity": sev
                    })
                    break

    def run_all(self):
        if self.file_path.endswith(".py"):
            self.scan_python()
        elif self.file_path.endswith(".java"):
            self.scan_java()
        return self.findings 