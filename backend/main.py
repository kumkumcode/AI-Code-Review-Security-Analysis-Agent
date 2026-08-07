import sys
import os

# Explicitly add your absolute project root directory to Python's path
PROJECT_ROOT = r"C:\Users\smile\OneDrive\Desktop\ai-code-review-security-analysis"
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import time
import traceback
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Consistent relative imports for backend modules
from .remediation_agent import analyze_and_remediate
from .coordinator import CoordinatorAgent
from .pr_summary_agent import PRSummaryAgent
from .code_quality_agent import run_quality_analysis
from .security_agent import run_security_agent as run_security_analysis
from .rag_chat_agent import RAGChatAssistant
app = FastAPI(
    title="RAG-Enhanced AI Code Analysis Pipeline",
    description="Automated security and quality scanning with OWASP standards, ChromaDB RAG verification, and multi-agent remediation.",
    version="2.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the RAG Chat Assistant globally once at startup for high performance
chat_assistant = RAGChatAssistant()


# ==========================================
# 🛠️ Multi-Tool Execution Helper
# ==========================================
def run_full_analysis(code: str, filename: str = "test.py", api_key: Optional[str] = None) -> dict:
    start_time = time.time()

    # 1. Run Security Analysis
    security_res = run_security_analysis(code)
    
    # 2. Run Code Quality Analysis
    quality_res = run_quality_analysis(code)

    # Safely extract security findings (handles list or dict format)
    if isinstance(security_res, list):
        sec_findings = security_res
    elif isinstance(security_res, dict):
        sec_findings = security_res.get("findings", []) or security_res.get("security_findings", [])
    else:
        sec_findings = []

    # Safely extract quality findings (handles quality_findings key)
    if isinstance(quality_res, dict):
        qual_findings = quality_res.get("quality_findings", []) or quality_res.get("findings", [])
    elif isinstance(quality_res, list):
        qual_findings = quality_res
    else:
        qual_findings = []

    # Re-assign unique IDs across combined list so IDs don't collide
    combined_findings = sec_findings + qual_findings
    for idx, finding in enumerate(combined_findings, 1):
        finding["id"] = idx

    # 3. Generate LLM Auto-Fixes & Diffs (Milestone 2)
    for finding in combined_findings:
        if not finding.get("remediation"):
            snippet_context = finding.get("context", code)
            finding["remediation"] = analyze_and_remediate(snippet_context)
            
    # 4. Run Coordinator Agent & PR Summary Agent (Milestone 3 Orchestration)
    remediation_text = "Standard remediation applied."
    pr_summary_text = "No summary generated."
    
    if api_key:
        try:
            coordinator = CoordinatorAgent(api_key=api_key)
            coord_res = coordinator.orchestrate_workflow(code, sec_findings, qual_findings)
            remediation_text = coord_res.get("remediation_output", remediation_text)

            pr_agent = PRSummaryAgent(api_key=api_key)
            pr_summary_text = pr_agent.generate_summary(sec_findings, qual_findings, remediation_text)
        except Exception as agent_err:
            print(f"Warning: Milestone 3 Agent execution failed: {agent_err}")

    elapsed_ms = (time.time() - start_time) * 1000

    # Extract quality metrics if present
    complexity = quality_res.get("cyclomatic_complexity", 1.0) if isinstance(quality_res, dict) else 1.0
    maintainability = quality_res.get("maintainability_index", 100.0) if isinstance(quality_res, dict) else 100.0

    return {
        "execution_time_ms": elapsed_ms,
        "findings": combined_findings,
        "cyclomatic_complexity": complexity,
        "maintainability_index": maintainability,
        "pr_summary": pr_summary_text,
        "coordinator_remediation": remediation_text
    }


# ==========================================
# 📋 Pydantic Schemas (API Request/Response)
# ==========================================

class CodeScanRequest(BaseModel):
    code: str = Field(..., description="Raw code string to analyze")
    filename: str = Field(default="snippet.py", description="Filename or identifier including extension")
    api_key: Optional[str] = Field(default=None, description="Gemini API Key for LLM Agents")

class RAGVerification(BaseModel):
    verified: bool
    source: Optional[str] = None
    relevance_score: Optional[float] = None

class CodeDiff(BaseModel):
    before: str
    after: str

class FindingItem(BaseModel):
    id: int
    title: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    severity_score: float
    flagged_by: str
    line_number: int
    context: str
    simple_explanation: str      # 💡 Plain-English explanation
    business_impact: str         # 💡 Non-technical risk narrative
    code_diff: Optional[CodeDiff] = None # 💡 Before vs. After code fix
    rag_verification: RAGVerification
    remediation: str

class ScanResponse(BaseModel):
    filename: str
    execution_time_ms: float
    health_score: int            # 💡 Grade score (0-100%)
    health_grade: str            # 💡 Letter Grade ("A", "B", "C", "D", "F")
    executive_summary: str       # 💡 Plain-English summary
    total_findings: int
    summary_counts: dict
    findings: List[FindingItem]
    pr_summary: str              # 💡 Milestone 3 PR Review Output


# ==========================================
# 🚀 API Endpoints
# ==========================================

@app.get("/")
def health_check():
    return {
        "status": "online",
        "service": "RAG-Enhanced AI Code Review Engine",
        "phase": "Phase 3 - Milestone 3 Integration Active"
    }


@app.post("/api/v1/scan-code", response_model=ScanResponse)
def scan_code_snippet(payload: CodeScanRequest):
    """
    Accepts raw code as JSON text, runs multi-tool security and quality agents, 
    coordinator workflow, and PR summary generation.
    """
    if not payload.code.strip():
        raise HTTPException(status_code=400, detail="Code payload cannot be empty.")

    try:
        api_key = payload.api_key or os.getenv("GEMINI_API_KEY")
        report = run_full_analysis(payload.code, filename=payload.filename, api_key=api_key)
        return format_api_response(payload.filename, report)

    except Exception as e:
        print("\n=== PIPELINE CRASH TRACEBACK ===")
        traceback.print_exc()
        print("===============================\n")
        raise HTTPException(status_code=500, detail=f"Pipeline error: {str(e)}")


class ChatRequest(BaseModel):
    query: str
    code_context: Optional[str] = ""
    chat_history: Optional[List[dict]] = []
    api_key: Optional[str] = None

@app.post("/api/v1/chat")
def conversational_code_assistant(payload: ChatRequest):
    """
    RAG-powered conversational endpoint for answering code review questions.
    """
    try:
        answer = chat_assistant.get_response(
            query=payload.query,
            chat_history=payload.chat_history or [],
            code_context=payload.code_context or ""
        )
        return {"response": answer}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Chat assistant error: {str(e)}")


# ==========================================
# 🛠️ Helper Transformer
# ==========================================

def format_api_response(filename: str, pipeline_report: dict) -> ScanResponse:
    """Converts raw findings report into standardized, human-friendly Pydantic API response."""
    if not isinstance(pipeline_report, dict):
        pipeline_report = {}

    findings_list = pipeline_report.get("findings", [])
    
    summary_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    formatted_findings = []

    deductions = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
    current_score = 100

    for idx, f in enumerate(findings_list, 1):
        if not isinstance(f, dict):
            continue

        sev = str(f.get("severity", "MEDIUM")).upper()
        if sev in summary_counts:
            summary_counts[sev] += 1
            current_score -= deductions.get(sev, 10)
        else:
            summary_counts[sev] = 1

        current_score = max(0, current_score)

        verification_text = str(f.get("verification", ""))
        is_rag_verified = "RAG Verified" in verification_text
        kb_source = f.get("kb_reference") if is_rag_verified else None

        title = str(f.get("category", f.get("title", "Code Issue")))
        context_str = str(f.get("context", ""))

        simple_exp = f"This line of code contains a {sev.lower()}-risk pattern that violates security/quality guidelines."
        impact = "May degrade application stability or expose internal data."

        title_lower = title.lower()
        if "secret" in title_lower or "key" in title_lower:
            simple_exp = "Your secret key or password is written directly in the code file instead of being hidden safely."
            impact = "💸 Critical Breach Risk: Attackers can extract this key to steal cloud resources or private data."
        elif "sql" in title_lower or "injection" in title_lower:
            simple_exp = "Database queries are joined with untrusted user input directly."
            impact = "🚨 Data Theft: Attackers can view, alter, or delete database tables."
        elif "duplication" in title_lower:
            simple_exp = "This block of code is repeated multiple times."
            impact = "🧹 Maintenance Overhead: Bugs fixed in one place might remain unfixed in duplicate code."

        remediation_text = str(f.get("remediation", "Review flagged code block for security best practices."))
        
        code_diff = CodeDiff(
            before=context_str if context_str else "Scanned code snippet",
            after=f"# Safe Alternative:\n# {remediation_text}"
        )

        formatted_findings.append(
            FindingItem(
                id=idx,
                title=title,
                severity=sev,
                severity_score=float(f.get("score", f.get("severity_score", 5.0))),
                flagged_by=str(f.get("agent_id", f.get("flagged_by", "Analysis Agent"))),
                line_number=int(f.get("line", f.get("line_number", 0))),
                context=context_str,
                simple_explanation=simple_exp,
                business_impact=impact,
                code_diff=code_diff,
                rag_verification=RAGVerification(
                    verified=is_rag_verified,
                    source=kb_source,
                    relevance_score=None
                ),
                remediation=remediation_text
            )
        )

    if current_score >= 90:
        grade = "A (Excellent)"
    elif current_score >= 75:
        grade = "B (Good)"
    elif current_score >= 60:
        grade = "C (Needs Attention)"
    elif current_score >= 40:
        grade = "D (High Risk)"
    else:
        grade = "F (Critical Risk)"

    total_issues = len(formatted_findings)
    if total_issues == 0:
        summary = "✅ Your codebase passed all scans with flying colors! No security vulnerabilities or quality flaws detected."
    else:
        crit_count = summary_counts.get("CRITICAL", 0)
        high_count = summary_counts.get("HIGH", 0)
        summary = f"⚠️ Scan complete: We found {total_issues} issue(s) ({crit_count} Critical, {high_count} High). Overall code health is rated at {current_score}% (Grade {grade}). Review the recommended fixes below to secure your code."

    return ScanResponse(
        filename=filename,
        execution_time_ms=float(pipeline_report.get("execution_time_ms", 0.0)),
        health_score=current_score,
        health_grade=grade,
        executive_summary=summary,
        total_findings=total_issues,
        summary_counts=summary_counts,
        findings=formatted_findings,
        pr_summary=pipeline_report.get("pr_summary", "PR summary generation pending.")
    )


# ==========================================
# 🖥️ Streamlit Frontend Interface
# ==========================================
import streamlit as st
import requests

# Only runs when executed via Streamlit (streamlit run main.py)
if __name__ == "__main__" or "streamlit" in sys.modules:
    st.title("🤖 RAG-Enhanced AI Code Reviewer")

    st.subheader("💬 Conversational Code Assistant")

    if "messages" not in st.session_state:
        st.session_state.messages = []

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if user_query := st.chat_input("Ask a question about your code or security findings..."):
        st.session_state.messages.append({"role": "user", "content": user_query})
        with st.chat_message("user"):
            st.markdown(user_query)

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    current_code = st.session_state.get("scanned_code", "")
                    
                    payload = {
                        "query": user_query,
                        "code_context": current_code,
                        "chat_history": st.session_state.messages[:-1]
                    }
                    
                    response = requests.post("http://localhost:8000/api/v1/chat", json=payload)
                    if response.status_code == 200:
                        answer = response.json().get("response", "No response returned.")
                    else:
                        answer = f"Error from backend: {response.text}"
                    
                    st.markdown(answer)
                    st.session_state.messages.append({"role": "assistant", "content": answer})
                except Exception as e:
                    error_msg = f"Failed to connect to backend chat endpoint: {e}"
                    st.markdown(error_msg)
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})