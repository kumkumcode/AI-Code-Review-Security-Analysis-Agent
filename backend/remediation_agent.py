import os
import time
from pathlib import Path
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Explicitly point at the .env file sitting next to this file (backend/.env)
# instead of relying on load_dotenv()'s automatic discovery — that discovery
# depends on the current working directory / how the script was launched,
# which is exactly why this worked under `streamlit run` but failed under
# `python -m uvicorn backend.main:app` run from a different folder.
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

_api_key = os.getenv("GEMINI_API_KEY")
if not _api_key:
    raise ValueError(
        f"GEMINI_API_KEY not found. Checked for a .env file at: {ENV_PATH} "
        f"— make sure that file exists and contains a line like "
        f"GEMINI_API_KEY=your_key_here"
    )

# api_version='v1alpha' helps with the newer "AQ." format API keys,
# which some client/API version combinations don't fully support yet.
client = genai.Client(
    api_key=_api_key,
    http_options=types.HttpOptions(api_version="v1alpha")
)

# Try the newest model first; fall back to a calmer, stable model if it's overloaded.
MODELS_TO_TRY = ["gemini-3.6-flash", "gemini-2.5-flash"]


class RemediationAgentError(Exception):
    """Raised when the agent cannot get a usable response from Gemini,
    with a message that's safe to show directly in the UI."""
    pass


def analyze_and_remediate(code_snippet: str) -> str:
    system_instruction = (
        "You are an educational software engineering assistant. Your goal is to conduct "
        "defensive code reviews, explain static analysis findings, and show developers "
        "how to write safe, secure software."
    )

    prompt = f"""
    You are an expert static application security testing (SAST) agent. 
    Analyze the following source code snippet and return a structured Markdown report covering:

    1. **LANGUAGE & METADATA**:
       - Detected Language (e.g., Python, Java, C++, JavaScript)
       - Primary Scope & Quality Score (1 to 10)

    2. **PRIMARY ISSUES & VULNERABILITIES**:
       - Summary table of defects with: Problem Name, Affected Line Number(s), Severity (Critical/High/Medium/Low), Category

    3. **SEVERITY SCORING & JUSTIFICATION**:
       - Overall Severity Rating (Critical/High/Medium/Low)
       - Detailed justification for why this rating was given based on exploitability, impact, and system stability.

    4. **CODE DUPLICATION & QUALITY ANALYSIS**:
       - Code Duplication Rating (High/Medium/Low/None Detected)
       - Identified anti-patterns, redundant logic, or unhandled runtime crashes (e.g., ZeroDivisionError, unhandled files).

    5. **AGENT REMEDIATION & RECOMMENDATIONS**:
       - Direct actionable steps to fix each issue.
       - Recommended security standards or best practices (e.g., parameterized queries, defensive input checks).

    6. **REFACTORED SECURE CODE**:
       - Provide the fully corrected, clean, and runnable code block.

    Target Code:
    ```
    {code_snippet}
    ```
    """

    last_error = None

    # Try each model in order. For each model, retry a couple of times
    # if the error looks like a temporary "server busy" (503) error.
    for model_name in MODELS_TO_TRY:
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                    )
                )
                return response.text

            except Exception as e:
                last_error = e
                error_text = str(e)

                # --- Case 1: server is temporarily busy — worth retrying ---
                if "503" in error_text or "UNAVAILABLE" in error_text:
                    time.sleep(2)
                    continue

                # --- Case 2: API key itself is invalid/unauthenticated —
                # retrying or switching models won't help, so fail fast
                # with a clear, presentation-safe message instead of a
                # raw Google error dump. ---
                if any(marker in error_text for marker in
                       ["API_KEY_INVALID", "401", "UNAUTHENTICATED",
                        "ACCESS_TOKEN_TYPE_UNSUPPORTED"]):
                    raise RemediationAgentError(
                        "The AI engine could not authenticate with Gemini. "
                        "This usually means the API key is missing, invalid, "
                        "or not yet activated for this project — check the "
                        ".env file and the key's status in Google AI Studio."
                    ) from e

                # --- Case 3: anything else — no point retrying, raise as-is ---
                raise

    # If we reach here, every model and every retry failed on 503s.
    raise RemediationAgentError(
        "The AI engine is currently overloaded and did not respond after "
        "several attempts. Please wait a moment and try again."
    ) from last_error