import os
import time
from pathlib import Path
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Explicitly point at the .env file sitting next to this file (backend/.env)
# instead of relying on load_dotenv()'s automatic discovery.
ENV_PATH = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)

_api_key = os.getenv("GEMINI_API_KEY")
if not _api_key:
    raise ValueError(
        f"GEMINI_API_KEY not found. Checked for a .env file at: {ENV_PATH} "
        f"— make sure that file exists and contains a line like "
        f"GEMINI_API_KEY=your_key_here"
    )

client = genai.Client(
    api_key=_api_key,
    http_options=types.HttpOptions(api_version="v1alpha")
)

# gemini-3.5-flash-lite is the fastest tier — tried first so the audit feels
# quick. Falls back to gemini-3.6-flash (slower but more thorough) if the
# lite model is unavailable or errors out.
MODELS_TO_TRY = ["gemini-3.5-flash-lite", "gemini-3.6-flash"]


class RemediationAgentError(Exception):
    """Raised when the agent cannot get a usable response from Gemini,
    with a message that's safe to show directly in the UI."""
    pass


def _build_prompt(code_snippet: str) -> tuple[str, str]:
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
       - Brief justification (2-3 sentences) based on exploitability, impact, and system stability.

    4. **CODE DUPLICATION & QUALITY ANALYSIS**:
       - Code Duplication Rating (High/Medium/Low/None Detected)
       - Identified anti-patterns, redundant logic, or unhandled runtime crashes — as a short bullet list.

    5. **AGENT REMEDIATION & RECOMMENDATIONS**:
       - Direct actionable steps to fix each issue, as a concise bullet list.

    6. **REFACTORED SECURE CODE**:
       - Provide the fully corrected, clean, and runnable code block.

    Keep sections 3-5 concise — bullet points over long paragraphs — so the report
    generates quickly without losing the essential information.

    Target Code:
    ```
    {code_snippet}
    ```
    """
    return system_instruction, prompt


def analyze_and_remediate_stream(code_snippet: str, on_chunk=None) -> str:
    """
    Same analysis as analyze_and_remediate(), but streams the response as it's
    generated. If on_chunk is provided, it's called with the accumulated text
    so far after every chunk — used to show live progress in the UI instead of
    a frozen spinner. Returns the final full report text either way.
    """
    system_instruction, prompt = _build_prompt(code_snippet)
    last_error = None

    for model_name in MODELS_TO_TRY:
        for attempt in range(2):
            try:
                full_text = ""
                stream = client.models.generate_content_stream(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_instruction,
                    )
                )
                for chunk in stream:
                    if chunk.text:
                        full_text += chunk.text
                        if on_chunk:
                            on_chunk(full_text)

                if full_text.strip():
                    return full_text
                # Empty stream — treat like a failure and retry/fallback.
                raise RuntimeError("Model returned an empty response.")

            except Exception as e:
                last_error = e
                error_text = str(e)

                if "503" in error_text or "UNAVAILABLE" in error_text:
                    time.sleep(2)
                    continue

                if "404" in error_text or "NOT_FOUND" in error_text:
                    # This model isn't available — move to the next one.
                    break

                if any(marker in error_text for marker in
                       ["API_KEY_INVALID", "401", "UNAUTHENTICATED",
                        "ACCESS_TOKEN_TYPE_UNSUPPORTED"]):
                    raise RemediationAgentError(
                        "The AI engine could not authenticate with Gemini. "
                        "This usually means the API key is missing, invalid, "
                        "or not yet activated for this project — check the "
                        ".env file and the key's status in Google AI Studio."
                    ) from e

                raise

    raise RemediationAgentError(
        "The AI engine is currently overloaded and did not respond after "
        "several attempts. Please wait a moment and try again."
    ) from last_error


def analyze_and_remediate(code_snippet: str) -> str:
    """Non-streaming version — kept for any code that just wants the final
    text (e.g. background/batch calls). UI code should prefer
    analyze_and_remediate_stream() so the user sees live progress."""
    return analyze_and_remediate_stream(code_snippet, on_chunk=None)


def ask_cipher(prompt, code, report, history=None):
    """Real implementation of CipHer chat using Gemini with code and report context."""
    system_instruction = (
        "You are CipHer, an expert AI Security Assistant and code review companion. "
        "You help developers understand static security audit reports, fix vulnerabilities, "
        "and write secure code. Be direct, helpful, and concise."
    )
    
    # Format chat history if provided
    formatted_history = ""
    if history:
        for role, text in history:
            formatted_history += f"{role.upper()}: {text}\n"

    chat_prompt = f"""
    Context - Source Code:
    ```
    {code}
    ```

    Context - Security Audit Report:
    {report}

    Chat History:
    {formatted_history}

    User Question: {prompt}
    """

    for model_name in MODELS_TO_TRY:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=chat_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                )
            )
            if response.text and response.text.strip():
                return response.text.strip()
        except Exception:
            continue

    return "CipHer is currently unable to process your request. Please try again."