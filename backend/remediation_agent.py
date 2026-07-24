import os
import time
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Try the newest model first; fall back to a calmer, stable model if it's overloaded.
MODELS_TO_TRY = ["gemini-3.6-flash", "gemini-2.5-flash"]


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

                if "503" in error_text or "UNAVAILABLE" in error_text:
                    # Server is busy — wait a moment and try again.
                    time.sleep(2)
                    continue
                else:
                    # A different kind of error (bad key, bad request, etc.)
                    # There's no point retrying this — raise it immediately.
                    raise

    # If we reach here, every model and every retry failed.
    raise last_error