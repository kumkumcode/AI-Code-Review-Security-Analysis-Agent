from google import genai
from google.genai import types


class PRSummaryAgent:

  def __init__(self, api_key: str):
    self.client = genai.Client(api_key=api_key)
    self.model_name = "gemini-2.5-flash"

  def generate_summary(
      self,
      security_findings: list,
      quality_findings: list,
      remediation_output: str,
  ) -> str:
    """Compiles findings into a multi-line bulleted summary with guaranteed spacing."""
    prompt = f"""
        Security Findings:
        {security_findings}
        
        Quality Findings:
        {quality_findings}
        
        Remediation Details:
        {remediation_output}
        
        Generate a professional PR review summary. You MUST format your response as 5 separate bullet points. 
        Separate every single bullet point with double line breaks so they never appear on the same line.
        """

    # Using a system instruction to strictly dictate output layout behavior
    response = self.client.models.generate_content(
        model=self.model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=(
                "You are a strict code formatter. Always output each bullet"
                " point on a completely new line separated by actual newline"
                " characters (\\n\\n). Never collapse lists into a single"
                " line."
            ),
            temperature=0.1,
        ),
    )

    # Fallback safety: If the text still lacks line breaks, force-split them if needed
    text = response.text
    if "\n" not in text and "•" in text:
      text = text.replace("•", "\n\n•")
    elif "\n" not in text and "-" in text:
      text = text.replace("-", "\n\n-")

    return text