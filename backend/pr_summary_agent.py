from google import genai

class PRSummaryAgent:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")

    def generate_summary(self, security_findings: list, quality_findings: list, remediation_output: str) -> str:
        """
        Compiles all agent outputs into a structured PR-style review summary.
        """
        prompt = f"""
        You are an expert Code Reviewer. Generate a professional Pull Request review summary based on the following data:
        
        Security Findings:
        {security_findings}
        
        Quality Findings:
        {quality_findings}
        
        Remediation Details:
        {remediation_output}
        
        Format the output using Markdown with the following sections:
        1. **Executive Overview**: A 2-3 sentence summary of the overall code health.
        2. **Severity Breakdown**: Count or list of High, Medium, and Low severity issues found.
        3. **Prioritized Fix List**: A clear bulleted list of fixes ordered by priority.
        """
        
        response = self.model.generate_content(prompt)
        return response.text