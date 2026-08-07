from google import genai

class CoordinatorAgent:
    def __init__(self, api_key: str):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel("gemini-2.5-flash")

    def orchestrate_workflow(self, code_snippet: str, security_findings: list, quality_findings: list) -> dict:
        """
        Takes raw findings from security and quality checks, 
        orchestrates the remediation, and prepares a unified payload.
        """
        # Step 1: Synthesize findings for the Remediation Agent
        prompt = f"""
        You are the Lead Technical Coordinator. Review the following code and its identified issues:
        
        Code Snippet:
        {code_snippet}
        
        Security Findings:
        {security_findings}
        
        Quality Findings:
        {quality_findings}
        
        Task: Coordinate and generate clean remediation recommendations, corrected code, and brief explanations.
        """
        
        response = self.model.generate_content(prompt)
        
        return {
            "status": "success",
            "remediation_output": response.text
        }