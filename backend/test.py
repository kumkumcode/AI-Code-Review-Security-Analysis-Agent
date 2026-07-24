from remediation_agent import analyze_and_remediate

sample_code = "def login(u): return 'SELECT * FROM users WHERE user=' + u"

print("--- AGENT OUTPUT ---")
print(analyze_and_remediate(sample_code))