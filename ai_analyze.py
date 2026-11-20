"""
AI triage (MVP step 2): explain findings, map to OWASP/CWE, suggest fixes.
Needs: export ANTHROPIC_API_KEY=your_key
"""
import json
import anthropic

MODEL = "claude-sonnet-5-5"

SYSTEM = """You are a careful application security analyst.
For each finding: explain it in simple language, give severity (Critical/High/Medium/Low/Info),
map to OWASP Top 10 and a CWE id, and give a concrete fix (config or code snippet).
Only use the evidence provided. If a finding may be a false positive, say so and why.
Do not invent vulnerabilities. Finish with a short executive summary and a
'fix these first' priority list. Output Markdown."""

def analyze(findings, target):
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    msg = client.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=SYSTEM,
        messages=[{"role": "user",
                   "content": f"Target: {target}\nFindings (JSON):\n{json.dumps(findings, indent=2)}"}],
    )
    return msg.content[0].text
