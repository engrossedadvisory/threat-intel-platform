import os
import json
import re
import requests
from typing import Optional

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

_SCHEMA = {
    "threat_actor": "string — name of threat actor or malware strain, or 'Unknown'",
    "target_industry": "string — e.g. Finance, Healthcare, Government, or 'Unknown'",
    "ttps": ["array of MITRE ATT&CK technique IDs, e.g. T1566, T1059.001"],
    "associated_cves": ["array of CVE IDs explicitly mentioned"],
    "iocs": [{"type": "ip|domain|url|hash_md5|hash_sha256|email", "value": "string", "malware_family": "string or null"}],
    "confidence_score": "integer 0-100 — how specific and actionable is this intel",
    "summary": "2-3 sentence plain-English summary of the threat",
}

_PROMPT = """\
You are a Cyber Threat Intelligence analyst. Analyze the following threat data and extract structured intelligence.

Return ONLY a valid JSON object matching this exact schema:
{schema}

Rules:
- confidence_score: 0-100. Security research tools or benign software get < 20.
- ttps must be valid MITRE ATT&CK IDs (T####[.###]) or an empty array.
- Only include IOCs explicitly present in the text.
- Keep summary factual. Two to three sentences maximum.

Threat data:
{text}"""


def _parse(raw: str) -> Optional[dict]:
    clean = raw.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
    return None


def _via_ollama(text: str) -> Optional[dict]:
    prompt = _PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:6000])
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False, "format": "json"},
            timeout=120,
        )
        resp.raise_for_status()
        return _parse(resp.json().get("response", ""))
    except Exception:
        return None


def _via_claude(text: str) -> Optional[dict]:
    if not CLAUDE_API_KEY:
        return None
    prompt = _PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:8000])
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            messages=[{"role": "user", "content": prompt}],
        )
        return _parse(msg.content[0].text)
    except Exception:
        return None


def _via_gemini(text: str) -> Optional[dict]:
    if not GEMINI_API_KEY:
        return None
    prompt = _PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:8000])
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        result = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        return _parse(result.text)
    except Exception:
        return None


def analyze(text: str) -> Optional[dict]:
    """Try Ollama → Claude → Gemini in order, return first valid result."""
    for fn in (_via_ollama, _via_claude, _via_gemini):
        result = fn(text)
        if result and isinstance(result.get("confidence_score"), int):
            return result
    return None
