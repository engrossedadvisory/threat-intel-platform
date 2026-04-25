import os
import json
import re
import logging
import requests
from typing import Optional

log = logging.getLogger(__name__)

OLLAMA_URL    = os.getenv("OLLAMA_URL",    "http://host.docker.internal:11434")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Comma-separated list of local Ollama models to try in order.
# E.g. "llama3.2,mistral,phi3,gemma2" — first one that responds wins.
# Falls back to the legacy OLLAMA_MODEL single-value var if OLLAMA_MODELS not set.
_raw_models = os.getenv("OLLAMA_MODELS") or os.getenv("OLLAMA_MODEL", "llama3.2")
LOCAL_MODELS: list[str] = [m.strip() for m in _raw_models.split(",") if m.strip()]

# Optional LM Studio (or any OpenAI-compatible local server).
# Set LMSTUDIO_URL=http://host.docker.internal:1234 to enable.
LMSTUDIO_URL   = os.getenv("LMSTUDIO_URL", "")
LMSTUDIO_MODEL = os.getenv("LMSTUDIO_MODEL", "local-model")

_SCHEMA = {
    "threat_actor": "string — name of threat actor or malware strain, or 'Unknown'",
    "target_industry": "string — e.g. Finance, Healthcare, Government, or 'Unknown'",
    "ttps": ["array of MITRE ATT&CK technique IDs, e.g. T1566, T1059.001"],
    "associated_cves": ["array of CVE IDs explicitly mentioned"],
    "iocs": [{"type": "ip|domain|url|hash_md5|hash_sha256|email",
              "value": "string", "malware_family": "string or null"}],
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


# ─── Parsing ──────────────────────────────────────────────────────────────────

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


# ─── Local model helpers ──────────────────────────────────────────────────────

def _ollama_reachable() -> bool:
    """Ping the Ollama API root with a 2-second timeout.
    Connection refused / timeout returns False instantly — no wasted time."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return r.ok
    except Exception:
        return False


def _via_ollama_model(text: str, model: str) -> Optional[dict]:
    """Run inference on one specific Ollama model."""
    prompt = _PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:6000])
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=90,
        )
        resp.raise_for_status()
        result = _parse(resp.json().get("response", ""))
        if result and isinstance(result.get("confidence_score"), int):
            log.info(f"[analyzer] Ollama/{model} produced valid result.")
            return result
        return None
    except Exception as exc:
        log.debug(f"[analyzer] Ollama/{model} failed: {exc}")
        return None


def _via_ollama(text: str) -> Optional[dict]:
    """Try each configured local Ollama model in order.
    Skipped entirely if Ollama server is not reachable (fast check)."""
    if not _ollama_reachable():
        log.debug("[analyzer] Ollama server unreachable — skipping all local models.")
        return None
    for model in LOCAL_MODELS:
        result = _via_ollama_model(text, model)
        if result:
            return result
    return None


def _lmstudio_reachable() -> bool:
    if not LMSTUDIO_URL:
        return False
    try:
        r = requests.get(f"{LMSTUDIO_URL}/v1/models", timeout=2)
        return r.ok
    except Exception:
        return False


def _via_lmstudio(text: str) -> Optional[dict]:
    """OpenAI-compatible local inference via LM Studio (or similar)."""
    if not LMSTUDIO_URL:
        return None
    if not _lmstudio_reachable():
        log.debug("[analyzer] LM Studio unreachable — skipping.")
        return None
    prompt = _PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:6000])
    try:
        resp = requests.post(
            f"{LMSTUDIO_URL}/v1/chat/completions",
            json={
                "model": LMSTUDIO_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1024,
            },
            timeout=90,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        result = _parse(content)
        if result and isinstance(result.get("confidence_score"), int):
            log.info(f"[analyzer] LM Studio/{LMSTUDIO_MODEL} produced valid result.")
            return result
        return None
    except Exception as exc:
        log.debug(f"[analyzer] LM Studio failed: {exc}")
        return None


# ─── Cloud fallbacks (only reached if all local models fail) ──────────────────

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
        result = _parse(msg.content[0].text)
        if result:
            log.info("[analyzer] Claude produced valid result (local models unavailable).")
        return result
    except Exception as exc:
        log.warning(f"[analyzer] Claude failed: {exc}")
        return None


def _via_gemini(text: str) -> Optional[dict]:
    if not GEMINI_API_KEY:
        return None
    prompt = _PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:8000])
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        result_obj = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        result = _parse(result_obj.text)
        if result:
            log.info("[analyzer] Gemini produced valid result (local models unavailable).")
        return result
    except Exception as exc:
        log.warning(f"[analyzer] Gemini failed: {exc}")
        return None


# ─── Public entry point ───────────────────────────────────────────────────────

def analyze(text: str) -> Optional[dict]:
    """Analyze threat text.

    Priority order — local first, cloud only as last resort:
      1. Ollama  (each model in OLLAMA_MODELS, skipped if server is down)
      2. LM Studio  (skipped if LMSTUDIO_URL not set or unreachable)
      3. Claude API  (skipped if CLAUDE_API_KEY not set)
      4. Gemini API  (skipped if GEMINI_API_KEY not set)
    """
    for fn in (_via_ollama, _via_lmstudio, _via_claude, _via_gemini):
        result = fn(text)
        if result and isinstance(result.get("confidence_score"), int):
            return result
    return None


def ai_query(prompt: str) -> Optional[dict]:
    """Free-form AI query for threat research.  Returns parsed JSON dict or None.
    Uses same backend priority chain as analyze(): Ollama → LM Studio → Claude → Gemini.
    The caller is responsible for embedding JSON schema instructions in the prompt.
    """
    def _try_ollama():
        if not _ollama_reachable():
            return None
        for model in LOCAL_MODELS:
            try:
                resp = requests.post(
                    f"{OLLAMA_URL}/api/generate",
                    json={"model": model, "prompt": prompt[:8000],
                          "stream": False, "format": "json"},
                    timeout=120,
                )
                resp.raise_for_status()
                result = _parse(resp.json().get("response", ""))
                if result is not None:
                    return result
            except Exception as exc:
                log.debug(f"[ai_query] Ollama/{model} failed: {exc}")
        return None

    def _try_lmstudio():
        if not LMSTUDIO_URL or not _lmstudio_reachable():
            return None
        try:
            resp = requests.post(
                f"{LMSTUDIO_URL}/v1/chat/completions",
                json={"model": LMSTUDIO_MODEL,
                      "messages": [{"role": "user", "content": prompt[:8000]}],
                      "temperature": 0.2, "max_tokens": 2048},
                timeout=120,
            )
            resp.raise_for_status()
            return _parse(resp.json()["choices"][0]["message"]["content"])
        except Exception as exc:
            log.debug(f"[ai_query] LM Studio failed: {exc}")
            return None

    def _try_claude():
        if not CLAUDE_API_KEY:
            return None
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=2048,
                messages=[{"role": "user", "content": prompt[:12000]}],
            )
            return _parse(msg.content[0].text)
        except Exception as exc:
            log.warning(f"[ai_query] Claude failed: {exc}")
            return None

    def _try_gemini():
        if not GEMINI_API_KEY:
            return None
        try:
            from google import genai
            client = genai.Client(api_key=GEMINI_API_KEY)
            result_obj = client.models.generate_content(
                model="gemini-2.0-flash", contents=prompt[:12000]
            )
            return _parse(result_obj.text)
        except Exception as exc:
            log.warning(f"[ai_query] Gemini failed: {exc}")
            return None

    for fn in (_try_ollama, _try_lmstudio, _try_claude, _try_gemini):
        result = fn()
        if result is not None:
            return result
    return None
