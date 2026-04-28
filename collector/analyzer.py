"""
Multi-tier Threat Intelligence Analyzer
========================================
Tier 1 — Primary deep analysis (gemma4:31b-cloud or env override)
  Full chain-of-thought attribution reasoning, rich schema extraction.

Tier 2 — Secondary correlation (remaining OLLAMA_MODELS)
  Validates & enriches Tier-1 output against local feed data context.
  Fills in gaps the primary model missed.

Tier 3 — Cloud fallback (LM Studio → Claude → Gemini)
  Only reached when no local Ollama model is available.
"""
import os
import json
import re
import logging
import requests
from typing import Optional

log = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────────

OLLAMA_URL     = os.getenv("OLLAMA_URL", "http://host.docker.internal:11434")
CLAUDE_API_KEY = os.getenv("CLAUDE_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Primary analysis model — best/largest model available
OLLAMA_PRIMARY_MODEL = os.getenv("OLLAMA_PRIMARY_MODEL", "gemma4:31b-cloud")

# Secondary correlation models (comma-separated, tried in order)
# Falls back to OLLAMA_MODELS / OLLAMA_MODEL for backwards compat
_raw_secondary = os.getenv("OLLAMA_MODELS") or os.getenv("OLLAMA_MODEL", "llama3.2")
SECONDARY_MODELS: list[str] = [m.strip() for m in _raw_secondary.split(",") if m.strip()]

# LM Studio (OpenAI-compatible fallback)
LMSTUDIO_URL   = os.getenv("LMSTUDIO_URL", "")
LMSTUDIO_MODEL = os.getenv("LMSTUDIO_MODEL", "local-model")


# ─── Output Schema ────────────────────────────────────────────────────────────

_SCHEMA = {
    "threat_actor": "string — specific named threat actor / APT group / malware family, or 'Unknown'",
    "target_industry": "string — e.g. Finance, Healthcare, Government, Energy, Technology, or 'Unknown'",
    "ttps": ["array of MITRE ATT&CK technique IDs, e.g. T1566, T1059.001 — only confirmed techniques"],
    "associated_cves": ["array of CVE IDs explicitly mentioned in the text"],
    "iocs": [{"type": "ip|domain|url|hash_md5|hash_sha256|hash_sha1|email|cidr",
              "value": "string", "malware_family": "string or null"}],
    "confidence_score": "integer 0-100 — specificity and actionability; infrastructure blocklists < 40; named actors > 70",
    "summary": "2-3 sentence plain-English threat narrative. Be specific about the actor, target, and method.",
    "attribution_reasoning": "1-2 sentences explaining WHY you attributed to this actor (TTPs, targets, infrastructure). 'Unknown' if no attribution.",
}

# ─── Primary Analysis Prompt (deep, chain-of-thought) ─────────────────────────

_PRIMARY_PROMPT = """\
You are a senior Cyber Threat Intelligence analyst at a global MSSP. Your task is \
to perform DEEP attribution analysis on the following threat data.

Think step by step:
1. Identify any named threat actors, APT groups, or malware families in the text.
2. Map observed behaviors to MITRE ATT&CK techniques (only techniques with \
clear evidence — do NOT invent).
3. Identify target industries based on victim data, lure themes, or sector language.
4. Extract all concrete IOCs present in the text.
5. Assess your confidence: named APT with multiple corroborating signals = 80-100; \
infrastructure data only = 20-40; unknown actor with behavioral signals = 40-60.
6. Write a specific, actionable summary — name the actor, method, and target.
7. Briefly justify your attribution or state 'Unknown' if insufficient evidence.

Return ONLY a valid JSON object matching this EXACT schema (no markdown, no prose):
{schema}

CRITICAL RULES:
- threat_actor MUST be a specific named entity (e.g. "APT28", "Lazarus Group", \
"LockBit") or exactly "Unknown" — never generic labels like "threat actor" or \
"malware operator"
- TTPs must be valid T#### or T####.### IDs only
- confidence_score: infrastructure blocklists (Spamhaus, DShield) = 20-35; \
confirmed C2/malware = 75-90; named APT = 80-100
- Do NOT include IOCs that aren't explicitly present in the input text

Threat data to analyze:
{text}"""

# ─── Secondary Correlation Prompt (validates & fills gaps) ────────────────────

_CORRELATION_PROMPT = """\
You are a CTI data correlation engine. You have received an initial threat \
intelligence analysis and need to validate it against local context, then \
improve any weak or missing fields.

INITIAL ANALYSIS:
{initial}

ADDITIONAL CONTEXT (local threat feed data):
{context}

Review the initial analysis critically:
- Is the threat_actor attribution well-supported or speculative?
- Are there additional TTPs the initial analysis missed?
- Does the confidence_score accurately reflect the evidence strength?
- Is the summary specific and actionable?

Return ONLY a valid JSON object with the SAME schema as the initial analysis, \
with improvements applied. If the initial analysis is already accurate, \
return it unchanged. Do NOT invent data — only use what is present in the \
threat data or context.

Schema:
{schema}"""


# ─── Parsing ──────────────────────────────────────────────────────────────────

def _parse(raw: str) -> Optional[dict]:
    """Extract and parse the first JSON object from a model response."""
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


def _valid(result: Optional[dict]) -> bool:
    """Check that a parsed result has the required numeric confidence field."""
    return bool(result and isinstance(result.get("confidence_score"), int))


def _merge(primary: dict, secondary: dict) -> dict:
    """Merge secondary model corrections into primary result.
    Secondary wins on actor (if primary is Unknown), TTPs (union), and summary."""
    merged = dict(primary)

    # Actor: take secondary if primary defaulted to Unknown
    if primary.get("threat_actor", "Unknown") == "Unknown" and \
       secondary.get("threat_actor", "Unknown") not in ("Unknown", "", None):
        merged["threat_actor"] = secondary["threat_actor"]
        merged["attribution_reasoning"] = secondary.get("attribution_reasoning", "")

    # TTPs: union (both models may catch different techniques)
    primary_ttps = set(primary.get("ttps") or [])
    secondary_ttps = set(secondary.get("ttps") or [])
    merged["ttps"] = sorted(primary_ttps | secondary_ttps)

    # CVEs: union
    merged["associated_cves"] = sorted(
        set(primary.get("associated_cves") or []) |
        set(secondary.get("associated_cves") or [])
    )

    # Confidence: take the higher of the two (secondary has more context)
    merged["confidence_score"] = max(
        primary.get("confidence_score", 0),
        secondary.get("confidence_score", 0),
    )

    # Summary: prefer secondary if it's longer and more specific
    pri_summary = primary.get("summary", "")
    sec_summary = secondary.get("summary", "")
    if sec_summary and len(sec_summary) > len(pri_summary) + 20:
        merged["summary"] = sec_summary

    # IOCs: merge unique values
    pri_iocs = {i.get("value", ""): i for i in (primary.get("iocs") or [])}
    for ioc in (secondary.get("iocs") or []):
        v = ioc.get("value", "")
        if v and v not in pri_iocs:
            pri_iocs[v] = ioc
    merged["iocs"] = list(pri_iocs.values())

    return merged


# ─── Ollama helpers ───────────────────────────────────────────────────────────

def _ollama_reachable() -> bool:
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=2)
        return r.ok
    except Exception:
        return False


def _ollama_call(model: str, prompt: str, timeout: int = 120) -> Optional[dict]:
    """Call a single Ollama model and return parsed JSON dict or None."""
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False, "format": "json"},
            timeout=timeout,
        )
        resp.raise_for_status()
        return _parse(resp.json().get("response", ""))
    except Exception as exc:
        log.debug(f"[analyzer] Ollama/{model} error: {exc}")
        return None


# ─── Tier 1: Primary deep analysis ───────────────────────────────────────────

def _primary_analysis(text: str) -> Optional[dict]:
    """Run the primary large model for deep threat attribution analysis."""
    if not _ollama_reachable():
        log.debug("[analyzer] Ollama unreachable — skipping primary analysis.")
        return None

    prompt = _PRIMARY_PROMPT.format(
        schema=json.dumps(_SCHEMA, indent=2),
        text=text[:8000],
    )
    result = _ollama_call(OLLAMA_PRIMARY_MODEL, prompt, timeout=180)
    if _valid(result):
        log.info(f"[analyzer] Tier-1 ({OLLAMA_PRIMARY_MODEL}) produced valid result. "
                 f"Actor: {result.get('threat_actor')} | Confidence: {result.get('confidence_score')}")
        return result

    log.warning(f"[analyzer] Tier-1 ({OLLAMA_PRIMARY_MODEL}) returned no valid JSON.")
    return None


# ─── Tier 2: Secondary correlation ───────────────────────────────────────────

def _secondary_correlation(initial: dict, context: str = "") -> Optional[dict]:
    """Use secondary models to validate and improve the primary analysis."""
    if not _ollama_reachable():
        return None

    if not context:
        context = "(no additional context)"

    prompt = _CORRELATION_PROMPT.format(
        initial=json.dumps(initial, indent=2),
        context=context[:3000],
        schema=json.dumps(_SCHEMA, indent=2),
    )

    for model in SECONDARY_MODELS:
        # Skip primary model — it already ran in Tier 1
        if model == OLLAMA_PRIMARY_MODEL:
            continue
        result = _ollama_call(model, prompt, timeout=90)
        if _valid(result):
            log.info(f"[analyzer] Tier-2 ({model}) correlated. "
                     f"Actor: {result.get('threat_actor')} | TTPs: {result.get('ttps')}")
            return result
        log.debug(f"[analyzer] Tier-2 ({model}) returned no usable result.")

    return None


# ─── Tier 3: Cloud fallbacks ──────────────────────────────────────────────────

def _lmstudio_reachable() -> bool:
    if not LMSTUDIO_URL:
        return False
    try:
        r = requests.get(f"{LMSTUDIO_URL}/v1/models", timeout=2)
        return r.ok
    except Exception:
        return False


def _via_lmstudio(text: str) -> Optional[dict]:
    if not LMSTUDIO_URL or not _lmstudio_reachable():
        return None
    prompt = _PRIMARY_PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:6000])
    try:
        resp = requests.post(
            f"{LMSTUDIO_URL}/v1/chat/completions",
            json={
                "model": LMSTUDIO_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 1200,
            },
            timeout=90,
        )
        resp.raise_for_status()
        result = _parse(resp.json()["choices"][0]["message"]["content"])
        if _valid(result):
            log.info(f"[analyzer] LM Studio/{LMSTUDIO_MODEL} produced valid result.")
            return result
    except Exception as exc:
        log.debug(f"[analyzer] LM Studio failed: {exc}")
    return None


def _via_claude(text: str) -> Optional[dict]:
    if not CLAUDE_API_KEY:
        return None
    prompt = _PRIMARY_PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:8000])
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=CLAUDE_API_KEY)
        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1200,
            messages=[{"role": "user", "content": prompt}],
        )
        result = _parse(msg.content[0].text)
        if result:
            log.info("[analyzer] Claude produced valid result (cloud fallback).")
        return result
    except Exception as exc:
        log.warning(f"[analyzer] Claude failed: {exc}")
        return None


def _via_gemini(text: str) -> Optional[dict]:
    if not GEMINI_API_KEY:
        return None
    prompt = _PRIMARY_PROMPT.format(schema=json.dumps(_SCHEMA, indent=2), text=text[:8000])
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        result_obj = client.models.generate_content(model="gemini-2.0-flash", contents=prompt)
        result = _parse(result_obj.text)
        if result:
            log.info("[analyzer] Gemini produced valid result (cloud fallback).")
        return result
    except Exception as exc:
        log.warning(f"[analyzer] Gemini failed: {exc}")
        return None


# ─── Public entry point ───────────────────────────────────────────────────────

def analyze(text: str, context: str = "") -> Optional[dict]:
    """Multi-tier threat intelligence analysis.

    Tier 1 — Primary model (gemma4:31b-cloud or OLLAMA_PRIMARY_MODEL):
        Deep attribution analysis with chain-of-thought reasoning.

    Tier 2 — Secondary models (OLLAMA_MODELS):
        Correlation pass to validate and enrich Tier-1 output.
        Merged result combines both models' findings.

    Tier 3 — Cloud fallback (LM Studio → Claude → Gemini):
        Only used when Ollama is completely unavailable.

    Args:
        text:    Raw threat data string to analyze.
        context: Optional additional context for the correlation pass
                 (e.g. related feed data, actor profile text).
    """
    # ── Tier 1: Primary deep analysis ─────────────────────────────────────
    primary = _primary_analysis(text)

    if primary:
        # ── Tier 2: Secondary correlation ─────────────────────────────────
        # Only run if there's something to improve (actor unknown, no TTPs, etc.)
        needs_correlation = (
            primary.get("threat_actor", "Unknown") == "Unknown"
            or not primary.get("ttps")
            or primary.get("confidence_score", 0) < 60
            or context  # always correlate when caller provides extra context
        )
        if needs_correlation:
            secondary = _secondary_correlation(primary, context=context)
            if secondary:
                merged = _merge(primary, secondary)
                log.info(
                    f"[analyzer] Merged result — actor: {merged.get('threat_actor')} | "
                    f"TTPs: {len(merged.get('ttps', []))} | "
                    f"confidence: {merged.get('confidence_score')}"
                )
                return merged
        return primary

    # ── Tier 3: Cloud fallbacks ────────────────────────────────────────────
    log.info("[analyzer] Local AI unavailable — trying cloud fallbacks.")
    for fn in (_via_lmstudio, _via_claude, _via_gemini):
        result = fn(text)
        if _valid(result):
            return result

    return None


def ai_query(prompt: str) -> Optional[dict]:
    """Free-form AI query for threat research (used by webui AI Analyst tab).

    Uses the primary model first, then secondary, then cloud fallbacks.
    The caller embeds JSON schema instructions in the prompt directly.
    """
    def _try_primary():
        if not _ollama_reachable():
            return None
        result = _ollama_call(OLLAMA_PRIMARY_MODEL, prompt[:10000], timeout=180)
        if result is not None:
            log.info(f"[ai_query] Primary ({OLLAMA_PRIMARY_MODEL}) responded.")
        return result

    def _try_secondary():
        if not _ollama_reachable():
            return None
        for model in SECONDARY_MODELS:
            if model == OLLAMA_PRIMARY_MODEL:
                continue
            result = _ollama_call(model, prompt[:8000], timeout=120)
            if result is not None:
                log.info(f"[ai_query] Secondary ({model}) responded.")
                return result
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

    for fn in (_try_primary, _try_secondary, _try_lmstudio, _try_claude, _try_gemini):
        result = fn()
        if result is not None:
            return result
    return None
