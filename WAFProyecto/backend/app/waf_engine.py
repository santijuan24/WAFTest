"""
WAF Engine – analiza requests HTTP en busca de patrones maliciosos.
Detecta: SQL Injection, XSS, Path Traversal, Command Injection.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class WafResult:
    is_malicious: bool = False
    attack_type: Optional[str] = None
    risk_score: float = 0.0
    matched_rules: List[str] = field(default_factory=list)
    action: str = "allow"
    message: str = "Request is clean"


# ── Reglas estáticas del WAF ──────────────────────────────────────────────────
WAF_RULES = [
    {
        "id": "sqli-01",
        "name": "SQL Injection - Classic",
        "attack_type": "SQL Injection",
        "risk_score": 9.0,
        "patterns": [
            r"(\bUNION\b.+\bSELECT\b)",
            r"(\bSELECT\b.+\bFROM\b)",
            r"(\bDROP\b.+\bTABLE\b)",
            r"(\bINSERT\b.+\bINTO\b)",
            r"(\bDELETE\b.+\bFROM\b)",
            r"(--|;|\/\*|\*\/)",
            r"(\bOR\b\s+\d+=\d+)",
            r"(\bAND\b\s+\d+=\d+)",
            r"'.*('|;|--)",
        ],
    },
    {
        "id": "xss-01",
        "name": "XSS - Script Injection",
        "attack_type": "XSS",
        "risk_score": 8.0,
        "patterns": [
            r"<script[\s\S]*?>[\s\S]*?<\/script>",
            r"javascript\s*:",
            r"on\w+\s*=\s*[\"']",
            r"<img[^>]+src\s*=\s*[\"']?\s*javascript:",
            r"eval\s*\(",
            r"document\.(cookie|write|location)",
        ],
    },
    {
        "id": "pt-01",
        "name": "Path Traversal",
        "attack_type": "Path Traversal",
        "risk_score": 7.5,
        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e/",
            r"\.\.%2f",
            r"/etc/passwd",
            r"/etc/shadow",
            r"\\windows\\system32",
        ],
    },
    {
        "id": "cmdi-01",
        "name": "Command Injection",
        "attack_type": "Command Injection",
        "risk_score": 10.0,
        "patterns": [
            r";\s*(ls|cat|wget|curl|bash|sh|python|perl|nc|ncat)\b",
            r"\|\s*(ls|cat|wget|curl|bash|sh|python|perl|nc)\b",
            r"`[^`]+`",
            r"\$\([^)]+\)",
            r"&&\s*(ls|cat|wget|curl|rm|mkdir)\b",
        ],
    },
]


def _compile_rule(rule: dict):
    return [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]


# Compilar todas las reglas una sola vez al importar
_COMPILED_RULES = [
    {**rule, "_compiled": _compile_rule(rule)}
    for rule in WAF_RULES
]


def analyze(
    path: str,
    method: str = "GET",
    user_agent: str = "",
    body: str = "",
    headers: dict = None,
) -> WafResult:
    """
    Analiza los componentes de una solicitud HTTP y retorna un WafResult.
    """
    target = " ".join(filter(None, [path, user_agent or "", body or ""]))
    result = WafResult()
    highest_score = 0.0

    for rule in _COMPILED_RULES:
        for pattern in rule["_compiled"]:
            if pattern.search(target):
                result.is_malicious = True
                result.matched_rules.append(rule["id"])
                if rule["risk_score"] > highest_score:
                    highest_score = rule["risk_score"]
                    result.attack_type = rule["attack_type"]
                break  # una coincidencia por regla es suficiente

    result.risk_score = highest_score
    if result.is_malicious:
        result.action = "block"
        result.message = (
            f"Malicious request detected: {result.attack_type} "
            f"(score={result.risk_score})"
        )

    return result
