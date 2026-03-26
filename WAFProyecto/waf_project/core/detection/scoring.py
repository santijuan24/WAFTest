"""
ScoringEngine – applies compiled WAF rules to the request payload
and returns a ScoringResult with a 0–100 risk score.

Decision thresholds (from config.py, aligned with fn_evaluar_criticidad):
  score < 40   → Permitida (clean)
  40 ≤ score < 70 → Alerta / Advertencia
  score ≥ 70   → Bloqueada / Critico
"""

from dataclasses import dataclass, field
from typing import List, Optional
from core.detection.rules_loader import rule_manager
from config import SCORE_ALLOW, SCORE_WARN


@dataclass
class ScoringResult:
    score:       float = 0.0
    action:      str   = "allow"    # allow | block
    level:       str   = "clean"    # clean | warning | blocked
    attack_type: Optional[str] = None
    rule_hits:   List[str] = field(default_factory=list)


def evaluate(payload: str) -> ScoringResult:
    """
    Run every compiled rule against the payload.
    Uses the highest single-rule score as the final score
    (adds partial scores from additional hits, capped at 100).
    Thresholds come from config.py constants.
    """
    result  = ScoringResult()
    scores  = []
    hits    = []
    top_cat = None

    for category in rule_manager.get_categories():
        for rule in category["rules"]:
            if rule["pattern"].search(payload):
                scores.append(rule["score"])
                hits.append(rule["id"])
                if top_cat is None or rule["score"] > (scores[0] if scores else 0):
                    top_cat = category["category"]

    if not scores:
        return result   # clean

    # Primary score = max match; bonus for multiple hits (diminishing returns)
    primary = max(scores)
    bonus   = sum(s * 0.1 for s in sorted(scores, reverse=True)[1:])
    final   = min(100.0, primary + bonus)

    result.score      = round(final, 1)
    result.rule_hits  = hits
    result.attack_type = top_cat

    if final >= SCORE_WARN:
        result.action = "block"
        result.level  = "blocked"
    elif final >= SCORE_ALLOW:
        result.action = "allow"
        result.level  = "warning"
    else:
        result.action = "allow"
        result.level  = "clean"

    return result
