"""
ScoringEngine – applies compiled WAF rules to the request payload
and returns a ScoringResult with a 0–100 risk score.

Decision thresholds (from config.py):
  score < 40   → ALLOW
  40 ≤ score < 70 → ALLOW + log WARNING
  score ≥ 70   → BLOCK
"""

from dataclasses import dataclass, field
from typing import List, Optional
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from waf_proxy.rule_manager import rule_manager


@dataclass
class ScoringResult:
    score:       float = 0.0
    action:      str   = "allow"    # allow | block
    level:       str   = "clean"    # clean | warning | blocked
    attack_type: Optional[str] = None
    rule_hits:   List[str] = field(default_factory=list)


def evaluate(payload: str, db) -> ScoringResult:
    """
    Run every compiled rule against the payload, respecting live config from DB.
    Uses the highest single-rule score as the final score
    (adds partial scores from additional hits, capped at 100).
    """
    from models.system_config import SystemConfig

    # Load dynamic config
    conf_dict = {}
    for c in db.query(SystemConfig).all():
        conf_dict[c.key] = c.value

    score_block = float(conf_dict.get("score_block_threshold", "70"))
    score_warn  = float(conf_dict.get("score_warn_threshold", "40"))

    # Active categories
    active_cats = []
    if conf_dict.get("rules_sqli_enabled", "true").lower() == "true": active_cats.append("SQL Injection")
    if conf_dict.get("rules_xss_enabled", "true").lower() == "true":  active_cats.append("Cross-Site Scripting (XSS)")
    if conf_dict.get("rules_lfi_enabled", "true").lower() == "true":  active_cats.append("Local File Inclusion")

    result  = ScoringResult()
    scores  = []
    hits    = []
    top_cat = None

    for category in rule_manager.get_categories():
        if category["category"] not in active_cats:
            continue

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

    if final >= score_block:
        result.action = "block"
        result.level  = "blocked"
    elif final >= score_warn:
        result.action = "allow"
        result.level  = "warning"
    else:
        result.action = "allow"
        result.level  = "clean"

    return result
