"""
RuleManager – loads WAF detection rules from JSON files in rules/.
All rules are compiled into regex at startup for performance.
"""

import os
import json
import re
from typing import List, Dict, Any

from config import RULES_DIR


class RuleManager:
    def __init__(self):
        self._categories: List[Dict[str, Any]] = []
        self._load_all()

    def _load_all(self):
        rule_files = [
            "sqli_patterns.json",
            "xss_patterns.json",
            "lfi_patterns.json",
        ]
        for fname in rule_files:
            path = os.path.join(RULES_DIR, fname)
            if not os.path.exists(path):
                continue
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            compiled_rules = []
            for rule in data.get("rules", []):
                try:
                    compiled_rules.append({
                        "id":      rule["id"],
                        "name":    rule["name"],
                        "score":   rule["score"],
                        "pattern": re.compile(rule["pattern"], re.IGNORECASE),
                    })
                except re.error:
                    pass  # skip invalid patterns
            self._categories.append({
                "category":    data.get("category", "Unknown"),
                "base_score":  data.get("base_score", 50),
                "rules":       compiled_rules,
            })

    def get_categories(self) -> List[Dict[str, Any]]:
        return self._categories


# Singleton
rule_manager = RuleManager()
