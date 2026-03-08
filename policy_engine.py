"""
SentinelGate - Policy Engine
Evaluates security policies based on scan results and destination context.
"""

from dataclasses import dataclass
from typing import List, Optional
from detection_engine import ScanResult


@dataclass
class PolicyDecision:
    action: str          # ALLOW, BLOCK, WARN
    reason: str
    triggered_rules: List[str]


class PolicyEngine:
    """
    Evaluates a set of named rules against a ScanResult.
    Rules are checked in priority order; first match wins for BLOCK decisions.
    """

    def __init__(self):
        self._rules = self._default_rules()

    def _default_rules(self):
        return [
            {
                "name": "Block critical secrets",
                "severity_match": ["CRITICAL"],
                "action": "BLOCK",
                "description": "Block any transmission containing API keys, passwords, private keys, or tokens.",
            },
            {
                "name": "Block high-severity data",
                "severity_match": ["HIGH"],
                "action": "BLOCK",
                "description": "Block transmissions with high-severity sensitive data (credit cards, SSNs, JWTs, Bearer tokens).",
            },
            {
                "name": "Warn on medium-severity data",
                "severity_match": ["MEDIUM"],
                "action": "WARN",
                "description": "Warn when medium-severity data like emails or phone numbers are detected.",
            },
            {
                "name": "Log low-severity data",
                "severity_match": ["LOW"],
                "action": "WARN",
                "description": "Log low-severity signals such as internal IP addresses.",
            },
        ]

    def evaluate(self, scan_result: ScanResult, destination: Optional[str] = None) -> PolicyDecision:
        if not scan_result.is_sensitive:
            return PolicyDecision(
                action="ALLOW",
                reason="No sensitive data detected.",
                triggered_rules=[],
            )

        triggered = []
        final_action = "ALLOW"
        final_reason = "Passed all policy rules."

        for rule in self._rules:
            for detection in scan_result.detections:
                if detection.severity in rule["severity_match"]:
                    triggered.append(rule["name"])
                    if rule["action"] == "BLOCK":
                        final_action = "BLOCK"
                        final_reason = rule["description"]
                    elif rule["action"] == "WARN" and final_action != "BLOCK":
                        final_action = "WARN"
                        final_reason = rule["description"]

        triggered = list(dict.fromkeys(triggered))  # deduplicate while preserving order

        return PolicyDecision(
            action=final_action,
            reason=final_reason,
            triggered_rules=triggered,
        )
