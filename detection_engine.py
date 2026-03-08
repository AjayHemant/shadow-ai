"""
SentinelGate - Detection Engine
Scans outgoing data payloads for sensitive information using regex patterns.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Detection:
    data_type: str
    matched_value: str
    redacted_value: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str

@dataclass
class ScanResult:
    payload: str
    detections: List[Detection] = field(default_factory=list)

    @property
    def is_sensitive(self) -> bool:
        return len(self.detections) > 0

    @property
    def highest_severity(self) -> Optional[str]:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        for s in order:
            if any(d.severity == s for d in self.detections):
                return s
        return None


PATTERNS = [
    {
        "name": "OpenAI API Key",
        "pattern": r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
        "group": 0,
        "severity": "CRITICAL",
        "description": "OpenAI API key detected (sk- prefix)",
    },
    {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-[A-Za-z0-9_\-]{20,}",
        "group": 0,
        "severity": "CRITICAL",
        "description": "Anthropic Claude API key detected",
    },
    {
        "name": "HuggingFace Token",
        "pattern": r"hf_[A-Za-z0-9]{30,}",
        "group": 0,
        "severity": "CRITICAL",
        "description": "HuggingFace API token detected",
    },
    {
        "name": "API Key (Generic)",
        "pattern": r"(?i)(?:api[_\-]?key|apikey|api[_\-]?token|secret[_\-]?key|access[_\-]?token)[^\w]*[=:\"'\s]+([\w\-\.]{16,})",
        "group": 1,
        "severity": "CRITICAL",
        "description": "Generic API key or token detected",
    },
    {
        "name": "AWS Access Key",
        "pattern": r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])",
        "group": 1,
        "severity": "CRITICAL",
        "description": "AWS Access Key ID detected",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[^\w]*([A-Za-z0-9/+=]{40})",
        "group": 1,
        "severity": "CRITICAL",
        "description": "AWS Secret Access Key detected",
    },
    {
        "name": "Private Key (PEM)",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "group": 0,
        "severity": "CRITICAL",
        "description": "PEM private key block detected",
    },
    {
        "name": "Password in Payload",
        "pattern": r"(?i)(password|passwd|pwd)[^\w]*[=:\"' ]+([^\s\"'&,;]{6,})",
        "group": 2,
        "severity": "HIGH",
        "description": "Password field value detected in payload",
    },
    {
        "name": "Bearer Token",
        "pattern": r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)",
        "group": 1,
        "severity": "HIGH",
        "description": "HTTP Bearer token detected",
    },
    {
        "name": "Credit Card Number",
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "group": 0,
        "severity": "HIGH",
        "description": "Credit card number pattern detected",
    },
    {
        "name": "Social Security Number",
        "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "group": 0,
        "severity": "HIGH",
        "description": "US Social Security Number detected",
    },
    {
        "name": "Email Address",
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b",
        "group": 0,
        "severity": "MEDIUM",
        "description": "Email address detected in payload",
    },
    {
        "name": "IPv4 Address (Private)",
        "pattern": r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "group": 1,
        "severity": "LOW",
        "description": "Internal/private IP address detected",
    },
    {
        "name": "Phone Number",
        "pattern": r"\b(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})\b",
        "group": 0,
        "severity": "MEDIUM",
        "description": "Phone number detected in payload",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        "group": 0,
        "severity": "HIGH",
        "description": "JSON Web Token (JWT) detected",
    },
    {
        "name": "GitHub Token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "group": 0,
        "severity": "CRITICAL",
        "description": "GitHub personal access token detected",
    },
    {
        "name": "Slack Token",
        "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
        "group": 0,
        "severity": "CRITICAL",
        "description": "Slack API token detected",
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "group": 0,
        "severity": "CRITICAL",
        "description": "Google API key detected",
    },
]


def _redact(value: str) -> str:
    """Redact a sensitive value for safe logging."""
    if len(value) <= 6:
        return "***"
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


class DetectionEngine:
    def __init__(self):
        # Try to load the fast C++ scanner compiled with pybind11
        try:
            import sentinel_scanner
            self._cpp_scanner = sentinel_scanner.FastScanner()
        except ImportError:
            self._cpp_scanner = None
            
        self._compiled = [
            {**p, "_re": re.compile(p["pattern"])}
            for p in PATTERNS
        ]

    def scan(self, payload: str) -> ScanResult:
        result = ScanResult(payload=payload)
        seen = set()

        if self._cpp_scanner:
            cpp_results = self._cpp_scanner.scan(payload)
            for r in cpp_results:
                key = (r.data_type, r.matched_value)
                if key in seen:
                    continue
                seen.add(key)
                
                result.detections.append(Detection(
                    data_type=r.data_type,
                    matched_value=r.matched_value,
                    redacted_value=r.redacted_value,
                    severity=r.severity,
                    description=r.description,
                ))
            return result

        # Fallback to pure Python regex scan
        for rule in self._compiled:
            for match in rule["_re"].finditer(payload):
                # Extract matched value
                if rule["group"] == 0:
                    raw = match.group(0)
                else:
                    try:
                        raw = match.group(rule["group"])
                    except IndexError:
                        raw = match.group(0)

                key = (rule["name"], raw)
                if key in seen:
                    continue
                seen.add(key)

                detection = Detection(
                    data_type=rule["name"],
                    matched_value=raw,
                    redacted_value=_redact(raw),
                    severity=rule["severity"],
                    description=rule["description"],
                )
                result.detections.append(detection)

        return result
