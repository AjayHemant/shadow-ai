"""
SentinelGate - Demo Script
Runs a series of test payloads through the DLP pipeline and prints results.
Use this to demonstrate SentinelGate without the web dashboard.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from detection_engine import DetectionEngine
from policy_engine import PolicyEngine

engine = DetectionEngine()
policy = PolicyEngine()

RESET   = "\033[0m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "LOW":      GREEN,
}

ACTION_COLORS = {
    "BLOCK": RED,
    "WARN":  YELLOW,
    "ALLOW": GREEN,
}


def run_test(label: str, payload: str, source: str = "DemoApp", dest: str = "api.external.com"):
    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}{CYAN}  TEST: {label}{RESET}")
    print(f"{DIM}  Source: {source}  →  Dest: {dest}{RESET}")
    print(f"{'─'*70}")

    scan = engine.scan(payload)
    decision = policy.evaluate(scan, dest)

    action_color = ACTION_COLORS.get(decision.action, "")
    print(f"  {BOLD}ACTION : {action_color}{decision.action}{RESET}")
    print(f"  {BOLD}REASON : {RESET}{decision.reason}")

    if scan.detections:
        print(f"\n  {BOLD}DETECTIONS ({len(scan.detections)}):{RESET}")
        for d in scan.detections:
            c = SEV_COLORS.get(d.severity, "")
            print(f"    {c}[{d.severity:8}]{RESET}  {BOLD}{d.data_type}{RESET}")
            print(f"              Redacted : {MAGENTA}{d.redacted_value}{RESET}")
            print(f"              Info     : {DIM}{d.description}{RESET}")
    else:
        print(f"\n  {GREEN}No sensitive data detected — transmission permitted.{RESET}")

    if decision.triggered_rules:
        print(f"\n  {BOLD}TRIGGERED RULES:{RESET}")
        for r in decision.triggered_rules:
            print(f"    • {r}")


TESTS = [
    (
        "OpenAI API Key in HTTP Header",
        "Authorization: Bearer sk-abc123EXAMPLEKEY456def789ghi012jkl345mno678pqr901\nContent-Type: application/json",
        "ChatBot", "api.openai.com"
    ),
    (
        "Username + Password in POST Body",
        "username=ajay@company.com&password=MySuperSecretP@ss123!&remember=true",
        "LoginService", "auth.internal.com"
    ),
    (
        "Credit Card Number in Payload",
        "Order #4821 - Card: 4532015112830366 - CVV: 742 - Exp: 09/27 - Amount: $199.99",
        "PaymentModule", "checkout.stripe.com"
    ),
    (
        "AWS Access + Secret Keys",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "DeployScript", "s3.amazonaws.com"
    ),
    (
        "JWT Token in Authorization",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        "MobileApp", "api.backend.com"
    ),
    (
        "GitHub Personal Access Token",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890\ngit push origin main",
        "CIRunner", "github.com"
    ),
    (
        "Safe Public News Request (No Secrets)",
        "GET /news/technology HTTP/1.1\nHost: feeds.bbc.com\nAccept: application/json",
        "NewsReader", "feeds.bbc.com"
    ),
    (
        "Email Address Only (Medium Risk)",
        "Contact us at support@company-internal.com for more details.",
        "EmailClient", "smtp.company.com"
    ),
]


def main():
    print(f"\n{BOLD}{MAGENTA}{'█'*70}")
    print(f"  SentinelGate — Pre-Network DLP Engine Demo")
    print(f"  Zero Day Coders | Nagineni Ajay Hemanth & Chandike Sugreshwar")
    print(f"{'█'*70}{RESET}")

    for args in TESTS:
        run_test(*args)

    print(f"\n{BOLD}{'═'*70}{RESET}")
    print(f"{BOLD}{GREEN}  Demo complete. SentinelGate successfully intercepted sensitive data.{RESET}")
    print(f"{'═'*70}\n")


if __name__ == "__main__":
    main()
