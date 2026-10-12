"""Heuristic email-risk analyzer; it does not download or execute links."""

from dataclasses import dataclass
from pathlib import Path
import argparse
import re
from urllib.parse import urlparse


@dataclass(frozen=True)
class RiskFinding:
    category: str
    evidence: str
    severity: str


URGENT = re.compile(r"\b(?:urgent|immediate action required|act now|final notice|account suspended)\b", re.I)
SENSITIVE = re.compile(r"\b(?:password|passcode|one[- ]time password|otp|social security|credit card|bank account|wire transfer)\b", re.I)
URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}


def analyze_email(content: str) -> list[RiskFinding]:
    """Apply transparent heuristics and return findings, not a definitive verdict."""
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    findings: list[RiskFinding] = []
    for match in URGENT.finditer(content):
        findings.append(RiskFinding("urgency", match.group(0), "medium"))
    for match in SENSITIVE.finditer(content):
        findings.append(RiskFinding("sensitive-data request", match.group(0), "high"))
    for match in URL.finditer(content):
        raw = match.group(0).rstrip(".,);]!")
        parsed = urlparse(raw if raw.lower().startswith(("http://", "https://")) else "http://" + raw)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https":
            findings.append(RiskFinding("insecure link", raw, "medium"))
        if host in SHORTENERS:
            findings.append(RiskFinding("shortened link", raw, "medium"))
        if "xn--" in host or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            findings.append(RiskFinding("unusual link host", raw, "high"))
        if not parsed.netloc:
            findings.append(RiskFinding("malformed link", raw, "medium"))
    return findings


def analyze_file(path: str | Path) -> list[RiskFinding]:
    return analyze_email(Path(path).read_text(encoding="utf-8", errors="replace"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze email text using safe local heuristics.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--text")
    source.add_argument("--file", type=Path)
    args = parser.parse_args()
    findings = analyze_email(args.text) if args.text is not None else analyze_file(args.file)
    if not findings:
        print("No configured risk indicators found; review manually.")
    else:
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.category}: {finding.evidence}")


if __name__ == "__main__":
    main()
