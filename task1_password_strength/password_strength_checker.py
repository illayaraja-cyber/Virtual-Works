"""Password strength evaluation without ever printing the password."""

from dataclasses import dataclass
import argparse
import getpass
import string


@dataclass(frozen=True)
class PasswordReport:
    classification: str
    score: int
    feedback: list[str]
    checks: dict[str, bool]


def evaluate_password(password: str) -> PasswordReport:
    """Return a rule-based report. This is guidance, not a password policy engine."""
    checks = {
        "minimum length (12+)": len(password) >= 12,
        "uppercase letter": any(c.isupper() for c in password),
        "lowercase letter": any(c.islower() for c in password),
        "number": any(c.isdigit() for c in password),
        "special character": any(c in string.punctuation for c in password),
    }
    score = sum(checks.values())
    if checks["minimum length (12+)"] and score == len(checks):
        classification = "Strong"
    elif len(password) >= 8 and score >= 3:
        classification = "Medium"
    else:
        classification = "Weak"

    feedback = [f"Add a {name}." for name, passed in checks.items() if not passed]
    if not feedback:
        feedback.append("Use a unique password and store it in a password manager.")
    return PasswordReport(classification, score, feedback, checks)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate password strength locally.")
    parser.add_argument("--password", help="For demos only; omit to enter it privately.")
    args = parser.parse_args()
    password = args.password if args.password is not None else getpass.getpass("Password: ")
    report = evaluate_password(password)
    print(f"Classification: {report.classification} (score {report.score}/{len(report.checks)})")
    for item in report.feedback:
        print(f"- {item}")


if __name__ == "__main__":
    main()
