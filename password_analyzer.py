"""Private local password utilities. No history, fingerprints or plaintext results."""
import argparse
import json
import secrets
import string
import warnings
from getpass import GetPassWarning, getpass
from zxcvbn import zxcvbn


def analyze(password: str) -> dict:
    if not isinstance(password, str) or not 1 <= len(password) <= 128:
        raise ValueError("Enter between 1 and 128 characters; input is never truncated.")
    result = zxcvbn(password, max_length=128)
    return {
        "length": len(password),
        "score": result["score"],
        "strength": ["Very guessable", "Guessable", "Somewhat guessable", "Less guessable", "Harder to guess"][result["score"]],
        "guesses_log10": result["guesses_log10"],
        "warning": result["feedback"]["warning"],
        "suggestions": result["feedback"]["suggestions"],
        "patterns": sorted({item["pattern"] for item in result["sequence"]}),
        "breach_status": "Not checked",
        "limitations": "Statistical guessability estimate, not a guarantee. This CLI does not query breach services or detect reuse.",
    }


def generate_password(length=24, upper=True, lower=True, digits=True, symbols=True):
    groups = [chars for enabled, chars in [(upper, string.ascii_uppercase), (lower, string.ascii_lowercase), (digits, string.digits), (symbols, "!@#$%^&*()-_=+")] if enabled]
    if not groups or not isinstance(length, int) or isinstance(length, bool) or not max(8, len(groups)) <= length <= 128:
        raise ValueError("Choose a length of 8-128 and at least one character group.")
    pool = "".join(groups)
    # Rejection sampling is uniform over strings meeting the selected group constraints.
    while True:
        value = "".join(secrets.choice(pool) for _ in range(length))
        if all(any(c in group for c in value) for group in groups):
            return value


def main():
    parser = argparse.ArgumentParser(description="SentinelOps private password lab")
    parser.add_argument("--generate", type=int, metavar="LENGTH", help="Generate a password locally")
    args = parser.parse_args()
    if args.generate is not None:
        print(generate_password(args.generate))
        return
    with warnings.catch_warnings():
        warnings.simplefilter("error", GetPassWarning)
        try:
            password = getpass("Password (hidden; never saved): ")
        except (GetPassWarning, EOFError):
            parser.exit(2, "Hidden input is unavailable. Use a private terminal or the browser-local lab.\n")
    try:
        print(json.dumps(analyze(password), indent=2))
    except ValueError as e:
        parser.exit(2, str(e) + "\n")


if __name__ == "__main__":
    main()
