#!/usr/bin/env python3
"""
========================================================
  PASSWORD STRENGTH ANALYZER
  Thiranex Internship - Cyber Security Domain
  Intern : Kaartikey Kusshwaha
  ID     : THX-JUN1026-793
========================================================
  Concepts covered:
  - SHA-256 hashing (hashlib)
  - Entropy calculation (information theory)
  - Cryptographically secure password generation (secrets)
  - Password reuse detection via SQLite hash database
  - Regex-based pattern analysis
========================================================
"""

import re
import math
import hashlib
import sqlite3
import secrets
import string
import sys
from getpass import getpass


# ── ANSI Terminal Colors ──────────────────────────────
class C:
    RED    = '\033[91m'
    ORANGE = '\033[33m'
    YELLOW = '\033[93m'
    GREEN  = '\033[92m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    BOLD   = '\033[1m'
    RESET  = '\033[0m'


# ── Common / breached passwords list ─────────────────
COMMON_PASSWORDS = [
    'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
    'master', 'letmein', 'dragon', '111111', 'baseball', 'iloveyou',
    'trustno1', 'sunshine', 'princess', 'welcome', 'shadow', 'superman',
    'ninja', 'mustang', 'password1', 'admin', 'login', 'pass', 'test',
    'hello', '123456789', '1234567890', 'qwerty123', 'p@ssw0rd',
    'passw0rd', '1q2w3e', 'zxcvbnm', 'football', 'charlie'
]

DB_PATH = 'password_history.db'


# ── Database helpers (optional reuse detection) ───────
def init_database():
    """Create the password hash table if it does not exist."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS password_hashes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            hash       TEXT    NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def sha256(password: str) -> str:
    """Return the SHA-256 hex digest of a password string."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def is_reused(password: str) -> bool:
    """Return True if the SHA-256 hash of this password is already stored."""
    digest = sha256(password)
    conn   = sqlite3.connect(DB_PATH)
    row    = conn.execute(
        'SELECT id FROM password_hashes WHERE hash = ?', (digest,)
    ).fetchone()
    conn.close()
    return row is not None


def save_hash(password: str):
    """Store the SHA-256 hash of the password (never the plaintext)."""
    digest = sha256(password)
    conn   = sqlite3.connect(DB_PATH)
    try:
        conn.execute('INSERT INTO password_hashes (hash) VALUES (?)', (digest,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass   # already saved
    conn.close()


# ── Core analysis ─────────────────────────────────────
def calculate_entropy(password: str) -> float:
    """
    Calculate password entropy in bits.
    Formula: H = L * log2(N)
      L = password length
      N = size of the character pool used
    """
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'[0-9]', password): pool += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool += 32
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def estimate_crack_time(entropy: float) -> str:
    """
    Estimate brute-force crack time assuming 10 billion guesses/second
    (modern GPU cluster, offline attack scenario).
    """
    if entropy == 0:
        return "Instant"
    seconds = (2 ** entropy) / 1e10
    if seconds < 1:         return "Less than a second"
    elif seconds < 60:      return f"{int(seconds)} seconds"
    elif seconds < 3600:    return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:   return f"{int(seconds / 3600)} hours"
    elif seconds < 2.592e6: return f"{int(seconds / 86400)} days"
    elif seconds < 3.156e7: return f"{int(seconds / 2.592e6)} months"
    elif seconds < 3.156e9: return f"{int(seconds / 3.156e7)} years"
    else:                   return "Centuries (practically uncrackable)"


def analyze(password: str) -> dict:
    """
    Full password analysis. Returns a results dictionary with:
      score, strength, entropy, crack_time, checks, suggestions, flags.
    """
    checks = {
        'length_8':      len(password) >= 8,
        'length_12':     len(password) >= 12,
        'length_16':     len(password) >= 16,
        'has_upper':     bool(re.search(r'[A-Z]', password)),
        'has_lower':     bool(re.search(r'[a-z]', password)),
        'has_digit':     bool(re.search(r'[0-9]', password)),
        'has_special':   bool(re.search(r'[^a-zA-Z0-9]', password)),
        'no_common':     not any(c in password.lower() for c in COMMON_PASSWORDS),
        'no_sequential': not bool(re.search(
            r'(012|123|234|345|456|567|678|789|890|'
            r'abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|'
            r'klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|'
            r'uvw|vwx|wxy|xyz)', password.lower())),
        'no_repeated':   not bool(re.search(r'(.)\1{2,}', password)),
    }

    # Weighted score
    weights = {
        'length_8': 10, 'length_12': 10, 'length_16': 10,
        'has_upper': 15, 'has_lower': 10, 'has_digit': 15,
        'has_special': 20, 'no_common': 5, 'no_sequential': 5, 'no_repeated': 5,
    }
    score = sum(weights[k] for k, v in checks.items() if v)
    if len(password) > 20:
        score = min(100, score + 5)

    entropy    = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    is_common  = password.lower() in COMMON_PASSWORDS
    reused     = is_reused(password)

    # Strength label
    if is_common or score < 20: strength = 'VERY WEAK'
    elif score < 40:            strength = 'WEAK'
    elif score < 60:            strength = 'FAIR'
    elif score < 80:            strength = 'STRONG'
    else:                       strength = 'VERY STRONG'

    # Improvement suggestions
    suggestions = []
    if not checks['length_8']:
        suggestions.append("Use at least 8 characters")
    elif not checks['length_12']:
        suggestions.append("Increase to 12+ characters for better security")
    if not checks['has_upper']:
        suggestions.append("Add uppercase letters (A-Z)")
    if not checks['has_lower']:
        suggestions.append("Add lowercase letters (a-z)")
    if not checks['has_digit']:
        suggestions.append("Add numbers (0-9)")
    if not checks['has_special']:
        suggestions.append("Add special characters  e.g. !@#$%^&*")
    if is_common:
        suggestions.append("This is a well-known breached password — change it immediately!")
    if not checks['no_sequential']:
        suggestions.append("Avoid sequential patterns like '123' or 'abc'")
    if not checks['no_repeated']:
        suggestions.append("Avoid repeated characters like 'aaa' or '111'")
    if reused:
        suggestions.append("This password was used before — pick a new one!")

    return {
        'password':    password,
        'length':      len(password),
        'score':       min(100, score),
        'strength':    strength,
        'entropy':     entropy,
        'crack_time':  crack_time,
        'checks':      checks,
        'suggestions': suggestions,
        'is_common':   is_common,
        'is_reused':   reused,
        'hash_sha256': sha256(password),
    }


# ── Password generator ────────────────────────────────
def generate_password(length: int = 16,
                      upper: bool = True,
                      lower: bool = True,
                      digits: bool = True,
                      symbols: bool = True) -> str | None:
    """
    Generate a cryptographically secure password using secrets.
    secrets.choice() uses os.urandom() under the hood — far more
    secure than random.choice() for security-sensitive contexts.
    """
    pool     = ''
    required = []

    if upper:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if lower:
        pool += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if symbols:
        sym = '!@#$%^&*()-_=+[]{}|;:,.<>?'
        pool += sym
        required.append(secrets.choice(sym))

    if not pool:
        return None

    filler = [secrets.choice(pool) for _ in range(length - len(required))]
    chars  = required + filler
    secrets.SystemRandom().shuffle(chars)   # cryptographically safe shuffle
    return ''.join(chars)


# ── Display helpers ───────────────────────────────────
STRENGTH_COLOR = {
    'VERY WEAK':   C.RED,
    'WEAK':        C.ORANGE,
    'FAIR':        C.YELLOW,
    'STRONG':      C.GREEN,
    'VERY STRONG': C.BLUE,
}

CHECK_LABELS = {
    'length_8':      '8+ characters',
    'length_12':     '12+ characters',
    'length_16':     '16+ characters',
    'has_upper':     'Uppercase letters  (A-Z)',
    'has_lower':     'Lowercase letters  (a-z)',
    'has_digit':     'Numeric digits     (0-9)',
    'has_special':   'Special characters (!@#…)',
    'no_common':     'No common/breached words',
    'no_sequential': 'No sequential patterns',
    'no_repeated':   'No repeated characters',
}


def score_bar(score: int, width: int = 35) -> str:
    filled = int((score / 100) * width)
    return '█' * filled + '░' * (width - filled)


def print_header():
    print(f"\n{C.CYAN}{C.BOLD}")
    print("╔══════════════════════════════════════════════════╗")
    print("║         PASSWORD STRENGTH ANALYZER  v1.0        ║")
    print("║       Thiranex · Cyber Security Internship       ║")
    print("╚══════════════════════════════════════════════════╝")
    print(C.RESET)


def print_results(r: dict):
    sc = STRENGTH_COLOR.get(r['strength'], C.RESET)

    print(f"\n{C.BOLD}{'─' * 52}{C.RESET}")
    print(f"  {C.BOLD}ANALYSIS REPORT{C.RESET}")
    print(f"{'─' * 52}")

    print(f"\n  Strength   : {sc}{C.BOLD}{r['strength']}{C.RESET}")
    print(f"  Score      : {sc}{score_bar(r['score'])}{C.RESET}  {r['score']}/100")
    print(f"  Length     : {r['length']} characters")
    print(f"  Entropy    : {r['entropy']} bits")
    print(f"  Crack time : {C.BOLD}{r['crack_time']}{C.RESET}  (GPU brute-force, offline)")
    print(f"  SHA-256    : {C.CYAN}{r['hash_sha256'][:24]}…{C.RESET}")

    if r['is_common']:
        print(f"\n  {C.RED}{C.BOLD}⚠  CRITICAL — known breached password!{C.RESET}")
    if r['is_reused']:
        print(f"  {C.YELLOW}{C.BOLD}⚠  WARNING  — previously used password detected!{C.RESET}")

    print(f"\n  {C.BOLD}Criteria checklist:{C.RESET}")
    for key, label in CHECK_LABELS.items():
        ok   = r['checks'][key]
        icon = f"{C.GREEN}✔{C.RESET}" if ok else f"{C.RED}✖{C.RESET}"
        print(f"    {icon}  {label}")

    if r['suggestions']:
        print(f"\n  {C.YELLOW}{C.BOLD}How to improve:{C.RESET}")
        for s in r['suggestions']:
            print(f"    {C.YELLOW}→{C.RESET}  {s}")
    else:
        print(f"\n  {C.GREEN}{C.BOLD}✔  Password meets all security criteria!{C.RESET}")

    print()


# ── Main menu ─────────────────────────────────────────
def menu_analyze():
    print(f"\n  {C.YELLOW}Tip: Input is hidden while typing.{C.RESET}")
    try:
        password = getpass("  Enter password to analyze: ")
    except Exception:
        password = input("  Enter password to analyze: ")

    if not password:
        print(f"  {C.RED}No password entered.{C.RESET}")
        return

    results = analyze(password)
    print_results(results)

    save = input(
        f"  {C.CYAN}Save this password's hash to reuse history? (y/n): {C.RESET}"
    ).strip().lower()
    if save == 'y':
        save_hash(password)
        print(f"  {C.GREEN}Hash saved (plaintext is never stored).{C.RESET}\n")


def menu_generate():
    print(f"\n  {C.BOLD}Password Generator{C.RESET}")
    try:
        raw = input("  Length (8-64, default 16): ").strip()
        length = max(8, min(64, int(raw))) if raw else 16
    except ValueError:
        length = 16

    pw = generate_password(length=length)
    results = analyze(pw)
    sc = STRENGTH_COLOR.get(results['strength'], C.RESET)

    print(f"\n  {C.GREEN}{C.BOLD}Generated password:{C.RESET}")
    print(f"  {C.CYAN}{C.BOLD}{pw}{C.RESET}")
    print(f"  Strength : {sc}{results['strength']}{C.RESET}"
          f"  |  Score : {results['score']}/100"
          f"  |  Entropy : {results['entropy']} bits\n")


def main():
    init_database()
    print_header()

    while True:
        print(f"{C.BOLD}Options:{C.RESET}")
        print("  1  ->  Analyze a password")
        print("  2  ->  Generate a strong password")
        print("  3  ->  Exit\n")

        choice = input(f"{C.CYAN}  Choice: {C.RESET}").strip()

        if choice == '1':
            menu_analyze()
        elif choice == '2':
            menu_generate()
        elif choice == '3':
            print(f"\n{C.GREEN}  Stay secure.\n{C.RESET}")
            sys.exit(0)
        else:
            print(f"  {C.RED}Invalid — enter 1, 2, or 3.{C.RESET}\n")


if __name__ == "__main__":
    main()
