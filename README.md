# Password Strength Analyzer

**Thiranex Internship — Cyber Security Domain**
Intern: Kaartikey Kusshwaha | ID: THX-JUN1026-793

---

## What it does

A command-line tool that evaluates the strength of user-entered passwords using real cybersecurity concepts.

### Features
- Real-time strength scoring (0–100) with visual bar
- Entropy calculation in bits (H = L × log₂N)
- Estimated GPU brute-force crack time
- 10-point criteria checklist (length, complexity, patterns)
- Contextual improvement suggestions
- SHA-256 hashing demonstration
- Strong password generator using `secrets` (cryptographically secure)
- SQLite database to detect and warn about reused passwords

---

## How to run

**Requirements:** Python 3.10 or higher. No external libraries needed.

```bash
python password_analyzer.py
```

Then choose from the menu:
```
1 -> Analyze a password
2 -> Generate a strong password
3 -> Exit
```

---

## Project structure

```
password_strength_analyzer/
├── password_analyzer.py   # Main script — all logic lives here
├── test_analyzer.py       # Unit tests
├── requirements.txt       # Dependency notes (stdlib only)
├── README.md              # This file
└── password_history.db    # Auto-created on first run (SQLite)
```

---

## Cybersecurity concepts covered

| Concept | Where used |
|---|---|
| SHA-256 hashing | `hashlib.sha256()` — passwords stored as hashes, never plaintext |
| Password entropy | `math.log2(charset_size) * length` — measures unpredictability in bits |
| Brute-force estimation | `2^entropy / 10^10` — assumes 10B guesses/sec (modern GPU) |
| Secure randomness | `secrets` module uses `os.urandom()` — not predictable like `random` |
| Reuse detection | SQLite stores SHA-256 digests; plaintext is never written to disk |
| Pattern analysis | Regex checks for sequential (123, abc) and repeated (aaa) patterns |
| Common password list | Checks against 35 known breached passwords |

---

## Assignment checklist

- [x] Check password length, complexity, and uniqueness
- [x] Suggest stronger password alternatives
- [x] Integrate with a database to prevent reuse of old passwords (optional — done)

---

## Example output

```
Strength   : STRONG
Score      : ████████████████████████░░░░░░░░░░░  75/100
Length     : 9 characters
Entropy    : 58.99 bits
Crack time : 1 years  (GPU brute-force, offline)
SHA-256    : 849f1575ccfbf3a4d6cf00e6…

Criteria checklist:
  ✔  8+ characters
  ✖  12+ characters
  ✔  Uppercase letters  (A-Z)
  ✔  Lowercase letters  (a-z)
  ✔  Numeric digits     (0-9)
  ✔  Special characters (!@#…)
  ...
```
