"""
test_analyzer.py
----------------
Basic tests for password_analyzer.py
Run with: python test_analyzer.py
"""

from password_analyzer import analyze, generate_password, calculate_entropy, sha256, init_database
init_database()   # ensure DB table exists before tests run

PASS  = "\033[92m PASS \033[0m"
FAIL  = "\033[91m FAIL \033[0m"
total = 0
passed = 0


def test(name, condition):
    global total, passed
    total += 1
    if condition:
        passed += 1
        print(f"[{PASS}] {name}")
    else:
        print(f"[{FAIL}] {name}")


print("\n========== Password Analyzer Tests ==========\n")

# -- Entropy --
test("Entropy of empty string is 0",
     calculate_entropy("") == 0.0)

test("Entropy increases with charset size",
     calculate_entropy("aaaa") < calculate_entropy("aA1!"))

test("Entropy increases with length",
     calculate_entropy("abc") < calculate_entropy("abcdefgh"))

# -- SHA-256 --
test("SHA-256 returns 64-char hex string",
     len(sha256("password")) == 64)

test("Same input always gives same hash",
     sha256("hello") == sha256("hello"))

test("Different inputs give different hashes",
     sha256("hello") != sha256("Hello"))

# -- Scoring --
r_weak   = analyze("abc")
r_strong = analyze("Tr0ub4dor&3SecurePass!")

test("Short simple password scores low",
     r_weak['score'] < 40)

test("Long complex password scores high",
     r_strong['score'] >= 80)

test("Very weak password has VERY WEAK or WEAK strength",
     r_weak['strength'] in ('VERY WEAK', 'WEAK'))

test("Strong password has STRONG or VERY STRONG strength",
     r_strong['strength'] in ('STRONG', 'VERY STRONG'))

# -- Common password detection --
r_common = analyze("password")
test("'password' flagged as common",
     r_common['is_common'] == True)

test("'password' gets low score",
     r_common['score'] < 40)

# -- Criteria checks --
r = analyze("Hello123!")
test("Uppercase detected",        r['checks']['has_upper'])
test("Lowercase detected",        r['checks']['has_lower'])
test("Digit detected",            r['checks']['has_digit'])
test("Special char detected",     r['checks']['has_special'])
test("Meets 8-char minimum",      r['checks']['length_8'])

r_seq = analyze("abc123def")
test("Sequential pattern 'abc' detected", not r_seq['checks']['no_sequential'])

r_rep = analyze("aaabbbccc")
test("Repeated chars 'aaa' detected",     not r_rep['checks']['no_repeated'])

# -- Generator --
pw = generate_password(length=16)
test("Generator produces 16-char password",      len(pw) == 16)
test("Generated password has uppercase",         any(c.isupper() for c in pw))
test("Generated password has lowercase",         any(c.islower() for c in pw))
test("Generated password has digit",             any(c.isdigit() for c in pw))
test("Generated password has special char",      any(not c.isalnum() for c in pw))
test("Two generated passwords are different",    generate_password() != generate_password())

r_gen = analyze(pw)
test("Generated password scores 80+",            r_gen['score'] >= 80)

# -- Summary --
print(f"\n{'-' * 46}")
print(f"  Results: {passed}/{total} tests passed")
if passed == total:
    print("  \033[92mAll tests passed!\033[0m")
else:
    print(f"  \033[91m{total - passed} test(s) failed.\033[0m")
print(f"{'-' * 46}\n")
