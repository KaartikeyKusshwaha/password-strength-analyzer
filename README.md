# 🔐 PassGuard — Password Strength Analyzer

> **CyberSecurity Internship — Assignment 1**  
> A tool that evaluates the strength of user-entered passwords.

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)

## 📋 Assignment Description

Develop a tool that evaluates the strength of user-entered passwords.

### Key Features

- ✅ Check password **length**, **complexity**, and **uniqueness**
- ✅ Suggest **stronger password alternatives**
- ✅ Integrated with a local **database to prevent reuse** of old passwords

### Expected Outcome

Learn about **password security** and **basic cryptography concepts**.

---

## 🚀 Features

### Core Analysis
- **Real-time password strength scoring** (0–100 scale)
- **11 security criteria checks** including length, complexity, common passwords, keyboard patterns, sequential characters, and reuse detection
- **Shannon entropy calculation** for measuring password randomness
- **Estimated crack time** based on modern GPU brute-force speeds (10 billion guesses/sec)

### Password Intelligence
- **Common password database** — checks against 60+ frequently breached passwords
- **Leet speak detection** — identifies passwords like `p@$$w0rd` that are disguised common passwords
- **Keyboard pattern detection** — flags patterns like `qwerty`, `asdf`, `1qaz2wsx`
- **Sequential character detection** — catches `abc`, `123`, `cba`, etc.

### Password Generation
- **Stronger alternatives generator** — provides enhanced, random, and passphrase-style suggestions
- **One-click password generation** — creates cryptographically diverse 18-character passwords
- **Copy to clipboard** functionality

### History & Reuse Prevention
- **Local password history database** (via `localStorage`)
- **Reuse detection with visual warnings** — shake animation + alert when a previously used password is entered
- **Hash-based storage** — passwords are stored as hashes, not plaintext
- Stores up to 20 most recent entries with timestamps and scores

### UI/UX
- **Dark cybersecurity-themed design** with glassmorphism effects
- **Animated background** with floating particles and gradient glows
- **Real-time analysis** with smooth animations and transitions
- **Responsive design** — works on desktop, tablet, and mobile
- **Security best practices guide** — 6 tip cards for password education

---

## 🛠️ Tech Stack

| Technology | Purpose |
|------------|---------|
| HTML5 | Semantic structure |
| CSS3 | Styling, animations, glassmorphism |
| Vanilla JavaScript | Analysis engine, DOM manipulation |
| localStorage API | Password history database |
| Google Fonts | Inter & JetBrains Mono typography |

---

## 📂 Project Structure

```
assign-1/
├── index.html       # Main application page
├── styles.css       # Complete design system & styling
├── analyzer.js      # Password analysis engine & UI logic
└── README.md        # Documentation
```

---

## 🔧 How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/password-strength-analyzer.git
   ```
2. Open `index.html` in any modern browser.

> No build tools, frameworks, or server required — it's a pure frontend application.

---

## 🔒 Security Concepts Demonstrated

- **Password Entropy** — Shannon entropy calculation measuring information density per character
- **Brute-Force Estimation** — Time-to-crack based on character pool size and password length
- **Common Password Attacks** — Detection of dictionary words and breach database entries
- **Pattern Recognition** — Keyboard walks, sequential characters, and repeated characters
- **Leet Speak Substitution** — Reverse-mapping common substitutions (@ → a, 3 → e, etc.)
- **Password Hashing** — Hash-based history storage (simulated, not production-grade)
- **Password Reuse Prevention** — Local database tracking to prevent credential reuse

---

## 📸 Screenshots

Open the application in your browser to see the full interface with:
- Password input with visibility toggle
- Real-time strength meter and scoring
- Detailed security criteria checklist
- Character composition analysis with bar charts
- Crack time estimation
- Intelligent suggestions
- Stronger password alternatives with copy-to-clipboard
- Password history with reuse warnings

---

## 📄 License

This project is created for educational purposes as part of a CyberSecurity Internship program.
