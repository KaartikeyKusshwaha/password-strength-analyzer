/* ═══════════════════════════════════════════
   Password Strength Analyzer — Core Logic
   CyberSecurity Internship Assignment 1
   ═══════════════════════════════════════════ */

// ── Common Password & Pattern Databases ──────────────
const COMMON_PASSWORDS = new Set([
    'password', '123456', '123456789', 'qwerty', 'abc123', 'monkey', '1234567',
    'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine',
    'ashley', 'michael', 'shadow', '123123', '654321', 'superman', 'qazwsx',
    'michael', 'football', 'password1', 'password123', 'batman', 'login',
    'admin', 'princess', 'welcome', '!@#$%^&*', 'charlie', 'donald',
    'passw0rd', 'hello', 'charlie', 'freedom', 'whatever', 'qwerty123',
    'maggie', '000000', 'access', '696969', 'mustang', 'thunder', 'fuckoff',
    '1234', '12345', '12345678', '1234567890', 'abcdef', 'abcdefg',
    'nicole', 'joshua', 'jordan', 'thomas', 'daniel', 'andrew', 'amanda',
    'jessica', 'robert', 'william', 'jennifer', 'starwars', 'solo'
]);

const KEYBOARD_PATTERNS = [
    'qwerty', 'qwertyuiop', 'asdf', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
    'qazwsx', 'qweasd', '1qaz2wsx', '1q2w3e4r', '!@#$%^&*', 'poiuytrewq',
    'lkjhgfdsa', 'mnbvcxz', 'asdfjkl;'
];

const LEET_MAP = { '4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't' };

// ── DOM Elements ──────────────────────────────────────
const passwordInput = document.getElementById('passwordInput');
const toggleVisibility = document.getElementById('toggleVisibility');
const eyeIcon = document.getElementById('eyeIcon');
const eyeOffIcon = document.getElementById('eyeOffIcon');
const generateBtn = document.getElementById('generateBtn');
const charCount = document.getElementById('charCount');
const strengthLabel = document.getElementById('strengthLabel');
const strengthBar = document.getElementById('strengthBar');
const strengthScore = document.getElementById('strengthScore');
const strengthMeter = document.getElementById('strengthMeter');
const crackTimeCard = document.getElementById('crackTimeCard');
const crackTimeValue = document.getElementById('crackTimeValue');
const resultsGrid = document.getElementById('resultsGrid');
const criteriaList = document.getElementById('criteriaList');
const compositionBars = document.getElementById('compositionBars');
const entropyValue = document.getElementById('entropyValue');
const suggestionsList = document.getElementById('suggestionsList');
const alternativesList = document.getElementById('alternativesList');
const historyList = document.getElementById('historyList');
const historyCount = document.getElementById('historyCount');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

// ── State ─────────────────────────────────────────────
let passwordHistory = JSON.parse(localStorage.getItem('passguard_history') || '[]');
let debounceTimer = null;

// ── Initialize ────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    initParticles();
    renderHistory();
    
    passwordInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => analyzePassword(passwordInput.value), 150);
        charCount.textContent = passwordInput.value.length;
    });

    toggleVisibility.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        eyeIcon.style.display = isPassword ? 'none' : 'block';
        eyeOffIcon.style.display = isPassword ? 'block' : 'none';
    });

    generateBtn.addEventListener('click', () => {
        const generated = generateStrongPassword(18);
        passwordInput.value = generated;
        passwordInput.type = 'text';
        eyeIcon.style.display = 'none';
        eyeOffIcon.style.display = 'block';
        charCount.textContent = generated.length;
        analyzePassword(generated);
        showToast('🔐 Strong password generated!');
    });

    clearHistoryBtn.addEventListener('click', () => {
        passwordHistory = [];
        localStorage.setItem('passguard_history', '[]');
        renderHistory();
        showToast('🗑️ History cleared');
    });

    // Smooth scroll for nav links
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const target = document.querySelector(link.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
                link.classList.add('active');
            }
        });
    });
});

// ── Particle Background ──────────────────────────────
function initParticles() {
    const container = document.getElementById('particles');
    for (let i = 0; i < 25; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDuration = (8 + Math.random() * 12) + 's';
        particle.style.animationDelay = (Math.random() * 10) + 's';
        particle.style.width = particle.style.height = (1 + Math.random() * 2) + 'px';
        const colors = ['#00d4ff', '#a855f7', '#ec4899', '#3b82f6'];
        particle.style.background = colors[Math.floor(Math.random() * colors.length)];
        container.appendChild(particle);
    }
}

// ── Main Analysis Function ────────────────────────────
function analyzePassword(password) {
    if (!password) {
        resetUI();
        return;
    }

    const analysis = performAnalysis(password);
    updateUI(analysis, password);
    addToHistory(password, analysis);
}

function performAnalysis(password) {
    const length = password.length;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);
    
    const upperCount = (password.match(/[A-Z]/g) || []).length;
    const lowerCount = (password.match(/[a-z]/g) || []).length;
    const digitCount = (password.match(/\d/g) || []).length;
    const specialCount = length - upperCount - lowerCount - digitCount;

    // Check criteria
    const criteria = [
        { label: 'Minimum 8 characters', pass: length >= 8 },
        { label: 'Contains uppercase letters', pass: hasUpper },
        { label: 'Contains lowercase letters', pass: hasLower },
        { label: 'Contains numbers', pass: hasDigit },
        { label: 'Contains special characters', pass: hasSpecial },
        { label: 'At least 12 characters (recommended)', pass: length >= 12 },
        { label: 'No common passwords', pass: !isCommonPassword(password) },
        { label: 'No keyboard patterns', pass: !hasKeyboardPattern(password) },
        { label: 'No repeated characters (3+)', pass: !/(.)\1{2,}/.test(password) },
        { label: 'No sequential characters', pass: !hasSequentialChars(password) },
        { label: 'Not previously used', pass: !isReused(password) }
    ];

    // Calculate score
    let score = 0;
    
    // Length scoring (max 30)
    score += Math.min(30, length * 2.5);
    
    // Character variety (max 25)
    const charTypes = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;
    score += charTypes * 6.25;

    // Pattern penalties
    if (isCommonPassword(password)) score -= 30;
    if (hasKeyboardPattern(password)) score -= 15;
    if (/(.)\1{2,}/.test(password)) score -= 10;
    if (hasSequentialChars(password)) score -= 10;
    if (isReused(password)) score -= 15;
    
    // Uniqueness bonus (max 15)
    const uniqueChars = new Set(password).size;
    const uniqueRatio = uniqueChars / length;
    score += uniqueRatio * 15;

    // Entropy bonus (max 5)
    const entropy = calculateEntropy(password);
    score += Math.min(5, entropy / 1.0);

    score = Math.max(0, Math.min(100, Math.round(score)));

    // Determine strength level
    let level, levelClass;
    if (score < 20) { level = 'Critical'; levelClass = 'strength-critical'; }
    else if (score < 40) { level = 'Weak'; levelClass = 'strength-weak'; }
    else if (score < 60) { level = 'Fair'; levelClass = 'strength-fair'; }
    else if (score < 80) { level = 'Strong'; levelClass = 'strength-strong'; }
    else { level = 'Excellent'; levelClass = 'strength-excellent'; }

    // Crack time estimation
    const crackTime = estimateCrackTime(password);

    // Suggestions
    const suggestions = generateSuggestions(password, criteria, charTypes, length);

    // Stronger alternatives
    const alternatives = generateAlternatives(password);

    return {
        score, level, levelClass, criteria, crackTime, suggestions, alternatives,
        composition: { upperCount, lowerCount, digitCount, specialCount },
        entropy, length
    };
}

// ── Password Checks ──────────────────────────────────
function isCommonPassword(password) {
    const lower = password.toLowerCase();
    if (COMMON_PASSWORDS.has(lower)) return true;
    // Check leet speak variants
    let deleetified = '';
    for (const ch of lower) {
        deleetified += LEET_MAP[ch] || ch;
    }
    return COMMON_PASSWORDS.has(deleetified);
}

function hasKeyboardPattern(password) {
    const lower = password.toLowerCase();
    return KEYBOARD_PATTERNS.some(pattern => lower.includes(pattern));
}

function hasSequentialChars(password) {
    for (let i = 0; i < password.length - 2; i++) {
        const c1 = password.charCodeAt(i);
        const c2 = password.charCodeAt(i + 1);
        const c3 = password.charCodeAt(i + 2);
        if ((c2 - c1 === 1 && c3 - c2 === 1) || (c1 - c2 === 1 && c2 - c3 === 1)) {
            return true;
        }
    }
    return false;
}

function isReused(password) {
    const hash = simpleHash(password);
    return passwordHistory.some(entry => entry.hash === hash);
}

// ── Shannon Entropy ──────────────────────────────────
function calculateEntropy(password) {
    if (!password.length) return 0;
    const freq = {};
    for (const ch of password) {
        freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = password.length;
    for (const ch in freq) {
        const p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

// ── Crack Time Estimation ────────────────────────────
function estimateCrackTime(password) {
    let poolSize = 0;
    if (/[a-z]/.test(password)) poolSize += 26;
    if (/[A-Z]/.test(password)) poolSize += 26;
    if (/\d/.test(password)) poolSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;
    if (poolSize === 0) poolSize = 26;

    const combinations = Math.pow(poolSize, password.length);
    // Assuming 10 billion guesses per second (modern GPU)
    const seconds = combinations / 10e9;

    if (seconds < 0.001) return 'Instantly';
    if (seconds < 1) return 'Less than a second';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 86400 * 30) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 86400 * 365) return `${Math.round(seconds / (86400 * 30))} months`;
    if (seconds < 86400 * 365 * 1000) return `${Math.round(seconds / (86400 * 365))} years`;
    if (seconds < 86400 * 365 * 1e6) return `${Math.round(seconds / (86400 * 365 * 1000))}K years`;
    if (seconds < 86400 * 365 * 1e9) return `${Math.round(seconds / (86400 * 365 * 1e6))}M years`;
    if (seconds < 86400 * 365 * 1e12) return `${Math.round(seconds / (86400 * 365 * 1e9))}B years`;
    return 'Centuries+';
}

// ── Suggestion Generator ─────────────────────────────
function generateSuggestions(password, criteria, charTypes, length) {
    const suggestions = [];
    
    if (length < 8) {
        suggestions.push('Increase length to at least 8 characters — ideally 12 or more.');
    } else if (length < 12) {
        suggestions.push('Consider increasing to 12+ characters for stronger protection.');
    }

    if (charTypes < 3) {
        suggestions.push('Mix more character types: uppercase, lowercase, numbers, and symbols.');
    }

    if (isCommonPassword(password)) {
        suggestions.push('This password is in common breach databases. Choose something unique.');
    }

    if (hasKeyboardPattern(password)) {
        suggestions.push('Avoid keyboard patterns like "qwerty" or "asdf" — attackers check these first.');
    }

    if (/(.)\1{2,}/.test(password)) {
        suggestions.push('Avoid repeating the same character 3+ times (e.g., "aaa" or "111").');
    }

    if (hasSequentialChars(password)) {
        suggestions.push('Avoid sequential characters like "abc" or "123" — they reduce entropy.');
    }

    if (isReused(password)) {
        suggestions.push('⚠️ This password was previously used! Choose a new, unique password.');
    }

    const uniqueChars = new Set(password).size;
    if (uniqueChars / length < 0.6 && length > 4) {
        suggestions.push('Too many repeated characters. Use more diverse characters.');
    }

    if (suggestions.length === 0) {
        suggestions.push('Great password! Consider using a password manager to store it safely.');
    }

    return suggestions;
}

// ── Generate Stronger Alternatives ───────────────────
function generateAlternatives(password) {
    const alternatives = [];

    // 1. Strengthened version of user's password
    let strengthened = password;
    if (!/[A-Z]/.test(strengthened) && strengthened.length > 0) {
        strengthened = strengthened[0].toUpperCase() + strengthened.slice(1);
    }
    if (!/\d/.test(strengthened)) strengthened += Math.floor(Math.random() * 900 + 100);
    if (!/[!@#$%^&*]/.test(strengthened)) {
        const syms = '!@#$%^&*';
        strengthened += syms[Math.floor(Math.random() * syms.length)];
    }
    if (strengthened.length < 12) {
        const extra = generateStrongPassword(12 - strengthened.length);
        strengthened += extra;
    }
    if (strengthened !== password) {
        alternatives.push({ password: strengthened, label: 'Enhanced' });
    }

    // 2. Random strong password
    alternatives.push({ password: generateStrongPassword(16), label: 'Random' });

    // 3. Passphrase style
    alternatives.push({ password: generatePassphrase(), label: 'Passphrase' });

    return alternatives;
}

function generateStrongPassword(length) {
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const lower = 'abcdefghjkmnpqrstuvwxyz';
    const digits = '23456789';
    const special = '!@#$%^&*_+-=';
    const all = upper + lower + digits + special;

    let password = '';
    // Ensure at least one of each type
    password += upper[Math.floor(Math.random() * upper.length)];
    password += lower[Math.floor(Math.random() * lower.length)];
    password += digits[Math.floor(Math.random() * digits.length)];
    password += special[Math.floor(Math.random() * special.length)];

    for (let i = password.length; i < length; i++) {
        password += all[Math.floor(Math.random() * all.length)];
    }

    // Shuffle
    return password.split('').sort(() => Math.random() - 0.5).join('');
}

function generatePassphrase() {
    const words = [
        'crystal', 'thunder', 'falcon', 'nebula', 'cipher', 'quantum', 'ember',
        'vortex', 'prism', 'zenith', 'aurora', 'phoenix', 'cobalt', 'titan',
        'matrix', 'lunar', 'blaze', 'storm', 'cosmic', 'arctic', 'onyx',
        'nova', 'pulse', 'spark', 'drift', 'forge', 'crypt', 'steel',
        'shadow', 'riddle', 'vertex', 'omega', 'echo', 'nexus', 'byte'
    ];
    const selected = [];
    for (let i = 0; i < 4; i++) {
        let w = words[Math.floor(Math.random() * words.length)];
        if (i === 0) w = w[0].toUpperCase() + w.slice(1);
        selected.push(w);
    }
    const num = Math.floor(Math.random() * 90 + 10);
    const syms = ['!', '@', '#', '$', '&'];
    return selected.join('-') + num + syms[Math.floor(Math.random() * syms.length)];
}

// ── Simple Hash (for history comparison) ─────────────
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash |= 0;
    }
    // Convert to hex-like string for display
    const hex = (hash >>> 0).toString(16).padStart(8, '0');
    return `sha256:${hex}${'0'.repeat(56)}`.slice(0, 64);
}

// ── UI Update Functions ──────────────────────────────
function updateUI(analysis, password) {
    const { score, level, levelClass, criteria, crackTime, suggestions, alternatives, composition, entropy, length } = analysis;

    // Strength meter
    strengthMeter.className = `strength-meter ${levelClass}`;
    strengthLabel.textContent = level;
    strengthBar.style.width = score + '%';
    animateValue(strengthScore, parseInt(strengthScore.textContent), score, 400);

    // Crack time
    crackTimeCard.style.display = 'flex';
    crackTimeValue.textContent = crackTime;

    // Show results
    resultsGrid.style.display = 'grid';

    // Criteria
    criteriaList.innerHTML = criteria.map(c => `
        <div class="criteria-item ${c.pass ? 'passed' : ''}">
            <span class="criteria-icon ${c.pass ? 'pass' : 'fail'}">
                ${c.pass ? '✓' : '✗'}
            </span>
            <span class="criteria-text">${c.label}</span>
        </div>
    `).join('');

    // Composition
    const compData = [
        { label: 'Uppercase', count: composition.upperCount, cls: 'comp-uppercase', color: '#00d4ff' },
        { label: 'Lowercase', count: composition.lowerCount, cls: 'comp-lowercase', color: '#3b82f6' },
        { label: 'Numbers', count: composition.digitCount, cls: 'comp-numbers', color: '#a855f7' },
        { label: 'Special', count: composition.specialCount, cls: 'comp-special', color: '#ec4899' }
    ];
    compositionBars.innerHTML = compData.map(d => {
        const pct = length > 0 ? (d.count / length * 100) : 0;
        return `
        <div class="comp-bar-item ${d.cls}">
            <div class="comp-bar-header">
                <span class="comp-bar-label">${d.label}</span>
                <span class="comp-bar-value">${d.count} (${Math.round(pct)}%)</span>
            </div>
            <div class="comp-bar-track">
                <div class="comp-bar-fill" style="width: ${pct}%"></div>
            </div>
        </div>`;
    }).join('');

    entropyValue.textContent = entropy.toFixed(2);

    // Suggestions
    suggestionsList.innerHTML = suggestions.map(s => `
        <div class="suggestion-item">
            <span class="suggestion-bullet">⚡</span>
            <span>${s}</span>
        </div>
    `).join('');

    // Alternatives
    alternativesList.innerHTML = alternatives.map((alt, i) => `
        <div class="alt-item" onclick="copyAlternative(this, '${escapeHtml(alt.password)}')">
            <span class="alt-password">${escapeHtml(alt.password)}</span>
            <span class="alt-strength">${alt.label}</span>
            <button class="alt-copy-btn" title="Click to copy" id="altCopyBtn${i}">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                </svg>
            </button>
        </div>
    `).join('');
}

function resetUI() {
    strengthMeter.className = 'strength-meter';
    strengthLabel.textContent = 'Enter a password';
    strengthBar.style.width = '0%';
    strengthScore.textContent = '0';
    crackTimeCard.style.display = 'none';
    resultsGrid.style.display = 'none';
}

// ── History Management ───────────────────────────────
function addToHistory(password, analysis) {
    const hash = simpleHash(password);
    
    // Check for reuse (show warning)
    const isReuse = passwordHistory.some(entry => entry.hash === hash);
    
    if (!isReuse) {
        passwordHistory.unshift({
            hash: hash,
            score: analysis.score,
            level: analysis.level,
            levelClass: analysis.levelClass,
            date: new Date().toISOString(),
            length: password.length
        });

        // Keep only last 20 entries
        if (passwordHistory.length > 20) {
            passwordHistory = passwordHistory.slice(0, 20);
        }

        localStorage.setItem('passguard_history', JSON.stringify(passwordHistory));
    }

    renderHistory(isReuse);
}

function renderHistory(showReuseWarning = false) {
    historyCount.textContent = `${passwordHistory.length} stored`;

    if (passwordHistory.length === 0) {
        historyList.innerHTML = `
            <div class="history-empty">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.4">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                    <circle cx="12" cy="7" r="4"/>
                </svg>
                <span>No passwords analyzed yet</span>
            </div>`;
        return;
    }

    let html = '';

    if (showReuseWarning) {
        html += `
            <div class="history-reuse-warning">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                Password reuse detected! This password was previously used.
            </div>`;
    }

    html += passwordHistory.map(entry => {
        const date = new Date(entry.date);
        const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
        const timeStr = date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
        
        let badgeStyle = '';
        if (entry.levelClass === 'strength-critical') badgeStyle = 'background:rgba(239,68,68,0.12);color:#ef4444;border:1px solid rgba(239,68,68,0.2)';
        else if (entry.levelClass === 'strength-weak') badgeStyle = 'background:rgba(249,115,22,0.12);color:#f97316;border:1px solid rgba(249,115,22,0.2)';
        else if (entry.levelClass === 'strength-fair') badgeStyle = 'background:rgba(234,179,8,0.12);color:#eab308;border:1px solid rgba(234,179,8,0.2)';
        else if (entry.levelClass === 'strength-strong') badgeStyle = 'background:rgba(34,197,94,0.12);color:#22c55e;border:1px solid rgba(34,197,94,0.2)';
        else badgeStyle = 'background:rgba(0,212,255,0.12);color:#00d4ff;border:1px solid rgba(0,212,255,0.2)';

        return `
            <div class="history-item">
                <span class="history-hash" title="${entry.hash}">${entry.hash}</span>
                <span class="history-strength-badge" style="${badgeStyle}">${entry.level} (${entry.score})</span>
                <span class="history-date">${dateStr} ${timeStr}</span>
            </div>`;
    }).join('');

    historyList.innerHTML = html;
}

// ── Utilities ────────────────────────────────────────
function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML.replace(/'/g, "\\'");
}

function copyAlternative(element, text) {
    // Unescape the text
    const temp = document.createElement('textarea');
    temp.innerHTML = text;
    const cleanText = temp.value;
    
    navigator.clipboard.writeText(cleanText).then(() => {
        const btn = element.querySelector('.alt-copy-btn');
        btn.classList.add('copied');
        btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>`;
        showToast('📋 Password copied to clipboard!');
        setTimeout(() => {
            btn.classList.remove('copied');
            btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
        }, 2000);
    });
}

function animateValue(element, start, end, duration) {
    const startTime = performance.now();
    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const value = Math.round(start + (end - start) * eased);
        element.textContent = value;
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

function showToast(message) {
    let toast = document.querySelector('.toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.className = 'toast';
        document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 2500);
}
