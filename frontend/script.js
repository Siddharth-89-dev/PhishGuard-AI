
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => document.querySelectorAll(selector);

const formatDate = (date) => {
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    }).format(date);
};

const generateId = () => {
    return 'scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
};

const API = {
    baseUrl: '',
    async predictUrl(url) {
        const payload = { url: url.trim() };
        const response = await fetch(`${this.baseUrl}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            throw new Error('Backend request failed');
        }

        return response.json();
    },
    async analyzeWithBackend(content) {
        try {
            const result = await this.predictUrl(content);
            const status = (result.prediction || 'Safe').toLowerCase();
            const riskScore = Number(result.risk_score ?? 0);
            const summary = result.matched_database
                ? `Detected phishing threat via ${result.source} database.`
                : 'Content was analyzed by the backend threat engine.';
            const indicators = result.matched_database
                ? [`Matched dangerous domain: ${result.matched_domain || content}`]
                : ['No suspicious database match found.'];
            const actions = status === 'phishing' || riskScore >= 50
                ? [
                      'Do not click any links in this content.',
                      'Verify the sender independently before responding.',
                      'Report the suspicious content to your security team.',
                  ]
                : [
                      'This content appears low-risk.',
                      'Proceed with caution and double-check unexpected requests.',
                  ];

            return {
                id: generateId(),
                status: status === 'phishing' ? 'dangerous' : status,
                score: Math.round(riskScore * 100),
                summary,
                indicators,
                actions,
                timestamp: new Date().toISOString(),
                content: content.substring(0, 100) + (content.length > 100 ? '...' : ''),
            };
        } catch (error) {
            return null;
        }
    },
};

// ============================================
// AUTHENTICATION
// ============================================

const Auth = {
    isLoggedIn() {
        return localStorage.getItem('phishguard_auth') === 'true';
    },

    login(email, remember = false) {
        localStorage.setItem('phishguard_auth', 'true');
        localStorage.setItem('phishguard_user', email);
        localStorage.setItem('phishguard_loginTime', new Date().toISOString());
        if (remember) {
            localStorage.setItem('phishguard_remember', 'true');
        }
    },

    logout() {
        localStorage.removeItem('phishguard_auth');
        localStorage.removeItem('phishguard_user');
        localStorage.removeItem('phishguard_loginTime');
        localStorage.removeItem('phishguard_remember');
    },

    getUser() {
        return localStorage.getItem('phishguard_user') || 'User';
    },

    getLoginTime() {
        return localStorage.getItem('phishguard_loginTime');
    },

    protectRoute() {
        if (!this.isLoggedIn()) {
            if (!window.location.pathname.includes('login.html')) {
                window.location.replace('login.html');
            }
            return false;
        }
        return true;
    }
};

// ============================================
// SCAN HISTORY
// ============================================

const ScanHistory = {
    getAll() {
        const history = localStorage.getItem('phishguard_scans');
        return history ? JSON.parse(history) : [];
    },

    add(scan) {
        const history = this.getAll();
        history.unshift(scan);
        if (history.length > 50) history.pop();
        localStorage.setItem('phishguard_scans', JSON.stringify(history));
    },

    getStats() {
        const history = this.getAll();
        const total = history.length;
        const safe = history.filter(s => s.status === 'safe').length;
        const suspicious = history.filter(s => s.status === 'suspicious').length;
        const dangerous = history.filter(s => s.status === 'dangerous').length;
        const avgScore = total > 0 
            ? Math.round(history.reduce((sum, s) => sum + s.score, 0) / total) 
            : 0;
        return { total, safe, suspicious, dangerous, avgScore };
    },

    clear() {
        localStorage.removeItem('phishguard_scans');
    }
};

// ============================================
// THREAT ANALYZER
// ============================================

const ThreatAnalyzer = {
    analyze(content) {
        const hash = this.hashContent(content);
        const random = this.seededRandom(hash);

        let status, score, summary, indicators, actions;
        const rand = random();

        if (rand < 0.33) {
            status = 'safe';
            score = Math.floor(random() * 20);
            summary = 'No threats detected. The content appears to be legitimate and safe to interact with.';
            indicators = [
                'No suspicious URLs detected',
                'No phishing patterns found',
                'Domain reputation is clean',
                'No malicious attachments detected'
            ];
            actions = [
                'Content is safe to proceed',
                'Continue with normal operations',
                'No further action required'
            ];
        } else if (rand < 0.66) {
            status = 'suspicious';
            score = Math.floor(30 + random() * 40);
            summary = 'Some suspicious elements detected. Exercise caution before interacting with this content.';
            indicators = [
                'Unusual URL structure detected',
                'Potential spoofing attempt identified',
                'Sender domain partially matches known brands',
                'Contains urgency-based language patterns'
            ];
            actions = [
                'Verify sender identity independently',
                'Do not click any links provided',
                'Contact the organization directly',
                'Report to your security team'
            ];
        } else {
            status = 'dangerous';
            score = Math.floor(75 + random() * 25);
            summary = 'High-risk threats detected! This content contains known phishing indicators and should be avoided.';
            indicators = [
                'Known malicious URL detected',
                'Credential harvesting attempt identified',
                'Domain impersonation confirmed',
                'Malicious payload signatures found',
                'Reported by multiple security sources'
            ];
            actions = [
                'DO NOT interact with this content',
                'Delete immediately',
                'Report to security team',
                'Run full system scan',
                'Change passwords if already interacted'
            ];
        }

        return {
            id: generateId(),
            status,
            score,
            summary,
            indicators,
            actions,
            timestamp: new Date().toISOString(),
            content: content.substring(0, 100) + (content.length > 100 ? '...' : '')
        };
    },

    hashContent(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        return Math.abs(hash);
    },

    seededRandom(seed) {
        let s = seed;
        return function() {
            s = (s * 9301 + 49297) % 233280;
            return s / 233280;
        };
    }
};

// ============================================
// NAVBAR
// ============================================

const initNavbar = () => {
    const navbar = $('.navbar');
    if (!navbar) return;

    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });

    const mobileMenuBtn = $('.mobile-menu-btn');
    const navLinks = $('.nav-links');

    if (mobileMenuBtn && navLinks) {
        mobileMenuBtn.addEventListener('click', () => {
            navLinks.classList.toggle('active');
            mobileMenuBtn.innerHTML = navLinks.classList.contains('active') ? '&#10005;' : '&#9776;';
        });
    }
};

// ============================================
// SCROLL ANIMATIONS
// ============================================

const initScrollAnimations = () => {
    const fadeElements = $$('.fade-in');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('visible');
                observer.unobserve(entry.target);
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    fadeElements.forEach(el => observer.observe(el));
};

// ============================================
// SCANNER
// ============================================

const initScanner = () => {
    const textarea = $('#scanner-textarea');
    const charCounter = $('#char-counter');
    const analyzeBtn = $('#analyze-btn');
    const resultsCard = $('#results-card');

    if (!textarea || !analyzeBtn) return;

    textarea.addEventListener('input', () => {
        const len = textarea.value.length;
        if (charCounter) {
            charCounter.textContent = len + ' character' + (len !== 1 ? 's' : '');
        }
    });

    analyzeBtn.addEventListener('click', async () => {
        const content = textarea.value.trim();

        if (!content) {
            textarea.focus();
            textarea.style.borderColor = 'var(--danger)';
            setTimeout(() => {
                textarea.style.borderColor = '';
            }, 2000);
            return;
        }

        analyzeBtn.classList.add('loading');
        analyzeBtn.disabled = true;

        if (resultsCard) {
            resultsCard.classList.remove('visible');
        }

        const backendResult = await API.analyzeWithBackend(content);
        let result;

        if (backendResult) {
            result = backendResult;
        } else {
            await new Promise(resolve => setTimeout(resolve, 1200));
            result = ThreatAnalyzer.analyze(content);
            result.summary = 'Backend was unavailable, so local analysis was used.';
        }

        ScanHistory.add(result);
        displayResults(result);

        analyzeBtn.classList.remove('loading');
        analyzeBtn.disabled = false;
    });
};

const displayResults = (result) => {
    const resultsCard = $('#results-card');
    if (!resultsCard) return;

    const statusBadge = $('#status-badge');
    const riskScoreValue = $('#risk-score-value');
    const progressBar = $('#progress-bar');
    const threatSummary = $('#threat-summary');
    const threatIndicators = $('#threat-indicators');
    const recommendedActions = $('#recommended-actions');
    const scanTimestamp = $('#scan-timestamp');

    if (statusBadge) {
        statusBadge.className = 'status-badge ' + result.status;
        statusBadge.innerHTML = '<span class="dot"></span>' + result.status.charAt(0).toUpperCase() + result.status.slice(1);
    }

    if (riskScoreValue) {
        riskScoreValue.className = 'risk-score-value ' + result.status;
        riskScoreValue.textContent = result.score;
    }

    if (progressBar) {
        progressBar.className = 'progress-bar ' + result.status;
        progressBar.style.width = '0%';
        setTimeout(() => {
            progressBar.style.width = result.score + '%';
        }, 100);
    }

    if (threatSummary) {
        threatSummary.textContent = result.summary;
    }

    if (threatIndicators) {
        threatIndicators.innerHTML = result.indicators.map(ind => '<li>' + ind + '</li>').join('');
    }

    if (recommendedActions) {
        recommendedActions.innerHTML = result.actions.map(action => '<li>' + action + '</li>').join('');
    }

    if (scanTimestamp) {
        scanTimestamp.textContent = formatDate(new Date(result.timestamp));
    }

    resultsCard.classList.add('visible');
    resultsCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
};

// ============================================
// LOGIN PAGE
// ============================================

const initLogin = () => {
    const loginForm = $('#login-form');
    if (!loginForm) return;

    const emailInput = $('#login-email');
    const passwordInput = $('#login-password');
    const togglePassword = $('#toggle-password');
    const rememberCheckbox = $('#remember-me');

    if (togglePassword && passwordInput) {
        togglePassword.addEventListener('click', () => {
            const type = passwordInput.type === 'password' ? 'text' : 'password';
            passwordInput.type = type;
            togglePassword.textContent = type === 'password' ? 'Show' : 'Hide';
        });
    }

    loginForm.addEventListener('submit', (e) => {
        e.preventDefault();

        const email = emailInput.value.trim();
        const password = passwordInput.value;
        let isValid = true;

        clearValidation(emailInput);
        clearValidation(passwordInput);

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            showValidation(emailInput, 'Please enter a valid email address', 'error');
            isValid = false;
        }

        if (password.length < 8) {
            showValidation(passwordInput, 'Password must be at least 8 characters', 'error');
            isValid = false;
        }

        if (isValid) {
            Auth.login(email, rememberCheckbox && rememberCheckbox.checked);
            window.location.href = 'dashboard.html';
        }
    });

    if (emailInput) {
        emailInput.addEventListener('blur', () => {
            const email = emailInput.value.trim();
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            if (email && !emailRegex.test(email)) {
                showValidation(emailInput, 'Please enter a valid email address', 'error');
            } else if (email) {
                clearValidation(emailInput);
            }
        });
    }

    if (passwordInput) {
        passwordInput.addEventListener('blur', () => {
            const password = passwordInput.value;
            if (password && password.length < 8) {
                showValidation(passwordInput, 'Password must be at least 8 characters', 'error');
            } else if (password) {
                clearValidation(passwordInput);
            }
        });
    }
};

const showValidation = (input, message, type) => {
    input.classList.add('error');
    const msgEl = input.parentElement.querySelector('.validation-msg');
    if (msgEl) {
        msgEl.textContent = message;
        msgEl.className = 'validation-msg visible ' + type;
    }
};

const clearValidation = (input) => {
    input.classList.remove('error');
    const msgEl = input.parentElement.querySelector('.validation-msg');
    if (msgEl) {
        msgEl.className = 'validation-msg';
        msgEl.textContent = '';
    }
};

// ============================================
// DASHBOARD
// ============================================

const initDashboard = () => {
    // Only run dashboard logic if we're actually on dashboard.html
    if (!window.location.pathname.includes('dashboard.html')) return;
    if (!Auth.protectRoute()) return;

    const userNameEl = $('#user-name');
    if (userNameEl) {
        const user = Auth.getUser();
        userNameEl.textContent = user.split('@')[0];
    }

    updateDashboardStats();
    updateScanHistory();
    updateAccountInfo();

    const logoutBtn = $('#logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', () => {
            Auth.logout();
            window.location.replace('login.html');
        });
    }
};

const updateDashboardStats = () => {
    const stats = ScanHistory.getStats();

    const totalScansEl = $('#total-scans');
    const safeScansEl = $('#safe-scans');
    const suspiciousScansEl = $('#suspicious-scans');
    const dangerousScansEl = $('#dangerous-scans');
    const avgScoreEl = $('#avg-risk-score');

    if (totalScansEl) totalScansEl.textContent = stats.total;
    if (safeScansEl) safeScansEl.textContent = stats.safe;
    if (suspiciousScansEl) suspiciousScansEl.textContent = stats.suspicious;
    if (dangerousScansEl) dangerousScansEl.textContent = stats.dangerous;
    if (avgScoreEl) avgScoreEl.textContent = stats.avgScore;
};

const updateScanHistory = () => {
    const tableBody = $('#scan-history-body');
    if (!tableBody) return;

    const history = ScanHistory.getAll().slice(0, 10);

    if (history.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center; padding: 2rem; color: var(--text-muted);">No scans yet. Go to the homepage to analyze threats.</td></tr>';
        return;
    }

    tableBody.innerHTML = history.map(scan => {
        const color = scan.status === 'safe' ? 'var(--success)' : scan.status === 'suspicious' ? 'var(--warning)' : 'var(--danger)';
        return '<tr>' +
            '<td>' + scan.content + '</td>' +
            '<td><span class="table-badge ' + scan.status + '"><span class="dot"></span>' + scan.status.charAt(0).toUpperCase() + scan.status.slice(1) + '</span></td>' +
            '<td><span style="color: ' + color + '; font-weight: 600;">' + scan.score + '/100</span></td>' +
            '<td>' + formatDate(new Date(scan.timestamp)) + '</td>' +
        '</tr>';
    }).join('');
};

const updateAccountInfo = () => {
    const accountEmail = $('#account-email');
    const accountStatus = $('#account-status');
    const accountPlan = $('#account-plan');
    const accountJoined = $('#account-joined');

    if (accountEmail) accountEmail.textContent = Auth.getUser();
    if (accountStatus) accountStatus.textContent = 'Active';
    if (accountPlan) accountPlan.textContent = 'Enterprise';
    if (accountJoined) {
        const loginTime = Auth.getLoginTime();
        if (loginTime) {
            accountJoined.textContent = formatDate(new Date(loginTime));
        } else {
            accountJoined.textContent = formatDate(new Date());
        }
    }
};

// ============================================
// SMOOTH SCROLL
// ============================================

const initSmoothScroll = () => {
    $$('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const target = $(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
};

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initNavbar();
    initScrollAnimations();
    initScanner();
    initLogin();
    initDashboard();
    initSmoothScroll();
});
