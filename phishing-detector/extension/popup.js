/**
 * Sentinel AI — Popup Logic
 * =========================
 * Handles tab URL capture, backend API communication,
 * result rendering, history management, and error states.
 */

const API_BASE = 'http://127.0.0.1:8000';
const MAX_HISTORY = 8;

document.addEventListener('DOMContentLoaded', () => {
    // ── DOM References ────────────────────────────────────────────
    const urlText       = document.getElementById('current-url');
    const loadingState  = document.getElementById('loading');
    const errorState    = document.getElementById('error-state');
    const resultState   = document.getElementById('result-state');
    const errorMessage  = document.getElementById('error-message');
    const retryBtn      = document.getElementById('retry-btn');
    const scanBtn       = document.getElementById('scan-btn');

    const scoreCircle   = document.getElementById('score-circle');
    const scoreText     = document.getElementById('score-text');
    const threatLabel   = document.getElementById('threat-label');
    const verdictSub    = document.getElementById('verdict-sub');
    const reasonsList   = document.getElementById('reasons-list');

    const confMl        = document.getElementById('conf-ml');
    const confRules     = document.getElementById('conf-rules');
    const confApi       = document.getElementById('conf-api');
    const barMl         = document.getElementById('bar-ml');
    const barRules      = document.getElementById('bar-rules');
    const barApi        = document.getElementById('bar-api');

    const historyList   = document.getElementById('history-list');

    let currentUrl = '';

    // ── Initialization ────────────────────────────────────────────
    loadHistory();

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0 && tabs[0].url) {
            currentUrl = tabs[0].url;
            urlText.textContent = currentUrl;

            // Only auto-analyze http/https URLs
            if (currentUrl.startsWith('http://') || currentUrl.startsWith('https://')) {
                analyzeUrl(currentUrl);
            } else {
                showError('Cannot analyze this page type (chrome://, file://, etc.).');
            }
        } else {
            showError('Could not determine the active tab URL.');
        }
    });

    // ── API Call ──────────────────────────────────────────────────
    async function analyzeUrl(url) {
        showLoading();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout

            const response = await fetch(`${API_BASE}/analyze`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
                signal: controller.signal,
            });
            clearTimeout(timeout);

            if (!response.ok) {
                const err = await response.json().catch(() => ({}));
                throw new Error(err.detail || `Server error ${response.status}`);
            }

            const data = await response.json();
            displayResults(data);
            saveHistory(url, data);
        } catch (err) {
            console.error('Analysis Error:', err);
            if (err.name === 'AbortError') {
                showError('Request timed out. Is the backend running?');
            } else {
                showError(err.message || 'Engine offline / unreachable.');
            }
        }
    }

    // ── Render Results ───────────────────────────────────────────
    function displayResults(data) {
        hideAll();
        resultState.classList.remove('hidden');

        const prob  = data.phishing_probability;
        const pct   = Math.round(prob * 100);
        const label = data.label;
        const reasons = data.reasons || [];
        const breakdown = data.confidence_breakdown || {};

        // Score ring animation
        scoreCircle.setAttribute('stroke-dasharray', `${pct}, 100`);
        scoreText.textContent = `${pct}%`;

        // Verdict text
        threatLabel.textContent = label;
        const subtexts = {
            phishing:    'High risk — do NOT enter any information!',
            suspicious:  'Moderate risk — proceed with caution.',
            legitimate:  'This URL appears safe.',
        };
        verdictSub.textContent = subtexts[label] || '';

        // Theme
        document.body.className = '';
        if (label === 'phishing')        document.body.classList.add('theme-phishing');
        else if (label === 'suspicious') document.body.classList.add('theme-suspicious');
        else                             document.body.classList.add('theme-safe');

        // Confidence bars
        setConfidence(confMl, barMl, breakdown['ML Engine']);
        setConfidence(confRules, barRules, breakdown['Heuristic Rules']);
        setConfidence(confApi, barApi, breakdown['Threat Intelligence']);

        // Reasons list
        reasonsList.innerHTML = '';
        if (reasons.length === 0) {
            addReason('✅ No suspicious indicators found.');
        } else {
            reasons.forEach(r => addReason(r));
        }
    }

    function setConfidence(valueEl, barEl, score) {
        if (score === undefined || score === null) return;
        const pct = Math.round(score * 100);
        valueEl.textContent = `${pct}%`;

        // Delay for animation
        requestAnimationFrame(() => {
            barEl.style.width = `${pct}%`;
            if (pct >= 70)      barEl.style.background = 'var(--color-phishing)';
            else if (pct >= 40) barEl.style.background = 'var(--color-suspicious)';
            else                barEl.style.background = 'var(--color-safe)';
        });
    }

    function addReason(text) {
        const li = document.createElement('li');
        li.textContent = text;
        reasonsList.appendChild(li);
    }

    // ── History ──────────────────────────────────────────────────
    function saveHistory(url, data) {
        let history = JSON.parse(localStorage.getItem('sentinel_history') || '[]');
        // Remove duplicate if exists
        history = history.filter(h => h.url !== url);
        history.unshift({
            url,
            label: data.label,
            score: data.phishing_probability,
            timestamp: Date.now(),
        });
        // Keep only last N
        history = history.slice(0, MAX_HISTORY);
        localStorage.setItem('sentinel_history', JSON.stringify(history));
        renderHistory(history);
    }

    function loadHistory() {
        const history = JSON.parse(localStorage.getItem('sentinel_history') || '[]');
        renderHistory(history);
    }

    function renderHistory(history) {
        if (!history || history.length === 0) {
            historyList.innerHTML = '<p class="empty-history">No scans yet</p>';
            return;
        }
        historyList.innerHTML = '';
        history.forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';

            const dotClass = item.label === 'phishing' ? 'dot-phishing'
                           : item.label === 'suspicious' ? 'dot-suspicious'
                           : 'dot-safe';

            const scoreColor = item.label === 'phishing' ? 'var(--color-phishing)'
                             : item.label === 'suspicious' ? 'var(--color-suspicious)'
                             : 'var(--color-safe)';

            div.innerHTML = `
                <div class="history-dot ${dotClass}"></div>
                <span class="history-url" title="${item.url}">${truncateUrl(item.url)}</span>
                <span class="history-score" style="color:${scoreColor}">${Math.round(item.score * 100)}%</span>
            `;
            historyList.appendChild(div);
        });
    }

    function truncateUrl(url) {
        try {
            const u = new URL(url);
            return u.hostname + (u.pathname.length > 1 ? u.pathname.substring(0, 20) + '…' : '');
        } catch {
            return url.substring(0, 35) + '…';
        }
    }

    // ── State Helpers ────────────────────────────────────────────
    function showLoading() {
        hideAll();
        loadingState.classList.remove('hidden');
    }

    function showError(msg) {
        hideAll();
        errorState.classList.remove('hidden');
        errorMessage.textContent = msg;
    }

    function hideAll() {
        loadingState.classList.add('hidden');
        errorState.classList.add('hidden');
        resultState.classList.add('hidden');
    }

    // ── Event Listeners ──────────────────────────────────────────
    retryBtn.addEventListener('click', () => {
        if (currentUrl) analyzeUrl(currentUrl);
    });

    scanBtn.addEventListener('click', () => {
        if (currentUrl) analyzeUrl(currentUrl);
    });
});
