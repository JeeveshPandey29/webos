/**
 * Sentinel AI v3.0 - Popup Logic
 * Full feature display: Engines, URL Features, SSL, WHOIS, HTML
 */

const API_BASE = 'http://127.0.0.1:8000';
const MAX_HISTORY = 8;

document.addEventListener('DOMContentLoaded', () => {
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
    const featureGrid   = document.getElementById('feature-grid');
    const sslGrid       = document.getElementById('ssl-grid');
    const domainGrid    = document.getElementById('domain-grid');
    const htmlGrid      = document.getElementById('html-grid');
    const historyList   = document.getElementById('history-list');

    let currentUrl = '';

    // -- Tab Navigation --
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(btn.dataset.tab).classList.add('active');
        });
    });

    // -- Init --
    loadHistory();
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs.length > 0 && tabs[0].url) {
            currentUrl = tabs[0].url;
            urlText.textContent = currentUrl;
            if (currentUrl.startsWith('http://') || currentUrl.startsWith('https://')) {
                analyzeUrl(currentUrl);
            } else {
                showError('Cannot analyze this page type.');
            }
        } else {
            showError('Could not determine active tab.');
        }
    });

    // -- API Call --
    async function analyzeUrl(url) {
        showLoading();
        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 30000);
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
            if (err.name === 'AbortError') showError('Request timed out (30s). Is the backend running?');
            else showError(err.message || 'Engine offline.');
        }
    }

    // -- Render Results --
    function displayResults(data) {
        hideAll();
        resultState.classList.remove('hidden');

        const prob = data.phishing_probability;
        const pct = Math.round(prob * 100);
        const label = data.label;

        scoreCircle.setAttribute('stroke-dasharray', `${pct}, 100`);
        scoreText.textContent = `${pct}%`;
        threatLabel.textContent = label;
        verdictSub.textContent = { phishing: 'HIGH RISK - Do NOT enter information!', suspicious: 'Moderate risk - proceed with caution.', legitimate: 'This URL appears safe.' }[label] || '';

        document.body.className = '';
        document.body.classList.add(`theme-${label === 'phishing' ? 'phishing' : label === 'suspicious' ? 'suspicious' : 'safe'}`);

        // Engines
        setBar(confMl, barMl, data.confidence_breakdown?.['ML Engine']);
        setBar(confRules, barRules, data.confidence_breakdown?.['Heuristic Rules']);
        setBar(confApi, barApi, data.confidence_breakdown?.['Threat Intelligence']);

        // Reasons
        reasonsList.innerHTML = '';
        (data.reasons || ['No indicators found.']).forEach(r => {
            const li = document.createElement('li');
            li.textContent = r;
            reasonsList.appendChild(li);
        });

        // Features tab
        renderFeatures(data.feature_values || {});

        // SSL tab
        renderSSL(data.ssl_info || {});

        // Domain tab
        renderDomain(data.domain_info || {});

        // HTML tab
        renderHTML(data.html_info || {});
    }

    function setBar(valEl, barEl, score) {
        if (score == null) return;
        const pct = Math.round(score * 100);
        valEl.textContent = `${pct}%`;
        requestAnimationFrame(() => {
            barEl.style.width = `${pct}%`;
            barEl.style.background = pct >= 70 ? 'var(--color-phishing)' : pct >= 40 ? 'var(--color-suspicious)' : 'var(--color-safe)';
        });
    }

    // -- Feature Grid --
    function renderFeatures(f) {
        const items = [
            { label: 'URL Length',       value: f.url_length,       warn: v => v > 75, danger: v => v > 120 },
            { label: 'Dots in Host',     value: f.num_dots,         warn: v => v >= 3, danger: v => v >= 5 },
            { label: 'HTTPS',            value: f.has_https ? 'Yes' : 'No', isFlag: true, flagDanger: f.has_https === 0 },
            { label: 'IP as Host',       value: f.has_ip ? 'Yes' : 'No',    isFlag: true, flagDanger: f.has_ip === 1 },
            { label: 'Suspicious Words', value: f.keyword_count,    warn: v => v >= 1, danger: v => v >= 3 },
            { label: 'Hyphens',          value: f.num_hyphens,      warn: v => v >= 2, danger: v => v >= 4 },
            { label: 'Slashes',          value: f.num_slashes,      warn: v => v >= 4, danger: v => v >= 6 },
            { label: '@ Symbol',         value: f.has_at_symbol ? 'Yes' : 'No', isFlag: true, flagDanger: f.has_at_symbol === 1 },
            { label: 'Path Length',      value: f.path_length,      warn: v => v > 40, danger: v => v > 80 },
            { label: 'Subdomain Depth',  value: f.subdomain_depth,  warn: v => v >= 2, danger: v => v >= 4 },
        ];

        featureGrid.innerHTML = '';
        items.forEach(item => {
            const div = document.createElement('div');
            div.className = 'feature-item';
            let cls = 'safe';
            if (item.isFlag) {
                cls = item.flagDanger ? 'danger' : 'safe';
            } else if (item.danger && item.danger(item.value)) {
                cls = 'danger';
            } else if (item.warn && item.warn(item.value)) {
                cls = 'warn';
            }
            div.innerHTML = `<div class="feature-label">${item.label}</div><div class="feature-value ${cls}">${item.value ?? '--'}</div>`;
            featureGrid.appendChild(div);
        });
    }

    // -- SSL Panel --
    function renderSSL(ssl) {
        sslGrid.innerHTML = '';
        if (ssl.error && !ssl.has_ssl) {
            sslGrid.innerHTML = `<p class="empty-msg">${ssl.error}</p>`;
            return;
        }
        const rows = [
            ['SSL/TLS', ssl.has_ssl ? 'Enabled' : 'Not Found', ssl.has_ssl ? 'safe' : 'danger'],
            ['Valid', ssl.is_valid ? 'Yes' : 'No', ssl.is_valid ? 'safe' : 'danger'],
            ['Protocol', ssl.protocol || '--', ''],
            ['Issuer', ssl.issuer || '--', ''],
            ['Subject', ssl.subject || '--', ''],
            ['Expires In', ssl.expires_in_days != null ? `${ssl.expires_in_days} days` : '--', ssl.expires_in_days != null ? (ssl.expires_in_days < 30 ? 'danger' : ssl.expires_in_days < 90 ? 'warn' : 'safe') : ''],
            ['Valid From', ssl.not_before || '--', ''],
            ['Valid Until', ssl.not_after || '--', ''],
        ];
        rows.forEach(([label, value, cls]) => addInfoRow(sslGrid, label, value, cls));
    }

    // -- Domain Panel --
    function renderDomain(d) {
        domainGrid.innerHTML = '';
        if (d.error && !d.domain_age_days) {
            domainGrid.innerHTML = `<p class="empty-msg">${d.error}</p>`;
            return;
        }
        const ageCls = d.domain_age_days != null ? (d.domain_age_days < 90 ? 'danger' : d.domain_age_days < 365 ? 'warn' : 'safe') : '';
        const rows = [
            ['Domain', d.domain || '--', ''],
            ['Registrar', d.registrar || '--', ''],
            ['Domain Age', d.domain_age_days != null ? `${d.domain_age_days} days` : '--', ageCls],
            ['Created', d.creation_date || '--', ''],
            ['Expires', d.expiration_date || '--', ''],
            ['Country', d.country || '--', ''],
            ['Name Servers', (d.name_servers || []).join(', ') || '--', ''],
        ];
        rows.forEach(([label, value, cls]) => addInfoRow(domainGrid, label, value, cls));
    }

    // -- HTML Panel --
    function renderHTML(h) {
        htmlGrid.innerHTML = '';
        if (h.error && !h.page_title) {
            htmlGrid.innerHTML = `<p class="empty-msg">${h.error}</p>`;
            return;
        }
        const rows = [
            ['Page Title', h.page_title || '--', ''],
            ['Forms', h.forms_count, h.forms_count > 0 ? 'warn' : 'safe'],
            ['Password Fields', h.password_fields, h.password_fields > 0 ? 'warn' : 'safe'],
            ['External Forms', h.external_form_actions?.length || 0, (h.external_form_actions?.length || 0) > 0 ? 'danger' : 'safe'],
            ['External Scripts', h.external_scripts_count, h.external_scripts_count > 5 ? 'warn' : 'safe'],
            ['Hidden Iframes', h.hidden_iframes_count, h.hidden_iframes_count > 0 ? 'danger' : 'safe'],
            ['Meta Redirects', h.meta_redirects?.length || 0, (h.meta_redirects?.length || 0) > 0 ? 'danger' : 'safe'],
            ['Total Links', h.total_links, ''],
            ['External Links', h.external_links, ''],
            ['Ext. Link Ratio', h.external_link_ratio != null ? `${Math.round(h.external_link_ratio * 100)}%` : '--', h.external_link_ratio > 0.7 ? 'danger' : h.external_link_ratio > 0.4 ? 'warn' : 'safe'],
        ];
        rows.forEach(([label, value, cls]) => addInfoRow(htmlGrid, label, value, cls));
    }

    function addInfoRow(container, label, value, cls) {
        const row = document.createElement('div');
        row.className = 'info-row';
        row.innerHTML = `<span class="info-label">${label}</span><span class="info-value ${cls || ''}">${value}</span>`;
        container.appendChild(row);
    }

    // -- History --
    function saveHistory(url, data) {
        let history = JSON.parse(localStorage.getItem('sentinel_history') || '[]');
        history = history.filter(h => h.url !== url);
        history.unshift({ url, label: data.label, score: data.phishing_probability, timestamp: Date.now() });
        history = history.slice(0, MAX_HISTORY);
        localStorage.setItem('sentinel_history', JSON.stringify(history));
        renderHistory(history);
    }

    function loadHistory() {
        renderHistory(JSON.parse(localStorage.getItem('sentinel_history') || '[]'));
    }

    function renderHistory(history) {
        if (!history.length) { historyList.innerHTML = '<p class="empty-history">No scans yet</p>'; return; }
        historyList.innerHTML = '';
        history.forEach(item => {
            const div = document.createElement('div');
            div.className = 'history-item';
            const dotCls = item.label === 'phishing' ? 'dot-phishing' : item.label === 'suspicious' ? 'dot-suspicious' : 'dot-safe';
            const scoreClr = item.label === 'phishing' ? 'var(--color-phishing)' : item.label === 'suspicious' ? 'var(--color-suspicious)' : 'var(--color-safe)';
            div.innerHTML = `<div class="history-dot ${dotCls}"></div><span class="history-url" title="${item.url}">${truncUrl(item.url)}</span><span class="history-score" style="color:${scoreClr}">${Math.round(item.score * 100)}%</span>`;
            historyList.appendChild(div);
        });
    }

    function truncUrl(url) {
        try { const u = new URL(url); return u.hostname + (u.pathname.length > 1 ? u.pathname.substring(0, 18) + '...' : ''); }
        catch { return url.substring(0, 30) + '...'; }
    }

    function showLoading() { hideAll(); loadingState.classList.remove('hidden'); }
    function showError(msg) { hideAll(); errorState.classList.remove('hidden'); errorMessage.textContent = msg; }
    function hideAll() { loadingState.classList.add('hidden'); errorState.classList.add('hidden'); resultState.classList.add('hidden'); }

    retryBtn.addEventListener('click', () => { if (currentUrl) analyzeUrl(currentUrl); });
    scanBtn.addEventListener('click', () => { if (currentUrl) analyzeUrl(currentUrl); });
});
