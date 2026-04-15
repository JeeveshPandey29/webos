/**
 * Sentinel AI — Background Service Worker
 * ========================================
 * Handles auto-scan on page navigation and badge updates.
 */

const API_BASE = 'http://127.0.0.1:8000';

// Auto-scan when a tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Only scan http/https URLs
        if (tab.url.startsWith('http://') || tab.url.startsWith('https://')) {
            scanUrl(tabId, tab.url);
        }
    }
});

async function scanUrl(tabId, url) {
    try {
        const response = await fetch(`${API_BASE}/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url }),
        });

        if (!response.ok) return;

        const data = await response.json();
        const label = data.label;
        const score = Math.round(data.phishing_probability * 100);

        // Update extension badge
        let badgeColor, badgeText;
        if (label === 'phishing') {
            badgeColor = '#ef4444';
            badgeText = `${score}%`;
        } else if (label === 'suspicious') {
            badgeColor = '#f59e0b';
            badgeText = `${score}%`;
        } else {
            badgeColor = '#10b981';
            badgeText = '✓';
        }

        chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
        chrome.action.setBadgeText({ tabId, text: badgeText });

        // Alert for high-risk pages
        if (label === 'phishing') {
            chrome.scripting.executeScript({
                target: { tabId },
                func: showPhishingAlert,
                args: [score],
            }).catch(() => {}); // Ignore errors on restricted pages
        }

    } catch (err) {
        // Backend offline — silently fail
        console.log('Sentinel: Backend unreachable for auto-scan.');
    }
}

function showPhishingAlert(score) {
    // Injected into the page context
    if (document.getElementById('sentinel-alert')) return;

    const banner = document.createElement('div');
    banner.id = 'sentinel-alert';
    banner.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
        background: linear-gradient(135deg, #dc2626, #991b1b);
        color: white; padding: 14px 20px;
        font-family: -apple-system, sans-serif; font-size: 15px;
        display: flex; align-items: center; justify-content: space-between;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        animation: slideDown 0.3s ease;
    `;
    banner.innerHTML = `
        <span>🛡️ <strong>Sentinel AI Warning:</strong> This page has a ${score}% phishing probability. Do NOT enter any personal information!</span>
        <button onclick="this.parentElement.remove()" style="
            background: rgba(255,255,255,0.2); border: none; color: white;
            padding: 6px 14px; border-radius: 4px; cursor: pointer;
            font-weight: 600; font-size: 13px;
        ">Dismiss</button>
    `;

    const style = document.createElement('style');
    style.textContent = `@keyframes slideDown { from { transform: translateY(-100%); } to { transform: translateY(0); } }`;
    document.head.appendChild(style);
    document.body.prepend(banner);
}
