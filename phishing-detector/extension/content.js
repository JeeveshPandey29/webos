/**
 * Sentinel AI — Content Script
 * =============================
 * Injected into every page. Sends page metadata to popup if requested.
 * Also adds a subtle visual indicator of the page's safety status.
 */

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getPageInfo') {
        sendResponse({
            url: window.location.href,
            title: document.title,
            forms: document.querySelectorAll('form').length,
            externalScripts: countExternalScripts(),
            passwordFields: document.querySelectorAll('input[type="password"]').length,
        });
    }
    return true; // keep channel open for async
});

function countExternalScripts() {
    const scripts = document.querySelectorAll('script[src]');
    let external = 0;
    const currentHost = window.location.hostname;
    scripts.forEach(s => {
        try {
            const scriptHost = new URL(s.src).hostname;
            if (scriptHost !== currentHost) external++;
        } catch {}
    });
    return external;
}

console.log('[Sentinel AI] Content script loaded.');
