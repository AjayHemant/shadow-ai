/**
 * SentinelGate DLP — Background Service Worker
 * Handles API calls to the local backend to bypass CSP/PNA restrictions.
 * Now also intercepts omnibox/URL bar navigations for search queries.
 */

const SENTINEL_URL = 'http://127.0.0.1:5000/api/simulate';

function scanToServer(payload, src, dest) {
    return fetch(SENTINEL_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload, source_app: src, destination: dest }),
    }).then(res => res.json());
}

function scanFileToServer(fileData, filename, src, dest) {
    return fetch(SENTINEL_URL + '/file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_data: fileData, filename, source_app: src, destination: dest }),
    }).then(res => res.json());
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'SCAN_PAYLOAD') {
        scanToServer(request.data.payload, request.data.source_app, request.data.destination)
            .then(data => sendResponse({ success: true, data }))
            .catch(err => {
                console.error('[SentinelGate] Background Fetch Error:', err);
                sendResponse({ success: false, error: err.message });
            });
        return true; // Keep channel open for async response
    } else if (request.type === 'SCAN_FILE') {
        scanFileToServer(request.data.file_data, request.data.filename, request.data.source_app, request.data.destination)
            .then(data => sendResponse({ success: true, data }))
            .catch(err => {
                console.error('[SentinelGate] Background File Fetch Error:', err);
                sendResponse({ success: false, error: err.message });
            });
        return true;
    }
});

// Omnibox / URL bar interception for search engines
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    // Only intercept main frame (top-level) navigations
    if (details.frameId !== 0) return;

    try {
        const url = new URL(details.url);

        // Identify standard search queries on major engines
        if (url.hostname.includes('google') || url.hostname.includes('bing') || url.hostname.includes('duckduckgo') || url.hostname.includes('yahoo')) {
            const query = url.searchParams.get('q') || url.searchParams.get('p');

            if (query && query.length > 4) {
                // Scan the typed query against the Sentinel engine
                const result = await scanToServer(query, 'Chrome Omnibox', url.hostname);

                if (result && result.action !== 'ALLOW') {
                    // Instantly reroute the browser to the block screen
                    console.log('[SentinelGate] Omnibox search blocked:', result.detections);

                    // Directly use tabs.update to cancel the navigation or redirect the active tab, avoiding scripting bugs
                    chrome.tabs.update(details.tabId, {
                        url: chrome.runtime.getURL('block.html') + '?reason=' + encodeURIComponent('Omnibox Search Blocked: ' + result.highest_severity + ' Data')
                    });
                }
            }
        }
    } catch (e) {
        console.error('[SentinelGate] Background omnibox intercept error:', e);
    }
});

// Also catch URL changes via tabs.onUpdated to handle Chrome's Omnibox pre-rendering
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        try {
            const url = new URL(changeInfo.url);
            if (url.hostname.includes('google') || url.hostname.includes('bing') || url.hostname.includes('duckduckgo') || url.hostname.includes('yahoo')) {
                const query = url.searchParams.get('q') || url.searchParams.get('p');
                if (query && query.length > 4) {
                    const result = await scanToServer(query, 'Chrome Omnibox', url.hostname);
                    if (result && result.action !== 'ALLOW') {
                        console.log('[SentinelGate] Omnibox search blocked via tabs.onUpdated:', result.detections);
                        chrome.tabs.update(tabId, {
                            url: chrome.runtime.getURL('block.html') + '?reason=' + encodeURIComponent('Omnibox Search Blocked: ' + result.highest_severity + ' Data')
                        });
                    }
                }
            }
        } catch (e) { /* ignore invalid URLs */ }
    }
});
