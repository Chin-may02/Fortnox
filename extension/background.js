
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        if (request.action === "getPageDetails") {
            try {
                const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                if (!tab?.id) {
                    throw new Error("Could not find an active tab.");
                }
                const response = await chrome.tabs.sendMessage(tab.id, { action: "extractPageDetails" });
                sendResponse(response);
            } catch (error) {
                sendResponse({ error: `Content script error: ${error.message}` });
            }
            return;
        }

        if (request.action === "checkUrlWithBackend") {
            const urlToCheck = request.url;
            const modelName = request.modelName;
            if (!urlToCheck) {
                sendResponse({ error: "No URL provided for backend check." });
                return;
            }
            try {
                const response = await fetch('http://127.0.0.1:5000/check_url', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: urlToCheck, modelName }),
                });

                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }

                const data = await response.json();

                if (data.prediction === "phishing") {
                    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                    if (tab?.id && tab.url === urlToCheck) {
                        chrome.tabs.sendMessage(tab.id, {
                            action: "showWarning",
                            details: {
                                url: urlToCheck,
                                classification: data.prediction,
                                siteType: "the current page"
                            }
                        }).catch(e => console.warn(`Could not send warning to content script: ${e.message}`));
                    }
                }
                sendResponse({ type: 'backendResult', data: data });

            } catch (error) {
                sendResponse({ error: `Backend fetch error: ${error.message}. Is the Python server running?` });
            }
            return;
        }

        // New handler for email checking
        if (request.action === "checkEmailWithBackend") {
            const emailData = request.emailData;
            if (!emailData || !emailData.from_email) {
                sendResponse({ error: "No email data provided for backend check." });
                return;
            }
            try {
                console.log('[FORTNOX Background] Checking email:', emailData.from_email);
                const response = await fetch('http://127.0.0.1:5000/check_email', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(emailData),
                });

                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }

                const data = await response.json();
                console.log('[FORTNOX Background] Email analysis result:', data);

                sendResponse({ type: 'emailResult', data: data });

            } catch (error) {
                console.error('[FORTNOX Background] Email check error:', error);
                sendResponse({ error: `Backend fetch error: ${error.message}. Is the Python server running?` });
            }
            return;
        }

    })();

    return true;
});

// Track scanned URLs per tab to avoid duplicate scans in same session
const scannedTabs = new Map();
// Track in-flight scans to avoid duplicate concurrent requests
const scanningTabs = new Map();
// Track the last known safe page for each tab so the blocked page can send the user back somewhere useful.
const lastSafeUrlByTab = new Map();
// Track blocked URLs to prevent re-scanning (capped to avoid unbounded growth)
const blockedUrls = new Set();
const MAX_BLOCKED_URLS = 500;
const BYPASS_MARKER = '#fortnox-allow';

function isEmailAppUrl(url) {
    if (typeof url !== 'string') {
        return false;
    }

    try {
        const parsed = new URL(url);
        return parsed.hostname === 'mail.google.com';
    } catch (error) {
        return false;
    }
}

function hasBypassMarker(url) {
    return typeof url === 'string' && url.includes(BYPASS_MARKER);
}

function buildBlockedPageUrl(targetUrl, returnToUrl) {
    const params = new URLSearchParams({ target: targetUrl });

    if (returnToUrl) {
        params.set('returnTo', returnToUrl);
    }

    return `chrome-extension://${chrome.runtime.id}/blocked.html?${params.toString()}`;
}

// Auto-scan function
async function autoScanUrl(tabId, url) {
    // Skip non-http/https URLs (chrome://, about:, etc.)
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
        console.log(`[AUTO-SCAN] Skipping non-HTTP URL: ${url}`);
        return;
    }

    // Gmail pages should use the email classifier instead of the generic URL workflow.
    if (isEmailAppUrl(url)) {
        console.log(`[AUTO-SCAN] Skipping email app URL classification for: ${url}`);
        return;
    }

    // One-time user bypass from blocked page
    if (hasBypassMarker(url)) {
        console.log(`[AUTO-SCAN] User bypass marker found. Skipping scan once: ${url}`);
        return;
    }

    // Skip if already scanned for this tab
    if (scannedTabs.get(tabId) === url) {
        console.log(`[AUTO-SCAN] Already scanned this URL for tab ${tabId}: ${url}`);
        return;
    }

    // Skip if same URL is already being scanned
    if (scanningTabs.get(tabId) === url) {
        return;
    }

    // Check if auto-scan is enabled
    let autoScanEnabled = true; // Default to true
    try {
        const result = await chrome.storage.sync.get(['autoScanEnabled']);
        autoScanEnabled = result.autoScanEnabled !== false; // Default to true if not set
    } catch (e) {
        console.warn(`[AUTO-SCAN] Error reading storage: ${e.message}, defaulting to enabled`);
    }

    if (!autoScanEnabled) {
        console.log(`[AUTO-SCAN] Auto-scan is disabled, skipping ${url}`);
        return;
    }

    try {
        scanningTabs.set(tabId, url);
        console.log(`[AUTO-SCAN] ðŸ” Scanning URL: ${url}`);
        const response = await fetch('http://127.0.0.1:5000/check_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url }),
        });

        if (!response.ok) {
            console.warn(`[AUTO-SCAN] âš ï¸ Server error for ${url}: ${response.status}`);
            console.warn(`[AUTO-SCAN] Make sure Flask server is running: python app.py`);
            return;
        }

        const data = await response.json();
        scannedTabs.set(tabId, url); // Mark as scanned

        // Graduated response to reduce false-positive hard blocks.
        const phishingProbRaw = (typeof data.riskScore === 'number') ? data.riskScore : (data.probabilities?.[1] || 0);
        const phishingProbModel = Math.max(0, Math.min(1, phishingProbRaw));
        const hardBlockThreshold = 0.85;
        const warningThreshold = 0.60;
        const shouldHardBlock = phishingProbModel >= hardBlockThreshold;
        const shouldWarn = phishingProbModel >= warningThreshold || data.prediction === "phishing";

        if (shouldHardBlock) {
            console.log(`[AUTO-SCAN] THREAT DETECTED - BLOCKING: ${url}`);
            console.log(`[AUTO-SCAN] Risk Level: ${data.riskLevel || data.prediction}`);
            console.log(`[AUTO-SCAN] Probabilities: Safe=${((data.probabilities?.[0] || 0) * 100).toFixed(1)}%, Phishing=${((data.probabilities?.[1] || 0) * 100).toFixed(1)}%`);

            // Mark as blocked (evict oldest if at capacity)
            if (blockedUrls.size >= MAX_BLOCKED_URLS) {
                const oldest = blockedUrls.values().next().value;
                blockedUrls.delete(oldest);
            }
            blockedUrls.add(url);

            // Redirect to the blocked page
            const blockedPageUrl = buildBlockedPageUrl(url, lastSafeUrlByTab.get(tabId));
            chrome.tabs.update(tabId, { url: blockedPageUrl }).then(() => {
                console.log(`[AUTO-SCAN] Successfully blocked and redirected tab ${tabId}`);
            }).catch((error) => {
                console.error(`[AUTO-SCAN] Error blocking URL: ${error.message}`);
                // Fallback: try to send warning overlay
                setTimeout(() => {
                    chrome.tabs.sendMessage(tabId, {
                        action: "showWarning",
                        details: {
                            url: url,
                            classification: data.prediction || "phishing",
                            siteType: "this page"
                        }
                    }).catch(e => console.warn(`[AUTO-SCAN] Could not send warning: ${e.message}`));
                }, 1000);
            });
        } else if (shouldWarn) {
            console.log(`[AUTO-SCAN] Warning only (no hard block): ${url}`);
            blockedUrls.delete(url);
            chrome.tabs.sendMessage(tabId, {
                action: "showWarning",
                details: {
                    url: url,
                    classification: data.prediction || "phishing",
                    siteType: "this page"
                }
            }).catch(e => console.warn(`[AUTO-SCAN] Could not send warning: ${e.message}`));
        } else {
            console.log(`[AUTO-SCAN] âœ… URL is safe: ${url} (Risk: ${data.riskLevel || 'Low'})`);
            // Remove from blocked list if it was previously blocked
            blockedUrls.delete(url);
            lastSafeUrlByTab.set(tabId, url);
        }
    } catch (error) {
        console.error(`[AUTO-SCAN] âŒ Error scanning ${url}: ${error.message}`);
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError') || error.message.includes('ERR_CONNECTION_REFUSED')) {
            console.error(`[AUTO-SCAN] ðŸ’¡ Flask server is not running!`);
            console.error(`[AUTO-SCAN] ðŸ’¡ To start the server, run: python app.py`);
            console.error(`[AUTO-SCAN] ðŸ’¡ The server should be running on: http://127.0.0.1:5000`);
            // Don't mark as scanned if server is down, so it can retry later
            scannedTabs.delete(tabId);
        }
    } finally {
        if (scanningTabs.get(tabId) === url) {
            scanningTabs.delete(tabId);
        }
    }
}

// Listen for navigation BEFORE page loads (for faster blocking)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only process main frame navigations (not iframes)
    if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
        const url = details.url;
        const tabId = details.tabId;

        if (isEmailAppUrl(url)) {
            return;
        }

        // Explicit user bypass for this navigation
        if (hasBypassMarker(url)) {
            console.log(`[AUTO-SCAN] One-time bypass allowed for: ${url}`);
            blockedUrls.delete(url.replace(BYPASS_MARKER, ''));
            return;
        }
        
        // Skip if already blocked
        if (blockedUrls.has(url)) {
            console.log(`[AUTO-SCAN] ðŸš« URL already blocked, preventing navigation: ${url}`);
            chrome.tabs.update(tabId, { url: buildBlockedPageUrl(url, lastSafeUrlByTab.get(tabId)) }).catch(() => {
                // If blocked.html doesn't exist, use data URL
                const blockedMsg = `data:text/html,<html><body style="background:#991b1b;color:white;text-align:center;padding:50px;font-family:Arial"><h1>Blocked</h1><p>This site was previously identified as high risk.</p><button onclick="history.back()" style="padding:10px 20px;font-size:16px">Go Back</button><button onclick="if(confirm('Proceed to blocked site?'))location.href=decodeURIComponent('${encodeURIComponent(url)}')+'%23fortnox-allow'" style="padding:10px 20px;font-size:16px;margin-left:10px">Continue Anyway</button></body></html>`;
                chrome.tabs.update(tabId, { url: blockedMsg });
            });
            return;
        }
        
        // Check if auto-scan is enabled
        chrome.storage.sync.get(['autoScanEnabled'], (result) => {
            const autoScanEnabled = result.autoScanEnabled !== false;
            if (!autoScanEnabled) {
                return;
            }
            
            // Start scanning immediately (before page loads)
            console.log(`[AUTO-SCAN] ðŸ” Pre-scanning URL (before load): ${url}`);
            autoScanUrl(tabId, url);
        });
    }
});

// Also listen for tab updates (when page loads) as backup
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only scan when page is fully loaded and has a valid URL
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        if (isEmailAppUrl(tab.url)) {
            return;
        }
        if (hasBypassMarker(tab.url)) {
            return;
        }
        // Skip if already scanned or blocked
        const lastScannedUrl = scannedTabs.get(tabId);
        if (lastScannedUrl !== tab.url && !blockedUrls.has(tab.url)) {
            console.log(`[AUTO-SCAN] Tab ${tabId} updated: ${tab.url}`);
            autoScanUrl(tabId, tab.url);
        }
    }
});

// Also listen for new tabs being created
chrome.tabs.onCreated.addListener((tab) => {
    if (tab.url && tab.url.startsWith('http')) {
        if (isEmailAppUrl(tab.url)) {
            return;
        }
        console.log(`[AUTO-SCAN] New tab created: ${tab.url}`);
        // Wait for tab to load, then scan
        chrome.tabs.onUpdated.addListener(function listener(tabId, changeInfo, updatedTab) {
            if (tabId === tab.id && changeInfo.status === 'complete' && updatedTab.url) {
                chrome.tabs.onUpdated.removeListener(listener);
                if (!hasBypassMarker(updatedTab.url) && !isEmailAppUrl(updatedTab.url)) {
                    autoScanUrl(tabId, updatedTab.url);
                }
            }
        });
    }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
    scannedTabs.delete(tabId);
    scanningTabs.delete(tabId);
    lastSafeUrlByTab.delete(tabId);
});

chrome.runtime.onInstalled.addListener(() => {
    console.log("Phishing Detection ML Extension Prototype installed/updated.");
    // Set default auto-scan to enabled
    chrome.storage.sync.get(['autoScanEnabled'], (result) => {
        if (result.autoScanEnabled === undefined) {
            chrome.storage.sync.set({ autoScanEnabled: true });
        }
    });
});

