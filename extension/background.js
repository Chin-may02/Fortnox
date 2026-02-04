
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

    })();

    return true;
});

// Track scanned URLs per tab to avoid duplicate scans in same session
const scannedTabs = new Map();
// Track blocked URLs to prevent re-scanning
const blockedUrls = new Set();

// Auto-scan function
async function autoScanUrl(tabId, url) {
    // Skip non-http/https URLs (chrome://, about:, etc.)
    if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) {
        console.log(`[AUTO-SCAN] Skipping non-HTTP URL: ${url}`);
        return;
    }

    // Skip if already scanned for this tab
    if (scannedTabs.get(tabId) === url) {
        console.log(`[AUTO-SCAN] Already scanned this URL for tab ${tabId}: ${url}`);
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
        console.log(`[AUTO-SCAN] 🔍 Scanning URL: ${url}`);
        const response = await fetch('http://127.0.0.1:5000/check_url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url }),
        });

        if (!response.ok) {
            console.warn(`[AUTO-SCAN] ⚠️ Server error for ${url}: ${response.status}`);
            console.warn(`[AUTO-SCAN] Make sure Flask server is running: python app.py`);
            return;
        }

        const data = await response.json();
        scannedTabs.set(tabId, url); // Mark as scanned

        // Show warning and BLOCK if phishing or high risk detected
        const isPhishing = data.prediction === "phishing";
        const isHighRisk = data.riskLevel && (data.riskLevel.includes("High Risk") || data.riskLevel.includes("High"));
        
        if (isPhishing || isHighRisk) {
            console.log(`[AUTO-SCAN] 🚨 THREAT DETECTED - BLOCKING: ${url}`);
            console.log(`[AUTO-SCAN] Risk Level: ${data.riskLevel || data.prediction}`);
            console.log(`[AUTO-SCAN] Probabilities: Safe=${((data.probabilities?.[0] || 0) * 100).toFixed(1)}%, Phishing=${((data.probabilities?.[1] || 0) * 100).toFixed(1)}%`);
            
            // Mark as blocked
            blockedUrls.add(url);
            
            // Block the page by redirecting to a blocked page with warning
            try {
                // Generate detailed risk explanation
                const riskScore = ((data.riskScore || data.probabilities?.[1] || 0) * 100).toFixed(1);
                const safeProb = ((data.probabilities?.[0] || 0) * 100).toFixed(1);
                const phishingProb = ((data.probabilities?.[1] || 0) * 100).toFixed(1);
                
                let riskReasons = [];
                if (data.riskScore >= 0.7) {
                    riskReasons.push('Very high phishing probability detected (' + riskScore + '%)');
                }
                if (data.message && data.message.includes('phishing')) {
                    riskReasons.push('Phishing patterns identified in URL structure');
                }
                if (url.includes('login') || url.includes('verify') || url.includes('secure')) {
                    riskReasons.push('Suspicious login/verification page characteristics');
                }
                if (url.includes('webflow.io') || url.includes('wixsite.com') || url.includes('000webhost')) {
                    riskReasons.push('Free hosting domain often used for phishing attacks');
                }
                if (url.includes('ledger') && !url.includes('ledger.com')) {
                    riskReasons.push('Potential brand impersonation (fake Ledger website)');
                }
                if (!riskReasons.length) {
                    riskReasons.push('High risk score from machine learning analysis');
                    riskReasons.push('URL features match known phishing patterns');
                }
                
                const reasonsHtml = riskReasons.map(reason => `<li>${reason}</li>`).join('');
                const modelAccuracy = data.modelMetrics?.accuracy ? (data.modelMetrics.accuracy * 100).toFixed(1) + '%' : 'High';
                
                // Create a data URL with the blocked page HTML
                const blockedPageHtml = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Blocked - Phishing Threat Detected</title>
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #991b1b 0%, #dc2626 100%);
            color: white;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            text-align: center;
        }
        .container {
            max-width: 700px;
            padding: 40px;
        }
        h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
        }
        h2 {
            font-size: 1.5em;
            margin-top: 30px;
            margin-bottom: 15px;
            text-align: left;
        }
        p {
            font-size: 1.1em;
            line-height: 1.6;
            margin-bottom: 20px;
            text-align: left;
        }
        .url-display {
            background: rgba(255,255,255,0.15);
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9em;
        }
        .risk-box {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: left;
        }
        .risk-box ul {
            text-align: left;
            padding-left: 20px;
        }
        .risk-box li {
            margin: 10px 0;
            line-height: 1.5;
        }
        .stats {
            display: flex;
            justify-content: space-around;
            margin: 20px 0;
            flex-wrap: wrap;
        }
        .stat-item {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 8px;
            margin: 10px;
            min-width: 150px;
        }
        .stat-value {
            font-size: 1.8em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        button {
            padding: 15px 30px;
            font-size: 1.1em;
            font-weight: bold;
            cursor: pointer;
            border: 2px solid white;
            background-color: white;
            color: #991b1b;
            border-radius: 5px;
            margin: 10px;
        }
        button:hover {
            background-color: #f0f0f0;
            transform: scale(1.05);
        }
        .warning-icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning-icon">🚨</div>
        <h1>Threat Detected!</h1>
        <p><strong>This website has been blocked for your protection.</strong></p>
        
        <div class="url-display">${url}</div>
        
        <div class="stats">
            <div class="stat-item">
                <div class="stat-value">${riskScore}%</div>
                <div class="stat-label">Risk Score</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${phishingProb}%</div>
                <div class="stat-label">Phishing Probability</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">${safeProb}%</div>
                <div class="stat-label">Safe Probability</div>
            </div>
        </div>
        
        <div class="risk-box">
            <h2>Why was this site blocked?</h2>
            <p>Our AI-powered phishing detection system analyzed this website and identified the following risk factors:</p>
            <ul>
                ${reasonsHtml}
            </ul>
            <p style="margin-top: 20px;"><strong>Risk Level:</strong> ${data.riskLevel || 'High Risk'}</p>
            <p><strong>Model Confidence:</strong> ${modelAccuracy}</p>
        </div>
        
        <div style="margin-top: 30px;">
            <p><strong>⚠️ It is strongly advised NOT to proceed to this website.</strong></p>
            <p>This site may attempt to steal your personal information, login credentials, or financial details.</p>
        </div>
        
        <div style="margin-top: 30px;">
            <button onclick="window.history.back()">Go Back to Safety</button>
            <button onclick="window.location.href='https://www.google.com'">Go to Google</button>
        </div>
    </div>
</body>
</html>`;
                
                const blockedPageUrl = 'data:text/html;charset=utf-8,' + encodeURIComponent(blockedPageHtml);
                
                // Redirect the tab to the blocked page
                chrome.tabs.update(tabId, { url: blockedPageUrl }, () => {
                    console.log(`[AUTO-SCAN] ✅ Successfully blocked and redirected tab ${tabId}`);
                });
                
            } catch (error) {
                console.error(`[AUTO-SCAN] ❌ Error blocking URL: ${error.message}`);
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
            }
        } else {
            console.log(`[AUTO-SCAN] ✅ URL is safe: ${url} (Risk: ${data.riskLevel || 'Low'})`);
            // Remove from blocked list if it was previously blocked
            blockedUrls.delete(url);
        }
    } catch (error) {
        console.error(`[AUTO-SCAN] ❌ Error scanning ${url}: ${error.message}`);
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError') || error.message.includes('ERR_CONNECTION_REFUSED')) {
            console.error(`[AUTO-SCAN] 💡 Flask server is not running!`);
            console.error(`[AUTO-SCAN] 💡 To start the server, run: python app.py`);
            console.error(`[AUTO-SCAN] 💡 The server should be running on: http://127.0.0.1:5000`);
            // Don't mark as scanned if server is down, so it can retry later
            scannedTabs.delete(tabId);
        }
    }
}

// Listen for navigation BEFORE page loads (for faster blocking)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    // Only process main frame navigations (not iframes)
    if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
        const url = details.url;
        const tabId = details.tabId;
        
        // Skip if already blocked
        if (blockedUrls.has(url)) {
            console.log(`[AUTO-SCAN] 🚫 URL already blocked, preventing navigation: ${url}`);
            chrome.tabs.update(tabId, { url: 'chrome-extension://' + chrome.runtime.id + '/blocked.html' }).catch(() => {
                // If blocked.html doesn't exist, use data URL
                const blockedMsg = `data:text/html,<html><body style="background:#991b1b;color:white;text-align:center;padding:50px;font-family:Arial"><h1>🚨 Blocked</h1><p>This site was previously identified as high risk.</p><button onclick="history.back()" style="padding:10px 20px;font-size:16px">Go Back</button></body></html>`;
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
            console.log(`[AUTO-SCAN] 🔍 Pre-scanning URL (before load): ${url}`);
            autoScanUrl(tabId, url);
        });
    }
});

// Also listen for tab updates (when page loads) as backup
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    // Only scan when page is fully loaded and has a valid URL
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        // Skip if already scanned or blocked
        const lastScannedUrl = scannedTabs.get(tabId);
        if (lastScannedUrl !== tab.url && !blockedUrls.has(tab.url)) {
            console.log(`[AUTO-SCAN] Tab ${tabId} updated: ${tab.url}`);
            // Small delay to ensure page is fully loaded
            setTimeout(() => {
                autoScanUrl(tabId, tab.url);
            }, 1000);
        }
    }
});

// Also listen for new tabs being created
chrome.tabs.onCreated.addListener((tab) => {
    if (tab.url && tab.url.startsWith('http')) {
        console.log(`[AUTO-SCAN] New tab created: ${tab.url}`);
        // Wait for tab to load, then scan
        chrome.tabs.onUpdated.addListener(function listener(tabId, changeInfo, updatedTab) {
            if (tabId === tab.id && changeInfo.status === 'complete' && updatedTab.url) {
                chrome.tabs.onUpdated.removeListener(listener);
                setTimeout(() => {
                    autoScanUrl(tabId, updatedTab.url);
                }, 1000);
            }
        });
    }
});

// Clean up when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
    scannedTabs.delete(tabId);
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
