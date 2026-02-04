console.log(`[CONTENT SCRIPT] Loaded on: ${document.location.href}`);

let warningOverlayVisible = false;

function showWarningOverlay(details) {
    if (warningOverlayVisible) return;
    warningOverlayVisible = true;

    document.body.style.overflow = 'hidden';

    const overlay = document.createElement('div');
    overlay.id = 'security-warning-overlay';

    let warningTitle = "Security Alert!";
    let siteType = details.siteType || "this page";

    if (details.classification === "phishing") {
        warningTitle = "Phishing Attempt Detected!";
    } else if (details.classification === "malware") {
        warningTitle = "Malware Threat Detected!";
    }

    overlay.innerHTML = `
        <h1>${warningTitle}</h1>
        <p>Our security scan has identified ${siteType} as potentially dangerous due to ${details.classification} activity. 
        It is strongly advised to go back.</p>
        <div class="warning-buttons">
            <button id="warning-go-back">Go Back to Safety</button>
            <button id="warning-proceed" style="display: none;">Proceed Anyway (Risky)</button> 
        </div>
    `;

    document.body.appendChild(overlay);

    // Wait for DOM to be ready, then attach event listeners
    setTimeout(() => {
        const goBackButton = document.getElementById('warning-go-back');
        if (goBackButton) {
            // Remove any existing listeners and add new one
            goBackButton.addEventListener('click', function handleGoBack(e) {
                e.preventDefault();
                e.stopPropagation();
                console.log('[WARNING] Go Back button clicked');
                
                // Try to go back in history
                if (window.history.length > 1) {
                    try {
                        window.history.back();
                        // If history.back() doesn't work, try after a short delay
                        setTimeout(() => {
                            // Fallback: redirect to a safe page
                            if (document.location.href === window.location.href) {
                                window.location.href = 'https://www.google.com';
                            }
                        }, 500);
                    } catch (error) {
                        console.error('[WARNING] Error going back:', error);
                        // Fallback: redirect to Google
                        window.location.href = 'https://www.google.com';
                    }
                } else {
                    // No history, redirect to safe page
                    console.log('[WARNING] No history, redirecting to safe page');
                    window.location.href = 'https://www.google.com';
                }
            }, { once: true, capture: true });
            
            // Also handle via onclick as backup
            goBackButton.onclick = function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (window.history.length > 1) {
                    window.history.back();
                } else {
                    window.location.href = 'https://www.google.com';
                }
                return false;
            };
        } else {
            console.error('[WARNING] Go Back button not found!');
        }
    }, 100);
}


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("[CONTENT SCRIPT] Message received in content.js:", request);
    if (request.action === "extractPageDetails") {
        console.log("[CONTENT SCRIPT] 'extractPageDetails' action recognized.");
        const pageTitle = document.title;
        const paragraphCount = document.getElementsByTagName('p').length;
        const firstH1Text = document.getElementsByTagName('h1')[0] ? document.getElementsByTagName('h1')[0].innerText.substring(0, 100) + '...' : "No H1 tag found";

        sendResponse({
            title: pageTitle,
            pCount: paragraphCount,
            h1Text: firstH1Text
        });
    } else if (request.action === "showWarning") {
        console.log("[CONTENT SCRIPT] 'showWarning' action recognized with details:", request.details);
        showWarningOverlay(request.details);
        sendResponse({ status: "Warning displayed" });
    }
});