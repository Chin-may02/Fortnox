/**
 * Gmail Content Script for Email Phishing Detection
 *
 * This script runs in the context of Gmail (mail.google.com) and:
 * 1. Monitors for email opens
 * 2. Extracts email content (sender, subject, body, etc.)
 * 3. Sends to background for analysis
 * 4. Displays inline risk indicators
 */

console.log('[FortNox Gmail] Content script loaded');

// Track analyzed emails to avoid duplicates
const analyzedEmails = new Set();

// Debounce timer for email changes
let emailCheckTimeout = null;

function getVisibleElements(selector, root = document) {
    return Array.from(root.querySelectorAll(selector)).filter((element) => {
        const style = window.getComputedStyle(element);
        return style.display !== 'none' && style.visibility !== 'hidden';
    });
}

function getActiveEmailBodyElement() {
    const visibleBodies = getVisibleElements('.a3s.aiL');
    return visibleBodies.length ? visibleBodies[visibleBodies.length - 1] : document.querySelector('.a3s.aiL');
}

function getEmailScope(bodyElement) {
    return bodyElement?.closest('.adn.ads') || document;
}

function getFieldText(scope, selector, fallbackScope = document) {
    const scopedElement = scope.querySelector(selector);
    if (scopedElement?.textContent?.trim()) {
        return scopedElement.textContent.trim();
    }

    const fallbackElement = fallbackScope.querySelector(selector);
    return fallbackElement?.textContent?.trim() || '';
}

function getEmailAttribute(scope, selector, attribute, fallbackScope = document) {
    const scopedElement = scope.querySelector(selector);
    const scopedValue = scopedElement?.getAttribute(attribute)?.trim();
    if (scopedValue) {
        return scopedValue;
    }

    const fallbackElement = fallbackScope.querySelector(selector);
    return fallbackElement?.getAttribute(attribute)?.trim() || '';
}

/**
 * Extract email data from Gmail UI
 */
function extractEmailData() {
    try {
        const bodyElement = getActiveEmailBodyElement();
        const scope = getEmailScope(bodyElement);

        // Prefer the currently visible message, but keep document-level fallbacks.
        const fromEmail = getEmailAttribute(scope, '.gD[email], [email]', 'email');
        const senderNameElement = scope.querySelector('.gD') || document.querySelector('.gD');
        const fromName = senderNameElement
            ? senderNameElement.getAttribute('name') || senderNameElement.textContent.trim()
            : '';

        // Get subject
        const subjectElement = document.querySelector('.hP');
        const subject = subjectElement ? subjectElement.textContent.trim() : '';

        // Get email body text
        const bodyText = bodyElement ? bodyElement.innerText : '';

        // Get HTML body for additional analysis
        const bodyHtml = bodyElement ? bodyElement.innerHTML : '';

        // Extract recipient (current user's email)
        const toEmail = getFieldText(scope, '.go');

        // Extract reply-to if different (check for "via" in Gmail)
        const replyTo = getEmailAttribute(scope, '.gD[aria-label*="via"]', 'email');

        // Get attachment info
        const attachmentElements = scope.querySelectorAll('.aZo span[download], .aQH span[download]');
        const attachments = Array.from(attachmentElements)
            .map((element) => element.textContent.trim())
            .filter(Boolean);

        // Create unique email ID based on sender + subject + partial body
        const emailId = `${fromEmail}_${subject}_${bodyText.substring(0, 50)}`;

        return {
            emailId,
            from_email: fromEmail,
            from_name: fromName,
            to_email: toEmail,
            subject: subject,
            body_text: bodyText,
            body_html: bodyHtml,
            reply_to: replyTo,
            attachments: attachments
        };
    } catch (error) {
        console.error('[FortNox Gmail] Error extracting email data:', error);
        return null;
    }
}

/**
 * Create and insert risk indicator badge in Gmail UI
 */
function createRiskBadge(riskLevel, riskScore, riskFactors) {
    // Remove existing badge if present
    const existingBadge = document.getElementById('fortnox-email-risk-badge');
    if (existingBadge) {
        existingBadge.remove();
    }

    const badge = document.createElement('div');
    badge.id = 'fortnox-email-risk-badge';
    badge.style.cssText = `
        position: fixed;
        top: 70px;
        right: 20px;
        z-index: 10000;
        background: white;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        padding: 12px 16px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        max-width: 300px;
        animation: slideIn 0.3s ease-out;
    `;

    // Determine color based on risk level
    let color, icon;
    if (riskLevel === 'High Risk') {
        color = '#dc3545';
        icon = '⚠️';
    } else if (riskLevel === 'Medium Risk') {
        color = '#ffc107';
        icon = '⚡';
    } else {
        color = '#28a745';
        icon = '✓';
    }

    // Format risk score as percentage
    const riskPercentage = Math.round(riskScore * 100);

    badge.innerHTML = `
        <style>
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            #fortnox-email-risk-badge .risk-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 8px;
            }
            #fortnox-email-risk-badge .risk-title {
                font-weight: 600;
                font-size: 14px;
                color: #333;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            #fortnox-email-risk-badge .close-btn {
                cursor: pointer;
                font-size: 18px;
                color: #666;
                border: none;
                background: none;
                padding: 0;
                width: 20px;
                height: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            #fortnox-email-risk-badge .close-btn:hover {
                color: #333;
            }
            #fortnox-email-risk-badge .risk-score {
                font-size: 24px;
                font-weight: bold;
                color: ${color};
                margin: 8px 0;
            }
            #fortnox-email-risk-badge .risk-level {
                font-size: 12px;
                font-weight: 500;
                color: ${color};
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            #fortnox-email-risk-badge .risk-factors {
                margin-top: 12px;
                padding-top: 12px;
                border-top: 1px solid #e0e0e0;
            }
            #fortnox-email-risk-badge .factor-title {
                font-size: 11px;
                font-weight: 600;
                color: #666;
                margin-bottom: 6px;
                text-transform: uppercase;
            }
            #fortnox-email-risk-badge .factor-item {
                font-size: 12px;
                color: #555;
                margin: 4px 0;
                padding-left: 12px;
                position: relative;
            }
            #fortnox-email-risk-badge .factor-item:before {
                content: '•';
                position: absolute;
                left: 0;
                color: ${color};
            }
            #fortnox-email-risk-badge .powered-by {
                margin-top: 12px;
                font-size: 10px;
                color: #999;
                text-align: center;
            }
        </style>
        <div class="risk-header">
            <div class="risk-title">
                <span>${icon}</span>
                <span>FortNox Security</span>
            </div>
            <button class="close-btn" id="fortnox-close-badge">×</button>
        </div>
        <div class="risk-score">${riskPercentage}%</div>
        <div class="risk-level">${riskLevel}</div>
        ${riskFactors && riskFactors.length > 0 ? `
            <div class="risk-factors">
                <div class="factor-title">Risk Factors</div>
                ${riskFactors.slice(0, 4).map(factor => `<div class="factor-item">${factor}</div>`).join('')}
            </div>
        ` : ''}
        <div class="powered-by">Powered by FortNox</div>
    `;

    document.body.appendChild(badge);

    // Add close button handler
    document.getElementById('fortnox-close-badge').addEventListener('click', () => {
        badge.remove();
    });

    // Auto-hide after 10 seconds for low risk
    if (riskLevel === 'Low Risk') {
        setTimeout(() => {
            if (badge.parentNode) {
                badge.style.transition = 'opacity 0.3s ease-out';
                badge.style.opacity = '0';
                setTimeout(() => badge.remove(), 300);
            }
        }, 10000);
    }
}

/**
 * Show warning overlay for high-risk emails
 */
function showEmailWarningOverlay(data) {
    // Check if overlay already exists
    if (document.getElementById('fortnox-email-warning-overlay')) {
        return;
    }

    const overlay = document.createElement('div');
    overlay.id = 'fortnox-email-warning-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `;

    overlay.innerHTML = `
        <div style="
            background: white;
            border-radius: 12px;
            padding: 32px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        ">
            <div style="font-size: 64px; margin-bottom: 16px;">⚠️</div>
            <h2 style="
                color: #dc3545;
                font-size: 24px;
                font-weight: 600;
                margin: 0 0 12px 0;
            ">Phishing Email Detected</h2>
            <p style="
                color: #666;
                font-size: 16px;
                line-height: 1.5;
                margin: 0 0 24px 0;
            ">
                This email shows multiple signs of a phishing attempt.
                Do not click any links or download attachments.
            </p>
            <div style="
                background: #f8f9fa;
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 24px;
                text-align: left;
            ">
                <div style="font-size: 12px; font-weight: 600; color: #666; margin-bottom: 8px;">
                    DETECTED RISKS:
                </div>
                ${data.riskFactors.map(factor => `
                    <div style="font-size: 14px; color: #333; margin: 6px 0;">
                        • ${factor}
                    </div>
                `).join('')}
            </div>
            <button id="fortnox-email-warning-close" style="
                background: #dc3545;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 12px 24px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: background 0.2s;
            ">I Understand</button>
        </div>
    `;

    document.body.appendChild(overlay);

    document.getElementById('fortnox-email-warning-close').addEventListener('click', () => {
        overlay.remove();
    });
}

/**
 * Analyze current email
 */
async function analyzeCurrentEmail() {
    const emailData = extractEmailData();

    if (!emailData || !emailData.from_email) {
        console.log('[FortNox Gmail] No valid email data found');
        return;
    }

    // Check if already analyzed
    if (analyzedEmails.has(emailData.emailId)) {
        console.log('[FortNox Gmail] Email already analyzed');
        return;
    }

    analyzedEmails.add(emailData.emailId);
    console.log('[FortNox Gmail] Analyzing email from:', emailData.from_email);

    try {
        // Send to background for analysis
        const response = await chrome.runtime.sendMessage({
            action: 'checkEmailWithBackend',
            emailData: emailData
        });

        if (response.error) {
            console.error('[FortNox Gmail] Analysis error:', response.error);
            return;
        }

        const result = response.data;
        console.log('[FortNox Gmail] Analysis result:', result);

        // Display risk badge
        createRiskBadge(result.riskLevel, result.riskScore, result.riskFactors);

        // Show warning overlay for high-risk emails
        if (result.riskLevel === 'High Risk') {
            showEmailWarningOverlay(result);
        }

    } catch (error) {
        console.error('[FortNox Gmail] Error during analysis:', error);
    }
}

/**
 * Monitor for email changes
 */
function monitorEmailChanges() {
    // Check if we're viewing an email (presence of email body)
    const emailBody = getActiveEmailBodyElement();

    if (emailBody) {
        // Debounce to avoid multiple triggers
        clearTimeout(emailCheckTimeout);
        emailCheckTimeout = setTimeout(() => {
            analyzeCurrentEmail();
        }, 500);
    }
}

// Set up observer for Gmail DOM changes
const observer = new MutationObserver((mutations) => {
    monitorEmailChanges();
});

// Start observing when Gmail is ready
function initializeGmailMonitoring() {
    const gmailContainer = document.querySelector('body');
    if (gmailContainer) {
        observer.observe(gmailContainer, {
            childList: true,
            subtree: true
        });
        console.log('[FortNox Gmail] Monitoring initialized');

        // Check current state
        monitorEmailChanges();
    } else {
        // Retry after a delay
        setTimeout(initializeGmailMonitoring, 1000);
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeGmailMonitoring);
} else {
    initializeGmailMonitoring();
}

// Listen for manual scan requests from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'scanCurrentEmail') {
        analyzeCurrentEmail();
        sendResponse({ success: true });
    }
    return true;
});
