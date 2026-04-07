console.log(`[CONTENT SCRIPT] Loaded on: ${document.location.href}`);

const PERMISSION_MONITOR_SOURCE = 'FORTNOX_PERMISSION_MONITOR';
const PERMISSION_MONITOR_REQUEST_SOURCE = 'FORTNOX_PERMISSION_CONTENT';
const PERMISSION_MONITOR_SNAPSHOT_REQUEST = 'FORTNOX_PERMISSION_SNAPSHOT_REQUEST';
const PERMISSION_TOAST_LIFETIME_MS = 6500;
const PERMISSION_TOAST_ROOT_ID = 'fortnox-permission-toast-root';
const TRACKED_PERMISSION_ORDER = ['location', 'camera', 'microphone', 'notifications', 'clipboard', 'screenCapture'];
const TRACKED_PERMISSION_LABELS = {
    location: 'Location',
    camera: 'Camera',
    microphone: 'Microphone',
    notifications: 'Notifications',
    clipboard: 'Clipboard',
    screenCapture: 'Screen Capture'
};

let warningOverlayVisible = false;
let permissionSummaryReady = false;
let initialPermissionToastShown = false;
let permissionToastDomReadyListenerBound = false;

const permissionToastQueue = [];
const pendingPermissionSummaryResolvers = [];
const lastPermissionAlertSignature = new Map();
const permissionStateByKey = createDefaultPermissionState();

function createDefaultPermissionState() {
    return TRACKED_PERMISSION_ORDER.reduce((records, key) => {
        records[key] = {
            key,
            label: TRACKED_PERMISSION_LABELS[key] || key,
            state: key === 'screenCapture' ? 'not-requested' : 'unknown',
            access: 'not_observed',
            lastEvent: null,
            lastUpdated: null
        };
        return records;
    }, {});
}

function accessRank(access) {
    if (access === 'used') {
        return 2;
    }
    if (access === 'requested') {
        return 1;
    }
    return 0;
}

function normalizePermissionState(state) {
    const allowedStates = new Set(['granted', 'prompt', 'denied', 'unsupported', 'unknown', 'not-requested']);
    return allowedStates.has(state) ? state : 'unknown';
}

function normalizePermissionAccess(access) {
    const allowedAccessValues = new Set(['used', 'requested', 'not_observed']);
    return allowedAccessValues.has(access) ? access : 'not_observed';
}

function clonePermissionRecord(permission) {
    return {
        key: permission.key,
        label: permission.label,
        state: permission.state,
        access: permission.access,
        lastEvent: permission.lastEvent ? { ...permission.lastEvent } : null,
        lastUpdated: permission.lastUpdated
    };
}

function withBodyReady(callback) {
    if (document.body) {
        callback();
        return;
    }

    document.addEventListener('DOMContentLoaded', () => callback(), { once: true });
}

function showWarningOverlay(details) {
    withBodyReady(() => {
        const existing = document.getElementById('security-warning-overlay');
        if (existing) {
            existing.remove();
        }
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

        const warningBadgeText = details.classification === "phishing"
            ? "Phishing intercept"
            : "Threat intercept";

        overlay.innerHTML = `
            <div class="fortnox-warning-shell">
                <div class="fortnox-warning-badges">
                    <span class="fortnox-warning-badge">FORTNOX Shield</span>
                    <span class="fortnox-warning-badge fortnox-warning-badge-danger">${warningBadgeText}</span>
                </div>
                <h1>${warningTitle}</h1>
                <p>Our security scan has identified ${siteType} as potentially dangerous due to ${details.classification} activity.
                It is strongly advised to go back.</p>
                <div class="warning-buttons">
                    <button id="warning-go-back">Go Back to Safety</button>
                    <button id="warning-proceed" style="display: none;">Proceed Anyway (Risky)</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);

        setTimeout(() => {
            const goBackButton = document.getElementById('warning-go-back');
            if (goBackButton) {
                goBackButton.addEventListener('click', function handleGoBack(event) {
                    event.preventDefault();
                    event.stopPropagation();
                    console.log('[WARNING] Go Back button clicked');

                    if (window.history.length > 1) {
                        try {
                            window.history.back();
                            setTimeout(() => {
                                if (document.location.href === window.location.href) {
                                    window.location.href = 'https://www.google.com';
                                }
                            }, 500);
                        } catch (error) {
                            console.error('[WARNING] Error going back:', error);
                            window.location.href = 'https://www.google.com';
                        }
                    } else {
                        console.log('[WARNING] No history, redirecting to safe page');
                        window.location.href = 'https://www.google.com';
                    }
                }, { once: true, capture: true });

                goBackButton.onclick = function onWarningGoBack(event) {
                    event.preventDefault();
                    event.stopPropagation();
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
    });
}

function requestPermissionSnapshot() {
    window.postMessage({
        source: PERMISSION_MONITOR_REQUEST_SOURCE,
        type: PERMISSION_MONITOR_SNAPSHOT_REQUEST
    }, '*');
}

function resolvePendingPermissionSummaryRequests() {
    while (pendingPermissionSummaryResolvers.length) {
        const resolve = pendingPermissionSummaryResolvers.shift();
        resolve();
    }
}

function waitForPermissionSummary(timeoutMs = 450) {
    if (permissionSummaryReady) {
        return Promise.resolve();
    }

    requestPermissionSnapshot();

    return new Promise((resolve) => {
        const timeoutId = setTimeout(resolve, timeoutMs);
        pendingPermissionSummaryResolvers.push(() => {
            clearTimeout(timeoutId);
            resolve();
        });
    });
}

function mergePermissionRecord(rawPermission) {
    if (!rawPermission || !rawPermission.key || !permissionStateByKey[rawPermission.key]) {
        return false;
    }

    const permission = permissionStateByKey[rawPermission.key];
    let changed = false;

    const nextState = normalizePermissionState(rawPermission.state);
    if (permission.state !== nextState) {
        permission.state = nextState;
        changed = true;
    }

    const nextAccess = normalizePermissionAccess(rawPermission.access);
    const mergedAccess = accessRank(nextAccess) >= accessRank(permission.access) ? nextAccess : permission.access;
    if (permission.access !== mergedAccess) {
        permission.access = mergedAccess;
        changed = true;
    }

    if (rawPermission.lastEvent) {
        permission.lastEvent = { ...rawPermission.lastEvent };
        changed = true;
    }

    if (rawPermission.lastUpdated && permission.lastUpdated !== rawPermission.lastUpdated) {
        permission.lastUpdated = rawPermission.lastUpdated;
        changed = true;
    }

    return changed;
}

function mergePermissionSnapshot(detail) {
    if (!detail || !Array.isArray(detail.permissions)) {
        return false;
    }

    let changed = false;
    detail.permissions.forEach((permission) => {
        if (mergePermissionRecord(permission)) {
            changed = true;
        }
    });

    permissionSummaryReady = true;
    resolvePendingPermissionSummaryRequests();
    return changed;
}

function applyPermissionActivity(detail) {
    if (!detail || !detail.key || !permissionStateByKey[detail.key]) {
        return null;
    }

    const permission = permissionStateByKey[detail.key];
    const previous = clonePermissionRecord(permission);
    const stage = detail.stage;
    const timestamp = detail.timestamp || new Date().toISOString();

    if (stage === 'requested') {
        permission.access = accessRank(permission.access) >= accessRank('requested') ? permission.access : 'requested';
        if (permission.state === 'not-requested') {
            permission.state = 'prompt';
        }
    } else if (stage === 'used' || stage === 'granted') {
        permission.access = 'used';
        if (permission.state !== 'unsupported') {
            permission.state = 'granted';
        }
    } else if (stage === 'denied') {
        permission.access = permission.access === 'used' ? 'used' : 'requested';
        permission.state = 'denied';
    }

    permission.lastEvent = {
        key: detail.key,
        label: detail.label || permission.label,
        stage,
        api: detail.api || null,
        timestamp
    };
    permission.lastUpdated = timestamp;
    permissionSummaryReady = true;
    resolvePendingPermissionSummaryRequests();

    const signature = [permission.key, stage, permission.state, permission.access, detail.api || ''].join('|');
    const shouldNotify = (
        (previous.state !== permission.state ||
            previous.access !== permission.access ||
            previous.lastEvent?.stage !== permission.lastEvent.stage ||
            previous.lastEvent?.api !== permission.lastEvent.api) &&
        lastPermissionAlertSignature.get(permission.key) !== signature
    );

    if (shouldNotify) {
        lastPermissionAlertSignature.set(permission.key, signature);
        return {
            previous,
            permission: clonePermissionRecord(permission),
            detail: permission.lastEvent
        };
    }

    return null;
}

function buildPermissionSummaryPayload() {
    const permissions = TRACKED_PERMISSION_ORDER.map((key) => clonePermissionRecord(permissionStateByKey[key]));
    const counts = {
        tracked: permissions.length,
        granted: permissions.filter((permission) => permission.state === 'granted').length,
        denied: permissions.filter((permission) => permission.state === 'denied').length,
        requested: permissions.filter((permission) => permission.access === 'requested').length,
        used: permissions.filter((permission) => permission.access === 'used').length
    };

    const updatedAt = permissions
        .map((permission) => permission.lastUpdated)
        .filter(Boolean)
        .sort()
        .pop() || null;

    return {
        origin: window.location.origin,
        url: window.location.href,
        secureContext: window.isSecureContext,
        updatedAt,
        counts,
        permissions
    };
}

function formatPermissionStateText(permission) {
    if (permission.access === 'used') {
        return 'Used in this tab';
    }
    if (permission.access === 'requested') {
        return 'Requested in this tab';
    }
    if (permission.state === 'granted') {
        return 'Allowed by browser';
    }
    if (permission.state === 'denied') {
        return 'Blocked by browser';
    }
    if (permission.state === 'prompt') {
        return 'Will ask before access';
    }
    if (permission.state === 'unsupported') {
        return 'Not available here';
    }
    if (permission.state === 'not-requested') {
        return 'Not requested yet';
    }
    return 'No access observed';
}

function getInterestingPermissions(permissions) {
    return permissions.filter((permission) => (
        permission.access !== 'not_observed' ||
        permission.state === 'granted' ||
        permission.state === 'denied'
    ));
}

function buildInitialPermissionSummaryToast() {
    const summary = buildPermissionSummaryPayload();
    const interestingPermissions = getInterestingPermissions(summary.permissions).slice(0, 4);
    const hostname = window.location.hostname || 'this site';

    let description = `${hostname} has not been observed using any major sensitive permissions in this tab yet.`;
    if (summary.counts.used > 0) {
        description = `${hostname} has already used ${summary.counts.used} sensitive permission${summary.counts.used === 1 ? '' : 's'} in this tab.`;
    } else if (summary.counts.granted > 0) {
        description = `${hostname} currently has ${summary.counts.granted} sensitive permission${summary.counts.granted === 1 ? '' : 's'} allowed by the browser.`;
    } else if (summary.counts.denied > 0) {
        description = `${hostname} has sensitive permissions blocked or waiting for user approval.`;
    }

    return {
        variant: 'summary',
        title: 'Site permission summary',
        description,
        permissions: interestingPermissions
    };
}

function buildPermissionActivityToast(change) {
    const permission = change.permission;
    const stage = change.detail?.stage;
    const apiLabel = change.detail?.api ? ` via ${change.detail.api}` : '';
    const hostname = window.location.hostname || 'This site';

    let description = `${hostname} updated a sensitive permission.`;
    if (stage === 'requested') {
        description = `${hostname} asked for ${permission.label.toLowerCase()} access${apiLabel}.`;
    } else if (stage === 'used' || stage === 'granted') {
        description = `${hostname} is using ${permission.label.toLowerCase()} access${apiLabel}.`;
    } else if (stage === 'denied') {
        description = `${hostname} was blocked from ${permission.label.toLowerCase()} access${apiLabel}.`;
    }

    return {
        variant: 'update',
        title: `${permission.label} permission update`,
        description,
        permissions: [permission]
    };
}

function ensurePermissionToastRoot() {
    let root = document.getElementById(PERMISSION_TOAST_ROOT_ID);
    if (root) {
        return root;
    }

    if (!document.body) {
        return null;
    }

    root = document.createElement('div');
    root.id = PERMISSION_TOAST_ROOT_ID;
    document.body.appendChild(root);
    return root;
}

function schedulePermissionToastFlush() {
    if (permissionToastDomReadyListenerBound) {
        return;
    }

    permissionToastDomReadyListenerBound = true;
    document.addEventListener('DOMContentLoaded', () => {
        permissionToastDomReadyListenerBound = false;
        flushPermissionToastQueue();
    }, { once: true });
}

function createPermissionChip(permission) {
    const chip = document.createElement('div');
    chip.className = 'fortnox-permission-chip';

    if (permission.access === 'used' || permission.state === 'granted') {
        chip.classList.add('fortnox-permission-chip-alert');
    } else if (permission.access === 'requested') {
        chip.classList.add('fortnox-permission-chip-watch');
    } else if (permission.state === 'denied') {
        chip.classList.add('fortnox-permission-chip-blocked');
    }

    const label = document.createElement('span');
    label.className = 'fortnox-permission-chip-label';
    label.textContent = permission.label;

    const status = document.createElement('span');
    status.className = 'fortnox-permission-chip-status';
    status.textContent = formatPermissionStateText(permission);

    chip.appendChild(label);
    chip.appendChild(status);
    return chip;
}

function renderPermissionToast(root, toast) {
    const card = document.createElement('section');
    card.className = `fortnox-permission-toast fortnox-permission-toast-${toast.variant || 'summary'}`;

    const headerRow = document.createElement('div');
    headerRow.className = 'fortnox-permission-toast-header';

    const headingGroup = document.createElement('div');

    const eyebrow = document.createElement('p');
    eyebrow.className = 'fortnox-permission-toast-eyebrow';
    eyebrow.textContent = 'FORTNOX permission monitor';

    const title = document.createElement('h3');
    title.className = 'fortnox-permission-toast-title';
    title.textContent = toast.title;

    headingGroup.appendChild(eyebrow);
    headingGroup.appendChild(title);

    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'fortnox-permission-toast-close';
    closeButton.setAttribute('aria-label', 'Dismiss permission notice');
    closeButton.textContent = 'x';

    headerRow.appendChild(headingGroup);
    headerRow.appendChild(closeButton);

    const description = document.createElement('p');
    description.className = 'fortnox-permission-toast-description';
    description.textContent = toast.description;

    card.appendChild(headerRow);
    card.appendChild(description);

    if (Array.isArray(toast.permissions) && toast.permissions.length) {
        const chipList = document.createElement('div');
        chipList.className = 'fortnox-permission-chip-list';

        toast.permissions.forEach((permission) => {
            chipList.appendChild(createPermissionChip(permission));
        });

        card.appendChild(chipList);
    }

    closeButton.addEventListener('click', () => {
        card.remove();
    });

    root.appendChild(card);

    window.setTimeout(() => {
        if (card.isConnected) {
            card.classList.add('fortnox-permission-toast-hiding');
            window.setTimeout(() => card.remove(), 220);
        }
    }, PERMISSION_TOAST_LIFETIME_MS);
}

function flushPermissionToastQueue() {
    const root = ensurePermissionToastRoot();
    if (!root) {
        schedulePermissionToastFlush();
        return;
    }

    while (permissionToastQueue.length) {
        renderPermissionToast(root, permissionToastQueue.shift());
    }
}

function enqueuePermissionToast(toast) {
    permissionToastQueue.push(toast);
    flushPermissionToastQueue();
}

window.addEventListener('message', (event) => {
    if (event.source !== window || !event.data || event.data.source !== PERMISSION_MONITOR_SOURCE) {
        return;
    }

    if (event.data.eventType === 'permissionSnapshot') {
        mergePermissionSnapshot(event.data.detail);

        if (!initialPermissionToastShown) {
            initialPermissionToastShown = true;
            enqueuePermissionToast(buildInitialPermissionSummaryToast());
        }
        return;
    }

    if (event.data.eventType === 'permissionActivity') {
        const change = applyPermissionActivity(event.data.detail);
        if (change) {
            enqueuePermissionToast(buildPermissionActivityToast(change));
        }
    }
});

requestPermissionSnapshot();
window.addEventListener('load', () => requestPermissionSnapshot(), { once: true });

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("[CONTENT SCRIPT] Message received in content.js:", request);

    if (request.action === "extractPageDetails") {
        console.log("[CONTENT SCRIPT] 'extractPageDetails' action recognized.");
        const pageTitle = document.title;
        const paragraphCount = document.getElementsByTagName('p').length;
        const firstH1Text = document.getElementsByTagName('h1')[0]
            ? `${document.getElementsByTagName('h1')[0].innerText.substring(0, 100)}...`
            : "No H1 tag found";

        sendResponse({
            title: pageTitle,
            pCount: paragraphCount,
            h1Text: firstH1Text
        });
        return false;
    }

    if (request.action === "showWarning") {
        console.log("[CONTENT SCRIPT] 'showWarning' action recognized with details:", request.details);
        showWarningOverlay(request.details);
        sendResponse({ status: "Warning displayed" });
        return false;
    }

    if (request.action === "getPermissionSummary") {
        waitForPermissionSummary().then(() => {
            sendResponse({ summary: buildPermissionSummaryPayload() });
        }).catch((error) => {
            sendResponse({ error: error.message || 'Unable to build permission summary.' });
        });
        return true;
    }

    return false;
});
