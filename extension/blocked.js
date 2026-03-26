const BYPASS_MARKER = '#fortnox-allow';

function getQueryParams() {
    const params = new URLSearchParams(window.location.search);
    return {
        target: params.get('target') || '',
        returnTo: params.get('returnTo') || ''
    };
}

function appendBypassMarker(url) {
    try {
        const parsed = new URL(url);
        parsed.hash = 'fortnox-allow';
        return parsed.toString();
    } catch (error) {
        return `${url}${BYPASS_MARKER}`;
    }
}

async function getCurrentTab() {
    try {
        return await chrome.tabs.getCurrent();
    } catch (error) {
        console.warn('[BLOCKED PAGE] Unable to read current tab:', error);
        return null;
    }
}

async function navigateCurrentTab(url) {
    const currentTab = await getCurrentTab();

    if (currentTab?.id) {
        await chrome.tabs.update(currentTab.id, { url });
        return;
    }

    window.location.href = url;
}

async function openSafeFallback() {
    const currentTab = await getCurrentTab();

    if (currentTab?.id) {
        const newTab = await chrome.tabs.create({});

        if (newTab?.id && currentTab.id !== newTab.id) {
            await chrome.tabs.remove(currentTab.id);
        }
        return;
    }

    window.location.href = 'about:blank';
}

async function closeCurrentTab() {
    const currentTab = await getCurrentTab();

    if (currentTab?.id) {
        await chrome.tabs.remove(currentTab.id);
        return;
    }

    window.close();
}

document.addEventListener('DOMContentLoaded', () => {
    const { target, returnTo } = getQueryParams();
    const blockedTarget = document.getElementById('blockedTarget');
    const goBackBtn = document.getElementById('goBackBtn');
    const continueBtn = document.getElementById('continueBtn');
    const closeTabBtn = document.getElementById('closeTabBtn');

    if (target) {
        blockedTarget.textContent = `Blocked URL: ${target}`;
    } else {
        blockedTarget.textContent = 'Blocked URL: unavailable';
        continueBtn.disabled = true;
    }

    if (!returnTo) {
        goBackBtn.textContent = 'Open Safe New Tab';
    }

    goBackBtn.addEventListener('click', async () => {
        try {
            if (returnTo) {
                await navigateCurrentTab(returnTo);
                return;
            }

            await openSafeFallback();
        } catch (error) {
            console.error('[BLOCKED PAGE] Failed to leave blocked page:', error);
            await openSafeFallback();
        }
    });

    continueBtn.addEventListener('click', async () => {
        if (!target) {
            return;
        }

        const ok = window.confirm(
            'This site was flagged as high risk. Continue only if you trust it. Do you still want to proceed?'
        );

        if (!ok) {
            return;
        }

        try {
            await navigateCurrentTab(appendBypassMarker(target));
        } catch (error) {
            console.error('[BLOCKED PAGE] Failed to continue to blocked target:', error);
        }
    });

    closeTabBtn.addEventListener('click', async () => {
        try {
            await closeCurrentTab();
        } catch (error) {
            console.error('[BLOCKED PAGE] Failed to close tab:', error);
            window.close();
        }
    });
});
