(() => {
    if (window.__fortnoxPermissionMonitorInstalled) {
        return;
    }
    window.__fortnoxPermissionMonitorInstalled = true;

    const MONITOR_SOURCE = 'FORTNOX_PERMISSION_MONITOR';
    const CONTENT_SOURCE = 'FORTNOX_PERMISSION_CONTENT';
    const SNAPSHOT_REQUEST = 'FORTNOX_PERMISSION_SNAPSHOT_REQUEST';
    const DEFAULT_ACCESS = 'not_observed';

    const TRACKED_PERMISSIONS = {
        location: {
            key: 'location',
            label: 'Location',
            queries: [{ name: 'geolocation' }],
            defaultState: 'unknown'
        },
        camera: {
            key: 'camera',
            label: 'Camera',
            queries: [{ name: 'camera' }],
            defaultState: 'unknown'
        },
        microphone: {
            key: 'microphone',
            label: 'Microphone',
            queries: [{ name: 'microphone' }],
            defaultState: 'unknown'
        },
        notifications: {
            key: 'notifications',
            label: 'Notifications',
            queries: [{ name: 'notifications' }],
            defaultState: 'unknown'
        },
        clipboard: {
            key: 'clipboard',
            label: 'Clipboard',
            queries: [{ name: 'clipboard-read' }, { name: 'clipboard-write' }],
            defaultState: 'unknown'
        },
        screenCapture: {
            key: 'screenCapture',
            label: 'Screen Capture',
            queries: [],
            defaultState: 'not-requested'
        }
    };

    const permissionStateByKey = Object.values(TRACKED_PERMISSIONS).reduce((records, permission) => {
        records[permission.key] = {
            key: permission.key,
            label: permission.label,
            state: permission.defaultState,
            access: DEFAULT_ACCESS,
            lastEvent: null,
            lastUpdated: null
        };
        return records;
    }, {});

    const permissionQueryStates = new Map();
    const observedStatuses = new WeakSet();

    function normalizePermissionState(value) {
        const allowedStates = new Set(['granted', 'prompt', 'denied', 'unsupported', 'unknown', 'not-requested']);
        return allowedStates.has(value) ? value : 'unknown';
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

    function clonePermission(permission) {
        return {
            key: permission.key,
            label: permission.label,
            state: permission.state,
            access: permission.access,
            lastEvent: permission.lastEvent ? { ...permission.lastEvent } : null,
            lastUpdated: permission.lastUpdated
        };
    }

    function emit(eventType, detail) {
        window.postMessage({
            source: MONITOR_SOURCE,
            eventType,
            detail,
            url: window.location.href,
            origin: window.location.origin
        }, '*');
    }

    function buildSnapshot(reason) {
        return {
            reason,
            generatedAt: new Date().toISOString(),
            permissions: Object.values(permissionStateByKey).map(clonePermission)
        };
    }

    function emitSnapshot(reason) {
        emit('permissionSnapshot', buildSnapshot(reason));
    }

    function collapsePermissionStates(states, fallbackState) {
        if (!states.length) {
            return fallbackState || 'unknown';
        }

        if (states.includes('granted')) {
            return 'granted';
        }
        if (states.includes('prompt')) {
            return 'prompt';
        }
        if (states.includes('denied')) {
            return 'denied';
        }
        if (states.includes('not-requested')) {
            return 'not-requested';
        }
        if (states.includes('unsupported')) {
            return 'unsupported';
        }
        return fallbackState || 'unknown';
    }

    function updatePermissionRecord(key, updates) {
        const permission = permissionStateByKey[key];
        if (!permission) {
            return false;
        }

        let changed = false;

        if (updates.state) {
            const nextState = normalizePermissionState(updates.state);
            if (permission.state !== nextState) {
                permission.state = nextState;
                changed = true;
            }
        }

        if (updates.access) {
            if (accessRank(updates.access) > accessRank(permission.access)) {
                permission.access = updates.access;
                changed = true;
            }
        }

        if (updates.lastEvent) {
            permission.lastEvent = { ...updates.lastEvent };
            changed = true;
        }

        const nextTimestamp = updates.lastUpdated || (changed ? new Date().toISOString() : permission.lastUpdated);
        if (nextTimestamp && permission.lastUpdated !== nextTimestamp) {
            permission.lastUpdated = nextTimestamp;
            changed = true;
        }

        return changed;
    }

    function setQueryState(permissionKey, queryName, nextState) {
        permissionQueryStates.set(`${permissionKey}:${queryName}`, normalizePermissionState(nextState));
    }

    function refreshPermissionStateFromQueries(permissionKey, reason) {
        const descriptor = TRACKED_PERMISSIONS[permissionKey];
        if (!descriptor) {
            return;
        }

        if (!descriptor.queries.length) {
            if (updatePermissionRecord(permissionKey, { state: descriptor.defaultState })) {
                emitSnapshot(reason);
            }
            return;
        }

        const observedStates = descriptor.queries.map((query) => (
            permissionQueryStates.get(`${permissionKey}:${query.name}`) || 'unsupported'
        ));

        const collapsedState = collapsePermissionStates(observedStates, descriptor.defaultState);
        if (updatePermissionRecord(permissionKey, { state: collapsedState })) {
            emitSnapshot(reason);
        }
    }

    async function observeBrowserPermission(descriptor) {
        if (!descriptor.queries.length) {
            updatePermissionRecord(descriptor.key, { state: descriptor.defaultState });
            return;
        }

        if (!navigator.permissions || typeof navigator.permissions.query !== 'function') {
            descriptor.queries.forEach((query) => {
                setQueryState(descriptor.key, query.name, 'unsupported');
            });
            refreshPermissionStateFromQueries(descriptor.key, 'permissions-api-unavailable');
            return;
        }

        await Promise.all(descriptor.queries.map(async (query) => {
            try {
                const status = await navigator.permissions.query(query);
                setQueryState(descriptor.key, query.name, status.state);

                if (!observedStatuses.has(status)) {
                    const handleChange = () => {
                        setQueryState(descriptor.key, query.name, status.state);
                        refreshPermissionStateFromQueries(descriptor.key, 'browser-permission-change');
                    };

                    if (typeof status.addEventListener === 'function') {
                        status.addEventListener('change', handleChange);
                    } else {
                        status.onchange = handleChange;
                    }

                    observedStatuses.add(status);
                }
            } catch (error) {
                setQueryState(descriptor.key, query.name, 'unsupported');
            }
        }));

        refreshPermissionStateFromQueries(descriptor.key, 'initial-query');
    }

    function recordPermissionEvent({ key, stage, api }) {
        const descriptor = TRACKED_PERMISSIONS[key];
        if (!descriptor) {
            return;
        }

        const timestamp = new Date().toISOString();
        const updates = {
            lastEvent: {
                key,
                label: descriptor.label,
                stage,
                api: api || null,
                timestamp
            },
            lastUpdated: timestamp
        };

        if (stage === 'requested') {
            updates.access = 'requested';
            if (permissionStateByKey[key].state === 'not-requested') {
                updates.state = 'prompt';
            }
        }

        if (stage === 'used' || stage === 'granted') {
            updates.access = 'used';
            if (permissionStateByKey[key].state !== 'unsupported') {
                updates.state = 'granted';
            }
        }

        if (stage === 'denied') {
            updates.access = permissionStateByKey[key].access === 'used' ? 'used' : 'requested';
            updates.state = 'denied';
        }

        updatePermissionRecord(key, updates);

        emit('permissionActivity', {
            key,
            label: descriptor.label,
            stage,
            api: api || null,
            state: permissionStateByKey[key].state,
            access: permissionStateByKey[key].access,
            timestamp
        });
        emitSnapshot('activity');
    }

    function isPermissionDeniedError(error) {
        if (!error) {
            return false;
        }

        const errorName = typeof error.name === 'string' ? error.name.toLowerCase() : '';
        const errorMessage = typeof error.message === 'string' ? error.message.toLowerCase() : '';

        return (
            errorName.includes('notallowed') ||
            errorName.includes('denied') ||
            errorName.includes('security') ||
            errorMessage.includes('denied') ||
            errorMessage.includes('permission')
        );
    }

    function safePatch(target, methodName, patchFactory) {
        if (!target || typeof target[methodName] !== 'function') {
            return;
        }

        try {
            const original = target[methodName].bind(target);
            target[methodName] = patchFactory(original);
        } catch (error) {
            // Ignore sites/browsers that expose read-only APIs.
        }
    }

    function patchGeolocation() {
        const geolocation = navigator.geolocation;
        if (!geolocation) {
            return;
        }

        safePatch(geolocation, 'getCurrentPosition', (original) => (
            function getCurrentPositionPatched(successCallback, errorCallback, options) {
                recordPermissionEvent({
                    key: 'location',
                    stage: 'requested',
                    api: 'navigator.geolocation.getCurrentPosition'
                });

                const wrappedSuccess = (...args) => {
                    recordPermissionEvent({
                        key: 'location',
                        stage: 'used',
                        api: 'navigator.geolocation.getCurrentPosition'
                    });
                    if (typeof successCallback === 'function') {
                        return successCallback.apply(this, args);
                    }
                    return undefined;
                };

                const wrappedError = (...args) => {
                    const error = args[0];
                    if (error && error.code === 1) {
                        recordPermissionEvent({
                            key: 'location',
                            stage: 'denied',
                            api: 'navigator.geolocation.getCurrentPosition'
                        });
                    }
                    if (typeof errorCallback === 'function') {
                        return errorCallback.apply(this, args);
                    }
                    return undefined;
                };

                return original(wrappedSuccess, wrappedError, options);
            }
        ));

        safePatch(geolocation, 'watchPosition', (original) => (
            function watchPositionPatched(successCallback, errorCallback, options) {
                recordPermissionEvent({
                    key: 'location',
                    stage: 'requested',
                    api: 'navigator.geolocation.watchPosition'
                });

                const wrappedSuccess = (...args) => {
                    recordPermissionEvent({
                        key: 'location',
                        stage: 'used',
                        api: 'navigator.geolocation.watchPosition'
                    });
                    if (typeof successCallback === 'function') {
                        return successCallback.apply(this, args);
                    }
                    return undefined;
                };

                const wrappedError = (...args) => {
                    const error = args[0];
                    if (error && error.code === 1) {
                        recordPermissionEvent({
                            key: 'location',
                            stage: 'denied',
                            api: 'navigator.geolocation.watchPosition'
                        });
                    }
                    if (typeof errorCallback === 'function') {
                        return errorCallback.apply(this, args);
                    }
                    return undefined;
                };

                return original(wrappedSuccess, wrappedError, options);
            }
        ));
    }

    function patchMediaDevices() {
        const mediaDevices = navigator.mediaDevices;
        if (!mediaDevices) {
            return;
        }

        safePatch(mediaDevices, 'getUserMedia', (original) => (
            function getUserMediaPatched(constraints) {
                const requestedPermissions = [];
                const hasAudio = Boolean(constraints && constraints.audio);
                const hasVideo = Boolean(constraints && constraints.video);

                if (hasAudio) {
                    requestedPermissions.push('microphone');
                    recordPermissionEvent({
                        key: 'microphone',
                        stage: 'requested',
                        api: 'navigator.mediaDevices.getUserMedia(audio)'
                    });
                }

                if (hasVideo) {
                    requestedPermissions.push('camera');
                    recordPermissionEvent({
                        key: 'camera',
                        stage: 'requested',
                        api: 'navigator.mediaDevices.getUserMedia(video)'
                    });
                }

                return original(constraints).then((stream) => {
                    requestedPermissions.forEach((permissionKey) => {
                        recordPermissionEvent({
                            key: permissionKey,
                            stage: 'used',
                            api: `navigator.mediaDevices.getUserMedia(${permissionKey})`
                        });
                    });
                    return stream;
                }).catch((error) => {
                    if (isPermissionDeniedError(error)) {
                        requestedPermissions.forEach((permissionKey) => {
                            recordPermissionEvent({
                                key: permissionKey,
                                stage: 'denied',
                                api: `navigator.mediaDevices.getUserMedia(${permissionKey})`
                            });
                        });
                    }
                    throw error;
                });
            }
        ));

        safePatch(mediaDevices, 'getDisplayMedia', (original) => (
            function getDisplayMediaPatched(constraints) {
                recordPermissionEvent({
                    key: 'screenCapture',
                    stage: 'requested',
                    api: 'navigator.mediaDevices.getDisplayMedia'
                });

                return original(constraints).then((stream) => {
                    recordPermissionEvent({
                        key: 'screenCapture',
                        stage: 'used',
                        api: 'navigator.mediaDevices.getDisplayMedia'
                    });
                    return stream;
                }).catch((error) => {
                    if (isPermissionDeniedError(error)) {
                        recordPermissionEvent({
                            key: 'screenCapture',
                            stage: 'denied',
                            api: 'navigator.mediaDevices.getDisplayMedia'
                        });
                    }
                    throw error;
                });
            }
        ));
    }

    function patchNotifications() {
        if (typeof Notification === 'undefined' || typeof Notification.requestPermission !== 'function') {
            return;
        }

        const originalRequestPermission = Notification.requestPermission.bind(Notification);

        Notification.requestPermission = function requestPermissionPatched(callback) {
            recordPermissionEvent({
                key: 'notifications',
                stage: 'requested',
                api: 'Notification.requestPermission'
            });

            if (typeof callback === 'function') {
                return originalRequestPermission((result) => {
                    if (result === 'granted') {
                        recordPermissionEvent({
                            key: 'notifications',
                            stage: 'used',
                            api: 'Notification.requestPermission'
                        });
                    } else if (result === 'denied') {
                        recordPermissionEvent({
                            key: 'notifications',
                            stage: 'denied',
                            api: 'Notification.requestPermission'
                        });
                    }
                    callback(result);
                });
            }

            const result = originalRequestPermission();
            if (result && typeof result.then === 'function') {
                return result.then((permissionResult) => {
                    if (permissionResult === 'granted') {
                        recordPermissionEvent({
                            key: 'notifications',
                            stage: 'used',
                            api: 'Notification.requestPermission'
                        });
                    } else if (permissionResult === 'denied') {
                        recordPermissionEvent({
                            key: 'notifications',
                            stage: 'denied',
                            api: 'Notification.requestPermission'
                        });
                    }
                    return permissionResult;
                });
            }

            return result;
        };
    }

    function patchClipboard() {
        const clipboard = navigator.clipboard;
        if (!clipboard) {
            return;
        }

        ['read', 'readText', 'write', 'writeText'].forEach((methodName) => {
            safePatch(clipboard, methodName, (original) => (
                function clipboardMethodPatched(...args) {
                    recordPermissionEvent({
                        key: 'clipboard',
                        stage: 'requested',
                        api: `navigator.clipboard.${methodName}`
                    });

                    const result = original(...args);
                    if (result && typeof result.then === 'function') {
                        return result.then((value) => {
                            recordPermissionEvent({
                                key: 'clipboard',
                                stage: 'used',
                                api: `navigator.clipboard.${methodName}`
                            });
                            return value;
                        }).catch((error) => {
                            if (isPermissionDeniedError(error)) {
                                recordPermissionEvent({
                                    key: 'clipboard',
                                    stage: 'denied',
                                    api: `navigator.clipboard.${methodName}`
                                });
                            }
                            throw error;
                        });
                    }

                    recordPermissionEvent({
                        key: 'clipboard',
                        stage: 'used',
                        api: `navigator.clipboard.${methodName}`
                    });
                    return result;
                }
            ));
        });
    }

    window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data) {
            return;
        }

        if (event.data.source === CONTENT_SOURCE && event.data.type === SNAPSHOT_REQUEST) {
            emitSnapshot('content-script-request');
        }
    });

    patchGeolocation();
    patchMediaDevices();
    patchNotifications();
    patchClipboard();

    Promise.all(Object.values(TRACKED_PERMISSIONS).map(observeBrowserPermission))
        .finally(() => {
            emitSnapshot('initial');
        });
})();
