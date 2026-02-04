
document.addEventListener('DOMContentLoaded', function () {
    const scanCurrentPageButton = document.getElementById('scanCurrentPageButton');
    const currentPageUrlElement = document.getElementById('currentPageUrl');

    const resultsDisplayArea = document.getElementById('resultsDisplayArea');
    const scanResultSubSection = document.getElementById('scanResultSubSection');
    const resultArea = document.getElementById('resultArea');
    const statusElement = document.getElementById('status');
    const messageElement = document.getElementById('message');
    const riskLevelElement = document.getElementById('riskLevel');
    const modelAccuracyLive = document.getElementById('modelAccuracyLive');
    const modelAUC = document.getElementById('modelAUC');
    const predictionConfidence = document.getElementById('predictionConfidence');
    const analysisBreakdownSection = document.getElementById('analysisBreakdownSection');
    const pageDetailsSubSection = document.getElementById('pageDetailsSubSection');

    const safePercentageSpan = document.getElementById('safePercentage');
    const phishingPercentageSpan = document.getElementById('phishingPercentage');
    const safeProgressBar = document.getElementById('safeProgressBar');
    const progressBarBackground = safeProgressBar ? safeProgressBar.parentElement : null;
    const tokenContainer = document.getElementById('tokenContainer');

    const pageDetailTitle = document.getElementById('pageDetailTitle');
    const pageDetailPCount = document.getElementById('pageDetailPCount');
    const pageDetailH1 = document.getElementById('pageDetailH1');
    const modelInsightsSection = document.getElementById('modelInsightsSection');
    const activeModelName = document.getElementById('activeModelName');
    const activeModelAccuracy = document.getElementById('activeModelAccuracy');
    const activeModelRecall = document.getElementById('activeModelRecall');
    const activeModelF1 = document.getElementById('activeModelF1');
    const activeModelAUC = document.getElementById('activeModelAUC');
    const modelComparisonGrid = document.getElementById('modelComparisonGrid');
    
    // Store model comparisons data for real-time switching
    let storedModelComparisons = {};
    let currentActiveModel = null;

    function showResultsDisplayArea() {
        if (resultsDisplayArea) resultsDisplayArea.style.display = 'block';
    }

    function hideAllSubSections() {
        if (scanResultSubSection) scanResultSubSection.style.display = 'none';
        if (pageDetailsSubSection) pageDetailsSubSection.style.display = 'none';
        if (analysisBreakdownSection) analysisBreakdownSection.style.display = 'none';
        if (modelInsightsSection) modelInsightsSection.style.display = 'none';
    }

    function deriveRiskInfo(result) {
        if (!result) {
            return { level: 'Unknown', score: null, cssClass: 'risk-unknown' };
        }

        const providedLevel = result.riskLevel;
        const providedScore = (typeof result.riskScore === 'number') ? result.riskScore : null;
        const probabilities = Array.isArray(result.probabilities) ? result.probabilities : null;

        let score = providedScore;
        if (score === null && probabilities && probabilities.length > 1 && typeof probabilities[1] === 'number') {
            score = probabilities[1];
        }

        if (typeof score === 'number') {
            score = Math.max(0, Math.min(1, score));
        }

        let level = providedLevel;
        if (!level) {
            if (typeof score === 'number') {
                if (score >= 0.50) level = 'High Risk';
                else level = 'Low Risk';
            } else {
                level = 'Unknown';
            }
        }

        const normalizedLevel = level.toLowerCase();
        let cssClass = 'risk-low';
        if (normalizedLevel.includes('high')) cssClass = 'risk-high';

        return { level, score, cssClass };
    }

    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
        if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
            currentPageUrlElement.textContent = "Error loading current URL.";
            return;
        }
        const currentUrl = tabs[0].url;
        const isWebPage = currentUrl.startsWith("http://") || currentUrl.startsWith("https://");

        currentPageUrlElement.textContent = currentUrl;
        if (!isWebPage) {
            currentPageUrlElement.textContent = "This is not a standard web page.";
            scanCurrentPageButton.disabled = true;
        }
    });

    function displayScanResult(result, source = "Backend") {
        showResultsDisplayArea();
        scanResultSubSection.style.display = 'block';
        statusElement.textContent = '';
        messageElement.textContent = '';
        resultArea.className = '';
        if (modelAccuracyLive) {
            modelAccuracyLive.style.display = 'none';
            modelAccuracyLive.textContent = 'Overall Model Accuracy —';
        }
        if (modelAUC) {
            modelAUC.style.display = 'none';
            modelAUC.textContent = 'Model AUC: —';
        }
        if (predictionConfidence) {
            predictionConfidence.style.display = 'none';
            predictionConfidence.textContent = 'Prediction Confidence —';
        }

        if (result?.error) {
            statusElement.textContent = `Status (Error):`;
            messageElement.textContent = result.error;
            resultArea.className = 'phishing';
        } else {
            const riskInfo = deriveRiskInfo(result);
            const detailMessage = result?.riskDescription || result?.message || `Analysis completed via ${source}.`;

            statusElement.textContent = `Status (${source}): ${riskInfo.level}`;
            messageElement.textContent = detailMessage;

            if (riskLevelElement) {
                const riskPercent = (typeof riskInfo.score === 'number') ? `${(riskInfo.score * 100).toFixed(1)}%` : '—';
                riskLevelElement.textContent = `Risk: ${riskInfo.level}${riskPercent !== '—' ? ` (${riskPercent})` : ''}`;
                riskLevelElement.className = `risk-pill ${riskInfo.cssClass}`;
            }

            // Live model accuracy pill
            if (modelAccuracyLive) {
                const accuracy =
                    (result?.modelMetrics && typeof result.modelMetrics.accuracy === 'number')
                        ? result.modelMetrics.accuracy
                        : (storedModelComparisons && currentActiveModel && storedModelComparisons[currentActiveModel]
                            ? storedModelComparisons[currentActiveModel].accuracy
                            : null);

                if (typeof accuracy === 'number') {
                    // This is overall model accuracy, not per-site; keep label explicit.
                    modelAccuracyLive.textContent = `Overall Model Accuracy ${(accuracy * 100).toFixed(1)}%`;
                    modelAccuracyLive.style.display = 'inline-block';
                }
            }

            // Model AUC display
            if (modelAUC) {
                const auc = 
                    (result?.modelMetrics && (typeof result.modelMetrics.auc === 'number' || typeof result.modelMetrics.auc_score === 'number'))
                        ? (result.modelMetrics.auc || result.modelMetrics.auc_score)
                        : (storedModelComparisons && currentActiveModel && storedModelComparisons[currentActiveModel]
                            ? (storedModelComparisons[currentActiveModel].auc || storedModelComparisons[currentActiveModel].auc_score)
                            : null);

                if (typeof auc === 'number' && auc > 0) {
                    // Display AUC as percentage (e.g., 98.7%)
                    modelAUC.textContent = `Model AUC: ${(auc * 100).toFixed(1)}%`;
                    modelAUC.style.display = 'inline-block';
                }
            }

            // Prediction confidence (max class probability)
            if (predictionConfidence) {
                let conf = null;
                if (Array.isArray(result?.probabilities) && result.probabilities.length > 0) {
                    conf = Math.max(...result.probabilities);
                }
                if (typeof conf === 'number') {
                    predictionConfidence.textContent = `Prediction Confidence ${(conf * 100).toFixed(1)}%`;
                    predictionConfidence.style.display = 'inline-block';
                }
            }

            // Map risk class to existing visual states
            if (riskInfo.cssClass === 'risk-high' || result?.prediction === "phishing") {
                resultArea.className = 'phishing';
            } else if (riskInfo.cssClass === 'risk-low' || result?.prediction === "safe") {
                resultArea.className = 'safe';
            } else {
                statusElement.textContent = `Status (${source}): Unknown`;
                messageElement.textContent = `The result was not in the expected format.`;
                resultArea.className = 'phishing';
            }

            // Display detailed risk reasons for high risk sites
            const riskReasonsDiv = document.getElementById('riskReasons');
            const riskReasonsList = document.getElementById('riskReasonsList');
            if (riskReasonsDiv && riskReasonsList) {
                if (riskInfo.cssClass === 'risk-high' || result?.prediction === "phishing") {
                    const url = result?.url || '';
                    const riskScore = (typeof riskInfo.score === 'number') ? (riskInfo.score * 100).toFixed(1) : '0';
                    
                    let reasons = [];
                    if (riskInfo.score >= 0.7) {
                        reasons.push(`Very high phishing probability detected (${riskScore}%)`);
                    }
                    if (result?.message && result.message.includes('phishing')) {
                        reasons.push('Phishing patterns identified in URL structure');
                    }
                    if (url.includes('login') || url.includes('verify') || url.includes('secure')) {
                        reasons.push('Suspicious login/verification page characteristics');
                    }
                    if (url.includes('webflow.io') || url.includes('wixsite.com') || url.includes('000webhost')) {
                        reasons.push('Free hosting domain often used for phishing attacks');
                    }
                    if (url.includes('ledger') && !url.includes('ledger.com')) {
                        reasons.push('Potential brand impersonation (fake Ledger website)');
                    }
                    if (url.includes('paypal') && !url.includes('paypal.com')) {
                        reasons.push('Potential brand impersonation (fake PayPal website)');
                    }
                    if (url.includes('amazon') && !url.includes('amazon.com') && !url.includes('amazon.co.uk')) {
                        reasons.push('Potential brand impersonation (fake Amazon website)');
                    }
                    if (url.includes('microsoft') && !url.includes('microsoft.com')) {
                        reasons.push('Potential brand impersonation (fake Microsoft website)');
                    }
                    if (!reasons.length) {
                        reasons.push('High risk score from machine learning analysis');
                        reasons.push('URL features match known phishing patterns');
                    }
                    
                    riskReasonsList.innerHTML = reasons.map(reason => `<li>${reason}</li>`).join('');
                    riskReasonsDiv.style.display = 'block';
                } else {
                    riskReasonsDiv.style.display = 'none';
                }
            }
        }
    }

    function displayAnalysisBreakdown(data) {
        if (!data || !data.probabilities || !data.tokens) return;
        analysisBreakdownSection.style.display = 'block';

        const [safeProb, phishingProb] = data.probabilities;
        const safePercent = (safeProb * 100).toFixed(1);
        const phishingPercent = (phishingProb * 100).toFixed(1);

        safePercentageSpan.textContent = `Safe: ${safePercent}%`;
        phishingPercentageSpan.textContent = `Phishing: ${phishingPercent}%`;
        
        // Check risk level to determine bar color (High Risk = red, Low Risk = green, Medium = yellow)
        const riskInfo = deriveRiskInfo(data);
        const isHighRisk = riskInfo.cssClass === 'risk-high' || data?.prediction === "phishing";
        const isLowRisk = riskInfo.cssClass === 'risk-low' || data?.prediction === "safe";
        
        // Show red bar for high risk/phishing, green for safe/low risk
        if (isHighRisk || phishingProb >= 0.5) {
            safeProgressBar.style.width = `${phishingPercent}%`;
            safeProgressBar.className = 'progress-bar-phishing';
            if (progressBarBackground) {
                progressBarBackground.style.backgroundColor = '#dc2626'; // lighter red background
            }
        } else {
            safeProgressBar.style.width = `${safePercent}%`;
            safeProgressBar.className = 'progress-bar-safe';
            if (progressBarBackground) {
                progressBarBackground.style.backgroundColor = '#f3f4f6'; // neutral base
            }
        }

        tokenContainer.innerHTML = '';
        data.tokens.forEach(token => {
            const tokenEl = document.createElement('span');
            tokenEl.className = 'token-tag';
            tokenEl.textContent = token;
            tokenContainer.appendChild(tokenEl);
        });
    }

    function formatPercentage(value) {
        if (value === undefined || value === null || isNaN(value)) {
            return '—';
        }
        return `${(value * 100).toFixed(1)}%`;
    }

    function updateActiveModelDisplay(modelName, modelMetrics) {
        if (!modelMetrics) return;
        
        if (activeModelName) {
            activeModelName.textContent = modelName || '—';
        }
        
        if (activeModelAccuracy) {
            activeModelAccuracy.textContent = `Accuracy ${formatPercentage(modelMetrics.accuracy)}`;
        }
        if (activeModelRecall) {
            activeModelRecall.textContent = `Phishing Recall ${formatPercentage(modelMetrics.recall_phishing)}`;
        }
        if (activeModelF1) {
            activeModelF1.textContent = `Phishing F1 ${formatPercentage(modelMetrics.f1_phishing)}`;
        }
        if (activeModelAUC) {
            activeModelAUC.textContent = `AUC ${formatPercentage(modelMetrics.auc || modelMetrics.auc_score)}`;
        }
        
        currentActiveModel = modelName;
    }

    function updateModelCardActiveStates() {
        if (!modelComparisonGrid) return;
        
        const cards = modelComparisonGrid.querySelectorAll('.model-card');
        cards.forEach(card => {
            const cardModelName = card.getAttribute('data-model-name');
            if (cardModelName === currentActiveModel) {
                card.classList.add('model-card-active');
            } else {
                card.classList.remove('model-card-active');
            }
        });
    }

    function createMetricCard(modelName, metrics, isActive = false) {
        const card = document.createElement('div');
        card.className = 'model-card';
        card.setAttribute('data-model-name', modelName);
        card.style.cursor = 'pointer';
        
        if (isActive) {
            card.classList.add('model-card-active');
        }

        const title = document.createElement('h5');
        title.textContent = modelName;
        card.appendChild(title);

        const metricList = document.createElement('ul');
        metricList.className = 'model-card-metrics';

        const metricsToDisplay = [
            { label: 'Accuracy', value: formatPercentage(metrics?.accuracy) },
            { label: 'Phishing Recall', value: formatPercentage(metrics?.recall_phishing) },
            { label: 'Phishing F1', value: formatPercentage(metrics?.f1_phishing) },
            { label: 'AUC', value: formatPercentage(metrics?.auc || metrics?.auc_score) }
        ];

        metricsToDisplay.forEach(item => {
            const li = document.createElement('li');
            li.innerHTML = `<span>${item.label}</span><span>${item.value}</span>`;
            metricList.appendChild(li);
        });

        card.appendChild(metricList);
        
        // Add click handler for real-time model switching
        card.addEventListener('click', function() {
            if (storedModelComparisons[modelName]) {
                updateActiveModelDisplay(modelName, storedModelComparisons[modelName]);
                updateModelCardActiveStates();
                
                // Add a subtle animation feedback
                card.style.transform = 'scale(0.98)';
                setTimeout(() => {
                    card.style.transform = '';
                }, 150);
            }
        });
        
        // Add hover effect
        card.addEventListener('mouseenter', function() {
            if (!card.classList.contains('model-card-active')) {
                card.style.boxShadow = 'var(--shadow-medium)';
            }
        });
        
        card.addEventListener('mouseleave', function() {
            if (!card.classList.contains('model-card-active')) {
                card.style.boxShadow = 'var(--shadow-small)';
            }
        });
        
        return card;
    }

    function displayModelInsights(data) {
        if (!data) {
            if (modelInsightsSection) {
                modelInsightsSection.style.display = 'none';
            }
            return;
        }

        if (modelInsightsSection) {
            modelInsightsSection.style.display = 'block';
        }

        // Store model comparisons data for real-time switching
        const comparisons = data.modelComparisons || {};
        storedModelComparisons = comparisons;
        
        // Set initial active model from data
        const initialModelName = data.modelName || Object.keys(comparisons)[0];
        const initialMetrics = data.modelMetrics || comparisons[initialModelName] || {};
        
        // Update active model display
        updateActiveModelDisplay(initialModelName, initialMetrics);

        if (modelComparisonGrid) {
            modelComparisonGrid.innerHTML = '';
            
            // Debug: Log comparisons to console
            console.log('Model Comparisons:', comparisons);
            
            // Ensure we iterate in a consistent order
            const modelOrder = ['Linear SVM', 'Logistic Regression', 'Random Forest', 'XGBoost'];
            modelOrder.forEach(modelName => {
                if (comparisons[modelName]) {
                    const modelMetrics = comparisons[modelName];
                    const isActive = modelName === initialModelName;
                    console.log(`Adding ${modelName}:`, modelMetrics);
                    modelComparisonGrid.appendChild(createMetricCard(modelName, modelMetrics, isActive));
                }
            });
        }
    }

    if (scanCurrentPageButton) {
        scanCurrentPageButton.addEventListener('click', function () {
            console.log("POPUP: 'Scan Current Page' button clicked.");
            hideAllSubSections();
            showResultsDisplayArea();
            scanResultSubSection.style.display = 'block';
            statusElement.textContent = "Analyzing...";
            messageElement.textContent = "Contacting backend server...";
            resultArea.className = '';

            chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                if (!tabs || tabs.length === 0) {
                    console.error("POPUP: Could not get current tab.");
                    return;
                }

                const currentUrl = tabs[0].url;
                const modelName = currentActiveModel;
                console.log(`POPUP: Sending URL to background for analysis: ${currentUrl} (model: ${modelName || 'default'})`);
                const backendCheckPromise = chrome.runtime.sendMessage({ action: "checkUrlWithBackend", url: currentUrl, modelName });

                backendCheckPromise.then(response => {
                    console.log("POPUP: Received response from background script:", response);
                    hideAllSubSections();

                    if (response?.error) {
                        console.error("POPUP: Background script returned an error:", response.error);
                        displayScanResult({ error: response.error });
                    } else if (response?.type === 'backendResult' && response.data) {
                        console.log("POPUP: Backend check successful. Data:", response.data);
                        displayScanResult(response.data, "Backend");
                        displayAnalysisBreakdown(response.data);
                        displayModelInsights(response.data);
                    } else {
                        console.error("POPUP: Received an invalid or unexpected response structure.");
                        displayScanResult({ error: "Received an invalid response from the background script." });
                    }
                }).catch(error => {
                    console.error("POPUP: Promise to background script failed.", error);
                    hideAllSubSections();
                    displayScanResult({ error: `Communication error: ${error.message}` });
                });
            });
        });
    }
});
