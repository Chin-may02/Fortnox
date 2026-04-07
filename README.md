# FORTNOX

FORTNOX is a research-oriented cybersecurity prototype that combines a Chromium browser extension with a local Flask backend to detect phishing websites and phishing emails in real time. The system is designed to be technically credible, easy to explain, and practical enough to demonstrate as a complete end-to-end project rather than as an isolated machine learning model.

## Abstract

Phishing remains one of the most common ways attackers steal credentials, money, and sensitive information. Traditional user-facing defenses often fail because they either act too late, provide poor explanations, or focus on only one attack surface at a time. FORTNOX addresses this gap through a hybrid system that protects users in three connected ways:

- It analyzes websites by classifying URLs with a machine learning model.
- It analyzes Gmail messages with a BERT-based email classifier supported by explainable heuristic signals.
- It monitors whether a visited website requests or uses sensitive browser permissions such as location, camera, microphone, notifications, clipboard, and screen capture.

The result is a local security prototype that can warn the user, block high-risk pages, summarize sensitive permission usage, and present clear reasons behind its decisions. This repository includes the browser extension, backend API, training pipeline, evaluation scripts, reports, and tests required to understand and reproduce the project.

## Why This Project Matters

Phishing attacks are effective because they mix technical deception with user manipulation. A malicious site may look visually normal while hiding a suspicious URL, and a phishing email may combine spoofed sender details, urgent language, risky links, and malicious attachments. At the same time, a compromised or deceptive page may ask for sensitive browser access that could be abused by an unauthorized actor.

FORTNOX is built around a simple idea: security warnings become more useful when they are:

- early, not delayed
- visible inside the user workflow
- explainable, not just binary
- multi-layered, not limited to one signal

## Project Goals

The main objectives of FORTNOX are:

- detect potentially malicious websites during browsing
- detect phishing emails inside Gmail
- monitor major browser permissions that may be abused by malicious pages
- provide user-facing warnings without relying only on black-box decisions
- run locally for privacy-focused research and demonstration
- compare multiple URL-classification models in a reproducible way

## What FORTNOX Contains

At a high level, the project has two major runtime parts and several supporting research components:

1. A browser extension
   - scans visited URLs
   - shows warnings and blocked-page flows
   - monitors sensitive site permission activity
   - extracts Gmail message content for analysis
   - presents results in the popup and on the page

2. A Flask backend
   - exposes API endpoints for URL and email analysis
   - loads trained models from local artifacts
   - computes risk scores and explanatory signals
   - returns structured results to the extension

3. Research and reproducibility assets
   - model training scripts
   - evaluation scripts
   - performance reports
   - validation and integration tests

## System Overview

```text
User visits a website or opens an email
        |
        v
Chromium Extension
  - background service worker
  - content scripts
  - Gmail content script
  - permission monitor
        |
        v
Local Flask API (127.0.0.1:5000)
  - /check_url
  - /check_email
        |
        v
Detection Layer
  - URL feature extraction + ML model
  - BERT email classifier
  - email heuristics
  - embedded URL analysis
        |
        v
Result Layer
  - safe / suspicious / phishing decision
  - risk score
  - explanation factors
  - warning / block / permission summary UI
```

## Core Contributions

FORTNOX is valuable as a project because it combines several ideas into one working system:

- A hybrid phishing-defense pipeline instead of a single classifier
- Real-time browser integration instead of an offline-only experiment
- Explainable outputs for both web and email analysis
- Sensitive permission monitoring as a security-awareness feature
- Comparative URL-model evaluation using multiple classical machine learning methods
- A local-first design that avoids sending browsing or email content to a remote cloud service by default

## Main Features

### 1. Website Phishing Detection

FORTNOX checks the current page URL through the backend and classifies it as safe or phishing. The extension supports both manual checking from the popup and automatic scanning during browsing.

Current behavior includes:

- navigation-aware URL scanning
- risk scoring and model output display
- warning overlays on suspicious pages
- a blocked-page flow for high-confidence malicious pages
- one-time bypass support for controlled continuation

### 2. Gmail Phishing Detection

When the user opens an email in Gmail, the extension extracts visible message details and sends them to the backend for analysis. The response is shown directly in the Gmail interface.

Current behavior includes:

- sender and display-name extraction
- subject and body analysis
- attachment-name collection
- embedded URL extraction and follow-up URL scoring
- inline risk badge display
- high-risk overlay warning for phishing emails

### 3. Site Permission Summary and Live Permission Alerts

FORTNOX includes a dedicated permission monitoring feature for major sensitive browser capabilities that could be abused by a malicious or unauthorized actor. These include:

- location
- camera
- microphone
- notifications
- clipboard read/write
- screen capture

This feature works in two user-facing ways:

- A popup summary shows which major permissions are currently allowed, requested, denied, or used by the active website.
- A live toast notification appears when the site asks for or begins using an additional sensitive permission.

This is important because permission abuse is a real security concern even when the page itself is not obviously malicious.

## Architecture in Detail

### Browser Extension Layer

The extension is implemented as a Manifest V3 Chromium extension. Its main parts are:

- `extension/background.js`
  Handles communication with the backend, automatic URL scanning, blocked-page routing, and coordination with other scripts.

- `extension/content.js`
  Displays on-page warnings, receives permission-monitor events, builds permission summaries, and serves page details to the popup.

- `extension/page_permission_monitor.js`
  Runs early in the page lifecycle and observes sensitive permission state and usage by monitoring standard browser APIs such as `navigator.geolocation`, `navigator.mediaDevices`, `Notification.requestPermission`, and `navigator.clipboard`.

- `extension/gmail_content.js`
  Watches Gmail for opened messages, extracts email content, requests backend analysis, and displays inline risk indicators.

- `extension/popup.html`, `extension/popup.js`, `extension/style.css`
  Provide the main dashboard for current-page scanning, permission summary display, and model comparison display.

- `extension/blocked.html`, `extension/blocked.js`
  Present the safety interstitial used when a page is considered high risk.

### Backend Layer

The backend is a Flask application stored in `app/`. It provides the main inference APIs and combines model predictions with explainable logic.

Key backend files:

- `app/app.py`
  Main Flask server, URL feature extraction, model loading, inference logic, threshold handling, and API routes.

- `app/email_features.py`
  Extracts structured phishing-related features from email metadata and content.

- `app/email_model.py`
  Loads the local BERT-based email model and performs email inference.

## Detection Methodology

### A. URL Detection Pipeline

FORTNOX uses a classical machine learning pipeline for URL classification. The backend first normalizes the URL and then extracts two kinds of signals:

1. Engineered numeric features
   - URL length
   - hostname and path characteristics
   - digit count
   - special-character patterns
   - entropy
   - suspicious keywords
   - suspicious top-level domains
   - shortener and IP-address patterns

2. Text-vector features
   - character-level TF-IDF features built from the normalized URL string

These features are combined and passed to a trained classifier. The training pipeline compares multiple models:

- Logistic Regression
- Random Forest
- Linear SVM
- XGBoost

The saved URL artifact also stores:

- the chosen model
- the scaler
- the vectorizer
- feature column order
- per-model metrics
- threshold information
- alternative trained models for comparison

### B. Email Detection Pipeline

Email analysis follows a hybrid approach instead of relying on only one model. This makes the system more understandable and more resilient when one signal source is weak.

The email pipeline combines:

- a local BERT classifier for message-level language understanding
- structured email heuristics for explainable risk factors
- URL analysis for links embedded in the email

The BERT model processes a combined text representation of the sender, recipient, subject, body, URLs, and attachments. This helps the model capture contextual phishing language, impersonation cues, and suspicious content patterns.

### C. Explainable Email Heuristics

In addition to BERT predictions, the backend extracts more than 30 email-oriented features. These include signals such as:

- suspicious sender domains
- freemail usage
- display-name brand impersonation
- reply-to mismatch
- urgency wording
- financial or account-related wording
- excessive capitalization
- suspicious or shortened URLs
- suspicious attachment extensions
- HTML login forms or input fields
- email authentication failure hints from headers

These features are used to compute a heuristic risk score and a human-readable list of risk factors. This makes the output more suitable for demonstration, discussion, and committee review because the system can explain why it raised a warning.

### D. Permission Monitoring Method

The permission-monitoring subsystem uses two complementary strategies:

1. Browser permission-state inspection
   - uses the Permissions API when available
   - records whether a permission is granted, denied, prompt-based, unsupported, or not yet requested

2. Sensitive API activity monitoring
   - observes common API entry points associated with major permissions
   - records when a site requests access and when it actually begins using that access

This allows FORTNOX to distinguish between:

- a permission that is allowed by the browser
- a permission that the site requested
- a permission that the site actively used in the current tab

That distinction is useful in real security interfaces because "allowed" and "actively used" do not mean the same thing.

## Runtime User Flow

### Website Flow

1. The user navigates to a page.
2. The extension background worker detects the navigation.
3. The URL is sent to `POST /check_url`.
4. The backend returns a prediction, probabilities, risk score, and model metadata.
5. The extension applies a graduated response:
   - allow the page if low risk
   - show a warning overlay if suspicious
   - redirect to a blocked page for high-confidence high-risk pages

### Gmail Flow

1. The user opens an email in Gmail.
2. The Gmail content script extracts sender, subject, body, reply-to, attachments, and related fields.
3. The payload is sent to `POST /check_email`.
4. The backend combines BERT output, heuristics, and URL analysis.
5. The extension shows:
   - a risk badge for the current email
   - a stronger warning overlay for high-risk messages

### Permission Flow

1. The page-level permission monitor starts at document load.
2. A snapshot of tracked sensitive permissions is built.
3. The content script displays an initial permission summary toast.
4. If the site later requests or uses a sensitive permission, the user sees a new update toast.
5. The extension popup can also request the current permission summary for the active tab and display it in card form.

## User Interface Design Logic

FORTNOX is not only a detection engine; it is also a warning-delivery system. The UI was designed around three principles:

- visibility
  Security signals should appear where the user already is: the web page, Gmail, or the extension popup.

- graduated intervention
  The system does not treat every risk equally. Lower-confidence cases can show warnings, while higher-confidence cases can trigger blocking behavior.

- explanation
  Users should see meaningful reasons, such as risk factors or permission usage, rather than only a vague red alert.

## API Summary

### `POST /check_url`

Purpose:
- analyzes a single URL for phishing risk

Input:

```json
{
  "url": "https://example.com",
  "modelName": "Linear SVM"
}
```

Important output fields:

- `prediction`
- `message`
- `probabilities`
- `riskLevel`
- `riskScore`
- `riskDescription`
- `decisionThreshold`
- `modelName`
- `modelMetrics`
- `modelComparisons`

### `POST /check_email`

Purpose:
- analyzes an email using BERT, heuristics, and embedded URL checks

Input:

```json
{
  "from_email": "alerts@example.com",
  "from_name": "Example Alerts",
  "subject": "Verify your account",
  "body_text": "Please confirm your account immediately.",
  "to_email": "user@example.com"
}
```

Important output fields:

- `prediction`
- `message`
- `probabilities`
- `riskLevel`
- `riskScore`
- `riskFactors`
- `emailFeatures`
- `urlAnalysis`
- `suspiciousUrlCount`
- `totalUrls`
- `emailModel`
- `modelName`
- `modelMetrics`

## Training and Evaluation

### URL Model Training

The URL training pipeline is implemented in `training/train_model.py`. It:

- loads the cleaned phishing URL dataset
- removes duplicates and empty records
- optionally downsamples for faster experimentation
- creates a train/test split
- extracts numeric URL features
- creates a character-level TF-IDF representation
- trains several candidate models
- selects thresholds using the precision-recall curve
- stores the chosen model and supporting artifacts in `models/final_phishing_model.joblib`

### Email Model Training

The email model training notebook is stored at:

```text
training/Bert_training.ipynb
```

The backend consumes the saved local model artifacts from:

```text
models/results
```

### Reported URL Model Performance

The current project reports in `reports/performance_summary.txt` and `reports/performance_summary.csv` summarize the following URL-model results:

| Model | Accuracy | Precision (Phishing) | Recall (Phishing) | F1 (Phishing) | Time (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Linear SVM | 96.24% | 88.95% | 95.04% | 91.89% | 147.46 |
| Logistic Regression | 95.93% | 88.07% | 94.69% | 91.26% | 1087.87 |
| Random Forest | 96.99% | 96.54% | 89.79% | 93.04% | 4881.03 |
| XGBoost | 92.63% | 82.15% | 85.80% | 83.93% | 128.75 |

How to interpret these numbers:

- Random Forest currently shows the strongest overall reported accuracy and phishing precision.
- Linear SVM offers strong performance with much lower training time than Random Forest.
- The project keeps multiple trained model metrics available for comparison in the extension UI.

## Important Research Qualities of the Project

For academic review, the strongest qualities of FORTNOX are:

- End-to-end completeness
  The project includes data handling, training, inference, UI, warning logic, and evaluation.

- Multi-modal security coverage
  It handles website URLs, email content, and browser permission behavior in one integrated system.

- Explainability
  The system produces risk factors and permission summaries instead of only opaque labels.

- Real-time deployment context
  The models are embedded into an actual user workflow through a browser extension.

- Reproducibility
  The repository includes scripts, reports, tests, and clear local setup instructions.

## Repository Structure

| Path | Purpose |
| --- | --- |
| `app/` | Flask backend, API routes, inference logic, email feature extraction, BERT integration |
| `extension/` | Browser extension scripts, popup UI, content scripts, blocked page, styles, permission monitor |
| `training/` | URL training pipeline and the BERT training notebook |
| `evaluation/` | Scripts for generating performance tables and graphs |
| `models/` | Saved model artifacts used at runtime |
| `data/` | Datasets used for training and experimentation |
| `reports/` | Generated graphs and metric summaries |
| `tests/` | Validation, API integration, and classifier tests |
| `requirements.txt` | Python dependencies |

## Technology Stack

### Backend and ML

- Python
- Flask
- Flask-CORS
- scikit-learn
- XGBoost
- pandas
- numpy
- torch
- transformers
- safetensors

### Browser Layer

- JavaScript
- Chrome/Edge/Chromium Extension APIs
- Manifest V3
- HTML
- CSS

## Setup

### 1. Create a virtual environment and install dependencies

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the backend

```powershell
.\venv\Scripts\python app\app.py
```

The backend runs locally at:

```text
http://127.0.0.1:5000
```

### 3. Load the extension

1. Open `chrome://extensions/` or `edge://extensions/`
2. Enable Developer mode
3. Choose `Load unpacked`
4. Select the `extension/` folder

## Reproducibility Notes

For full functionality, this project expects local model and dataset artifacts to be present. Some of these are intentionally ignored in Git because they can be large or environment-specific.

In particular, full runtime behavior depends on local availability of:

- `models/final_phishing_model.joblib`
- `models/results/`
- `data/phishing_email.csv`

These assets support full reproduction of the complete detection pipeline.

## Running Training and Evaluation

### Retrain the URL model

```powershell
cd training
..\venv\Scripts\python train_model.py
```

### Generate evaluation outputs

```powershell
cd evaluation
..\venv\Scripts\python generate_performance_table.py
..\venv\Scripts\python make_graph.py
```

## Testing and Validation

The repository includes several forms of validation:

- `tests/test_api_integration.py`
  checks backend response behavior and validates email and URL endpoint contracts

- `tests/test_email_classifier.py`
  exercises the email endpoint with realistic sample cases

- `tests/validation_test.py`
  checks basic API input validation behavior for the URL endpoint

- additional scripts in `tests/`
  support stress and functional testing

Example commands:

```powershell
.\venv\Scripts\python -m unittest tests\test_api_integration.py
.\venv\Scripts\python tests\test_email_classifier.py
.\venv\Scripts\python tests\validation_test.py
```

## Security and Privacy Perspective

FORTNOX is intentionally designed as a local-first prototype. This shapes how the system is used in practice:

1. Privacy advantage
   Browsing and email data do not need to be sent to a remote external service during normal local use.

2. Local deployment model
   The extension works together with the Flask backend running on the local machine, allowing analysis to stay within the same controlled environment.

The permission-monitoring feature is also privacy-relevant. It helps expose when a site is trying to access capabilities that users often overlook, especially location, camera, microphone, clipboard, and screen capture.

## Ethical Use

FORTNOX should be used responsibly:

- only on systems and accounts where monitoring is authorized
- with appropriate consent if used in a user study
- with care when handling real email content or personal data

If this project is presented in an academic setting, it should be described as a defensive cybersecurity prototype intended to improve user awareness and phishing detection, not as a tool for surveillance.

## Future Work

Strong next steps for the project include:

- broader support for additional email platforms
- richer attachment and payload inspection
- continuous retraining on fresher phishing datasets
- domain reputation or threat-intelligence integration
- more formal user studies on warning effectiveness
- dashboard-level analytics for repeated threats and permission patterns

## Conclusion

FORTNOX demonstrates how phishing defense can be improved when browser security, email analysis, machine learning, and human-readable warnings are treated as one connected system. Its main value lies in integration: it does not stop at model training, and it does not stop at UI. Instead, it shows how a research project can move from data and algorithms to a usable protective workflow.

For a review committee, the key takeaway is that FORTNOX is a complete applied cybersecurity project with clear research value, measurable results, and a strong balance between technical depth and practical usability.
