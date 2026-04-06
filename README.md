# FORTNOX

FORTNOX is a local phishing detection project built around two connected parts:
- A Flask backend API for phishing analysis
- A Chrome extension for real-time browser and Gmail detection

The project focuses on two use cases:
- Detecting risky or phishing URLs while browsing
- Analyzing Gmail messages for phishing signals such as sender issues, suspicious wording, risky links, and dangerous attachments

## What The Project Includes

FORTNOX combines model-based URL detection with BERT-powered email classification plus explainable email risk analysis. The browser extension handles collection and display, while the Flask backend performs the actual analysis and returns a structured risk result.

At a high level:
- The extension sends URLs to the backend for phishing checks
- The Gmail content script extracts visible email data and sends it to the backend
- The backend returns a prediction, risk score, and supporting details
- The extension then warns, blocks, or highlights the result in the browser UI

## Main Features

### URL Phishing Detection

- Real-time URL scanning through the Chrome extension
- Backend URL classification through `POST /check_url`
- Feature-based URL analysis combined with text vectorization
- Risk-driven behavior in the extension such as allow, warning, or block flow
- Reuse of a saved trained model from `models/final_phishing_model.joblib`

### Gmail Email Detection

- Automatic email monitoring inside Gmail
- Email extraction directly from the Gmail interface
- BERT-based classification of combined email text using the saved model in `models/results`
- Additional risk scoring based on sender, subject, body, links, HTML structure, and attachments
- Per-email risk badge shown in the Gmail UI
- High-risk warning overlay for suspicious emails
- URL extraction from email content with follow-up URL analysis on detected links

## Project Components

- `app/`
  Contains the Flask backend. This includes the main API in `app.py` and the email feature extraction logic in `email_features.py`.

- `extension/`
  Contains the Chrome extension. This includes the background service worker, popup, content scripts, Gmail content script, blocked page, styles, and manifest.

- `training/`
  Contains the scripts used to train the URL phishing model and produce the saved model artifact used at inference time.

- `evaluation/`
  Contains scripts used to generate model summaries and comparison outputs from trained model results.

- `models/`
  Stores trained model artifacts. The backend depends on the active saved model file in this folder.

- `data/`
  Stores the project datasets used for phishing URL training and related data processing.

- `reports/`
  Stores generated model comparison outputs and summary files.

- `tests/`
  Contains validation and stress tests for the backend and project behavior.

## How The System Works

### URL Detection Flow

1. The extension detects a page navigation or page update.
2. The URL is sent to the Flask backend through `POST /check_url`.
3. The backend extracts numerical URL features and text-based URL features.
4. The trained model predicts whether the URL is safe or phishing.
5. The backend returns a risk score, prediction, and model metadata.
6. The extension decides whether to allow the page, show a warning, or redirect to the blocked page.

### Gmail Email Detection Flow

1. `gmail_content.js` watches Gmail for opened email content.
2. When an email is opened, it extracts fields such as:
   - sender email
   - sender name
   - recipient
   - subject
   - plain text body
   - HTML body
   - reply-to
   - attachment names
3. The content script sends this payload to the background script.
4. The background script forwards it to `POST /check_email`.
5. The backend extracts email-specific features and scans URLs found in the message.
6. The backend returns a risk result with:
   - prediction
   - risk score
   - risk level
   - risk factors
   - URL analysis summary
7. The Gmail content script displays a badge, and for high-risk messages, an overlay warning.

## Detection Logic

### URL Analysis

The URL backend uses a trained model with engineered URL features and vectorized text features. This is the model-driven part of the project and is the main source of URL phishing classification.

Examples of URL-oriented signals include:
- protocol usage
- domain structure
- suspicious TLDs
- presence of numbers or IP addresses
- suspicious keywords
- shortener patterns
- text vectorization of the normalized URL

### Email Analysis

The email flow now uses a hybrid path:
- A fine-tuned BERT classifier saved in `models/results`
- Existing feature extraction for explainable email signals
- Existing URL classification for embedded links found in the message

The feature and URL layer still evaluates a message using extracted signals such as:
- sender domain traits
- freemail usage
- suspicious TLDs
- reply-to mismatch
- brand impersonation in display names
- urgency and financial keywords in subject and body
- excessive capitalization
- number and quality of embedded URLs
- suspicious attachments
- HTML forms or input fields in the email body

The backend also analyzes up to 10 extracted URLs from an email using the URL classifier and folds that into the final email risk score without affecting the standalone `/check_url` flow.

Email results are returned as:
- `Low Risk`
- `Medium Risk`
- `High Risk`

## Setup

Create and activate a virtual environment, then install the Python dependencies:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

The main dependencies include Flask, pandas, numpy, scikit-learn, joblib, xgboost, requests, torch, transformers, and safetensors.

## Running The Backend

From the project root:

```powershell
.\venv\Scripts\python app\app.py
```

The backend runs locally at:

```text
http://127.0.0.1:5000
```

This API must be running for the extension to perform URL or Gmail analysis.

## Loading The Chrome Extension

1. Open `chrome://extensions/`
2. Turn on Developer mode
3. Click Load unpacked
4. Select the `extension/` folder from this project

The extension uses permissions for browser tabs, storage, navigation events, and host access to Gmail and the local backend.

## Main API Endpoints

- `POST /check_url`
  Accepts a URL and returns a phishing prediction, risk score, probabilities, and model details.

- `POST /check_email`
  Accepts extracted email content and returns a BERT-backed email risk result, supporting features, and URL analysis data for links found in the message.

## Training

### URL Model

To retrain the URL model:

```powershell
cd training
..\venv\Scripts\python train_model.py
```

This updates the saved model artifact used by the backend:

```text
models/final_phishing_model.joblib
```

### Email Model

The BERT training notebook is stored at:

```text
training/Bert_training.ipynb
```

The email dataset used for that training is stored at:

```text
data/phishing_email.csv
```

The saved email model artifacts consumed by the backend are stored at:

```text
models/results
```

## Reports

To generate report outputs:

```powershell
..\venv\Scripts\python ..\evaluation\generate_performance_table.py
..\venv\Scripts\python ..\evaluation\make_graph.py
```

These scripts generate summary outputs in the `reports/` folder.

## Notes

- The project is intended to run locally during development and testing
- The backend depends on the saved model file inside `models/`
- Gmail analysis depends on both the extension and the running Flask backend
- URL detection and Gmail detection share the same backend, but they use different analysis paths
