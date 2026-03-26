# FORTNOX

FORTNOX is a comprehensive security project combining phishing URL detection and email phishing classification:
- A Flask backend API for model inference (URLs and emails)
- A Chrome extension with Gmail integration
- A machine learning training and evaluation pipeline

The system classifies URLs as `safe` or `phishing`, analyzes emails for phishing indicators, returns risk/confidence values, and exposes model metrics for reporting.

## Key Features

### 🌐 URL Phishing Detection
- Real-time URL scanning as you browse
- 4 trained ML models (Linear SVM, Logistic Regression, Random Forest, XGBoost)
- 24+ URL features + TF-IDF text analysis
- Graduated risk response (block/warn/allow)
- Model switching and comparison

### 📧 Email Phishing Detection (NEW!)
- **Seamless Gmail integration** - no copy-paste needed
- **Real-time email analysis** as you read
- **30+ email features** analyzed (sender, subject, body, URLs, attachments)
- **Inline risk indicators** with detailed risk factors
- **URL extraction and analysis** using ML models
- **Visual warnings** for high-risk emails

**See [EMAIL_CLASSIFIER_GUIDE.md](EMAIL_CLASSIFIER_GUIDE.md) for detailed email classifier documentation.**

## Project Structure

- `app/`
  Flask API (`app.py`), email feature extraction (`email_features.py`), and API tests.
- `training/`
  Model training script (`train_model.py`) and model selection logic.
- `evaluation/`
  Scripts to generate report tables and graphs from saved model metrics.
- `extension/`
  Chrome extension files (popup, background, content scripts, Gmail integration, manifest).
- `data/`
  Dataset files (`phishing_site_urls.csv`, `phishing_site_urls_cleaned.csv`).
- `models/`
  Active model artifact and backups.
- `reports/`
  Generated report outputs (`performance_summary.*`, graph image).
- `tests/`
  Validation, stress test, and email classifier test scripts.

## How It Works

### URL Classification
1. A URL is sent to `POST /check_url`.
2. API loads `models/final_phishing_model.joblib`.
3. URL is preprocessed:
   - normalized text
   - engineered numerical URL features
   - character-level TF-IDF features
4. Features are combined and passed to selected model.
5. API returns:
   - prediction (`safe` or `phishing`)
   - probability/risk score
   - model name and model metrics

### Email Classification (NEW!)
1. Gmail content script extracts email data (sender, subject, body, attachments).
2. Email sent to `POST /check_email`.
3. API extracts 32 email-specific features:
   - Sender validation (domain, authentication, brand impersonation)
   - Subject analysis (urgency, financial keywords, caps ratio)
   - Body analysis (entropy, keywords, structure)
   - URL extraction and individual analysis with ML models
   - Attachment analysis (suspicious file types)
4. Risk score calculated using weighted heuristics + URL risk.
5. API returns:
   - prediction (`safe`, `suspicious`, or `phishing`)
   - risk score and level
   - list of detected risk factors
   - URL analysis results

## Model Artifact (`.joblib`) Contents

The saved model bundle includes:
- `classifier`
- `numerical_scaler`
- `text_vectorizer`
- `feature_columns`
- `model_name`
- `best_model_metrics`
- `all_model_metrics`
- `trained_models`

## Setup

Create and activate your virtual environment, then install dependencies:

```powershell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Run the API

From project root:

```powershell
.\venv\Scripts\python app\app.py
```

API runs on `http://127.0.0.1:5000`.

## Train the Model

From `training/`:

```powershell
$env:PYTHONIOENCODING='utf-8'
..\venv\Scripts\python train_model.py
```

This updates:
- `models/final_phishing_model.joblib`

## Generate Reports

From `reports/`:

```powershell
..\venv\Scripts\python ..\evaluation\generate_performance_table.py
..\venv\Scripts\python ..\evaluation\make_graph.py
```

This updates:
- `reports/performance_summary.txt`
- `reports/performance_summary.csv`
- `reports/model_comparison_graph.png`

## Useful Tests

- API payload/metric check: `app/test_metrics_api.py`
- Input validation test: `tests/validation_test.py`
- Stress test: `tests/stress_test.py`

## Current Important Notes

- Keep training and inference feature logic aligned (`training/train_model.py` and `app/app.py`).
- Back up model artifacts before retraining to avoid accidental overwrite.
- Reporting scripts read metrics from the current saved model, so stale model files produce stale reports.

