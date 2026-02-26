# FORTNOX

FORTNOX is a phishing URL detection project built with:
- A Flask backend API for model inference
- A Chrome extension UI
- A machine learning training and evaluation pipeline

The system classifies URLs as `safe` or `phishing`, returns risk/confidence values, and exposes model metrics for reporting.

## Project Structure

- `app/`  
  Flask API (`app.py`) and API tests.
- `training/`  
  Model training script (`train_model.py`) and model selection logic.
- `evaluation/`  
  Scripts to generate report tables and graphs from saved model metrics.
- `extension/`  
  Chrome extension files (popup, background, content scripts, manifest).
- `data/`  
  Dataset files (`phishing_site_urls.csv`, `phishing_site_urls_cleaned.csv`).
- `models/`  
  Active model artifact and backups.
- `reports/`  
  Generated report outputs (`performance_summary.*`, graph image).
- `tests/`  
  Validation and stress test scripts.

## How It Works

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

