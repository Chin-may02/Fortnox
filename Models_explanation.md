# Models And Logic Gist

## Models Used

Training script (`training/train_model.py`) trains 4 classifiers:

- `Linear SVM` (`LinearSVC`)
- `Logistic Regression`
- `Random Forest`
- `XGBoost`

All trained models are saved in the model bundle under `trained_models`, and one is chosen as the active `classifier`.

## Feature + Preprocessing Logic

### 1) URL normalization
- lowercasing
- strip `http://` / `https://`
- strip `www.`
- remove trailing slash

### 2) Numerical URL features
Examples:
- domain length
- subdomain count
- suspicious TLD flag
- hyphen in domain
- domain entropy
- URL/path length
- slash count
- suspicious keyword count
- brand keyword count

Numeric features are scaled using `StandardScaler`.

### 3) Text features
- character-level TF-IDF (`ngram_range=(2,4)`, `max_features=3000`, `min_df=2`)

### 4) Final feature vector
- `hstack([scaled_numeric_features, tfidf_features])`

## Model Selection Logic

Current selection in `training/train_model.py` is **recall-first** for phishing class:

1. Maximize `recall_phishing`
2. Tie-break with higher `f1_phishing`

The selected model and all model metrics are saved to:
- `models/final_phishing_model.joblib`

## Inference/API Logic (`app/app.py`)

Endpoint: `POST /check_url`

Flow:
1. Load model bundle (`classifier`, scaler, vectorizer, feature columns, metrics, trained models).
2. Build features for incoming URL.
3. Predict label + probabilities.
4. Return prediction, risk score, probabilities, model metadata.

### Model switching
- API can use a requested model via `modelName` if present in `trained_models`.

### Important runtime rule
- `app.py` currently includes `is_whitelisted_domain(...)`.
- If URL is whitelisted, prediction is overridden to `safe` and probabilities are adjusted by internal whitelist logic.

## Current Reported Metrics (from `reports/performance_summary.txt`)

- Linear SVM: Accuracy `96.24%`, Recall `0.9504`, F1 `0.9189`
- Logistic Regression: Accuracy `95.93%`, Recall `0.9469`, F1 `0.9126`
- Random Forest: Accuracy `96.99%`, Recall `0.8979`, F1 `0.9304`
- XGBoost: Accuracy `92.63%`, Recall `0.8580`, F1 `0.8393`

## Quick Interpretation

- Best **accuracy/F1** in report: `Random Forest`
- Best **phishing recall**: `Linear SVM`
- So there is a tradeoff between catching more phishing URLs (recall) and overall accuracy/F1.

