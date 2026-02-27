# Models Explanation

## Models Used

`training/train_model.py` trains 4 classifiers:

- `Linear SVM` (`LinearSVC`)
- `Logistic Regression`
- `Random Forest`
- `XGBoost`

All models are stored in `trained_models` inside the saved `.joblib` bundle, and one model is selected as the active `classifier`.

## Preprocessing And Features

### 1) URL normalization

- lowercase
- remove `http://` or `https://`
- remove `www.`
- trim trailing `/`

### 2) Numerical features

The pipeline extracts lexical/domain features including:

- protocol/https/http flags
- domain length, subdomain count, suspicious TLD
- domain entropy, numeric/hyphen/domain-shape indicators
- URL/path/query lengths and symbol counts
- IP-address pattern flag
- suspicious keyword and brand keyword counts
- shortener/domain-ratio and character-ratio features

Numerical features are scaled with `StandardScaler`.

### 3) Text features

- Character-level TF-IDF with `ngram_range=(2,4)`, `max_features=3000`, `min_df=2`

### 4) Final feature matrix

- `hstack([scaled_numerical_features, tfidf_text_features])`

## Model Selection Logic

Current best-model selection in `training/train_model.py` is **accuracy-first**:

1. highest `accuracy`
2. tie-break by higher `recall_phishing`
3. final tie-break by higher `f1_phishing`

The final trained artifact can be saved with configurable name via `MODEL_OUTPUT_NAME`.
Current production artifact used in this project is:

- `models/Phishing_final.joblib`

## API Inference Logic (`app/app.py`)

Endpoint: `POST /check_url`

Flow:

1. load model bundle (classifier + scaler + vectorizer + schema + metrics)
2. extract features for incoming URL
3. predict class + probability
4. return prediction, risk score, and model metrics metadata

Important:

- No whitelist override is applied now.
- API output is model-driven.
- `modelName` request field can switch to another model in `trained_models`.
- Default model file is `../models/Phishing_final.joblib` (can be overridden via `MODEL_FILE` env var).

## Latest Metrics (Phishing_final)

From `reports/performance_summary_Phishing_final.txt`:

- Linear SVM: Accuracy `94.87%`, Recall `0.9321`, F1 `0.8908`
- Logistic Regression: Accuracy `94.60%`, Recall `0.9281`, F1 `0.8852`
- Random Forest: Accuracy `95.91%`, Recall `0.8607`, F1 `0.9043`
- XGBoost: Accuracy `91.27%`, Recall `0.8086`, F1 `0.8060`

## Interpretation

- Best overall accuracy/F1 in this run: `Random Forest`
- Best phishing recall in this run: `Linear SVM`
- This shows the expected accuracy-recall tradeoff between models.
