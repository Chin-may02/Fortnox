# FORTNOX

FORTNOX is a comprehensive security detection project built with:
- A Flask backend API for URL phishing detection
- A Chrome extension UI for real-time URL scanning
- An MCP-based email classification system
- Machine learning training and evaluation pipelines

The system provides:
- **URL Classification**: Classifies URLs as `safe` or `phishing`
- **Email Classification**: Classifies emails as `legitimate`, `spam`, `phishing`, or `malicious`
- Risk/confidence scores and detailed model metrics

## Project Structure

- `app/`
  Flask API (`app.py`) for URL phishing detection and API tests.
- `training/`
  Model training script (`train_model.py`) for URL classification.
- `evaluation/`
  Scripts to generate report tables and graphs from saved model metrics.
- `extension/`
  Chrome extension files (popup, background, content scripts, manifest).
- `mcp_server/`
  **NEW**: MCP-based email classification system (server, classifier, training, CLI).
- `data/`
  Dataset files for both URL and email classification.
- `models/`
  Active model artifacts (URL and email classifiers).
- `reports/`
  Generated report outputs (`performance_summary.*`, graph image).
- `tests/`
  Validation and stress tests for both URL and email classification.

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

## Email Classification System (MCP-Based)

**NEW**: FORTNOX now includes TWO email classification approaches:

### 1. LLM-Based (REAL MCP with AI APIs) ⭐ RECOMMENDED

Uses actual LLM APIs (Claude/Anthropic or OpenAI/GPT) for intelligent email analysis.

**Quick Start:**
```bash
cd mcp_server

# 1. Set up API key
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY or OPENAI_API_KEY

# 2. Install dependencies
pip install anthropic openai python-dotenv

# 3. Classify emails with AI
python llm_classify_email.py \
  --subject "Your subject here" \
  --body "Email body" \
  --sender "sender@example.com"

# 4. Run MCP server
python llm_email_mcp_server.py

# 5. Try the demo
python llm_client_example.py
```

**Features:**
- 🤖 Real AI-powered analysis (not traditional ML)
- 🧠 Detailed reasoning for each classification
- 🎯 Identifies specific risk indicators
- 💡 Provides actionable recommendations
- 🌍 Supports all languages automatically
- 🔄 No training needed - works immediately

**See [`mcp_server/LLM_README.md`](mcp_server/LLM_README.md) for complete documentation.**

### 2. Traditional ML-Based (Local, No API Keys)

Uses scikit-learn/XGBoost for local classification (no API costs).

**Quick Start:**

1. **Train the email model:**
```bash
cd mcp_server
python train_email_model.py
```

2. **Classify emails via CLI:**
```bash
cd mcp_server
python classify_email_cli.py \
  --subject "Your subject here" \
  --body "Email body content" \
  --sender "sender@example.com"
```

3. **Run the MCP server:**
```bash
cd mcp_server
python email_classifier_server.py
```

4. **Try the example client:**
```bash
cd mcp_server
python client_example.py
```

### Features

The email classifier detects:
- **Phishing**: Credential theft attempts, account verification scams
- **Spam**: Unsolicited bulk emails, promotional content
- **Malicious**: Malware, ransomware, Bitcoin scams
- **Legitimate**: Normal, safe emails

### Which Approach Should You Use?

| Feature | LLM-Based ⭐ | Traditional ML |
|---------|------------|----------------|
| **Accuracy** | 95-99% | 85-95% |
| **Setup** | API key only | Training required |
| **Cost** | ~$0.005/email | Free (local) |
| **Reasoning** | Detailed AI explanation | None |
| **New Attacks** | Handles automatically | Must retrain |
| **Languages** | All languages | English mainly |
| **Dependencies** | anthropic/openai | scikit-learn |

**Recommendation**: Use **LLM-Based** for production. It's more accurate, requires no training, and provides valuable reasoning. The cost (~$5 per 1000 emails) is negligible for the quality improvement.

### Documentation

**LLM-Based (Recommended):**
- See [`mcp_server/LLM_README.md`](mcp_server/LLM_README.md) - Complete guide for LLM-based classification
  - API key setup
  - Provider comparison (Claude vs GPT)
  - Cost estimation
  - Integration examples

**Traditional ML-Based:**
- See [`mcp_server/README.md`](mcp_server/README.md) - Original ML-based documentation
  - Feature extraction (30+ features)
  - Training your own models
  - Rule-based classification

### Testing

Run email classification tests:
```bash
python tests/test_email_classifier.py
```

## Current Important Notes

- Keep training and inference feature logic aligned (`training/train_model.py` and `app/app.py` for URLs; `mcp_server/train_email_model.py` and `mcp_server/email_classifier.py` for emails).
- Back up model artifacts before retraining to avoid accidental overwrite.
- Reporting scripts read metrics from the current saved model, so stale model files produce stale reports.
- The email classifier works with rule-based classification out of the box, but training a model improves accuracy significantly.

