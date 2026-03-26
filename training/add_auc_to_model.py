"""
Script to add AUC scores to an existing model file by recalculating them.
Uses the saved scaler and vectorizer from the model file to ensure feature
parity with training. Reproduces the same downsampling and train/test split
used during training so the test set is identical.
"""
import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from scipy.sparse import hstack
from scipy.special import expit
import re
import os
import shutil
from urllib.parse import urlparse


def normalize_url(url):
    if pd.isna(url): return ""
    url = str(url).lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    return url.rstrip('/')


def calculate_entropy(text):
    if not text: return 0
    char_counts = {char: text.count(char) for char in set(text)}
    length = len(text)
    entropy = -sum((count / length) * np.log2(count / length) for count in char_counts.values())
    return entropy


def extract_url_features(url):
    """Must match the 28-feature function in train_model.py and app.py exactly."""
    normalized_url = normalize_url(url)
    original_url = str(url).lower()
    features = {}
    try:
        parsed = urlparse('http://' + normalized_url)
        domain = parsed.netloc or normalized_url.split('/')[0]
        path = parsed.path
        query = parsed.query
    except:
        domain = normalized_url.split('/')[0] if '/' in normalized_url else normalized_url
        path, query = '', ''

    features['has_protocol'] = int(any(p in original_url for p in ['http://', 'https://']))
    features['is_https'] = int('https://' in original_url)
    features['is_http'] = int('http://' in original_url and 'https://' not in original_url)
    features['domain_length'] = len(domain)
    features['subdomain_count'] = max(0, domain.count('.') - 1)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top']
    features['has_suspicious_tld'] = int(any(tld in domain for tld in suspicious_tlds))
    features['domain_has_numbers'] = int(bool(re.search(r'\d', domain)))
    features['domain_has_hyphen'] = int('-' in domain)
    features['domain_entropy'] = calculate_entropy(domain)
    features['url_length'] = len(normalized_url)
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    features['slash_count'] = normalized_url.count('/')
    features['dot_count'] = normalized_url.count('.')
    features['hyphen_count'] = normalized_url.count('-')
    features['underscore_count'] = normalized_url.count('_')
    features['question_count'] = normalized_url.count('?')
    features['equal_count'] = normalized_url.count('=')
    features['and_count'] = normalized_url.count('&')
    features['at_count'] = normalized_url.count('@')
    features['has_ip'] = int(bool(re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', normalized_url)))
    phishing_keywords = ['secure', 'account', 'update', 'login', 'verify', 'suspend', 'confirm', 'urgent', 'expired', 'locked', 'security', 'warning', 'alert']
    features['suspicious_keyword_count'] = sum(1 for word in phishing_keywords if word in normalized_url)
    brand_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'bank', 'visa', 'mastercard', 'ebay', 'netflix', 'adobe']
    features['brand_keyword_count'] = sum(1 for word in brand_keywords if word in normalized_url)
    shortener_domains = ['bit.ly', 'tinyurl', 'ow.ly', 't.co', 'goo.gl', 'short']
    features['is_url_shortener'] = int(any(short in domain for short in shortener_domains))

    if len(normalized_url) > 0:
        features['char_diversity'] = len(set(normalized_url)) / len(normalized_url)
        features['vowel_ratio'] = sum(1 for c in normalized_url if c in 'aeiou') / len(normalized_url)
    else:
        features['char_diversity'] = 0
        features['vowel_ratio'] = 0

    total_len = len(normalized_url)
    if total_len > 0:
        features['domain_to_url_ratio'] = len(domain) / total_len
        features['path_to_url_ratio'] = len(path) / total_len
    else:
        features['domain_to_url_ratio'] = 0
        features['path_to_url_ratio'] = 0

    return features


# --- Load model file ---
model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'final_phishing_model.joblib')
print("Loading model file...")
model_data = joblib.load(model_path)

# Retrieve the saved scaler, vectorizer and feature columns from the model
numerical_scaler = model_data.get('numerical_scaler')
text_vectorizer = model_data.get('text_vectorizer')
feature_columns = model_data.get('feature_columns')

if numerical_scaler is None or text_vectorizer is None or feature_columns is None:
    raise RuntimeError("Model file is missing scaler, vectorizer, or feature_columns. Re-run training.")

# --- Load and prepare dataset identically to train_model.py ---
data_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'phishing_site_urls_cleaned.csv')
print("Loading dataset...")
df = pd.read_csv(data_path)
df.dropna(inplace=True)
df = df.drop_duplicates(subset=['URL'])
df['normalized_url'] = df['URL'].apply(normalize_url)
df = df[df['normalized_url'] != '']

# Reproduce the same downsampling used during training (default MAX_SAMPLES=220000)
max_samples = int(os.environ.get('MAX_SAMPLES', '220000'))
if len(df) > max_samples:
    df, _ = train_test_split(
        df,
        train_size=max_samples,
        random_state=42,
        stratify=df['Label']
    )
    df = df.reset_index(drop=True)
    print(f"Downsampled dataset to {len(df)} rows (matching training).")

X = df['URL']
y = df['Label'].apply(lambda label: 1 if label == 'bad' else 0)

# Reproduce the same 80/20 split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Test set: {len(X_test)} samples.")

# --- Build features using the SAVED scaler & vectorizer ---
print("Extracting features (using saved scaler/vectorizer)...")
test_features_df = pd.DataFrame([extract_url_features(url) for url in X_test])

# Ensure column order matches training
for col in feature_columns:
    if col not in test_features_df.columns:
        test_features_df[col] = 0
test_features_df = test_features_df[feature_columns]

X_test_num = numerical_scaler.transform(test_features_df)
X_test_text = text_vectorizer.transform(X_test.apply(normalize_url))
X_test_combined = hstack([X_test_num, X_test_text])

# --- Recalculate AUC for each model ---
print("Recalculating AUC for each model...")
trained_models = model_data.get('trained_models', {})
all_model_metrics = model_data.get('all_model_metrics', {}).copy()

for model_name, model in trained_models.items():
    if model_name not in all_model_metrics:
        continue

    print(f"  Calculating AUC for {model_name}...")
    try:
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test_combined)[:, 1]
        else:
            # For LinearSVC, use decision_function + sigmoid (same as train_model.py)
            y_decision = model.decision_function(X_test_combined)
            if y_decision.ndim > 1:
                y_decision = y_decision[:, 1] if y_decision.shape[1] > 1 else y_decision[:, 0]
            y_prob = expit(y_decision)

        auc = roc_auc_score(y_test, y_prob)
        if np.isnan(auc) or auc < 0 or auc > 1:
            auc = 0.5
        print(f"    AUC: {auc:.4f}")
        all_model_metrics[model_name]['auc_score'] = float(auc)

    except Exception as e:
        print(f"    Error calculating AUC for {model_name}: {e}")
        all_model_metrics[model_name]['auc_score'] = 0.0

# Update the model data
model_data['all_model_metrics'] = all_model_metrics

# Update best_model_metrics
active_model_name = model_data.get('model_name')
if active_model_name and active_model_name in all_model_metrics:
    model_data['best_model_metrics'] = all_model_metrics[active_model_name].copy()

# Create backup
backup_path = model_path + '.backup'
print(f"\nCreating backup: {backup_path}")
shutil.copy(model_path, backup_path)

# Save updated model
joblib.dump(model_data, model_path)
print("\n[OK] Model updated with AUC scores!")

# Display results
print("\nUpdated metrics:")
for model_name, metrics in all_model_metrics.items():
    auc = metrics.get('auc_score', 0)
    print(f"\n{model_name}:")
    print(f"  Accuracy: {metrics.get('accuracy', 0):.4f} ({metrics.get('accuracy', 0)*100:.1f}%)")
    print(f"  Recall (phishing): {metrics.get('recall_phishing', 0):.4f} ({metrics.get('recall_phishing', 0)*100:.1f}%)")
    print(f"  F1 (phishing): {metrics.get('f1_phishing', 0):.4f} ({metrics.get('f1_phishing', 0)*100:.1f}%)")
    print(f"  AUC: {auc:.4f} ({auc*100:.1f}%)")
