"""
Script to add AUC scores to an existing model file by recalculating them.
This is faster than retraining the entire model.
"""
import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack
import re
from urllib.parse import urlparse
import shutil

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
    normalized_url = normalize_url(url)
    original_url = str(url).lower()
    features = {}
    try:
        parsed = urlparse('http://' + normalized_url)
        domain = parsed.netloc
        path = parsed.path
    except:
        domain, path = normalized_url, ''
    
    features['domain_length'] = len(domain)
    features['subdomain_count'] = max(0, domain.count('.') - 1)
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top']
    features['has_suspicious_tld'] = int(any(tld in domain for tld in suspicious_tlds))
    features['domain_has_hyphen'] = int('-' in domain)
    features['domain_entropy'] = calculate_entropy(domain)
    features['url_length'] = len(normalized_url)
    features['path_length'] = len(path)
    features['slash_count'] = normalized_url.count('/')
    phishing_keywords = ['secure', 'account', 'update', 'login', 'verify', 'suspend', 'confirm', 'urgent', 'expired', 'locked', 'security', 'warning', 'alert']
    features['suspicious_keyword_count'] = sum(1 for word in phishing_keywords if word in normalized_url)
    brand_keywords = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'bank', 'visa', 'mastercard', 'ebay', 'netflix', 'adobe']
    features['brand_keyword_count'] = sum(1 for word in brand_keywords if word in normalized_url)
    
    return features

print("Loading model file...")
model_data = joblib.load('final_phishing_model.joblib')

print("Loading dataset...")
df = pd.read_csv('phishing_site_urls_cleaned.csv')
df.dropna(inplace=True)
df = df.drop_duplicates(subset=['URL'])
df['normalized_url'] = df['URL'].apply(normalize_url)
df = df[df['normalized_url'] != '']

X = df['URL']
y = df['Label'].apply(lambda label: 1 if label == 'bad' else 0)

# Use the same random state as training script
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("Extracting features...")
train_features_df = pd.DataFrame([extract_url_features(url) for url in X_train])
test_features_df = pd.DataFrame([extract_url_features(url) for url in X_test])
feature_columns = list(train_features_df.columns)

scaler = StandardScaler()
X_train_num = scaler.fit_transform(train_features_df)
X_test_num = scaler.transform(test_features_df)
vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(2, 4), max_features=3000, min_df=2)
X_train_text = vectorizer.fit_transform(X_train.apply(normalize_url))
X_test_text = vectorizer.transform(X_test.apply(normalize_url))
X_test_combined = hstack([X_test_num, X_test_text])

print("Recalculating AUC for each model...")
trained_models = model_data.get('trained_models', {})
all_model_metrics = model_data.get('all_model_metrics', {}).copy()

for model_name, model in trained_models.items():
    if model_name not in all_model_metrics:
        continue
    
    print(f"  Calculating AUC for {model_name}...")
    try:
        # Get predictions
        y_pred = model.predict(X_test_combined)
        
        # Get probabilities/scores for AUC
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test_combined)[:, 1]
        else:
            # For LinearSVC, use decision_function
            y_prob = model.decision_function(X_test_combined)
            # Normalize decision function scores to [0, 1] range for better AUC calculation
            # This is a common approach when using decision_function
            y_prob = (y_prob - y_prob.min()) / (y_prob.max() - y_prob.min() + 1e-10)
        
        # Calculate AUC
        auc = roc_auc_score(y_test, y_prob)
        print(f"    AUC: {auc:.4f}")
        
        # Update metrics
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
backup_file = 'final_phishing_model.joblib.backup'
print(f"\nCreating backup: {backup_file}")
shutil.copy('final_phishing_model.joblib', backup_file)

# Save updated model
joblib.dump(model_data, 'final_phishing_model.joblib')
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






