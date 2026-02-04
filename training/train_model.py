import pandas as pd
import joblib
import re
import numpy as np
import time
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.svm import LinearSVC
from sklearn.preprocessing import StandardScaler
from scipy.sparse import hstack
from urllib.parse import urlparse
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support, roc_auc_score
import os

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

try:
    print("Attempting to load CLEANED dataset: 'phishing_site_urls_cleaned.csv'")
    df = pd.read_csv('phishing_site_urls_cleaned.csv')
    print(f"✓ Cleaned dataset loaded successfully: {len(df)} rows")
except FileNotFoundError:
    print("\nFATAL ERROR: 'phishing_site_urls_cleaned.csv' not found.")
    print("Please run the 'test.py' script first to generate the cleaned file.")
    exit()

df.dropna(inplace=True)
df = df.drop_duplicates(subset=['URL'])
df['normalized_url'] = df['URL'].apply(normalize_url)
df = df[df['normalized_url'] != '']
X = df['URL']
y = df['Label'].apply(lambda label: 1 if label == 'bad' else 0)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f"Data prepared. Training with {len(X_train)} samples.")

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
X_train_combined = hstack([X_train_num, X_train_text])
X_test_combined = hstack([X_test_num, X_test_text])
print("Features combined successfully.")

models = {
    'Logistic Regression': LogisticRegression(
        solver='liblinear',
        class_weight='balanced',
        C=1.0,
        random_state=42,
        max_iter=1000
    ),
    'Random Forest': RandomForestClassifier(
        n_estimators=150,
        max_depth=None,
        min_samples_leaf=1,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    ),
    'Linear SVM': LinearSVC(
        C=1.0,
        class_weight='balanced',
        random_state=42,
        max_iter=5000,
        dual=False
    ),
    'XGBoost': XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=4,
        scale_pos_weight=3,
        eval_metric='logloss',
        random_state=42,
        use_label_encoder=False
    )
}

model_metrics = {}
best_model_name = None
best_model = None
best_recall = -1
best_f1 = -1

print("\n--- Model Evaluation Summary ---")
for model_name, model in models.items():
    print(f"\nTraining {model_name}...")
    # Measure training time
    start_time = time.time()
    model.fit(X_train_combined, y_train)
    training_time = time.time() - start_time
    y_pred = model.predict(X_test_combined)

    # Calculate AUC
    try:
        if hasattr(model, "predict_proba"):
            y_prob = model.predict_proba(X_test_combined)[:, 1]
        else:
            # For LinearSVC, use decision_function
            y_prob = model.decision_function(X_test_combined)
            if y_prob.ndim > 1:
                y_prob = y_prob[:, 1] if y_prob.shape[1] > 1 else y_prob[:, 0]
        
        auc = roc_auc_score(y_test, y_prob)
        if np.isnan(auc) or auc < 0 or auc > 1:
            auc = 0.5
    except Exception as e:
        print(f"    Warning: Error calculating AUC: {e}")
        auc = 0.5

    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test,
        y_pred,
        labels=[0, 1],
        zero_division=0
    )

    phishing_metrics = {
        'precision': float(precision[1]),
        'recall': float(recall[1]),
        'f1_score': float(f1[1])
    }

    metrics = {
        'accuracy': float(accuracy),
        'precision_phishing': phishing_metrics['precision'],
        'recall_phishing': phishing_metrics['recall'],
        'f1_phishing': phishing_metrics['f1_score'],
        'auc_score': float(auc),
        'training_time': float(training_time),
        'classification_report': classification_report(
            y_test,
            y_pred,
            digits=4
        )
    }

    model_metrics[model_name] = metrics

    print(f"Accuracy: {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.1f}%)")
    print(f"Recall (phishing): {metrics['recall_phishing']:.4f} ({metrics['recall_phishing']*100:.1f}%)")
    print(f"F1 (phishing): {metrics['f1_phishing']:.4f} ({metrics['f1_phishing']*100:.1f}%)")
    print(f"AUC: {metrics['auc_score']:.4f} ({metrics['auc_score']*100:.1f}%)")
    print(f"Training Time: {metrics['training_time']:.4f} seconds")

    if (
        metrics['recall_phishing'] > best_recall or
        (
            np.isclose(metrics['recall_phishing'], best_recall) and
            metrics['f1_phishing'] > best_f1
        )
    ):
        best_recall = metrics['recall_phishing']
        best_f1 = metrics['f1_phishing']
        best_model_name = model_name
        best_model = model

if best_model is None:
    raise RuntimeError("No model was selected during training. Please check the dataset.")

print("\n" + "="*70)
print("Updated metrics:")
print("="*70)
for model_name, metrics in model_metrics.items():
    print(f"\n{model_name}:")
    print(f"  Accuracy: {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.1f}%)")
    print(f"  Recall (phishing): {metrics['recall_phishing']:.4f} ({metrics['recall_phishing']*100:.1f}%)")
    print(f"  F1 (phishing): {metrics['f1_phishing']:.4f} ({metrics['f1_phishing']*100:.1f}%)")
    print(f"  AUC: {metrics['auc_score']:.4f} ({metrics['auc_score']*100:.1f}%)")
    print(f"  Time (s): {metrics.get('training_time', 0):.4f}")

print("\n" + "-"*70)
print("Selected best-performing model:")
print(f"  • Model: {best_model_name}")
print(f"  • Recall (phishing): {best_recall:.4f}")
print(f"  • F1-score (phishing): {best_f1:.4f}")
if best_recall < 0.90:
    print("⚠️  Warning: Best model phishing recall is below the 0.90 target specified by the supervisor.")
else:
    print("✓ Best model meets the ≥ 0.90 phishing recall target.")

print("\nSaving model components...")
model_components = {
    'classifier': best_model,
    'numerical_scaler': scaler,
    'text_vectorizer': vectorizer,
    'feature_columns': feature_columns,
    'model_name': best_model_name,
    'best_model_metrics': model_metrics[best_model_name],
    'all_model_metrics': model_metrics,
    # Store all trained models so the extension can switch between them in real-time.
    'trained_models': models
}
joblib.dump(model_components, 'final_phishing_model.joblib')
print("✓ Model saved as 'final_phishing_model.joblib' successfully!")
