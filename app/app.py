import pandas as pd
import joblib
import re
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse
from scipy.sparse import hstack
from scipy.special import expit
import os

app = Flask(__name__)
CORS(app)

def normalize_url(url):
    if pd.isna(url):
        return ""
    url = str(url).lower().strip()
    url = re.sub(r'^https?://', '', url)
    url = re.sub(r'^www\.', '', url)
    url = url.rstrip('/')
    return url

def calculate_entropy(text):
    if not text:
        return 0
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    length = len(text)
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * np.log2(probability)
    return entropy

def extract_url_features(url):
    normalized_url = normalize_url(url)
    original_url = str(url).lower()
    features = {}
    try:
        parse_url = 'http://' + normalized_url
        parsed = urlparse(parse_url)
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

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.environ.get('MODEL_FILE', '../models/Phishing_final.joblib')
MODEL_PATH = os.path.join(MODEL_DIR, MODEL_FILE)

model_components = None
try:
    model_components = joblib.load(MODEL_PATH)
    print(f"Model components from '{MODEL_FILE}' loaded successfully.")
except FileNotFoundError:
    print(f"FATAL ERROR: Model file '{MODEL_FILE}' not found.")
    print("Please run the training script to generate it.")
except Exception as e:
    print(f"FATAL ERROR: Could not load model. {e}")

def predict_single_url(url, components, requested_model_name=None):
    """Prepares features and predicts a single URL using the selected model."""
    if components is None:
        return 1, [0.0, 1.0], ["model", "not", "loaded"], None

    # Default to the primary classifier
    classifier = components.get('classifier')

    # If multiple trained models are available (saved during training), allow selection by name
    trained_models = components.get('trained_models') or {}
    if requested_model_name and requested_model_name in trained_models:
        classifier = trained_models[requested_model_name]
        active_model_name = requested_model_name
    else:
        active_model_name = components.get('model_name') or (classifier.__class__.__name__ if classifier else None)

    numerical_scaler = components.get('numerical_scaler')
    text_vectorizer = components.get('text_vectorizer')
    feature_columns = components.get('feature_columns')

    if classifier is None or numerical_scaler is None or text_vectorizer is None or feature_columns is None:
        return 1, [0.0, 1.0], ["model", "not", "available"], active_model_name

    features_dict = extract_url_features(url)
    feature_df = pd.DataFrame([features_dict])
    
    for col in feature_columns:
        if col not in feature_df.columns:
            feature_df[col] = 0
    feature_df = feature_df[feature_columns]
    
    numerical_features = numerical_scaler.transform(feature_df)
    
    normalized_url = normalize_url(url)
    text_features = text_vectorizer.transform([normalized_url])
    
    combined_features = hstack([numerical_features, text_features])
    
    prediction = classifier.predict(combined_features)[0]

    # Get probabilities - always use actual model probabilities for live display
    try:
        probabilities = classifier.predict_proba(combined_features)[0]
    except AttributeError:
        # For LinearSVC, use decision_function and convert to probabilities
        decision = classifier.decision_function(combined_features)
        if isinstance(decision, np.ndarray):
            # Flatten if needed
            if decision.ndim > 1:
                decision = decision.flatten()
            
            # Convert decision scores to probabilities using sigmoid (expit)
            # This gives realistic probability distributions instead of binary [0,1]
            decision_score = float(decision[0] if len(decision) == 1 else decision[0])
            # Use sigmoid to convert to probability - this gives smooth probabilities
            phishing_prob = expit(decision_score)
            safe_prob = 1.0 - phishing_prob
            # Ensure probabilities are valid and sum to 1
            probabilities = np.array([safe_prob, phishing_prob], dtype=float)
            probabilities = np.clip(probabilities, 0.0, 1.0)  # Ensure in valid range
            probabilities = probabilities / probabilities.sum()  # Normalize to sum to 1
        else:
            # Fallback: use prediction directly but still show some probability
            if prediction == 1:
                probabilities = np.array([0.1, 0.9], dtype=float)  # Phishing with some uncertainty
            else:
                probabilities = np.array([0.9, 0.1], dtype=float)  # Safe with some uncertainty

    tokens = text_vectorizer.build_analyzer()(normalized_url)

    return int(prediction), probabilities.tolist(), tokens, active_model_name

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided or invalid format'}), 400
    
    url_to_check = data.get('url', '')
    if not url_to_check:
        return jsonify({'error': 'URL cannot be empty'}), 400

    # Always run model prediction only (no whitelist overrides).
    requested_model_name = data.get('modelName')
    prediction, probabilities, tokens, used_model_name = predict_single_url(
        url_to_check,
        model_components,
        requested_model_name
    )

    prediction_label = "phishing" if prediction == 1 else "safe"
    risk_score = float(probabilities[1])
    risk_score = max(0.0, min(1.0, risk_score))

    if prediction_label == "safe":
        risk_level = "Low Risk"
        message = "This URL appears to be safe."
    elif risk_score >= 0.50:
        risk_level = "High Risk"
        message = "High risk detected - site likely phishing or vulnerable."
    else:
        risk_level = "Low Risk"
        message = "Low risk detected - site appears safer."
    
    # Build response payload
    response_payload = {
        'url': url_to_check,
        'prediction': prediction_label,
        'message': message,
        'probabilities': probabilities,
        'tokens': tokens[:20] if tokens else [],
        'riskLevel': risk_level,
        'riskScore': risk_score,
        'riskDescription': message
    }
    
    # Include model metrics and comparisons for UI display
    if model_components is not None:
        active_model_name = used_model_name or model_components.get('model_name') or 'Linear SVM'
        response_payload['modelName'] = active_model_name

        all_model_metrics = model_components.get('all_model_metrics', {})
        selected_metrics = all_model_metrics.get(active_model_name) or model_components.get('best_model_metrics', {})
        normalized_selected_metrics = {
            'accuracy': float(selected_metrics.get('accuracy', 0)),
            'recall_phishing': float(selected_metrics.get('recall_phishing', 0)),
            'f1_phishing': float(selected_metrics.get('f1_phishing', 0)),
            'precision_phishing': float(selected_metrics.get('precision_phishing', 0)),
            'auc': float(selected_metrics.get('auc_score', 0))
        }
        response_payload['modelMetrics'] = normalized_selected_metrics

        model_comparisons = {}
        for model_name, metrics in all_model_metrics.items():
            model_comparisons[model_name] = {
                'accuracy': float(metrics.get('accuracy', 0)),
                'recall_phishing': float(metrics.get('recall_phishing', 0)),
                'f1_phishing': float(metrics.get('f1_phishing', 0)),
                'precision_phishing': float(metrics.get('precision_phishing', 0)),
                'auc': float(metrics.get('auc_score', 0))
            }
        response_payload['modelComparisons'] = model_comparisons

    return jsonify(response_payload)

if __name__ == '__main__':
    if model_components is None:
        print("\nWARNING: Server is starting WITHOUT a loaded model. Predictions will fail.")
    print("\nFlask server is running. Ready to receive requests.")
    app.run(debug=True, port=5000)
