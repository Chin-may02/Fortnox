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

# Import email feature extraction
from email_features import extract_email_features, get_email_feature_columns

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
MODEL_FILE = os.environ.get('MODEL_FILE', '../models/final_phishing_model.joblib')
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
        return 1, [0.0, 1.0], ["model", "not", "loaded"], None, 0.5

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
        return 1, [0.0, 1.0], ["model", "not", "available"], active_model_name, 0.5

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
    
    model_thresholds = components.get('model_thresholds') or {}
    decision_threshold = float(model_thresholds.get(active_model_name, components.get('decision_threshold', 0.5)))
    decision_threshold = max(0.05, min(0.99, decision_threshold))

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
            raw_prediction = classifier.predict(combined_features)[0]
            if raw_prediction == 1:
                probabilities = np.array([0.1, 0.9], dtype=float)  # Phishing with some uncertainty
            else:
                probabilities = np.array([0.9, 0.1], dtype=float)  # Safe with some uncertainty

    phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else 1.0
    prediction = 1 if phishing_prob >= decision_threshold else 0
    tokens = text_vectorizer.build_analyzer()(normalized_url)

    return int(prediction), probabilities.tolist(), tokens, active_model_name, decision_threshold

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'No URL provided or invalid format'}), 400
    
    url_to_check = data.get('url', '')
    if not isinstance(url_to_check, str) or not url_to_check.strip():
        return jsonify({'error': 'URL must be a non-empty string'}), 400

    # Always run model prediction only (no whitelist overrides).
    requested_model_name = data.get('modelName')
    prediction, probabilities, tokens, used_model_name, decision_threshold = predict_single_url(
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
        'riskDescription': message,
        'decisionThreshold': float(decision_threshold)
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


@app.route('/check_email', methods=['POST'])
def check_email():
    """
    Endpoint for email phishing classification.

    Expected JSON payload:
    {
        "from_email": "sender@example.com",
        "from_name": "John Doe",
        "subject": "Email subject",
        "body_text": "Email body content",
        "body_html": "<html>...</html>",  // optional
        "reply_to": "reply@example.com",  // optional
        "to_email": "recipient@example.com",  // optional
        "headers": {...},  // optional
        "attachments": ["file1.pdf", "file2.doc"],  // optional
        "urls": ["http://example.com"]  // optional, will be extracted if not provided
    }

    Returns:
    {
        "prediction": "safe" | "phishing",
        "riskScore": 0.0-1.0,
        "riskLevel": "Low Risk" | "Medium Risk" | "High Risk",
        "probabilities": [safe_prob, phishing_prob],
        "emailFeatures": {...},
        "urlAnalysis": [...],  // Analysis of extracted URLs
        "message": "...",
        "modelName": "...",
        "modelMetrics": {...}
    }
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Validate required fields
    required_fields = ['from_email', 'subject', 'body_text']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400

    try:
        # Extract email features
        email_features = extract_email_features(data)
        extracted_urls = email_features.pop('extracted_urls', [])

        # Analyze extracted URLs using existing URL classifier
        url_analysis = []
        suspicious_url_count = 0
        max_url_risk = 0.0

        for url in extracted_urls[:10]:  # Limit to first 10 URLs to avoid overload
            try:
                _, url_probabilities, _, _, _ = predict_single_url(url, model_components)
                url_risk = float(url_probabilities[1])
                max_url_risk = max(max_url_risk, url_risk)

                url_analysis.append({
                    'url': url,
                    'risk': url_risk,
                    'classification': 'phishing' if url_risk >= 0.5 else 'safe'
                })

                if url_risk >= 0.6:
                    suspicious_url_count += 1
            except Exception as e:
                print(f"Error analyzing URL {url}: {e}")

        # Calculate email risk score based on features and URL analysis
        # This is a simple heuristic - could be replaced with a trained model
        risk_score = 0.0
        risk_factors = []

        # Sender-based risk
        if email_features.get('sender_is_freemail', 0) == 1:
            risk_score += 0.1
        if email_features.get('sender_has_suspicious_tld', 0) == 1:
            risk_score += 0.15
            risk_factors.append('Suspicious sender domain')
        if email_features.get('reply_to_mismatch', 0) == 1:
            risk_score += 0.2
            risk_factors.append('Reply-to address mismatch')
        if email_features.get('from_name_has_brand', 0) == 1:
            risk_score += 0.15
            risk_factors.append('Brand impersonation attempt')

        # Subject-based risk
        urgency_count = email_features.get('subject_urgency_count', 0)
        if urgency_count > 0:
            risk_score += min(0.2, urgency_count * 0.1)
            risk_factors.append(f'Urgency keywords detected ({urgency_count})')

        financial_count = email_features.get('subject_financial_count', 0)
        if financial_count > 0:
            risk_score += min(0.15, financial_count * 0.08)
            risk_factors.append(f'Financial keywords detected ({financial_count})')

        # Body-based risk
        if email_features.get('body_urgency_count', 0) > 2:
            risk_score += 0.15
            risk_factors.append('High urgency in email body')

        if email_features.get('body_caps_ratio', 0) > 0.3:
            risk_score += 0.1
            risk_factors.append('Excessive capitalization')

        # URL-based risk
        if suspicious_url_count > 0:
            risk_score += min(0.3, suspicious_url_count * 0.15)
            risk_factors.append(f'Suspicious URLs detected ({suspicious_url_count})')

        # Incorporate max URL risk
        risk_score = max(risk_score, max_url_risk * 0.7)

        # Attachment risk
        if email_features.get('has_suspicious_attachment', 0) == 1:
            risk_score += 0.25
            risk_factors.append('Suspicious attachment detected')

        # HTML form risk (phishing pages)
        if email_features.get('html_has_form', 0) == 1 and email_features.get('html_has_input', 0) == 1:
            risk_score += 0.2
            risk_factors.append('Email contains login form')

        # Authentication failure
        if email_features.get('has_auth_failure', 0) == 1:
            risk_score += 0.15
            risk_factors.append('Email authentication failed')

        # Normalize risk score to 0-1 range
        risk_score = min(1.0, risk_score)

        # Determine risk level and prediction
        if risk_score >= 0.65:
            risk_level = "High Risk"
            prediction = "phishing"
            message = "This email shows multiple signs of a phishing attempt."
        elif risk_score >= 0.4:
            risk_level = "Medium Risk"
            prediction = "suspicious"
            message = "This email contains some suspicious elements. Exercise caution."
        else:
            risk_level = "Low Risk"
            prediction = "safe"
            message = "This email appears to be safe."

        # Convert phishing probability for consistency with URL classifier
        phishing_prob = risk_score
        safe_prob = 1.0 - risk_score

        # Build response
        response_payload = {
            'prediction': prediction,
            'message': message,
            'probabilities': [float(safe_prob), float(phishing_prob)],
            'riskLevel': risk_level,
            'riskScore': float(risk_score),
            'riskFactors': risk_factors,
            'emailFeatures': email_features,
            'urlAnalysis': url_analysis,
            'suspiciousUrlCount': suspicious_url_count,
            'totalUrls': len(extracted_urls)
        }

        # Include model info for consistency
        if model_components is not None:
            active_model_name = model_components.get('model_name', 'Email Heuristic Classifier')
            response_payload['modelName'] = active_model_name

            # For email, we're using heuristics, so provide appropriate metrics
            response_payload['modelMetrics'] = {
                'type': 'rule-based',
                'features_analyzed': len(email_features),
                'urls_analyzed': len(url_analysis)
            }

        return jsonify(response_payload)

    except Exception as e:
        return jsonify({'error': f'Error processing email: {str(e)}'}), 500


if __name__ == '__main__':
    if model_components is None:
        print("\nWARNING: Server is starting WITHOUT a loaded model. Predictions will fail.")
    print("\nFlask server is running. Ready to receive requests.")
    app.run(debug=os.environ.get('FLASK_DEBUG', '0') == '1', port=5000)
