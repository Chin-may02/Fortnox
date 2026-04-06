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

try:
    from .email_features import extract_email_features
    from .email_model import predict_email_with_model
except ImportError:
    from email_features import extract_email_features
    from email_model import predict_email_with_model

app = Flask(__name__)
CORS(app)

DEFAULT_DECISION_THRESHOLD = 0.5
URL_PHISHING_THRESHOLD = 0.5
SUSPICIOUS_EMAIL_URL_THRESHOLD = 0.6
EMAIL_MEDIUM_RISK_THRESHOLD = 0.45
EMAIL_HIGH_RISK_THRESHOLD = 0.75


def clamp(value, minimum=0.0, maximum=1.0):
    return max(minimum, min(maximum, value))


def normalize_model_metrics(metrics):
    metrics = metrics or {}
    return {
        'accuracy': float(metrics.get('accuracy', 0)),
        'recall_phishing': float(metrics.get('recall_phishing', 0)),
        'f1_phishing': float(metrics.get('f1_phishing', 0)),
        'precision_phishing': float(metrics.get('precision_phishing', 0)),
        'auc': float(metrics.get('auc_score', 0))
    }


def get_url_risk_response(prediction_label, risk_score):
    if prediction_label == "safe":
        return "Low Risk", "This URL appears to be safe."
    if risk_score >= URL_PHISHING_THRESHOLD:
        return "High Risk", "High risk detected - site likely phishing or vulnerable."
    return "Low Risk", "Low risk detected - site appears safer."


def get_email_risk_response(risk_score):
    if risk_score >= EMAIL_HIGH_RISK_THRESHOLD:
        return "phishing", "High Risk", "This email shows multiple signs of a phishing attempt."
    if risk_score >= EMAIL_MEDIUM_RISK_THRESHOLD:
        return "suspicious", "Medium Risk", "This email contains some suspicious elements. Exercise caution."
    return "safe", "Low Risk", "This email appears to be safe."


def get_email_model_metadata(email_model_result):
    return {
        'available': bool(email_model_result.get('available')),
        'name': email_model_result.get('model_name', 'BERT Email Classifier'),
        'riskScore': float(email_model_result.get('risk_score', 0.0)),
        'probabilities': email_model_result.get('probabilities', [1.0, 0.0]),
        'decisionThreshold': float(email_model_result.get('decision_threshold', DEFAULT_DECISION_THRESHOLD)),
        'tokenCount': int(email_model_result.get('token_count', 0)),
        'error': email_model_result.get('error')
    }


def normalize_url(url):
    if pd.isna(url):
        return ""
    cleaned_url = str(url).lower().strip()
    cleaned_url = re.sub(r'^https?://', '', cleaned_url)
    cleaned_url = re.sub(r'^www\.', '', cleaned_url)
    return cleaned_url.rstrip('/')

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
        parsed = urlparse('http://' + normalized_url)
        domain = parsed.netloc or normalized_url.split('/')[0]
        path = parsed.path
        query = parsed.query
    except Exception:
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
    
    if normalized_url:
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


def get_url_probabilities(classifier, combined_features):
    try:
        return classifier.predict_proba(combined_features)[0]
    except AttributeError:
        decision = np.asarray(classifier.decision_function(combined_features)).reshape(-1)
        if decision.size:
            phishing_prob = expit(float(decision[0]))
            safe_prob = 1.0 - phishing_prob
            probabilities = np.array([safe_prob, phishing_prob], dtype=float)
            probabilities = np.clip(probabilities, 0.0, 1.0)
            return probabilities / probabilities.sum()

        raw_prediction = classifier.predict(combined_features)[0]
        return np.array([0.1, 0.9], dtype=float) if raw_prediction == 1 else np.array([0.9, 0.1], dtype=float)

def predict_single_url(url, components, requested_model_name=None):
    """Prepares features and predicts a single URL using the selected model."""
    if components is None:
        return 1, [0.0, 1.0], ["model", "not", "loaded"], None, DEFAULT_DECISION_THRESHOLD

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
        return 1, [0.0, 1.0], ["model", "not", "available"], active_model_name, DEFAULT_DECISION_THRESHOLD

    features_dict = extract_url_features(url)
    feature_df = pd.DataFrame([features_dict]).reindex(columns=feature_columns, fill_value=0)
    numerical_features = numerical_scaler.transform(feature_df)
    
    normalized_url = normalize_url(url)
    text_features = text_vectorizer.transform([normalized_url])
    
    combined_features = hstack([numerical_features, text_features])
    
    model_thresholds = components.get('model_thresholds') or {}
    decision_threshold = float(model_thresholds.get(active_model_name, components.get('decision_threshold', DEFAULT_DECISION_THRESHOLD)))
    decision_threshold = clamp(decision_threshold, 0.05, 0.99)

    probabilities = get_url_probabilities(classifier, combined_features)

    phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else 1.0
    prediction = 1 if phishing_prob >= decision_threshold else 0
    tokens = text_vectorizer.build_analyzer()(normalized_url)

    return int(prediction), probabilities.tolist(), tokens, active_model_name, decision_threshold


def analyze_email_urls(extracted_urls):
    """Analyze URLs embedded in an email using the existing URL classifier."""
    if model_components is None:
        return [], 0, 0.0

    url_analysis = []
    suspicious_url_count = 0
    max_url_risk = 0.0

    for url in extracted_urls[:10]:
        try:
            _, url_probabilities, _, _, _ = predict_single_url(url, model_components)
            url_risk = float(url_probabilities[1])
            max_url_risk = max(max_url_risk, url_risk)

            url_analysis.append({
                'url': url,
                'risk': url_risk,
                'classification': 'phishing' if url_risk >= URL_PHISHING_THRESHOLD else 'safe'
            })

            if url_risk >= SUSPICIOUS_EMAIL_URL_THRESHOLD:
                suspicious_url_count += 1
        except Exception as e:
            print(f"Error analyzing URL {url}: {e}")

    return url_analysis, suspicious_url_count, max_url_risk


def calculate_email_heuristic_risk(email_features, suspicious_url_count, max_url_risk):
    """
    Preserve the existing feature-based email signals so BERT can be combined
    with explainable metadata and URL evidence.
    """
    heuristic_score = 0.0
    risk_factors = []

    if email_features.get('sender_is_freemail', 0) == 1:
        heuristic_score += 0.1
    if email_features.get('sender_has_suspicious_tld', 0) == 1:
        heuristic_score += 0.15
        risk_factors.append('Suspicious sender domain')
    if email_features.get('reply_to_mismatch', 0) == 1:
        heuristic_score += 0.2
        risk_factors.append('Reply-to address mismatch')
    if email_features.get('from_name_has_brand', 0) == 1:
        heuristic_score += 0.15
        risk_factors.append('Brand impersonation attempt')

    urgency_count = email_features.get('subject_urgency_count', 0)
    if urgency_count > 0:
        heuristic_score += min(0.2, urgency_count * 0.1)
        risk_factors.append(f'Urgency keywords detected ({urgency_count})')

    financial_count = email_features.get('subject_financial_count', 0)
    if financial_count > 0:
        heuristic_score += min(0.15, financial_count * 0.08)
        risk_factors.append(f'Financial keywords detected ({financial_count})')

    if email_features.get('body_urgency_count', 0) > 2:
        heuristic_score += 0.15
        risk_factors.append('High urgency in email body')

    if email_features.get('body_caps_ratio', 0) > 0.3:
        heuristic_score += 0.1
        risk_factors.append('Excessive capitalization')

    if suspicious_url_count > 0:
        heuristic_score += min(0.3, suspicious_url_count * 0.15)
        risk_factors.append(f'Suspicious URLs detected ({suspicious_url_count})')

    heuristic_score = max(heuristic_score, max_url_risk * 0.7)

    if email_features.get('has_suspicious_attachment', 0) == 1:
        heuristic_score += 0.25
        risk_factors.append('Suspicious attachment detected')

    if email_features.get('html_has_form', 0) == 1 and email_features.get('html_has_input', 0) == 1:
        heuristic_score += 0.2
        risk_factors.append('Email contains login form')

    if email_features.get('has_auth_failure', 0) == 1:
        heuristic_score += 0.15
        risk_factors.append('Email authentication failed')

    return min(1.0, heuristic_score), risk_factors


def combine_email_risk_scores(email_model_result, heuristic_score, max_url_risk, email_features):
    """Blend BERT email inference with the existing feature and URL signals."""
    model_risk = float(email_model_result.get('risk_score', 0.0))
    model_available = bool(email_model_result.get('available'))

    if model_available:
        combined_risk = max(model_risk, (0.65 * model_risk) + (0.35 * heuristic_score))
    else:
        combined_risk = heuristic_score

    if max_url_risk > 0:
        if model_available:
            combined_risk = max(combined_risk, (0.55 * model_risk) + (0.45 * max_url_risk), max_url_risk * 0.9)
        else:
            combined_risk = max(combined_risk, max_url_risk * 0.9)

    strong_signal_bonus = 0.0
    if email_features.get('has_suspicious_attachment', 0) == 1:
        strong_signal_bonus += 0.08
    if email_features.get('html_has_form', 0) == 1 and email_features.get('html_has_input', 0) == 1:
        strong_signal_bonus += 0.05
    if email_features.get('has_auth_failure', 0) == 1:
        strong_signal_bonus += 0.05

    return min(1.0, max(0.0, combined_risk + strong_signal_bonus))

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
    risk_score = clamp(float(probabilities[1]))
    risk_level, message = get_url_risk_response(prediction_label, risk_score)
    
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
        response_payload['modelMetrics'] = normalize_model_metrics(selected_metrics)
        response_payload['modelComparisons'] = {
            model_name: normalize_model_metrics(metrics)
            for model_name, metrics in all_model_metrics.items()
        }

    return jsonify(response_payload)


@app.route('/check_email', methods=['POST'])
def check_email():
    """
    Endpoint for email phishing classification using BERT text inference
    combined with existing explainable feature and URL analysis.

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

        url_analysis, suspicious_url_count, max_url_risk = analyze_email_urls(extracted_urls)
        heuristic_risk_score, risk_factors = calculate_email_heuristic_risk(
            email_features,
            suspicious_url_count,
            max_url_risk
        )
        email_model_result = predict_email_with_model(data, extracted_urls)

        model_risk_score = float(email_model_result.get('risk_score', 0.0))
        if email_model_result.get('available'):
            if model_risk_score >= 0.75:
                risk_factors.insert(0, 'BERT email model detected phishing-like wording')
            elif model_risk_score >= 0.45:
                risk_factors.insert(0, 'BERT email model detected suspicious wording')

        risk_score = combine_email_risk_scores(
            email_model_result,
            heuristic_risk_score,
            max_url_risk,
            email_features
        )

        prediction, risk_level, message = get_email_risk_response(risk_score)

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
            'totalUrls': len(extracted_urls),
            'emailModel': get_email_model_metadata(email_model_result)
        }

        if email_model_result.get('available'):
            response_payload['modelName'] = email_model_result.get('model_name', 'BERT Email Classifier')
            response_payload['modelMetrics'] = {
                'type': 'bert-hybrid',
                'features_analyzed': len(email_features),
                'urls_analyzed': len(url_analysis),
                'decision_threshold': float(email_model_result.get('decision_threshold', DEFAULT_DECISION_THRESHOLD))
            }
        else:
            response_payload['modelName'] = 'Email Heuristic Fallback'
            response_payload['modelMetrics'] = {
                'type': 'rule-based-fallback',
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
