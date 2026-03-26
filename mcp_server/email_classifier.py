"""
Email Classifier Module
Handles email classification as phishing, malicious, spam, or legitimate.
Uses feature extraction and machine learning similar to URL classification.
"""

import re
import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional
from urllib.parse import urlparse
from scipy.sparse import hstack


class EmailClassifier:
    """Email classifier for detecting phishing, malicious, and spam emails"""

    # Classification categories
    LEGITIMATE = "legitimate"
    SPAM = "spam"
    PHISHING = "phishing"
    MALICIOUS = "malicious"

    def __init__(self, model_path: Optional[str] = None):
        """Initialize the email classifier"""
        if model_path is None:
            # Default to models directory
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, '..', 'models', 'email_classifier_model.joblib')

        self.model_path = model_path
        self.model_components = None

    async def load_model(self):
        """Load the trained model"""
        try:
            if os.path.exists(self.model_path):
                self.model_components = joblib.load(self.model_path)
                print(f"Email classifier model loaded from: {self.model_path}")
            else:
                print(f"Warning: Model file not found at {self.model_path}")
                print("Please train the model first using train_email_model.py")
                self.model_components = None
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model_components = None

    def extract_email_features(self, subject: str, body: str, sender: str,
                               headers: Dict = None, links: List[str] = None) -> Dict:
        """Extract features from email for classification"""
        headers = headers or {}
        links = links or []

        # Combine text for analysis
        full_text = f"{subject} {body}".lower()
        subject_lower = subject.lower()
        body_lower = body.lower()
        sender_lower = sender.lower()

        features = {}

        # === SUBJECT FEATURES ===
        features['subject_length'] = len(subject)
        features['subject_has_urgency'] = int(any(word in subject_lower for word in [
            'urgent', 'immediate', 'action required', 'respond now', 'act now', 'expire'
        ]))
        features['subject_has_reward'] = int(any(word in subject_lower for word in [
            'winner', 'prize', 'reward', 'free', 'won', 'congratulations'
        ]))
        features['subject_has_security'] = int(any(word in subject_lower for word in [
            'security', 'verify', 'confirm', 'alert', 'suspended', 'locked', 'update'
        ]))
        features['subject_all_caps_ratio'] = sum(1 for c in subject if c.isupper()) / len(subject) if len(subject) > 0 else 0
        features['subject_exclamation_count'] = subject.count('!')
        features['subject_question_count'] = subject.count('?')

        # === SENDER FEATURES ===
        features['sender_length'] = len(sender)
        features['sender_has_numbers'] = int(bool(re.search(r'\d', sender)))
        features['sender_suspicious_tld'] = int(any(tld in sender_lower for tld in [
            '.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top', '.xyz'
        ]))

        # Check if sender matches common legitimate domains
        legitimate_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
                            'icloud.com', 'aol.com', 'protonmail.com']
        features['sender_common_provider'] = int(any(domain in sender_lower for domain in legitimate_domains))

        # Check for brand impersonation in sender
        brand_names = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
                      'bank', 'visa', 'mastercard', 'ebay', 'netflix', 'adobe', 'wells',
                      'chase', 'irs', 'dhl', 'fedex', 'usps']
        features['sender_brand_impersonation'] = int(any(brand in sender_lower for brand in brand_names))

        # === BODY FEATURES ===
        features['body_length'] = len(body)
        features['body_word_count'] = len(body.split())

        # Phishing indicators
        phishing_keywords = [
            'verify', 'confirm', 'account', 'suspended', 'locked', 'expire',
            'update', 'login', 'password', 'click here', 'link', 'urgent',
            'immediate', 'secure', 'security', 'unusual activity', 'unauthorized'
        ]
        features['phishing_keyword_count'] = sum(1 for word in phishing_keywords if word in full_text)

        # Spam indicators
        spam_keywords = [
            'free', 'winner', 'prize', 'guaranteed', 'money back', 'no cost',
            'limited time', 'act now', 'order now', 'million', 'inheritance',
            'nigerian', 'prince', 'lottery', 'congratulations'
        ]
        features['spam_keyword_count'] = sum(1 for word in spam_keywords if word in full_text)

        # Malicious indicators
        malicious_keywords = [
            'malware', 'virus', 'trojan', 'ransomware', 'infection', 'bitcoin',
            'cryptocurrency', 'wallet', 'transfer', 'wire', 'western union'
        ]
        features['malicious_keyword_count'] = sum(1 for word in malicious_keywords if word in full_text)

        # === URL/LINK FEATURES ===
        features['link_count'] = len(links)

        if links:
            # Analyze URLs in the email
            suspicious_url_count = 0
            ip_url_count = 0
            shortened_url_count = 0

            for link in links:
                link_lower = link.lower()
                # Check for IP addresses
                if re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', link):
                    ip_url_count += 1

                # Check for URL shorteners
                shorteners = ['bit.ly', 'tinyurl', 'ow.ly', 't.co', 'goo.gl', 'short']
                if any(short in link_lower for short in shorteners):
                    shortened_url_count += 1

                # Check for suspicious TLDs
                suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top', '.xyz']
                if any(tld in link_lower for tld in suspicious_tlds):
                    suspicious_url_count += 1

            features['suspicious_url_count'] = suspicious_url_count
            features['ip_url_count'] = ip_url_count
            features['shortened_url_count'] = shortened_url_count
        else:
            features['suspicious_url_count'] = 0
            features['ip_url_count'] = 0
            features['shortened_url_count'] = 0

        # === TEXT ANALYSIS ===
        features['special_char_count'] = sum(1 for c in full_text if not c.isalnum() and not c.isspace())
        features['number_count'] = sum(1 for c in full_text if c.isdigit())
        features['uppercase_ratio'] = sum(1 for c in body if c.isupper()) / len(body) if len(body) > 0 else 0

        # Entropy (randomness) of text
        features['text_entropy'] = self._calculate_entropy(full_text)

        # === HEADER FEATURES ===
        features['has_reply_to'] = int('reply-to' in [k.lower() for k in headers.keys()])
        features['has_return_path'] = int('return-path' in [k.lower() for k in headers.keys()])

        # Check if reply-to differs from sender
        reply_to = headers.get('Reply-To', headers.get('reply-to', ''))
        features['reply_to_mismatch'] = int(reply_to != '' and reply_to.lower() != sender_lower)

        return features

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        length = len(text)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * np.log2(probability)

        return entropy

    async def classify(self, subject: str, body: str, sender: str,
                      headers: Dict = None, links: List[str] = None) -> Dict:
        """Classify an email and return detailed results"""

        # Extract features
        features_dict = self.extract_email_features(subject, body, sender, headers, links)

        # If model is not loaded, use rule-based classification
        if self.model_components is None:
            return self._rule_based_classification(features_dict, subject, body, sender)

        # Use ML model for classification
        return await self._ml_classification(features_dict, subject, body, sender)

    def _rule_based_classification(self, features: Dict, subject: str,
                                   body: str, sender: str) -> Dict:
        """Rule-based classification when ML model is not available"""

        # Calculate risk scores
        phishing_score = (
            features['phishing_keyword_count'] * 0.3 +
            features['sender_brand_impersonation'] * 0.4 +
            features['subject_has_security'] * 0.2 +
            features['suspicious_url_count'] * 0.1
        ) / 1.0

        spam_score = (
            features['spam_keyword_count'] * 0.4 +
            features['subject_has_reward'] * 0.3 +
            features['subject_all_caps_ratio'] * 0.2 +
            features['subject_exclamation_count'] * 0.1
        ) / 1.0

        malicious_score = (
            features['malicious_keyword_count'] * 0.5 +
            features['ip_url_count'] * 0.3 +
            features['shortened_url_count'] * 0.2
        ) / 1.0

        # Determine classification
        max_score = max(phishing_score, spam_score, malicious_score)

        if max_score < 0.3:
            classification = self.LEGITIMATE
            confidence = 1.0 - max_score
        elif phishing_score == max_score:
            classification = self.PHISHING
            confidence = min(0.95, phishing_score)
        elif spam_score == max_score:
            classification = self.SPAM
            confidence = min(0.95, spam_score)
        else:
            classification = self.MALICIOUS
            confidence = min(0.95, malicious_score)

        # Determine risk level
        if confidence > 0.8 and classification != self.LEGITIMATE:
            risk_level = "High"
        elif confidence > 0.5 and classification != self.LEGITIMATE:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "classification": classification,
            "confidence": round(confidence, 3),
            "risk_level": risk_level,
            "risk_scores": {
                "phishing": round(phishing_score, 3),
                "spam": round(spam_score, 3),
                "malicious": round(malicious_score, 3)
            },
            "features": features,
            "method": "rule-based",
            "warnings": self._generate_warnings(features, classification)
        }

    async def _ml_classification(self, features: Dict, subject: str,
                                body: str, sender: str) -> Dict:
        """ML-based classification using trained model"""

        classifier = self.model_components.get('classifier')
        numerical_scaler = self.model_components.get('numerical_scaler')
        text_vectorizer = self.model_components.get('text_vectorizer')
        feature_columns = self.model_components.get('feature_columns')

        # Prepare features
        feature_df = pd.DataFrame([features])

        # Ensure all expected columns are present
        for col in feature_columns:
            if col not in feature_df.columns:
                feature_df[col] = 0
        feature_df = feature_df[feature_columns]

        # Scale numerical features
        numerical_features = numerical_scaler.transform(feature_df)

        # Vectorize text (combine subject and body)
        text_content = f"{subject} {body}"
        text_features = text_vectorizer.transform([text_content])

        # Combine features
        combined_features = hstack([numerical_features, text_features])

        # Get prediction
        prediction = classifier.predict(combined_features)[0]
        probabilities = classifier.predict_proba(combined_features)[0]

        # Map prediction to classification
        class_names = self.model_components.get('class_names',
                                                [self.LEGITIMATE, self.SPAM, self.PHISHING, self.MALICIOUS])
        classification = class_names[prediction]
        confidence = float(probabilities[prediction])

        # Determine risk level
        if confidence > 0.8 and classification != self.LEGITIMATE:
            risk_level = "High"
        elif confidence > 0.5 and classification != self.LEGITIMATE:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return {
            "classification": classification,
            "confidence": round(confidence, 3),
            "risk_level": risk_level,
            "probabilities": {
                class_names[i]: round(float(probabilities[i]), 3)
                for i in range(len(probabilities))
            },
            "features": features,
            "method": "machine-learning",
            "model_name": self.model_components.get('model_name', 'Unknown'),
            "warnings": self._generate_warnings(features, classification)
        }

    def _generate_warnings(self, features: Dict, classification: str) -> List[str]:
        """Generate human-readable warnings based on features"""
        warnings = []

        if features.get('sender_brand_impersonation', 0) > 0:
            warnings.append("Sender address contains a brand name - possible impersonation")

        if features.get('subject_has_urgency', 0) > 0:
            warnings.append("Subject contains urgent language")

        if features.get('phishing_keyword_count', 0) > 3:
            warnings.append("Multiple phishing-related keywords detected")

        if features.get('suspicious_url_count', 0) > 0:
            warnings.append("Email contains suspicious URLs")

        if features.get('ip_url_count', 0) > 0:
            warnings.append("Email contains URLs with IP addresses instead of domains")

        if features.get('reply_to_mismatch', 0) > 0:
            warnings.append("Reply-To address differs from sender")

        if features.get('subject_all_caps_ratio', 0) > 0.5:
            warnings.append("Subject is mostly in capital letters")

        if classification != self.LEGITIMATE and not warnings:
            warnings.append("Email exhibits suspicious characteristics")

        return warnings
