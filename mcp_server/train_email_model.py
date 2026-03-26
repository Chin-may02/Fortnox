"""
Email Classifier Training Script
Trains a machine learning model to classify emails as legitimate, spam, phishing, or malicious.
"""

import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from scipy.sparse import hstack
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import os
import sys

# Add parent directory to path to import email_classifier
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from email_classifier import EmailClassifier


def load_email_dataset(dataset_path: str) -> pd.DataFrame:
    """Load email dataset from CSV file"""
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        print("Creating a sample dataset for demonstration...")
        return create_sample_dataset()

    df = pd.read_csv(dataset_path)
    print(f"Loaded {len(df)} emails from {dataset_path}")
    return df


def create_sample_dataset() -> pd.DataFrame:
    """Create a sample email dataset for demonstration"""
    print("Creating sample email dataset...")

    # Sample legitimate emails
    legitimate_emails = [
        {
            "subject": "Meeting tomorrow at 2 PM",
            "body": "Hi team, just a reminder about our project meeting tomorrow at 2 PM in conference room A. Please bring your status updates.",
            "sender": "manager@company.com",
            "label": "legitimate"
        },
        {
            "subject": "Your order has been shipped",
            "body": "Thank you for your order. Your package has been shipped and will arrive in 3-5 business days. Track your order with code: ABC123.",
            "sender": "orders@amazon.com",
            "label": "legitimate"
        },
        {
            "subject": "Weekly newsletter",
            "body": "Here are this week's top stories and updates from our blog. Enjoy reading!",
            "sender": "newsletter@techblog.com",
            "label": "legitimate"
        }
    ]

    # Sample phishing emails
    phishing_emails = [
        {
            "subject": "URGENT: Verify your account now!",
            "body": "Your account has been suspended due to unusual activity. Click here to verify your identity immediately: http://192.168.1.1/verify",
            "sender": "security@paypa1.com",
            "label": "phishing"
        },
        {
            "subject": "Security Alert - Action Required",
            "body": "We detected suspicious login attempts. Please confirm your password by clicking this link: http://bit.ly/confirm123",
            "sender": "security@amaz0n-security.tk",
            "label": "phishing"
        },
        {
            "subject": "Your PayPal account has been limited",
            "body": "Dear customer, your PayPal account has been limited. Click here to restore access: http://paypal-secure.cc/restore",
            "sender": "no-reply@paypal-security.xyz",
            "label": "phishing"
        }
    ]

    # Sample spam emails
    spam_emails = [
        {
            "subject": "Congratulations! You've won $1,000,000!!!",
            "body": "You are the lucky winner of our million dollar prize! Act now to claim your reward. No cost to you, 100% guaranteed!",
            "sender": "lottery@winner-prize.com",
            "label": "spam"
        },
        {
            "subject": "FREE iPhone 15 - Limited Time Offer!",
            "body": "Get your FREE iPhone 15 now! Click here before this amazing offer expires. Act now! Limited time only!",
            "sender": "offers@free-phones.top",
            "label": "spam"
        },
        {
            "subject": "Lose 50 pounds in 2 weeks - Guaranteed!",
            "body": "Amazing weight loss pills! Guaranteed results or money back. Order now and get 50% off!",
            "sender": "sales@miracle-pills.com",
            "label": "spam"
        }
    ]

    # Sample malicious emails
    malicious_emails = [
        {
            "subject": "Invoice Attached - Please Review",
            "body": "Please review the attached invoice. Download here: http://192.168.1.1/invoice.exe. Your immediate attention is required.",
            "sender": "billing@company-invoice.ml",
            "label": "malicious"
        },
        {
            "subject": "Your system has been infected",
            "body": "Your computer has been infected with ransomware. Pay 1 Bitcoin to recover your files. Send payment to wallet: ABC123XYZ.",
            "sender": "hacker@encrypted.cc",
            "label": "malicious"
        }
    ]

    # Combine all emails
    all_emails = legitimate_emails * 5 + phishing_emails * 5 + spam_emails * 5 + malicious_emails * 5

    df = pd.DataFrame(all_emails)
    print(f"Created sample dataset with {len(df)} emails")
    print(f"Label distribution:\n{df['label'].value_counts()}")

    return df


def extract_features_from_dataset(df: pd.DataFrame) -> tuple:
    """Extract features from email dataset"""
    classifier = EmailClassifier()

    features_list = []
    text_list = []

    print("Extracting features from emails...")

    for _, row in df.iterrows():
        subject = str(row.get('subject', ''))
        body = str(row.get('body', ''))
        sender = str(row.get('sender', ''))

        # Extract features
        features = classifier.extract_email_features(subject, body, sender)
        features_list.append(features)

        # Combine text for TF-IDF
        text_list.append(f"{subject} {body}")

    features_df = pd.DataFrame(features_list)
    print(f"Extracted {len(features_df.columns)} numerical features")

    return features_df, text_list


def train_models(X_train, X_test, y_train, y_test, feature_columns, text_vectorizer,
                numerical_scaler, label_encoder):
    """Train multiple models and select the best one"""

    print("\n" + "=" * 60)
    print("TRAINING MULTIPLE MODELS")
    print("=" * 60)

    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
        "XGBoost": XGBClassifier(n_estimators=100, random_state=42, eval_metric='mlogloss')
    }

    best_model = None
    best_accuracy = 0
    best_model_name = None
    all_results = {}

    for name, model in models.items():
        print(f"\n--- Training {name} ---")
        model.fit(X_train, y_train)

        # Predictions
        y_pred = model.predict(X_test)

        # Metrics
        accuracy = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {accuracy:.4f}")

        print("\nClassification Report:")
        print(classification_report(y_test, y_pred,
                                   target_names=label_encoder.classes_))

        print("\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        all_results[name] = {
            "accuracy": accuracy,
            "model": model
        }

        if accuracy > best_accuracy:
            best_accuracy = accuracy
            best_model = model
            best_model_name = name

    print("\n" + "=" * 60)
    print(f"BEST MODEL: {best_model_name} (Accuracy: {best_accuracy:.4f})")
    print("=" * 60)

    return best_model, best_model_name, all_results


def main():
    """Main training function"""

    # Paths
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    DATASET_PATH = os.path.join(SCRIPT_DIR, '..', 'data', 'email_dataset.csv')
    MODEL_DIR = os.path.join(SCRIPT_DIR, '..', 'models')
    MODEL_PATH = os.path.join(MODEL_DIR, 'email_classifier_model.joblib')

    # Create models directory if it doesn't exist
    os.makedirs(MODEL_DIR, exist_ok=True)

    print("=" * 60)
    print("EMAIL CLASSIFIER TRAINING")
    print("=" * 60)

    # Load dataset
    df = load_email_dataset(DATASET_PATH)

    # Extract features
    features_df, text_list = extract_features_from_dataset(df)

    # Encode labels
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['label'])
    print(f"\nClass mapping: {dict(enumerate(label_encoder.classes_))}")

    # Split data
    X_train_num, X_test_num, y_train, y_test, text_train, text_test = train_test_split(
        features_df, y, text_list, test_size=0.2, random_state=42, stratify=y
    )

    print(f"\nTraining set size: {len(X_train_num)}")
    print(f"Test set size: {len(X_test_num)}")

    # Scale numerical features
    numerical_scaler = StandardScaler()
    X_train_num_scaled = numerical_scaler.fit_transform(X_train_num)
    X_test_num_scaled = numerical_scaler.transform(X_test_num)

    # Vectorize text
    text_vectorizer = TfidfVectorizer(
        max_features=1000,
        ngram_range=(1, 2),
        stop_words='english'
    )
    X_train_text = text_vectorizer.fit_transform(text_train)
    X_test_text = text_vectorizer.transform(text_test)

    print(f"Text features: {X_train_text.shape[1]}")
    print(f"Numerical features: {X_train_num_scaled.shape[1]}")

    # Combine features
    X_train = hstack([X_train_num_scaled, X_train_text])
    X_test = hstack([X_test_num_scaled, X_test_text])

    print(f"Combined features shape: {X_train.shape}")

    # Train models
    best_model, best_model_name, all_results = train_models(
        X_train, X_test, y_train, y_test,
        features_df.columns.tolist(),
        text_vectorizer,
        numerical_scaler,
        label_encoder
    )

    # Save model
    model_components = {
        'classifier': best_model,
        'numerical_scaler': numerical_scaler,
        'text_vectorizer': text_vectorizer,
        'feature_columns': features_df.columns.tolist(),
        'label_encoder': label_encoder,
        'class_names': label_encoder.classes_.tolist(),
        'model_name': best_model_name,
        'all_results': {name: {"accuracy": res["accuracy"]} for name, res in all_results.items()}
    }

    joblib.dump(model_components, MODEL_PATH)
    print(f"\n✓ Model saved to: {MODEL_PATH}")

    # Test the saved model
    print("\n" + "=" * 60)
    print("TESTING SAVED MODEL")
    print("=" * 60)

    test_emails = [
        {
            "subject": "Team meeting tomorrow",
            "body": "Hi everyone, we have our weekly team meeting tomorrow at 10 AM.",
            "sender": "manager@company.com"
        },
        {
            "subject": "URGENT: Verify your PayPal account NOW!",
            "body": "Your account will be suspended. Click here: http://192.168.1.1/verify",
            "sender": "security@paypa1.tk"
        }
    ]

    for i, email in enumerate(test_emails, 1):
        print(f"\n--- Test Email {i} ---")
        print(f"Subject: {email['subject']}")
        print(f"From: {email['sender']}")

        # Extract features
        classifier = EmailClassifier(MODEL_PATH)
        import asyncio
        asyncio.run(classifier.load_model())
        result = asyncio.run(classifier.classify(
            email['subject'],
            email['body'],
            email['sender']
        ))

        print(f"Classification: {result['classification'].upper()}")
        print(f"Confidence: {result['confidence']:.2%}")
        print(f"Risk Level: {result['risk_level']}")

    print("\n" + "=" * 60)
    print("TRAINING COMPLETE!")
    print("=" * 60)


if __name__ == "__main__":
    main()
