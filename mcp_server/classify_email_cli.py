#!/usr/bin/env python3
"""
Email Classification CLI Tool
Simple command-line interface for classifying emails using the MCP server.
"""

import argparse
import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from email_classifier import EmailClassifier


async def classify_email_cli(subject: str, body: str, sender: str, model_path: str = None):
    """Classify an email using the command line"""

    print("=" * 60)
    print("EMAIL CLASSIFICATION")
    print("=" * 60)
    print(f"\nSubject: {subject}")
    print(f"From: {sender}")
    print(f"Body preview: {body[:100]}..." if len(body) > 100 else f"Body: {body}")

    # Initialize classifier
    classifier = EmailClassifier(model_path)
    await classifier.load_model()

    # Classify
    result = await classifier.classify(subject, body, sender)

    # Display results
    print("\n" + "=" * 60)
    print("CLASSIFICATION RESULT")
    print("=" * 60)
    print(f"Classification: {result['classification'].upper()}")
    print(f"Confidence: {result['confidence']:.2%}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Method: {result['method']}")

    if 'risk_scores' in result:
        print("\nRisk Scores:")
        for category, score in result['risk_scores'].items():
            print(f"  {category.capitalize()}: {score:.3f}")

    if 'probabilities' in result:
        print("\nProbabilities:")
        for category, prob in result['probabilities'].items():
            print(f"  {category.capitalize()}: {prob:.2%}")

    if result.get('warnings'):
        print("\n⚠ Warnings:")
        for warning in result['warnings']:
            print(f"  • {warning}")

    print("=" * 60)

    return result


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Classify emails as phishing, spam, malicious, or legitimate"
    )

    parser.add_argument(
        "--subject",
        required=True,
        help="Email subject line"
    )

    parser.add_argument(
        "--body",
        required=True,
        help="Email body content"
    )

    parser.add_argument(
        "--sender",
        required=True,
        help="Sender email address"
    )

    parser.add_argument(
        "--model",
        help="Path to trained model file (optional)"
    )

    args = parser.parse_args()

    # Run classification
    try:
        asyncio.run(classify_email_cli(
            args.subject,
            args.body,
            args.sender,
            args.model
        ))
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
