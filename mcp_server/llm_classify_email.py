#!/usr/bin/env python3
"""
LLM Email Classification CLI Tool
Uses actual AI (Claude or GPT) for intelligent email analysis.
"""

import argparse
import asyncio
import sys
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from llm_email_classifier import LLMEmailClassifier


async def classify_email_cli(subject: str, body: str, sender: str,
                            provider: str = "anthropic"):
    """Classify an email using LLM"""

    print("=" * 70)
    print("LLM-POWERED EMAIL CLASSIFICATION")
    print("=" * 70)
    print(f"\nProvider: {provider.upper()}")
    print(f"Subject: {subject}")
    print(f"From: {sender}")
    print(f"Body preview: {body[:100]}..." if len(body) > 100 else f"Body: {body}")

    # Initialize LLM classifier
    try:
        classifier = LLMEmailClassifier(provider=provider)
    except ValueError as e:
        print(f"\n❌ Error: {e}")
        print("\nPlease set the appropriate API key in your .env file or environment:")
        print("  - ANTHROPIC_API_KEY for Claude/Anthropic")
        print("  - OPENAI_API_KEY for OpenAI/GPT")
        sys.exit(1)

    print("\n⏳ Analyzing email with AI...")

    # Classify
    result = await classifier.classify(subject, body, sender)

    # Display results
    print("\n" + "=" * 70)
    print("AI CLASSIFICATION RESULT")
    print("=" * 70)

    if "error" in result:
        print(f"❌ Error: {result['error']}")
        return result

    print(f"Classification: {result['classification'].upper()}")
    print(f"Confidence: {result['confidence']:.1%}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Method: {result.get('method', 'llm-based')}")
    print(f"Model: {result.get('model', 'N/A')}")

    if result.get('reasoning'):
        print(f"\n🤔 AI Reasoning:")
        print(f"   {result['reasoning']}")

    if result.get('risk_indicators'):
        print(f"\n⚠️  Risk Indicators:")
        for indicator in result['risk_indicators']:
            print(f"   • {indicator}")

    if result.get('recommendations'):
        print(f"\n💡 Recommendations:")
        print(f"   {result['recommendations']}")

    print("=" * 70)

    return result


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="Classify emails using AI (Claude or GPT)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using Claude/Anthropic (default)
  python llm_classify_email.py \\
    --subject "Meeting tomorrow" \\
    --body "Hi team, meeting at 2pm" \\
    --sender "manager@company.com"

  # Using OpenAI/GPT
  python llm_classify_email.py \\
    --provider openai \\
    --subject "URGENT: Verify your account" \\
    --body "Click here to verify..." \\
    --sender "security@example.com"

Environment variables required:
  ANTHROPIC_API_KEY  - For Claude/Anthropic (default)
  OPENAI_API_KEY     - For OpenAI/GPT
  LLM_PROVIDER       - Optional: "anthropic" or "openai"
        """
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
        "--provider",
        choices=["anthropic", "openai"],
        default=os.getenv("LLM_PROVIDER", "anthropic"),
        help="LLM provider to use (default: anthropic)"
    )

    args = parser.parse_args()

    # Run classification
    try:
        asyncio.run(classify_email_cli(
            args.subject,
            args.body,
            args.sender,
            args.provider
        ))
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
