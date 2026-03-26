#!/usr/bin/env python3
"""
Fortnox Comprehensive Security Scanner
Combines URL phishing detection with email classification for complete security analysis.
"""

import asyncio
import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'mcp_server'))

from email_classifier import EmailClassifier


def analyze_url_in_text(text: str) -> list:
    """Extract URLs from text for analysis"""
    import re
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)


async def comprehensive_security_check(email_subject: str, email_body: str,
                                       email_sender: str) -> dict:
    """
    Perform comprehensive security analysis on an email.
    Combines email classification with URL analysis.
    """

    print("=" * 70)
    print("FORTNOX COMPREHENSIVE SECURITY SCAN")
    print("=" * 70)

    # Extract URLs from email
    all_text = f"{email_subject} {email_body}"
    urls_found = analyze_url_in_text(all_text)

    print(f"\n📧 Email Analysis")
    print(f"   Subject: {email_subject}")
    print(f"   From: {email_sender}")
    print(f"   Body preview: {email_body[:100]}...")
    print(f"   URLs found: {len(urls_found)}")

    # Initialize email classifier
    email_classifier = EmailClassifier()
    await email_classifier.load_model()

    # Classify email
    email_result = await email_classifier.classify(
        subject=email_subject,
        body=email_body,
        sender=email_sender,
        links=urls_found
    )

    print(f"\n✅ Email Classification Results")
    print(f"   Classification: {email_result['classification'].upper()}")
    print(f"   Confidence: {email_result['confidence']:.2%}")
    print(f"   Risk Level: {email_result['risk_level']}")

    if email_result.get('warnings'):
        print(f"\n⚠️  Security Warnings:")
        for warning in email_result['warnings']:
            print(f"   • {warning}")

    # Overall threat assessment
    threat_level = "CRITICAL" if email_result['risk_level'] == "High" else \
                   "MODERATE" if email_result['risk_level'] == "Medium" else "LOW"

    print(f"\n🛡️  Overall Threat Level: {threat_level}")
    print("=" * 70)

    return {
        'email_classification': email_result,
        'urls_found': urls_found,
        'threat_level': threat_level
    }


async def main():
    """Main function with example security scans"""

    print("\nFORTNOX - Comprehensive Email & URL Security Scanner\n")

    # Test Case 1: Legitimate email
    print("\n" + "=" * 70)
    print("TEST CASE 1: Legitimate Business Email")
    print("=" * 70)
    await comprehensive_security_check(
        email_subject="Q4 Financial Report Review",
        email_body="Hi team, Please review the attached Q4 financial report. Let's discuss in tomorrow's meeting at 2 PM.",
        email_sender="cfo@company.com"
    )

    # Test Case 2: Phishing email with suspicious URL
    print("\n" + "=" * 70)
    print("TEST CASE 2: Phishing Email with Suspicious URL")
    print("=" * 70)
    await comprehensive_security_check(
        email_subject="URGENT: Your Account Will Be Suspended!",
        email_body="Dear customer, Your account has been compromised. Click here immediately to verify: http://192.168.1.100/verify-account.php?id=12345&token=abc",
        email_sender="security@paypal-verify.tk"
    )

    # Test Case 3: Spam email
    print("\n" + "=" * 70)
    print("TEST CASE 3: Spam/Promotional Email")
    print("=" * 70)
    await comprehensive_security_check(
        email_subject="🎉 YOU'VE WON $10,000! CLAIM NOW!!!",
        email_body="Congratulations! You are our lucky winner! Click here to claim your prize: http://winner-prizes.top/claim?id=999 Act now before this amazing offer expires!",
        email_sender="lottery@free-money-winners.xyz"
    )

    # Test Case 4: Malicious email with ransomware threat
    print("\n" + "=" * 70)
    print("TEST CASE 4: Malicious Email with Ransomware Threat")
    print("=" * 70)
    await comprehensive_security_check(
        email_subject="Your files have been encrypted",
        email_body="Your computer has been infected with ransomware. All files are encrypted. Pay 1.5 Bitcoin to wallet address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa within 24 hours to recover your data. http://darknet-payment.onion/pay",
        email_sender="ransomware@encrypted.cc"
    )

    print("\n" + "=" * 70)
    print("SCAN COMPLETE")
    print("=" * 70)
    print("\n✅ Fortnox Security Scanner Results:")
    print("   • All emails have been analyzed for threats")
    print("   • URLs extracted and flagged when suspicious")
    print("   • Email classification completed")
    print("   • Security warnings generated")
    print("\n🛡️  Your security is our priority!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
