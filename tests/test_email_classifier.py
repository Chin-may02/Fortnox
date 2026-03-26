"""
Test script for Email Phishing Classifier

This script tests the email classification endpoint with sample phishing
and legitimate email examples.
"""

import requests
import json

# Flask API endpoint
API_URL = "http://127.0.0.1:5000/check_email"


# Test cases
test_emails = [
    {
        "name": "Legitimate Email - Personal",
        "data": {
            "from_email": "john.doe@company.com",
            "from_name": "John Doe",
            "subject": "Meeting tomorrow at 2pm",
            "body_text": "Hi, just wanted to confirm our meeting tomorrow at 2pm. See you then! Best, John",
            "to_email": "me@example.com"
        },
        "expected": "safe"
    },
    {
        "name": "Phishing - Fake PayPal",
        "data": {
            "from_email": "security@paypa1-verify.tk",
            "from_name": "PayPal Security Team",
            "subject": "URGENT: Verify your account NOW or it will be SUSPENDED!",
            "body_text": "Dear valued customer, Your PayPal account has been temporarily suspended due to unusual activity. Click here immediately to verify: http://paypal-secure-login.tk/verify",
            "reply_to": "phishing@suspicious.com",
            "to_email": "victim@example.com",
            "attachments": []
        },
        "expected": "phishing"
    },
    {
        "name": "Phishing - Prize Scam",
        "data": {
            "from_email": "winner@lottery-claim.xyz",
            "from_name": "MICROSOFT LOTTERY",
            "subject": "CONGRATULATIONS! YOU WON $1,000,000!!!",
            "body_text": "DEAR WINNER, YOU HAVE WON ONE MILLION DOLLARS IN THE MICROSOFT LOTTERY! CLAIM YOUR PRIZE NOW by sending your bank details to claim-prize@winner-center.tk. ACT FAST - OFFER EXPIRES TODAY!",
            "to_email": "victim@example.com",
            "attachments": []
        },
        "expected": "phishing"
    },
    {
        "name": "Phishing - Fake Bank",
        "data": {
            "from_email": "security-alert@bank-0f-america.com",
            "from_name": "Bank of America",
            "subject": "Security Alert - Action Required",
            "body_text": "Dear customer, We detected suspicious activity on your account. Please verify your identity immediately by logging in: http://bank-verify-secure.com/login.php",
            "to_email": "victim@example.com",
            "attachments": ["account_details.exe"]
        },
        "expected": "phishing"
    },
    {
        "name": "Legitimate Email - Newsletter",
        "data": {
            "from_email": "newsletter@github.com",
            "from_name": "GitHub",
            "subject": "Your weekly GitHub digest",
            "body_text": "Hello! Here's what happened in your repositories this week: 5 new stars, 3 new forks. Check out the trending repositories in Python.",
            "to_email": "user@example.com"
        },
        "expected": "safe"
    },
    {
        "name": "Suspicious - Urgency Tactics",
        "data": {
            "from_email": "support@random-service.com",
            "from_name": "Customer Support",
            "subject": "URGENT: Your payment failed - Update billing NOW!",
            "body_text": "Your recent payment failed. Update your billing information immediately to avoid service suspension. Click here: http://bit.ly/3xYz123",
            "to_email": "customer@example.com",
            "attachments": []
        },
        "expected": "suspicious"
    }
]


def test_email_classification():
    """Run tests on email classifier"""
    print("=" * 80)
    print("FORTNOX Email Classifier - Test Suite")
    print("=" * 80)
    print()

    passed = 0
    failed = 0

    for i, test in enumerate(test_emails, 1):
        print(f"Test {i}: {test['name']}")
        print("-" * 80)

        try:
            # Send request
            response = requests.post(API_URL, json=test['data'], timeout=10)

            if response.status_code != 200:
                print(f"❌ FAILED: HTTP {response.status_code}")
                print(f"   Response: {response.text}")
                failed += 1
                print()
                continue

            result = response.json()

            # Display results
            print(f"From: {test['data']['from_email']}")
            print(f"Subject: {test['data']['subject']}")
            print()
            print(f"Prediction: {result['prediction'].upper()}")
            print(f"Risk Score: {result['riskScore']:.2%}")
            print(f"Risk Level: {result['riskLevel']}")
            print()

            if result.get('riskFactors'):
                print("Risk Factors:")
                for factor in result['riskFactors']:
                    print(f"  • {factor}")
                print()

            if result.get('urlAnalysis'):
                print(f"URLs Analyzed: {len(result['urlAnalysis'])}")
                for url_info in result['urlAnalysis'][:3]:  # Show first 3
                    print(f"  • {url_info['url']}: {url_info['classification']} ({url_info['risk']:.2%})")
                print()

            # Check if prediction matches expected
            expected = test['expected']
            actual = result['prediction']

            # Allow some flexibility in matching
            match = (
                (expected == "safe" and actual == "safe") or
                (expected == "phishing" and actual in ["phishing", "suspicious"]) or
                (expected == "suspicious" and actual in ["suspicious", "phishing"])
            )

            if match:
                print(f"✅ PASSED (Expected: {expected}, Got: {actual})")
                passed += 1
            else:
                print(f"❌ FAILED (Expected: {expected}, Got: {actual})")
                failed += 1

        except requests.exceptions.ConnectionError:
            print(f"❌ FAILED: Cannot connect to API at {API_URL}")
            print("   Make sure Flask server is running: python app/app.py")
            failed += 1
        except requests.exceptions.Timeout:
            print(f"❌ FAILED: Request timeout")
            failed += 1
        except Exception as e:
            print(f"❌ FAILED: {str(e)}")
            failed += 1

        print()

    # Summary
    print("=" * 80)
    print("Test Summary")
    print("=" * 80)
    print(f"Total Tests: {len(test_emails)}")
    print(f"Passed: {passed} ✅")
    print(f"Failed: {failed} ❌")
    print(f"Success Rate: {passed/len(test_emails)*100:.1f}%")
    print()

    if failed == 0:
        print("🎉 All tests passed!")
    else:
        print("⚠️  Some tests failed. Review the output above.")

    return passed, failed


if __name__ == "__main__":
    print("\n🚀 Starting email classifier tests...")
    print("⚠️  Make sure Flask server is running: python app/app.py")
    print()
    input("Press Enter to continue...")
    print()

    passed, failed = test_email_classification()

    # Exit code for CI/CD
    exit(0 if failed == 0 else 1)
